"""Тесты для исправлений Discord CDN/Media загрузки аватарок и картинок,
Single-Flight DNS, пропуска избыточного DoH, синхронизации белого списка и MAJOR_BLOCKED_PATTERNS.
"""

import unittest
from unittest.mock import MagicMock, patch
import time
import socket

from flowguard.proxy import (
    DPIBypassProxy,
    DISCORD_CLOUDFLARE_ANYCAST_IPS,
    DISCORD_CORE_ANYCAST_IPS,
    DISCORD_CDN_ANYCAST_IPS,
    DISCORD_MEDIA_ANYCAST_IPS,
    is_discord_media_host,
    is_discord_network_host,
    mark_ip_working,
    mark_ip_dead,
    _WORKING_IP_CACHE,
    _DEAD_IP_CACHE,
    _get_host_lock,
    _set_socket_meta,
    _get_socket_meta,
)
from flowguard.config import Config
from flowguard.strategy import (
    ThompsonStrategySelector,
    MAJOR_BLOCKED_PATTERNS,
)


class TestDiscordCDNAndWhitelistFixes(unittest.TestCase):
    """Проверка исправлений Discord CDN, Whitelist и Single-Flight DNS."""

    def setUp(self):
        self.config = Config()
        self.proxy = DPIBypassProxy(self.config)
        self.proxy.shadow_prober = MagicMock()
        _WORKING_IP_CACHE.clear()
        _DEAD_IP_CACHE.clear()

    def tearDown(self):
        _WORKING_IP_CACHE.clear()
        _DEAD_IP_CACHE.clear()

    def test_discord_cloudflare_anycast_pool_expanded(self):
        """Проверяет, что DISCORD_CLOUDFLARE_ANYCAST_IPS содержит все verified API, CDN и Media IP."""
        expected_ips = [
            # Discord API / Gateway
            "162.159.136.232", "162.159.134.234", "162.159.137.232", "162.159.138.232",
            # Discord CDN (cdn.discordapp.com, attachments)
            "162.159.129.233", "162.159.130.233", "162.159.133.233", "162.159.134.233", "162.159.135.233",
            # Discord Media (media.discordapp.net, images-ext)
            "162.159.128.232", "162.159.129.232", "162.159.130.232", "162.159.133.232", "162.159.134.232"
        ]
        for ip in expected_ips:
            self.assertIn(ip, DISCORD_CLOUDFLARE_ANYCAST_IPS)

    def test_is_discord_network_host_and_media_host(self):
        """Проверяет правильность классификации сетевых и медиа хостов Discord."""
        self.assertTrue(is_discord_network_host("cdn.discordapp.com"))
        self.assertTrue(is_discord_network_host("media.discordapp.net"))
        self.assertTrue(is_discord_network_host("images-ext-1.discordapp.net"))
        self.assertTrue(is_discord_network_host("attachments.discord.net"))
        self.assertTrue(is_discord_network_host("discord.com"))
        self.assertTrue(is_discord_network_host("gateway.discord.gg"))
        self.assertFalse(is_discord_network_host("rotterdam.discord.media"))

        self.assertTrue(is_discord_media_host("cdn.discordapp.com"))
        self.assertTrue(is_discord_media_host("media.discordapp.net"))
        self.assertTrue(is_discord_media_host("images-ext-2.discordapp.net"))
        self.assertFalse(is_discord_media_host("discord.com"))
        self.assertFalse(is_discord_media_host("gateway.discord.gg"))

    def test_discord_media_ttl_300s(self):
        """Для Discord Media TTL кэша рабочих IP устанавливается в 300 секунд, предотвращая устаревание в чате."""
        host = "cdn.discordapp.com"
        ip = "162.159.130.233"
        mark_ip_working(ip, host)
        self.assertEqual(_WORKING_IP_CACHE.get(host), ip)

        # Спустя 20 секунд IP все еще в кэше (300с TTL)
        with patch("time.time", return_value=time.time() + 20.0):
            self.assertEqual(_WORKING_IP_CACHE.get(host), ip)

        # Спустя 305 секунд IP истекает
        with patch("time.time", return_value=time.time() + 305.0):
            self.assertIsNone(_WORKING_IP_CACHE.get(host))

    def test_discord_media_probe_warms_cache_immediately(self):
        """При успешном рукопожатии Discord CDN сразу прогревает кэш для параллельных потоков аватарок."""
        client_sock = MagicMock()
        mock_sock = MagicMock()
        target_ip = "162.159.130.233"
        _set_socket_meta(mock_sock, target_ip=target_ip, connect_rtt=0.02)
        self.proxy._probe_socket_response = MagicMock(return_value=("success", b"\x16\x03\x03\x00\x50", 15.0))
        self.proxy._send_tls_client_hello_with_bypass = MagicMock(return_value=("combo_tlsrec_tcpsplit", "cdn.discordapp.com"))

        with patch("flowguard.proxy.is_tls_client_hello", return_value=True):
            res_sock, strat, eff_host, resp = self.proxy._handshake_with_fast_fallback(
                client_sock, mock_sock, "cdn.discordapp.com", 443, b"\x16\x03\x01\x00\x10"
            )
        self.assertIsNotNone(res_sock)
        self.assertEqual(_WORKING_IP_CACHE.get("cdn.discordapp.com"), target_ip)

    def test_discord_core_ttl_300s(self):
        """Для Discord Core (discord.com) TTL кэша рабочих IP также устанавливается в 300 секунд."""
        host = "discord.com"
        ip = "162.159.136.232"
        mark_ip_working(ip, host)
        self.assertEqual(_WORKING_IP_CACHE.get(host), ip)

        # Спустя 20 секунд IP все еще в кэше (300с TTL)
        with patch("time.time", return_value=time.time() + 20.0):
            self.assertEqual(_WORKING_IP_CACHE.get(host), ip)

        # Спустя 305 секунд IP истекает
        with patch("time.time", return_value=time.time() + 305.0):
            self.assertIsNone(_WORKING_IP_CACHE.get(host))

    def test_discord_core_probe_preserves_pmtu_guard(self):
        """Для discord.com рукопожатие не кэширует IP до получения реальных данных (PMTU 32KB Black Hole guard)."""
        client_sock = MagicMock()
        mock_sock = MagicMock()
        target_ip = "162.159.136.232"
        _set_socket_meta(mock_sock, target_ip=target_ip, connect_rtt=0.02)
        self.proxy._probe_socket_response = MagicMock(return_value=("success", b"\x16\x03\x03\x00\x50", 15.0))
        self.proxy._send_tls_client_hello_with_bypass = MagicMock(return_value=("combo_tlsrec_tcpsplit", "discord.com"))

        with patch("flowguard.proxy.is_tls_client_hello", return_value=True):
            res_sock, strat, eff_host, resp = self.proxy._handshake_with_fast_fallback(
                client_sock, mock_sock, "discord.com", 443, b"\x16\x03\x01\x00\x10"
            )
        self.assertIsNotNone(res_sock)
        self.assertIsNone(_WORKING_IP_CACHE.get("discord.com"))

    def test_discord_cdn_anycast_rotation_cycles_across_requests(self):
        """Параллельные запросы к cdn.discordapp.com циклически перебирают Anycast IP из DISCORD_CDN_ANYCAST_IPS."""
        connected_ips = []

        with patch("socket.getaddrinfo", return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("162.159.130.233", 443))
        ]):
            for _ in range(3):
                mock_sock = MagicMock()
                mock_sock.connect_ex.return_value = 0
                with patch("socket.socket", return_value=mock_sock):
                    s = self.proxy._connect_target("cdn.discordapp.com", 443)
                    self.assertIsNotNone(s)
                    meta = _get_socket_meta(s)
                    connected_ips.append(meta.get("target_ip"))

        # Проверяем, что подключились к разным IP из пула CDN
        self.assertEqual(len(connected_ips), 3)
        for ip in connected_ips:
            self.assertIn(ip, DISCORD_CDN_ANYCAST_IPS)
        # Все 3 вызова получили РАЗНЫЕ IP благодаря ротации
        self.assertEqual(len(set(connected_ips)), 3)

    def test_single_flight_lock_prevents_doh_stampede(self):
        """Single-Flight замок гарантирует, что для одного хоста выдается один замок."""
        lock1 = _get_host_lock("cdn.discordapp.com")
        lock2 = _get_host_lock("cdn.discordapp.com")
        lock3 = _get_host_lock("CDN.DISCORDAPP.COM.")
        self.assertIs(lock1, lock2)
        self.assertIs(lock1, lock3)

    def test_select_strategy_with_is_whitelisted_returns_combo(self):
        """При is_whitelisted=True select_strategy гарантированно возвращает combo_tlsrec_tcpsplit."""
        engine = ThompsonStrategySelector()
        domain = "proton.me"
        strat = engine.select_strategy(domain, is_whitelisted=True)
        self.assertEqual(strat, "combo_tlsrec_tcpsplit")

        domain2 = "soundcloud.com"
        strat2 = engine.select_strategy(domain2, is_whitelisted=True)
        self.assertEqual(strat2, "combo_tlsrec_tcpsplit")

    def test_major_blocked_patterns_contain_required_domains(self):
        """MAJOR_BLOCKED_PATTERNS содержит proton.me, soundcloud.com, signal.org, gulagu.net и зеркала."""
        for pattern in ("proton.me", "protonweb.com", "soundcloud.com", "sndcdn.com", "signal.org", "gulagu.net"):
            self.assertIn(pattern, MAJOR_BLOCKED_PATTERNS)

    def test_dead_ips_not_revived_with_fallback_alive(self):
        """Если все IP хоста находятся в _DEAD_IP_CACHE, _connect_target возвращает None немедленно."""
        host = "dead-host.example.com"
        dead_ip = "198.51.100.1"
        mark_ip_dead(dead_ip, duration=300.0)
        self.proxy.doh_harvester = None
        self.proxy.dns_failover = None

        with patch("socket.getaddrinfo", return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (dead_ip, 443))
        ]), patch("flowguard.proxy.resolve_fallback_dns", return_value=None):
            sock = self.proxy._connect_target(host, 443)
            self.assertIsNone(sock)


if __name__ == "__main__":
    unittest.main()

