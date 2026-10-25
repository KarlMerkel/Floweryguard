"""Unit-тесты для верификации фиксов YouTube обложек, Discord аватарок и RuTracker (HTTP 301)."""

import unittest
import socket
import inspect
import hashlib
from unittest.mock import MagicMock, patch

from flowguard.proxy import (
    DPIBypassProxy,
    YOUTUBE_WEB_ANYCAST_IPS,
    GOOGLE_EDGE_ANYCAST_IPS,
    _set_socket_meta,
    is_ip_dead,
    mark_ip_working,
    _WORKING_IP_CACHE,
    _DEAD_IP_CACHE
)
import Floweryguard.proxy as release_proxy
from flowguard.strategy import get_strategy_engine, ThompsonStrategySelector
import Floweryguard.strategy as release_strategy
from flowguard.config import Config, load_whitelist_domains, is_host_in_whitelist


class TestLiveFixesYtDiscordRuTracker(unittest.TestCase):

    def setUp(self):
        self.config = Config()
        self.proxy = DPIBypassProxy(self.config)
        self.proxy.is_running = True
        self.release_proxy = release_proxy.DPIBypassProxy(self.config)
        self.release_proxy.is_running = True
        self.engine = get_strategy_engine()

    # =========================================================================
    # 1. YouTube Thumbnails (i.ytimg.com, yt3.ggpht.com) Anycast IP Fixes
    # =========================================================================

    def test_youtube_anycast_pool_contains_tested_ips(self):
        """Проверяет наличие всех протестированных Anycast IP в пулах flowguard и release."""
        required_ips = [
            "209.85.233.119",
            "142.250.150.119",
            "64.233.163.119",
            "64.233.164.198",
            "64.233.162.198"
        ]
        for ip in required_ips:
            self.assertIn(ip, YOUTUBE_WEB_ANYCAST_IPS)
            self.assertIn(ip, release_proxy.YOUTUBE_WEB_ANYCAST_IPS)
            self.assertIn(ip, GOOGLE_EDGE_ANYCAST_IPS)
            self.assertIn(ip, release_proxy.GOOGLE_EDGE_ANYCAST_IPS)

    def test_youtube_thumbnail_prioritizes_anycast_at_head_over_blocked_dns_ip(self):
        """Для хостов обложек (i.ytimg.com, yt3.ggpht.com) Anycast IP ставятся в начало candidate_ips,
        предотвращая зависание на мертвом провайдерском IP (например 108.177.14.119, 74.125.131.198).
        """
        dead_dns_ip = "108.177.14.119"
        # Эмулируем, что системный DNS вернул заблокированный TSPU IP 108.177.14.119
        fake_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (dead_dns_ip, 443))]

        with patch("socket.getaddrinfo", return_value=fake_addrinfo), \
             patch("socket.socket") as mock_sock_cls, \
             patch("select.select", return_value=([MagicMock()], [MagicMock()], [])):
            mock_s = MagicMock()
            mock_sock_cls.return_value = mock_s
            mock_s.connect_ex.return_value = 0
            self.proxy.doh_harvester = None
            self.proxy.dns_failover = None

            with patch("flowguard.proxy.resolve_fallback_dns", return_value=None):
                sock = self.proxy._connect_target("i.ytimg.com", 443)
                self.assertIsNotNone(sock)
                # Первый IP, к которому подключился сокет, должен быть из Anycast пула, а НЕ dead_dns_ip!
                target_ip = mock_s.connect_ex.call_args[0][0][0]
                self.assertIn(target_ip, YOUTUBE_WEB_ANYCAST_IPS)
                self.assertEqual(target_ip, YOUTUBE_WEB_ANYCAST_IPS[0])

    def test_youtube_avatar_host_prioritizes_anycast(self):
        """Для хоста yt3.ggpht.com Anycast IP также приоритизируются в начале списка кандидатов."""
        dead_dns_ip = "74.125.131.198"
        fake_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (dead_dns_ip, 443))]

        with patch("socket.getaddrinfo", return_value=fake_addrinfo), \
             patch("socket.socket") as mock_sock_cls, \
             patch("select.select", return_value=([MagicMock()], [MagicMock()], [])):
            mock_s = MagicMock()
            mock_sock_cls.return_value = mock_s
            mock_s.connect_ex.return_value = 0
            self.proxy.doh_harvester = None
            self.proxy.dns_failover = None

            with patch("flowguard.proxy.resolve_fallback_dns", return_value=None):
                sock = self.proxy._connect_target("yt3.ggpht.com", 443)
                self.assertIsNotNone(sock)
                target_ip = mock_s.connect_ex.call_args[0][0][0]
                self.assertIn(target_ip, YOUTUBE_WEB_ANYCAST_IPS)

    def test_youtube_web_includes_anycast_even_with_dns_results(self):
        """Для www.youtube.com Anycast IP всегда добавляются в кандидаты, даже если DNS вернул IP."""
        dns_ip = "192.0.2.1"
        fake_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (dns_ip, 443))]

        with patch("socket.getaddrinfo", return_value=fake_addrinfo), \
             patch("socket.socket") as mock_sock_cls, \
             patch("select.select", return_value=([MagicMock()], [MagicMock()], [])):
            mock_s = MagicMock()
            mock_sock_cls.return_value = mock_s
            mock_s.connect_ex.return_value = 0
            self.proxy.doh_harvester = None
            self.proxy.dns_failover = None

            with patch("flowguard.proxy.resolve_fallback_dns", return_value=None):
                # Проверяем, что в цикле перебора кандидатов Anycast IP присутствуют
                mock_s.connect_ex.side_effect = [-1, 0]  # первый (DNS) упал, второй (Anycast) успешен
                sock = self.proxy._connect_target("www.youtube.com", 443)
                self.assertIsNotNone(sock)
                second_ip = mock_s.connect_ex.call_args[0][0][0]
                self.assertIn(second_ip, YOUTUBE_WEB_ANYCAST_IPS)

    # =========================================================================
    # 2. Discord Media & Avatars (cdn.discordapp.com, media.discordapp.net)
    # =========================================================================

    def test_discord_media_strictly_uses_combo_tlsrec_tcpsplit(self):
        """Discord media хосты жестко выбирают стратегию combo_tlsrec_tcpsplit."""
        media_hosts = [
            "cdn.discordapp.com",
            "media.discordapp.net",
            "attachments.discord.net",
            "images-ext-1.discordapp.net",
            "discord.net"
        ]
        for host in media_hosts:
            strat = self.engine.select_strategy(host)
            self.assertEqual(strat, "combo_tlsrec_tcpsplit", f"Failed for {host}")
            rel_strat = release_strategy.get_strategy_engine().select_strategy(host)
            self.assertEqual(rel_strat, "combo_tlsrec_tcpsplit", f"Failed for release {host}")

    def test_discord_media_excludes_tcp_split_sni_mid(self):
        """Для Discord media техника tcp_split_sni_mid строго исключена из кандидатов и фоллбэка."""
        priors = self.engine._init_domain_priors("cdn.discordapp.com")
        self.assertEqual(priors["combo_tlsrec_tcpsplit"], [12.0, 1.0])
        self.assertEqual(priors["tcp_split_sni_mid"], [1.0, 5.0])

        fb = self.engine.get_fallback_strategy("cdn.discordapp.com", failed_strategy="combo_tlsrec_tcpsplit")
        self.assertNotEqual(fb, "tcp_split_sni_mid")

    def test_discord_media_small_image_records_success_and_does_not_mark_dead(self):
        """Скачивание мелкого аватара (<32KB, напр. 4096 байт) фиксирует успех и НЕ помечает IP мертвым."""
        host = "cdn.discordapp.com"
        target_ip = "162.159.130.233"
        mark_ip_working(target_ip, host)

        client_sock = MagicMock()
        target_sock = MagicMock()
        _set_socket_meta(target_sock, target_ip=target_ip, connect_rtt=0.020)

        # Сервер отправляет 4096 байт аватарки и закрывает сокет (EOF)
        target_sock.recv.side_effect = [b"GIF89a" + b"X" * 4090, b""]
        client_sock.recv.return_value = b""

        call_count = [0]
        def fake_select(r, w, x, timeout):
            call_count[0] += 1
            if call_count[0] == 1:
                return ([target_sock], [], [])
            elif call_count[0] == 2:
                return ([target_sock], [], [])  # EOF от сервера
            return ([], [], [])

        with patch("select.select", side_effect=fake_select), \
             patch.object(self.proxy.strategy_engine, "record_success") as mock_success, \
             patch.object(self.proxy.strategy_engine, "record_failure") as mock_fail:

            self.proxy._pipe_sockets(
                client_sock,
                target_sock,
                host=host,
                strategy="combo_tlsrec_tcpsplit"
            )

            mock_success.assert_called_with(host, "combo_tlsrec_tcpsplit", ip=target_ip)
            mock_fail.assert_not_called()
            self.assertFalse(is_ip_dead(target_ip))

    def test_whitelist_contains_discord_net(self):
        """Проверяет наличие discord.net и *.discord.net в whitelist.txt."""
        domains, _ = load_whitelist_domains("whitelist.txt")
        self.assertTrue(is_host_in_whitelist("discord.net", domains))
        self.assertTrue(is_host_in_whitelist("media.discord.net", domains))
        self.assertTrue(is_host_in_whitelist("attachments.discord.net", domains))

    # =========================================================================
    # 3. RuTracker & Blocked Websites ("Белый экран", HTTP 301)
    # =========================================================================

    def test_whitelist_contains_rutracker_domains(self):
        """Проверяет наличие всех зеркал и статических CDN RuTracker в whitelist.txt."""
        domains, _ = load_whitelist_domains("whitelist.txt")
        rutracker_hosts = [
            "rutracker.org",
            "static.rutracker.cc",
            "feed.rutracker.cc",
            "rutracker.net",
            "rutracker.cc",
            "rutracker.wiki"
        ]
        for host in rutracker_hosts:
            self.assertTrue(is_host_in_whitelist(host, domains), f"Missing {host} in whitelist")

    def test_http_301_redirect_for_whitelisted_host(self):
        """Незашифрованный HTTP-запрос (порт 80) к rutracker.org мгновенно перенаправляется на HTTPS 301."""
        client_sock = MagicMock()
        raw_req = b"GET /forum/viewtopic.php?t=123 HTTP/1.1\r\nHost: rutracker.org\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        target = "http://rutracker.org/forum/viewtopic.php?t=123"

        self.proxy._handle_http_request(client_sock, raw_req, target)

        # Проверяем отправку 301 Moved Permanently с правильным Location
        client_sock.sendall.assert_called_once()
        sent_data = client_sock.sendall.call_args[0][0].decode("latin1")
        self.assertIn("HTTP/1.1 301 Moved Permanently", sent_data)
        self.assertIn("Location: https://rutracker.org/forum/viewtopic.php?t=123", sent_data)
        client_sock.shutdown.assert_called_with(socket.SHUT_WR)

    def test_http_301_redirect_ipv6_host_bracketed(self):
        """HTTP 301 Location для IPv6 литерала обязан содержать квадратные скобки https://[IPv6]/path (RFC 3986)."""
        client_sock = MagicMock()
        raw_req = b"GET /forum/index.php HTTP/1.1\r\nHost: [2a02:6b8::1]\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        target = "http://[2a02:6b8::1]/forum/index.php"

        # Добавляем в whitelist для проверки 301
        with patch.object(self.proxy, "whitelist_domains", {"2a02:6b8::1", "[2a02:6b8::1]"}):
            self.proxy._handle_http_request(client_sock, raw_req, target)

            client_sock.sendall.assert_called_once()
            sent_data = client_sock.sendall.call_args[0][0].decode("latin1")
            self.assertIn("HTTP/1.1 301 Moved Permanently", sent_data)
            self.assertIn("Location: https://[2a02:6b8::1]/forum/index.php", sent_data)

    def test_http_301_redirect_path_normalization(self):
        """HTTP 301 Location корректно нормализует путь без слэша (например, ?query=1 -> /?query=1)."""
        client_sock = MagicMock()
        raw_req = b"GET http://rutracker.org?query=1 HTTP/1.1\r\nHost: rutracker.org\r\n\r\n"
        target = "http://rutracker.org?query=1"

        self.proxy._handle_http_request(client_sock, raw_req, target)

        client_sock.sendall.assert_called_once()
        sent_data = client_sock.sendall.call_args[0][0].decode("latin1")
        self.assertIn("Location: https://rutracker.org/?query=1", sent_data)

    def test_http_400_for_empty_host(self):
        """HTTP-запрос без заголовка Host и без хоста в URI возвращает 400 Bad Request без попытки соединения с loopback."""
        client_sock = MagicMock()
        raw_req = b"GET / HTTP/1.1\r\nUser-Agent: curl/7.68.0\r\n\r\n"
        target = "/"

        with patch.object(self.proxy, "_connect_target") as mock_connect:
            self.proxy._handle_http_request(client_sock, raw_req, target)
            mock_connect.assert_not_called()
            client_sock.sendall.assert_called_once()
            sent = client_sock.sendall.call_args[0][0].decode("latin1")
            self.assertIn("HTTP/1.1 400 Bad Request", sent)

    def test_rutracker_strategy_pinned_to_combo(self):
        """RuTracker и другие заблокированные торрент-трекеры привязаны к combo_tlsrec_tcpsplit."""
        trackers = ["rutracker.org", "nnmclub.to", "rutor.info", "kinozal.tv", "static.t-ru.org"]
        for t in trackers:
            strat = self.engine.select_strategy(t)
            self.assertEqual(strat, "combo_tlsrec_tcpsplit", f"Failed for {t}")

    def test_tracker_fallback_never_uses_direct(self):
        """Фоллбэк для торрент-трекеров (RuTracker и др.) никогда не выбирает direct (ТСПУ блокирует unfragmented)."""
        host = "rutracker.org"
        fb = self.engine.get_fallback_strategy(host, failed_strategy="combo_tlsrec_tcpsplit")
        self.assertNotEqual(fb, "direct")
        self.assertIn(fb, ["tcp_split_sni_mid", "tcp_split_sni_start", "multi_split", "tls_record_frag"])

    def test_discord_net_in_discord_cdn_cluster(self):
        """discord.net и attachments.discord.net правильно классифицируются в кластер discord."""
        from flowguard.strategy import classify_cdn_cluster
        self.assertEqual(classify_cdn_cluster("discord.net"), "discord")
        self.assertEqual(classify_cdn_cluster("attachments.discord.net"), "discord")
        self.assertEqual(classify_cdn_cluster("media.discord.net"), "discord")

    def test_youtube_googleusercontent_prioritizes_anycast(self):
        """Для хостов аватарок Google/YouTube (lh3.googleusercontent.com) Anycast IP приоритизируются во главе."""
        dead_dns_ip = "108.177.14.119"
        fake_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (dead_dns_ip, 443))]

        with patch("socket.getaddrinfo", return_value=fake_addrinfo), \
             patch("socket.socket") as mock_sock_cls, \
             patch("select.select", return_value=([MagicMock()], [MagicMock()], [])):
            mock_s = MagicMock()
            mock_sock_cls.return_value = mock_s
            mock_s.connect_ex.return_value = 0
            self.proxy.doh_harvester = None
            self.proxy.dns_failover = None

            with patch("flowguard.proxy.resolve_fallback_dns", return_value=None):
                sock = self.proxy._connect_target("lh3.googleusercontent.com", 443)
                self.assertIsNotNone(sock)
                target_ip = mock_s.connect_ex.call_args[0][0][0]
                self.assertIn(target_ip, YOUTUBE_WEB_ANYCAST_IPS)
                self.assertEqual(target_ip, YOUTUBE_WEB_ANYCAST_IPS[0])

    # =========================================================================
    # 4. Strict Codebase Parity (1:1 Bitwise Equality)
    # =========================================================================

    def test_strict_codebase_parity(self):
        """Гарантирует 1:1 побитовое соответствие между flowguard и Flowery_Release/Floweryguard."""
        file_pairs = [
            ("flowguard/proxy.py", "Flowery_Release/Floweryguard/proxy.py"),
            ("flowguard/strategy.py", "Flowery_Release/Floweryguard/strategy.py"),
            ("whitelist.txt", "Flowery_Release/whitelist.txt"),
        ]
        for f1, f2 in file_pairs:
            h1 = hashlib.sha256(open(f1, "rb").read()).hexdigest()
            h2 = hashlib.sha256(open(f2, "rb").read()).hexdigest()
            self.assertEqual(h1, h2, f"Hash mismatch between {f1} and {f2}")


if __name__ == "__main__":
    unittest.main()
