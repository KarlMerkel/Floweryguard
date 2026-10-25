import unittest
import socket
from unittest.mock import MagicMock, patch
from flowguard.config import Config

from flowguard.proxy import (
    DPIBypassProxy,
    is_bogon_or_sinkhole_ip,
    DISCORD_CDN_ANYCAST_IPS,
)


class TestDiscordBogonAndTimeoutFixes(unittest.TestCase):
    """Тесты фильтрации Fake-IP 198.18.0.0/15 и расширенного таймаута для медиа Discord."""

    def test_is_bogon_or_sinkhole_ip_filters_rfc2544_fake_ip(self):
        """Проверяет, что подсети RFC 2544 / Fake-IP (198.18.x.x и 198.19.x.x) фильтруются как богон."""
        self.assertTrue(is_bogon_or_sinkhole_ip("198.18.0.11"))
        self.assertTrue(is_bogon_or_sinkhole_ip("198.18.1.1"))
        self.assertTrue(is_bogon_or_sinkhole_ip("198.19.255.254"))
        # Публичные Anycast IP не должны фильтроваться
        self.assertFalse(is_bogon_or_sinkhole_ip("162.159.128.232"))
        self.assertFalse(is_bogon_or_sinkhole_ip("173.194.178.225"))

    def test_single_candidate_safe_access_without_config(self):
        """Проверяет, что при 1 кандидате в IP _connect_target безопасно читает enable_custom_dns."""
        proxy = object.__new__(DPIBypassProxy)
        proxy.timeout = 5.0
        proxy.dns_failover = None
        proxy.doh_harvester = None
        # proxy.config отсутствует намеренно (проверка на AttributeError)

        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0

        with patch("socket.socket", return_value=mock_sock):
            res = proxy._connect_target("example.com", 443, target_ip="93.184.216.34")
            self.assertIsNotNone(res)

    def test_pipe_sockets_select_timeout_uses_max_for_media(self):
        """Проверяет, что для media Discord таймаут ожидания ответа составляет не менее 15.0с даже при self.timeout=5.0."""
        import inspect
        source = inspect.getsource(DPIBypassProxy._pipe_sockets)
        self.assertIn("select_timeout = max(15.0, float(self.timeout))", source)


    def test_attachments_discord_net_fallback_to_media_anycast(self):
        """Проверяет, что при сбое DNS для attachments.discord.net подключение идет к DISCORD_MEDIA_ANYCAST_IPS."""
        from flowguard.proxy import DISCORD_MEDIA_ANYCAST_IPS
        proxy = DPIBypassProxy(Config("_test_defaults_missing.ini"))
        proxy.doh_harvester = None
        proxy.dns_failover = None
        proxy.timeout = 5.0
        connected_ips = []
        def fake_connect(addr, *args, **kwargs):
            connected_ips.append(addr[0])
            return 0

        with patch("socket.socket") as mock_sock_cls, \
             patch("flowguard.proxy.resolve_fallback_dns", return_value=None), \
             patch("socket.getaddrinfo", side_effect=Exception("DNS Hijacked/Empty")):
            mock_s = MagicMock()
            mock_s.connect_ex.side_effect = fake_connect
            mock_sock_cls.return_value = mock_s
            s = proxy._connect_target("attachments.discord.net", 443)
            self.assertIsNotNone(s)
            self.assertTrue(len(connected_ips) > 0)
            self.assertIn(connected_ips[0], DISCORD_MEDIA_ANYCAST_IPS)

    def test_attachments_discord_net_ejects_poisoned_cached_ip(self):
        """Проверяет, что невалидный (не-media) IP в _WORKING_IP_CACHE для attachments.discord.net вычищается."""
        from flowguard.proxy import _WORKING_IP_CACHE, DISCORD_MEDIA_ANYCAST_IPS
        proxy = DPIBypassProxy(Config("_test_defaults_missing.ini"))
        proxy.doh_harvester = None
        proxy.dns_failover = None
        proxy.timeout = 5.0
        _WORKING_IP_CACHE.set("attachments.discord.net", "198.18.0.55")

        connected_ips = []
        def fake_connect(addr, *args, **kwargs):
            connected_ips.append(addr[0])
            return 0

        with patch("socket.socket") as mock_sock_cls, \
             patch("flowguard.proxy.resolve_fallback_dns", return_value=None), \
             patch("socket.getaddrinfo", side_effect=Exception("DNS Empty")):
            mock_s = MagicMock()
            mock_s.connect_ex.side_effect = fake_connect
            mock_sock_cls.return_value = mock_s
            s = proxy._connect_target("attachments.discord.net", 443)
            self.assertIsNotNone(s)
            self.assertNotIn("198.18.0.55", _WORKING_IP_CACHE)
            self.assertTrue(len(connected_ips) > 0)
            self.assertIn(connected_ips[0], DISCORD_MEDIA_ANYCAST_IPS)


if __name__ == "__main__":
    unittest.main()

