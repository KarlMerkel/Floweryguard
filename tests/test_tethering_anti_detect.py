"""Unit-тесты для модуля анти-детекта мобильного тетеринга и hosts.txt."""

import unittest
from Floweryguard.proxy import (
    DPIBypassProxy,
    load_custom_hosts,
    get_custom_host_ip,
    resolve_fallback_dns,
)
from Floweryguard.config import Config


class TestTetheringAntiDetect(unittest.TestCase):
    """Тестирование перехвата Windows NCSI, маскировки User-Agent и сопоставлений hosts.txt."""

    def setUp(self):
        self.config = Config()
        self.proxy = DPIBypassProxy(self.config)

    def test_is_ncsi_request(self):
        # Должен распознавать все варианты NCSI / Connect Test
        self.assertTrue(DPIBypassProxy._is_ncsi_request("www.msftncsi.com", "/ncsi.txt"))
        self.assertTrue(DPIBypassProxy._is_ncsi_request("msftncsi.com", "/"))
        self.assertTrue(DPIBypassProxy._is_ncsi_request("www.msftconnecttest.com", "/connecttest.txt"))
        self.assertTrue(DPIBypassProxy._is_ncsi_request("ipv6.msftncsi.com", "/ncsi.txt"))

        # Обычные сайты не должны срабатывать
        self.assertFalse(DPIBypassProxy._is_ncsi_request("google.com", "/search"))
        self.assertFalse(DPIBypassProxy._is_ncsi_request("discord.com", "/app"))

    def test_handle_ncsi_response(self):
        resp_ncsi = DPIBypassProxy._handle_ncsi_response("www.msftncsi.com", "/ncsi.txt")
        self.assertIn(b"HTTP/1.1 200 OK", resp_ncsi)
        self.assertIn(b"Microsoft NCSI", resp_ncsi)

        resp_ct = DPIBypassProxy._handle_ncsi_response("www.msftconnecttest.com", "/connecttest.txt")
        self.assertIn(b"HTTP/1.1 200 OK", resp_ct)
        self.assertIn(b"Microsoft Connect Test", resp_ct)

    def test_mask_user_agent(self):
        # Десктопный Windows User-Agent
        req = (
            b"GET / HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
            b"Accept: */*\r\n\r\n"
        )
        masked = self.proxy._mask_user_agent(req)
        self.assertNotIn(b"Windows NT", masked)
        self.assertIn(b"Android 14; Mobile", masked)

        # Мобильный User-Agent не должен ломаться
        mob_req = (
            b"GET / HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 16_5)\r\n\r\n"
        )
        unmasked = self.proxy._mask_user_agent(mob_req)
        self.assertEqual(mob_req, unmasked)

    def test_ncsi_dns_fallback(self):
        # dns.msftncsi.com должен моментально возвращать 131.107.255.255
        self.config.set_override('ncsi_spoof', True)
        ip = resolve_fallback_dns("dns.msftncsi.com", self.config)
        self.assertEqual(ip, "131.107.255.255")

    def test_custom_hosts(self):
        # Проверяем загрузку hosts.txt
        hosts = load_custom_hosts("hosts.txt")
        self.assertIsInstance(hosts, dict)
        if "gateway.discord.gg" in hosts:
            self.assertEqual(get_custom_host_ip("gateway.discord.gg"), hosts["gateway.discord.gg"])


if __name__ == "__main__":
    unittest.main()
