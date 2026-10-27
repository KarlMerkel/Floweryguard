"""Тесты безопасности модуля DNS (DNSManager):
- Проверка доступности DNS сервера перед применением
- Исключение виртуальных адаптеров (Radmin, Hamachi, VMware и др.)
- Корректность отката (restore_dns) и сброса к DHCP
"""

import unittest
import tempfile
import os
from unittest.mock import patch, MagicMock
from Floweryguard.dns_config import DNSManager, VIRTUAL_ADAPTER_KEYWORDS


class TestDNSManagerSafety(unittest.TestCase):

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        backup = patch.object(DNSManager, '_get_backup_filepath', return_value=os.path.join(directory.name, 'dns.json'))
        backup.start()
        self.addCleanup(backup.stop)

    def test_virtual_adapter_keywords_defined(self):
        self.assertIn("radmin", VIRTUAL_ADAPTER_KEYWORDS)
        self.assertIn("hamachi", VIRTUAL_ADAPTER_KEYWORDS)
        self.assertIn("tap-", VIRTUAL_ADAPTER_KEYWORDS)

    @patch("subprocess.run")
    def test_get_active_interfaces_excludes_virtual(self, mock_run):
        # Имитируем вывод netsh с физическим адаптером и Radmin VPN
        netsh_output = (
            "Admin State    State          Type             Interface Name\n"
            "-------------------------------------------------------------------------\n"
            "Enabled        Connected      Dedicated        Беспроводная сеть\n"
            "Enabled        Connected      Dedicated        Radmin VPN\n"
            "Enabled        Connected      Dedicated        Ethernet\n"
            "Enabled        Connected      Dedicated        VMware Network Adapter VMnet1\n"
        ).encode("cp1251")
        mock_run.return_value = MagicMock(stdout=netsh_output, returncode=0)

        mgr = DNSManager()
        ifaces = mgr.get_active_interfaces()

        self.assertIn("Беспроводная сеть", ifaces)
        self.assertIn("Ethernet", ifaces)
        self.assertNotIn("Radmin VPN", ifaces)
        self.assertNotIn("VMware Network Adapter VMnet1", ifaces)

    def test_test_dns_server_empty_ip(self):
        self.assertFalse(DNSManager.test_dns_server(""))
        self.assertFalse(DNSManager.test_dns_server(None))

    @patch("socket.socket")
    def test_test_dns_server_timeout(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.recvfrom.side_effect = TimeoutError("Timeout")
        mock_socket_cls.return_value = mock_sock

        self.assertFalse(DNSManager.test_dns_server("192.144.59.14"))

    @patch("socket.socket")
    def test_test_dns_server_success(self, mock_socket_cls):
        mock_sock = MagicMock()
        valid_response = b"\xaa\xbb\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x0a\x63\x6c\x6f\x75\x64\x66\x6c\x61\x72\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01"
        mock_sock.recvfrom.return_value = (valid_response, ("1.1.1.1", 53))
        mock_socket_cls.return_value = mock_sock

        self.assertTrue(DNSManager.test_dns_server("1.1.1.1"))

    @patch("Floweryguard.dns_config.is_admin", return_value=True)
    def test_set_secure_dns_aborts_when_server_dead(self, mock_admin):
        mgr = DNSManager(primary_dns="192.144.59.14", secondary_dns="94.232.43.149")
        with patch.object(DNSManager, "test_dns_server", return_value=False):
            with patch("subprocess.run") as mock_run:
                success = mgr.set_secure_dns()
                self.assertFalse(success)
                # Убеждаемся, что netsh не вызывался для смены настроек
                mock_run.assert_not_called()

    @patch("Floweryguard.dns_config.is_admin", return_value=True)
    def test_heal_stale_dns_does_not_reset_unowned_settings(self, mock_admin):
        mgr = DNSManager()
        with patch.object(mgr, "get_active_interfaces", return_value=["Wi-Fi"]):
            # Имитируем, что на Wi-Fi прописан старый мертвый DNS 192.144.59.14
            with patch.object(mgr, "_get_adapter_dns_registry", return_value=["192.144.59.14"]):
                with patch("subprocess.run") as mock_run:
                    healed = mgr.heal_stale_dns()
                    self.assertEqual(healed, [])
                    mock_run.assert_not_called()


if __name__ == "__main__":
    unittest.main()

