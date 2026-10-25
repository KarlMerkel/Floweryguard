"""Тесты для исправления зависания Starting в Discord (PMTU Black Hole, IP Cache Trap, MTU 1380, EnumWindows callback).
"""

import sys
import unittest
from unittest.mock import MagicMock, patch

from flowguard.proxy import DPIBypassProxy, _WORKING_IP_CACHE, is_ip_dead, mark_ip_dead, _DEAD_IP_CACHE, _set_socket_meta
from flowguard.ttl_fix import MTUManager
from flowguard.config import Config
from flowguard.main import acquire_single_instance_mutex


class TestDiscordPMTUAndStartingFixes(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.proxy = DPIBypassProxy(self.config)
        self.proxy.shadow_prober = MagicMock()
        self.proxy.is_running = True
        self.proxy.strategy_engine = MagicMock()
        _WORKING_IP_CACHE.clear()
        _DEAD_IP_CACHE.clear()

    def tearDown(self):
        _WORKING_IP_CACHE.clear()
        _DEAD_IP_CACHE.clear()

    def test_mtu_manager_default_is_1380(self):
        """MTUManager по умолчанию инициализируется с target_mtu=1380."""
        mgr = MTUManager()
        self.assertEqual(mgr.target_mtu, 1380)

    def test_mtu_manager_applies_and_restores_ipv4_and_ipv6_on_not_equal(self):
        """MTUManager применяет MTU если current_mtu != target_mtu (включая 1420 -> 1380) и настраивает IPv4 и IPv6."""
        mgr = MTUManager(target_mtu=1380)
        mgr.get_active_interfaces = lambda: [("Wi-Fi", 1420)]
        mgr.get_default_gateway_interfaces = lambda: ["Wi-Fi"]
        mgr._get_ipv6_mtu = lambda iface: 1420

        with patch("flowguard.ttl_fix.is_admin", return_value=True), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)

            applied = mgr.apply_mtu()
            self.assertTrue(applied)
            self.assertEqual(mgr.original_mtus, {"Wi-Fi": 1420})

            # Проверяем, что были вызваны команды netsh и для ipv4, и для ipv6
            calls = [c[0][0] for c in mock_run.call_args_list]
            v4_calls = [c for c in calls if "ipv4" in c and "1380" in " ".join(c)]
            v6_calls = [c for c in calls if "ipv6" in c and "1380" in " ".join(c)]
            self.assertGreaterEqual(len(v4_calls), 1)
            self.assertGreaterEqual(len(v6_calls), 1)

            # Теперь восстанавливаем MTU
            mock_run.reset_mock()
            restored = mgr.restore_mtu()
            self.assertTrue(restored)
            self.assertEqual(len(mgr.original_mtus), 0)

            restore_calls = [c[0][0] for c in mock_run.call_args_list]
            r_v4 = [c for c in restore_calls if "ipv4" in c and "1420" in " ".join(c)]
            r_v6 = [c for c in restore_calls if "ipv6" in c and "1420" in " ".join(c)]
            self.assertGreaterEqual(len(r_v4), 1)
            self.assertGreaterEqual(len(r_v6), 1)

    def test_mtu_manager_distinct_ipv4_and_ipv6_restoration(self):
        """MTUManager корректно запоминает и восстанавливает разные исходные MTU для IPv4 (1420) и IPv6 (1500)."""
        mgr = MTUManager(target_mtu=1380)
        mgr.get_active_interfaces = lambda: [("Ethernet 2", 1420)]
        mgr.get_default_gateway_interfaces = lambda: ["Ethernet 2"]
        mgr._get_ipv6_mtu = lambda iface: 1500

        with patch("flowguard.ttl_fix.is_admin", return_value=True), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)

            applied = mgr.apply_mtu()
            self.assertTrue(applied)
            self.assertEqual(mgr.original_mtus, {"Ethernet 2": 1420})
            self.assertEqual(mgr.original_mtus_v6, {"Ethernet 2": 1500})

            mock_run.reset_mock()
            restored = mgr.restore_mtu()
            self.assertTrue(restored)

            restore_calls = [c[0][0] for c in mock_run.call_args_list]
            r_v4 = [c for c in restore_calls if "ipv4" in c and "1420" in " ".join(c)]
            r_v6 = [c for c in restore_calls if "ipv6" in c and "1500" in " ".join(c)]
            self.assertGreaterEqual(len(r_v4), 1)
            self.assertGreaterEqual(len(r_v6), 1)

    def test_discord_stall_invalidates_cache_and_marks_ip_dead(self):
        """При таймауте/обрыве клиента Discord при <32KB данных серверный IP штрафуется,
        а кэш _WORKING_IP_CACHE сбрасывается для смены Anycast IP.
        """
        host = "discord.com"
        target_ip = "162.159.135.233"
        _WORKING_IP_CACHE.set(host, target_ip)

        client_sock = MagicMock()
        target_sock = MagicMock()
        _set_socket_meta(target_sock, target_ip=target_ip, connect_rtt=0.01)

        # Клиент отправляет запрос, но сервер не вернул ответ (0 байт)
        # Затем клиент закрывает соединение (b'') из-за зависания
        client_sock.recv.side_effect = [b"GET / HTTP/1.1\r\n\r\n", b""]
        target_sock.recv.side_effect = []

        call_idx = [0]
        def fake_select(r, w, x, timeout):
            call_idx[0] += 1
            if call_idx[0] == 1:
                return ([client_sock], [], [])
            elif call_idx[0] == 2:
                return ([client_sock], [], [])
            return ([], [], [])

        with patch("select.select", side_effect=fake_select):
            self.proxy._pipe_sockets(
                client_sock,
                target_sock,
                host=host,
                strategy="combo_tlsrec_tcpsplit"
            )

        # 1. IP удален из _WORKING_IP_CACHE
        self.assertIsNone(_WORKING_IP_CACHE.get(host))
        # 2. IP помечен как мертвый
        self.assertTrue(is_ip_dead(target_ip))
        # 3. Зафиксирован штраф (failure) для стратегии и IP
        self.proxy.strategy_engine.record_failure.assert_called_with(
            host, "combo_tlsrec_tcpsplit", ip=target_ip, is_tspu=False
        )
        # 4. Успех НЕ зафиксирован
        self.proxy.strategy_engine.record_success.assert_not_called()

    def test_discord_select_timeout_stalls_and_invalidates_cache(self):
        """При таймауте select на зависшем Discord соединении (клиент отправил запрос, 0 байт ответа)
        фиксируется сбой, IP вытесняется из кэша и помечается мертвым, а успех НЕ фиксируется.
        """
        host = "discord.com"
        target_ip = "162.159.135.233"
        _WORKING_IP_CACHE.set(host, target_ip)

        client_sock = MagicMock()
        target_sock = MagicMock()
        _set_socket_meta(target_sock, target_ip=target_ip, connect_rtt=0.01)

        # Клиент отправил запрос, но сервер не ответил (0 байт), наступил таймаут
        client_sock.recv.side_effect = [b"GET / HTTP/1.1\r\n\r\n"]

        with patch("select.select", side_effect=[([client_sock], [], []), ([], [], [])]):
            self.proxy._pipe_sockets(
                client_sock,
                target_sock,
                host=host,
                strategy="combo_tlsrec_tcpsplit"
            )

        # Проверяем, что кэш сброшен, IP помечен как мертвый, а успех не зафиксирован
        self.assertIsNone(_WORKING_IP_CACHE.get(host))
        self.assertTrue(is_ip_dead(target_ip))
        self.proxy.strategy_engine.record_failure.assert_called_with(
            host, "combo_tlsrec_tcpsplit", ip=target_ip, is_tspu=False
        )
        self.proxy.strategy_engine.record_success.assert_not_called()

    def test_discord_probe_does_not_cache_ip_before_data(self):
        """Проверка, что успешный probe TLS ServerHello не помещает IP Discord в _WORKING_IP_CACHE."""
        client_sock = MagicMock()
        mock_sock = MagicMock()
        _set_socket_meta(mock_sock, target_ip="162.159.135.233", connect_rtt=0.02)
        self.proxy._probe_socket_response = MagicMock(return_value=("success", b"\x16\x03\x03\x00\x50", 20.0))
        self.proxy._send_tls_client_hello_with_bypass = MagicMock(return_value=("combo_tlsrec_tcpsplit", "discord.com"))

        with patch("flowguard.proxy.is_tls_client_hello", return_value=True):
            res_sock, strat, eff_host, resp = self.proxy._handshake_with_fast_fallback(
                client_sock, mock_sock, "discord.com", 443, b"\x16\x03\x01\x00\x10"
            )
        self.assertIsNotNone(res_sock)
        # IP не должен быть записан в кэш рабочих IP до передачи >= 32KB
        self.assertIsNone(_WORKING_IP_CACHE.get("discord.com"))

    def test_discord_large_transfer_records_success(self):
        """Если объем данных от сервера превысил 32KB, фиксируется успех обхода PMTU Black Hole."""
        host = "discord.com"
        target_ip = "162.159.135.233"

        client_sock = MagicMock()
        target_sock = MagicMock()
        _set_socket_meta(target_sock, target_ip=target_ip, connect_rtt=0.01)

        # Сервер передал 35000 байт (> 32KB)
        target_sock.recv.side_effect = [b"A" * 35000]

        call_idx = [0]
        def fake_select(r, w, x, timeout):
            call_idx[0] += 1
            if call_idx[0] == 1:
                return ([target_sock], [], [])
            return ([], [], [])

        with patch("select.select", side_effect=fake_select):
            self.proxy._pipe_sockets(
                client_sock,
                target_sock,
                host=host,
                strategy="combo_tlsrec_tcpsplit"
            )

        self.proxy.strategy_engine.record_success.assert_called_with(
            host, "combo_tlsrec_tcpsplit", ip=target_ip
        )
        self.assertEqual(_WORKING_IP_CACHE.get(host), target_ip)

    def test_real_acquire_single_instance_mutex_enum_windows_callback(self):
        """Проверка реального вызова acquire_single_instance_mutex с моком EnumWindows."""
        mock_kernel32 = MagicMock()
        mock_kernel32.GetLastError.return_value = 183  # ERROR_ALREADY_EXISTS
        mock_user32 = MagicMock()

        # Моделируем окно с заголовком Flowery
        mock_user32.GetWindowTextLengthW.return_value = 14
        def fake_get_text(hwnd, buff, max_len):
            buff.value = "Flowery (Glue)"
            return 14
        mock_user32.GetWindowTextW.side_effect = fake_get_text

        def fake_enum_windows(callback, lparam):
            # Передаем реальный integer 0 в callback, как делает Win32 EnumWindows
            callback(101, lparam)
            return True

        mock_user32.EnumWindows.side_effect = fake_enum_windows

        try:
            with patch("sys.platform", "win32"), \
                 patch("ctypes.windll.kernel32", mock_kernel32), \
                 patch("ctypes.windll.user32", mock_user32):
                result = acquire_single_instance_mutex()
                self.assertFalse(result)
                mock_user32.ShowWindow.assert_called_with(101, 9)
                mock_user32.SetForegroundWindow.assert_called_with(101)
        finally:
            import flowguard.main as fm
            fm._SINGLE_INSTANCE_MUTEX = None


if __name__ == "__main__":
    unittest.main()
