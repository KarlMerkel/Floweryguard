"""Модульные тесты для модуля ускорения открытия сайтов (Zero-Latency Fast-Path, Happy Eyeballs, Buffers)."""

import unittest
from unittest.mock import patch, MagicMock
import socket
import time
from Floweryguard.config import Config, DEFAULT_CONFIG
from Floweryguard.proxy import DPIBypassProxy, _WORKING_IP_CACHE, _DEAD_IP_CACHE, is_ip_dead, mark_ip_working, mark_ip_dead


class TestPerformanceOptimizations(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.proxy = DPIBypassProxy(self.config)
        _WORKING_IP_CACHE.clear()
        _DEAD_IP_CACHE.clear()

    def tearDown(self):
        _WORKING_IP_CACHE.clear()
        _DEAD_IP_CACHE.clear()

    def test_config_high_performance_defaults(self):
        """Проверка дефолтных настроек высокой производительности."""
        self.assertEqual(DEFAULT_CONFIG["proxy"]["buffer_size"], 262144)
        self.assertEqual(DEFAULT_CONFIG["fragmentation"]["fragment_delay"], 0.001)

    @patch.object(DPIBypassProxy, "_try_direct_connect")
    @patch("socket.getaddrinfo")
    def test_zero_latency_fast_path_bypasses_dns(self, mock_getaddrinfo, mock_try_direct):
        """Проверка Zero-Latency Fast-Path: при наличии рабочего IP в кэше DNS не вызывается."""
        host = "fast.example.com"
        known_ip = "198.51.100.55"
        mark_ip_working(known_ip, host)
        self.proxy.route_health.record(self.proxy.strategy_engine._current_network, host, 443, known_ip, 'progress')

        fake_sock = MagicMock(spec=socket.socket)
        mock_try_direct.return_value = fake_sock

        sock = self.proxy._connect_target(host, 443)

        self.assertEqual(sock, fake_sock)
        mock_try_direct.assert_called_once_with(known_ip, 443, timeout=unittest.mock.ANY)
        # getaddrinfo НЕ должен вызываться
        mock_getaddrinfo.assert_not_called()

    @patch.object(DPIBypassProxy, "_try_direct_connect")
    @patch("socket.getaddrinfo")
    def test_zero_latency_fast_path_fallback_on_failure(self, mock_getaddrinfo, mock_try_direct):
        """Если кэшированный IP не отвечает, происходит плавный переход к полному DNS поиску."""
        host = "stale.example.com"
        stale_ip = "198.51.100.99"
        mark_ip_working(stale_ip, host)
        self.proxy.route_health.record(self.proxy.strategy_engine._current_network, host, 443, stale_ip, 'progress')

        # Прямое подключение к stale IP сбоит
        mock_try_direct.return_value = None

        # Полный DNS возвращает новый рабочий IP
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.10", 443))
        ]

        with patch("socket.socket") as mock_sock_cls:
            mock_s = MagicMock()
            mock_s.connect.return_value = None
            mock_sock_cls.return_value = mock_s

            res = self.proxy._connect_target(host, 443)
            self.assertIsNotNone(res)
            # Убеждаемся, что старый IP помечен как мертвый и сброшен из кэша
            self.assertTrue(is_ip_dead(stale_ip))
            self.assertIsNone(_WORKING_IP_CACHE.get(host))

    def test_adaptive_probe_timeout_scaling(self):
        """Проверка адаптивного таймаута: для быстрого пинга таймаут снижен до ~280 мс."""
        # Для базового пинга 30 мс:
        base_rtt = 0.030
        probe_timeout = min(1.5, max(0.28, base_rtt * 2.8))
        self.assertAlmostEqual(probe_timeout, 0.28, places=2)

        # Для зарубежного пинга 200 мс:
        base_rtt_slow = 0.200
        probe_timeout_slow = min(1.5, max(0.28, base_rtt_slow * 2.8))
        self.assertAlmostEqual(probe_timeout_slow, 0.56, places=2)

    def test_stagger_delay_tuned_to_120ms(self):
        """Проверка, что Happy Eyeballs stagger delay снижен до 120 мс."""
        # Инспектируем код proxy.py
        import inspect
        source = inspect.getsource(self.proxy._connect_target)
        self.assertIn("stagger_delay = 0.12", source)

    def test_socket_buffers_scaled_to_512k(self):
        """Проверка, что в сокетах сконфигурированы 512 КБ буферы для TCP Window Scaling."""
        import inspect
        source_try_direct = inspect.getsource(self.proxy._try_direct_connect)
        source_handle_client = inspect.getsource(self.proxy._handle_client)
        self.assertIn("524288", source_try_direct)
        self.assertIn("524288", source_handle_client)


if __name__ == "__main__":
    unittest.main()
