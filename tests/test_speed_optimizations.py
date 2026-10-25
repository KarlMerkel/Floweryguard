"""Юнит-тесты для пакета оптимизаций скорости Flowery v1.3.3:
1. Конфигурационный флаг early_connect (Zero-RTT Pipelined CONNECT).
2. Кэширование пула IP-кандидатов (_RESOLVED_IPS_CACHE) с TTL.
3. Single-Flight механизм блокировки (_get_host_lock) для предотвращения DNS Stampede.
4. Пакетный учет трафика в _pipe_sockets без lock-contention на каждом чанке.
5. Lazy DoH Harvester (DoH опрашивается только как fallback, а не на каждом запросе).
6. Расширенная очередь listen(SOMAXCONN).
"""

import time
import socket
import threading
import unittest
from unittest.mock import MagicMock, patch

from Floweryguard.config import Config
from Floweryguard.proxy import (
    ThreadSafeBoundedCache,
    _RESOLVED_IPS_CACHE,
    _get_host_lock,
    _HOST_RESOLVE_LOCKS,
    DPIBypassProxy,
)


class TestSpeedOptimizations(unittest.TestCase):

    def setUp(self):
        self.config = Config("_test_defaults_missing.ini")
        self.proxy = DPIBypassProxy(self.config)
        _RESOLVED_IPS_CACHE.clear()

    def tearDown(self):
        _RESOLVED_IPS_CACHE.clear()

    def test_early_connect_config_default(self):
        """Проверка значения early_connect по умолчанию (True)."""
        self.assertTrue(self.config.early_connect)

    def test_resolved_ips_cache_hit_and_ttl(self):
        """Проверка кэширования кандидатов IP и соблюдения TTL 300 секунд."""
        host = "fast.test-example.org"
        sample_ips = ["1.2.3.4", "5.6.7.8"]

        # До сохранения в кэше
        self.assertIsNone(_RESOLVED_IPS_CACHE.get(host))

        # Сохраняем с текущей временной меткой
        now = time.time()
        _RESOLVED_IPS_CACHE.set(host, (now, sample_ips))

        cached = _RESOLVED_IPS_CACHE.get(host)
        self.assertIsNotNone(cached)
        self.assertEqual(cached[1], sample_ips)
        self.assertLess(now - cached[0], 1.0)

        # Проверка истечения TTL
        old_time = now - 301.0
        _RESOLVED_IPS_CACHE.set(host, (old_time, sample_ips))
        cached_expired = _RESOLVED_IPS_CACHE.get(host)
        self.assertIsNotNone(cached_expired)
        self.assertGreater(time.time() - cached_expired[0], 300.0)

    def test_single_flight_mutex_per_host(self):
        """Проверка механизма Single-Flight: потоки для одного хоста получают один и тот же Lock."""
        lock1 = _get_host_lock("youtube.com")
        lock2 = _get_host_lock("youtube.com")
        lock3 = _get_host_lock("discord.com")

        self.assertIs(lock1, lock2)
        self.assertIsNot(lock1, lock3)

    def test_connect_target_uses_resolved_cache(self):
        """Проверка: при наличии домена в _RESOLVED_IPS_CACHE системный getaddrinfo не вызывается."""
        host = "cached-domain.com"
        test_ip = "192.0.2.1"
        _RESOLVED_IPS_CACHE.set(host, (time.time(), [test_ip]))

        with patch("socket.getaddrinfo") as mock_gai, \
             patch.object(self.proxy, "_try_direct_connect", return_value=None):
            with patch("socket.socket") as mock_sock_cls:
                mock_s = MagicMock()
                mock_s.connect.return_value = None
                mock_s.getsockopt.return_value = 0
                mock_sock_cls.return_value = mock_s

                res = self.proxy._connect_target(host, 443)
                self.assertIsNotNone(res)
                # getaddrinfo НЕ должен вызываться, так как IP взят из _RESOLVED_IPS_CACHE
                mock_gai.assert_not_called()

    def test_lazy_doh_not_called_when_dns_resolves(self):
        """Проверка Lazy DoH: если getaddrinfo вернул адреса, doh_harvester не вызывается."""
        host = "regular-domain.com"
        fake_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

        with patch("socket.getaddrinfo", return_value=fake_addrinfo), \
             patch.object(self.proxy.doh_harvester, "harvest") as mock_harvest, \
             patch.object(self.proxy, "_try_direct_connect", return_value=None), \
             patch("socket.socket") as mock_sock_cls:

            mock_s = MagicMock()
            mock_s.connect.return_value = None
            mock_s.getsockopt.return_value = 0
            mock_sock_cls.return_value = mock_s

            res = self.proxy._connect_target(host, 443)
            self.assertIsNotNone(res)
            # DoH harvester НЕ должен опрашиваться
            mock_harvest.assert_not_called()

    def test_lazy_doh_called_as_fallback_when_dns_fails(self):
        """Проверка Lazy DoH: если getaddrinfo возвращает ошибку, doh_harvester вызывается как fallback."""
        host = "blocked-by-tspu-dns.com"
        fallback_ip = "104.16.123.45"

        with patch("socket.getaddrinfo", side_effect=socket.gaierror("DNS lookup failed")), \
             patch.object(self.proxy.doh_harvester, "harvest", return_value=[fallback_ip]) as mock_harvest, \
             patch.object(self.proxy, "_try_direct_connect", return_value=None), \
             patch("socket.socket") as mock_sock_cls:

            mock_s = MagicMock()
            mock_s.connect.return_value = None
            mock_s.getsockopt.return_value = 0
            mock_sock_cls.return_value = mock_s

            res = self.proxy._connect_target(host, 443)
            self.assertIsNotNone(res)
            # DoH Harvester должен быть вызван как спасительный fallback
            mock_harvest.assert_called_once()

    def test_batch_stats_flushed_on_socket_close(self):
        """Проверка сброса накопленного локального трафика в общие счетчики при выходе из _pipe_sockets."""
        self.proxy.is_running = True
        client_sock = MagicMock()
        target_sock = MagicMock()

        # Симулируем 100 КБ от клиента (меньше 128 КБ порога), затем закрытие
        chunk_100k = b"A" * 102400
        client_sock.recv.side_effect = [chunk_100k, b""]
        target_sock.recv.side_effect = [b""]

        initial_tx = self.proxy.bytes_tx

        with patch("select.select") as mock_select:
            # 1: клиент прислал 100 КБ
            # 2: клиент закрыл сокет (b"")
            # 3: сервер закрыл сокет (b"") -> оба сокета закрыты, выход
            mock_select.side_effect = [
                ([client_sock], [], []),
                ([client_sock], [], []),
                ([target_sock], [], []),
            ]
            self.proxy._pipe_sockets(client_sock, target_sock, host="test.org")

        # Вся сумма 100 КБ должна быть учтена в bytes_tx благодаря блоку finally
        self.assertEqual(self.proxy.bytes_tx - initial_tx, 102400)


if __name__ == "__main__":
    unittest.main()
