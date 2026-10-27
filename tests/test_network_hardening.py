"""Unit tests for the 4 critical network subsystem hardening fixes.
UX Directive: "Включил и забыл" (set-and-forget, zero maintenance).

Verifies:
1. Graceful Socket Teardown (Winsock TCP RST Prevention via SHUT_WR & Symmetrical FIN)
2. Chromium Preconnect Pool Timeout (60s minimum for HTTP CONNECT)
3. Concurrency Semaphore Expansion (1024 slots for 300s keep-alive)
4. Connection Timeout (5.0s, no 4.0s clamp) and Transient IP Ban Relaxation (30.0s)
5. Strict Synchronization between flowguard/ and Flowery_Release/Floweryguard/
"""

import unittest
import socket
import threading
import time
import inspect
from unittest.mock import MagicMock, patch

from flowguard.config import Config
from flowguard.proxy import (
    DPIBypassProxy,
    _safe_close_socket,
    mark_ip_dead,
    mark_ip_working,
    is_ip_dead,
    _DEAD_IP_CACHE,
)
import Flowery_Release.Floweryguard.proxy as release_proxy


class TestNetworkSubsystemHardening(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.proxy = DPIBypassProxy(self.config)
        self.proxy.shadow_prober = MagicMock()
        self.proxy.is_running = True
        self.release_proxy_inst = release_proxy.DPIBypassProxy(self.config)
        self.release_proxy_inst.is_running = True

    # -------------------------------------------------------------------------
    # 1. Graceful Socket Teardown (Winsock TCP RST Prevention & Symmetrical FIN)
    # -------------------------------------------------------------------------
    def test_safe_close_socket_uses_shut_rdwr(self):
        """_safe_close_socket обязан вызывать shutdown(socket.SHUT_RDWR) для полной финализации."""
        mock_sock = MagicMock(spec=socket.socket)
        mock_sock.fileno.return_value = 123

        _safe_close_socket(mock_sock)

        mock_sock.shutdown.assert_called_once_with(socket.SHUT_RDWR)
        mock_sock.close.assert_called_once()

    def test_safe_close_socket_release_uses_shut_rdwr(self):
        """Flowery_Release _safe_close_socket обязан вызывать shutdown(socket.SHUT_RDWR)."""
        mock_sock = MagicMock(spec=socket.socket)
        mock_sock.fileno.return_value = 123

        release_proxy._safe_close_socket(mock_sock)

        mock_sock.shutdown.assert_called_once_with(socket.SHUT_RDWR)
        mock_sock.close.assert_called_once()

    def test_safe_close_socket_handles_oserror_gracefully(self):
        """Если пир уже закрыл соединение (WSAENOTSOCK / WSAENOTCONN), shutdown
        генерирует OSError/socket.error, но close() всё равно обязан выполниться без исключений.
        """
        mock_sock = MagicMock(spec=socket.socket)
        mock_sock.fileno.return_value = 123
        mock_sock.shutdown.side_effect = OSError(10057, "Socket is not connected")

        _safe_close_socket(mock_sock)

        mock_sock.shutdown.assert_called_once_with(socket.SHUT_RDWR)
        mock_sock.close.assert_called_once()

    def test_safe_close_socket_none_safe(self):
        """_safe_close_socket(None) не должен вызывать исключений."""
        try:
            _safe_close_socket(None)
            release_proxy._safe_close_socket(None)
        except Exception as e:
            self.fail(f"_safe_close_socket(None) raised exception: {e}")

    def test_pipe_sockets_server_eof_graceful_fin_and_immediate_exit(self):
        """Когда удалённый сервер присылает EOF (b''), _pipe_sockets обязан:
        1. Отправить клиенту FIN через shutdown(socket.SHUT_WR).
        2. Мгновенно завершить сессию (break), не зависая на 300с в ожидании клиентского сокета.
        """
        client_sock = MagicMock(spec=socket.socket)
        target_sock = MagicMock(spec=socket.socket)

        # target_sock готов к чтению и отдаёт EOF
        target_sock.recv.return_value = b""

        with patch("select.select") as mock_select:
            # Имитируем, что target_sock стал readable
            mock_select.return_value = ([target_sock], [], [])

            start_t = time.time()
            self.proxy._pipe_sockets(client_sock, target_sock, host="example.com", strategy="direct")
            duration = time.time() - start_t

        # Сессия завершилась немедленно
        self.assertLess(duration, 1.0)
        # Клиент получил аккуратный FIN
        client_sock.shutdown.assert_any_call(socket.SHUT_WR)
        # Окончательное безопасное закрытие сокетов в finally
        client_sock.close.assert_called()
        target_sock.close.assert_called()

    def test_pipe_sockets_server_eof_release_proxy_inst(self):
        """Аналогичная проверка корректного FIN и немедленного выхода для Flowery_Release."""
        client_sock = MagicMock(spec=socket.socket)
        target_sock = MagicMock(spec=socket.socket)
        target_sock.recv.return_value = b""

        with patch("select.select") as mock_select:
            mock_select.return_value = ([target_sock], [], [])

            start_t = time.time()
            self.release_proxy_inst._pipe_sockets(client_sock, target_sock, host="example.com", strategy="direct")
            duration = time.time() - start_t

        self.assertLess(duration, 1.0)
        client_sock.shutdown.assert_any_call(socket.SHUT_WR)

    def test_pipe_sockets_client_half_close_forwards_remaining_data(self):
        """Когда клиент отправляет EOF (Half-Close), _pipe_sockets обязан:
        1. Отправить серверу FIN через target_sock.shutdown(socket.SHUT_WR).
        2. Продолжать считывать оставшиеся данные с target_sock и пересылать их клиенту.
        3. Завершиться, когда сервер пришлёт свой EOF.
        """
        client_sock = MagicMock(spec=socket.socket)
        target_sock = MagicMock(spec=socket.socket)

        # Шаг 1: клиент прислал EOF
        # Шаг 2: сервер прислал ответные данные
        # Шаг 3: сервер прислал EOF
        client_sock.recv.return_value = b""
        target_sock.recv.side_effect = [b"HTTP/1.1 200 OK\r\n\r\nData", b""]

        call_idx = [0]
        def fake_select(rlist, wlist, xlist, to):
            idx = call_idx[0]
            call_idx[0] += 1
            if idx == 0:
                return ([client_sock], [], [])
            elif idx == 1:
                return ([target_sock], [], [])
            elif idx == 2:
                return ([target_sock], [], [])
            return ([], [], [])

        with patch("select.select", side_effect=fake_select):
            self.proxy._pipe_sockets(client_sock, target_sock, host="example.com", strategy="direct")

        # Сервер получил FIN от клиента
        target_sock.shutdown.assert_any_call(socket.SHUT_WR)
        # Клиент получил данные ответа
        client_sock.sendall.assert_called_with(b"HTTP/1.1 200 OK\r\n\r\nData")
        # Клиент получил ответный FIN от сервера
        client_sock.shutdown.assert_any_call(socket.SHUT_WR)

    # -------------------------------------------------------------------------
    # 2. Chromium Preconnect Pool Timeout (60s minimum)
    # -------------------------------------------------------------------------
    def test_chromium_preconnect_timeout_early_connect(self):
        """Для HTTP CONNECT с early_connect=True таймаут сокета перед recv(buffer_size)
        должен выставляться в float(self.timeout), предотвращая зависание неиспользуемых соединений.
        """
        self.proxy.config.set_override("early_connect", True)
        self.proxy.timeout = 15.0

        client_sock = MagicMock(spec=socket.socket)
        client_sock.recv.side_effect = [
            b"CONNECT example.com:443 HTTP/1.1\r\n\r\n",
            b"",  # client disconnects
        ]

        with patch.object(self.proxy, "_connect_target", return_value=None):
            self.proxy._handle_client(client_sock, ("127.0.0.1", 12345))

        # Проверяем, что client_sock.settimeout(15.0) был вызван перед чтением first_packet
        timeout_calls = [call[0][0] for call in client_sock.settimeout.call_args_list]
        self.assertIn(15.0, timeout_calls)

    def test_chromium_preconnect_timeout_non_early_connect(self):
        """Для HTTP CONNECT с early_connect=False таймаут сокета перед recv(buffer_size)
        также должен выставляться в float(self.timeout).
        """
        self.proxy.config.set_override("early_connect", False)
        self.proxy.timeout = 15.0

        client_sock = MagicMock(spec=socket.socket)
        client_sock.recv.side_effect = [
            b"CONNECT example.com:443 HTTP/1.1\r\n\r\n",
            b"",  # client disconnects
        ]
        target_sock = MagicMock(spec=socket.socket)

        with patch.object(self.proxy, "_connect_target", return_value=target_sock):
            self.proxy._handle_client(client_sock, ("127.0.0.1", 12345))

        timeout_calls = [call[0][0] for call in client_sock.settimeout.call_args_list]
        self.assertIn(15.0, timeout_calls)

    def test_chromium_preconnect_timeout_release_inst(self):
        """Проверка Flowery_Release для preconnect timeout."""
        self.release_proxy_inst.config.set_override("early_connect", True)
        self.release_proxy_inst.timeout = 15.0

        client_sock = MagicMock(spec=socket.socket)
        client_sock.recv.side_effect = [
            b"CONNECT example.com:443 HTTP/1.1\r\n\r\n",
            b"",
        ]

        with patch.object(self.release_proxy_inst, "_connect_target", return_value=None):
            self.release_proxy_inst._handle_client(client_sock, ("127.0.0.1", 12345))

        timeout_calls = [call[0][0] for call in client_sock.settimeout.call_args_list]
        self.assertIn(15.0, timeout_calls)

    def test_chromium_preconnect_timeout_preserves_higher_config_timeout(self):
        """Если в конфигурации задан таймаут выше 60с (например 90.0с), должен применяться именно он."""
        self.proxy.config.set_override("early_connect", False)
        self.proxy.timeout = 90.0

        client_sock = MagicMock(spec=socket.socket)
        client_sock.recv.side_effect = [
            b"CONNECT example.com:443 HTTP/1.1\r\n\r\n",
            b"",
        ]
        target_sock = MagicMock(spec=socket.socket)

        with patch.object(self.proxy, "_connect_target", return_value=target_sock):
            self.proxy._handle_client(client_sock, ("127.0.0.1", 12345))

        timeout_calls = [call[0][0] for call in client_sock.settimeout.call_args_list]
        self.assertIn(90.0, timeout_calls)

    # -------------------------------------------------------------------------
    # 3. Concurrency Semaphore Expansion for 300s Keep-Alive
    # -------------------------------------------------------------------------
    def test_concurrency_semaphore_expanded_to_1024(self):
        """Пул семафора одновременных подключений обязан вмещать 1024 соединения,
        чтобы не блокировать длительные 300с keep-alive сессии вкладок браузера и Discord.
        """
        # flowguard
        sem = self.proxy._concurrency_sem
        self.assertIsInstance(sem, threading.BoundedSemaphore)
        self.assertEqual(sem._value, 1024)

        # Flowery_Release
        rel_sem = self.release_proxy_inst._concurrency_sem
        self.assertIsInstance(rel_sem, threading.BoundedSemaphore)
        self.assertEqual(rel_sem._value, 1024)

    # -------------------------------------------------------------------------
    # 4. Connection Timeout and Transient IP Ban Relaxation
    # -------------------------------------------------------------------------
    def test_connect_target_default_timeout_is_5_seconds(self):
        """_connect_target должен использовать baseline таймаут 5.0с (вместо 2.0с) для мобильных сетей."""
        source_flowguard = inspect.getsource(self.proxy._connect_target)
        source_release = inspect.getsource(self.release_proxy_inst._connect_target)

        self.assertIn("min(5.0, float(self.timeout))", source_flowguard)
        self.assertIn("min(5.0, float(self.timeout))", source_release)

    def test_single_candidate_timeout_is_full_5s_not_clamped_to_4(self):
        """_connect_target для одиночного IP не должен ограничивать таймаут значением 4.0с
        (проверка ликвидации residual min(4.0, float(conn_to))).
        """
        test_ip = "198.51.100.1"
        mark_ip_working(test_ip)

        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock

            # flowguard
            self.proxy._connect_target(test_ip, 443, target_ip=None)
            timeout_calls = [call[0][0] for call in mock_sock.settimeout.call_args_list]
            self.assertIn(5.0, timeout_calls)
            self.assertNotIn(4.0, timeout_calls)

            # Flowery_Release
            mock_sock.reset_mock()
            self.release_proxy_inst._connect_target(test_ip, 443, target_ip=None)
            timeout_calls_rel = [call[0][0] for call in mock_sock.settimeout.call_args_list]
            self.assertIn(5.0, timeout_calls_rel)
            self.assertNotIn(4.0, timeout_calls_rel)

        mark_ip_working(test_ip)

    def test_fast_fallback_budget_is_8_seconds(self):
        """MAX_FALLBACK_BUDGET обязан быть равен 8.0с для надежности мобильных сетей."""
        source_flowguard = inspect.getsource(self.proxy._handshake_with_fast_fallback)
        source_release = inspect.getsource(self.release_proxy_inst._handshake_with_fast_fallback)

        self.assertIn("MAX_FALLBACK_BUDGET = 8.0", source_flowguard)
        self.assertIn("MAX_FALLBACK_BUDGET = 8.0", source_release)

    def test_fast_path_does_not_poison_current_ip(self):
        """В Fast-Path для YouTube/Discord при сбое Попытки 1 IP НЕ должен помечаться мертвым,
        чтобы не блокировать единственный GGC узел или Anycast IP.
        """
        source_flowguard = inspect.getsource(self.proxy._handshake_with_fast_fallback)
        source_release = inspect.getsource(self.release_proxy_inst._handshake_with_fast_fallback)

        self.assertNotIn("mark_ip_dead(current_ip", source_flowguard)
        self.assertNotIn("mark_ip_dead(current_ip", source_release)

    def test_transient_connect_failure_only_deprioritizes_route(self):
        """Кратковременный таймаут на мобильной сети не банит IP глобально: маршрут этого хоста
        понижается в приоритете на 45 с, а другие домены на том же Anycast IP не затрагиваются.
        """
        test_ip = "192.0.2.77"
        mark_ip_working(test_ip)
        self.assertFalse(is_ip_dead(test_ip))

        # Вызываем сбой одиночного кандидата
        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.connect.side_effect = socket.timeout("Connect timed out")
            mock_sock_cls.return_value = mock_sock

            with patch("flowguard.proxy.resolve_fallback_dns", return_value=None):
                self.proxy._connect_target(test_ip, 443, target_ip=None)

        network = self.proxy.strategy_engine._current_network
        self.assertIsNone(_DEAD_IP_CACHE.get(test_ip))
        self.assertEqual(self.proxy.route_health.status(network, test_ip, 443, test_ip), 'suspect')
        self.assertEqual(self.proxy.route_health.status(network, "other.example", 443, test_ip), 'unknown')

        mark_ip_working(test_ip)

    # -------------------------------------------------------------------------
    # 5. Strict Synchronization between flowguard/ and Flowery_Release/
    # -------------------------------------------------------------------------
    def test_codebase_synchronization_proxy_py(self):
        """Проверяет синхронность ключевых параметров между flowguard и Flowery_Release."""
        # 1. BoundedSemaphore value
        self.assertEqual(self.proxy._concurrency_sem._value, self.release_proxy_inst._concurrency_sem._value)

        # 2. _safe_close_socket implementation
        src1 = inspect.getsource(_safe_close_socket)
        src2 = inspect.getsource(release_proxy._safe_close_socket)
        self.assertIn("sock.shutdown(socket.SHUT_RDWR)", src1)
        self.assertIn("sock.shutdown(socket.SHUT_RDWR)", src2)
        self.assertNotIn("sock.shutdown(socket.SHUT_WR)", src1)
        self.assertNotIn("sock.shutdown(socket.SHUT_WR)", src2)

        # 3. _pipe_sockets server EOF break
        src_pipe1 = inspect.getsource(self.proxy._pipe_sockets)
        src_pipe2 = inspect.getsource(self.release_proxy_inst._pipe_sockets)
        self.assertIn("client_sock.shutdown(socket.SHUT_WR)", src_pipe1)
        self.assertIn("client_sock.shutdown(socket.SHUT_WR)", src_pipe2)


if __name__ == "__main__":
    unittest.main()
