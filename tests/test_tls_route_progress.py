"""Прокси не награждает TLS-рукопожатие и зависшую передачу."""
import socket
import threading
import unittest
from unittest.mock import MagicMock, patch

from flowguard.proxy import DPIBypassProxy, _set_socket_meta, _WORKING_IP_CACHE
from flowguard.route_health import RouteHealth


class TestTlsRouteProgress(unittest.TestCase):
    def setUp(self):
        _WORKING_IP_CACHE.clear()
        self.addCleanup(_WORKING_IP_CACHE.clear)
        self.proxy = object.__new__(DPIBypassProxy)
        self.proxy.timeout = 15
        self.proxy.buffer_size = 131072
        self.proxy.is_running = True
        self.proxy.bytes_rx = self.proxy.bytes_tx = 0
        self.proxy.strategy_engine = MagicMock()
        self.proxy.strategy_engine._current_network = 'wifi'
        self.proxy.route_health = RouteHealth()

    def run_flow(self, size, end_time=16, host='surfshark.com', client_error=False, route_network=None):
        client, upstream = MagicMock(spec=socket.socket), MagicMock(spec=socket.socket)
        ip = '104.18.120.10'
        _set_socket_meta(upstream, ip, 0.02)
        request = b'\x17' + b'C' * 300
        response = b'\x17' + b'S' * (size - 1)
        client.recv.side_effect = [request, ConnectionResetError() if client_error else b'']
        upstream.recv.return_value = response
        events = iter([(0, client), (1, upstream), (end_time, client), (end_time + 15, None)])
        now = [0]

        def ready(*args):
            now[0], sock = next(events)
            return ([sock] if sock is not None else []), [], []

        with patch('flowguard.proxy.time.monotonic', side_effect=lambda: now[0]), \
             patch('flowguard.proxy.select.select', side_effect=ready), \
             patch('flowguard.proxy.mark_ip_dead') as dead:
            self.proxy._pipe_sockets(client, upstream, host=host, strategy='combo_tlsrec_tcpsplit',
                                     got_initial_response=True, tls_tunnel=True, route_network=route_network)
        dead.assert_not_called()
        client.sendall.assert_called_once_with(response)
        upstream.sendall.assert_called_once_with(request)
        return self.proxy.route_health.status('wifi', host, 443, ip)

    def test_plateau_is_not_rewarded_and_next_route_is_deprioritized(self):
        for reset in (False, True):
            with self.subTest(reset=reset):
                self.proxy.strategy_engine.reset_mock()
                self.assertEqual(self.run_flow(14000, client_error=reset), 'suspect')
                self.proxy.strategy_engine.record_success.assert_not_called()
                self.proxy.strategy_engine.record_failure.assert_not_called()
                self.assertIsNone(_WORKING_IP_CACHE.get('surfshark.com'))

    def test_full_transfer_is_rewarded_once(self):
        self.assertEqual(self.run_flow(100000), 'progress')
        self.proxy.strategy_engine.record_success.assert_called_once()
        self.assertEqual(_WORKING_IP_CACHE.get('surfshark.com'), '104.18.120.10')

    def test_short_transfer_and_websocket_are_not_degraded(self):
        self.assertEqual(self.run_flow(500), 'unknown')
        self.assertEqual(self.run_flow(14000, host='gateway.discord.gg'), 'unknown')

    def test_immediate_cancel_does_not_become_suspect_while_draining(self):
        self.assertEqual(self.run_flow(14000, end_time=1.1), 'unknown')

    def test_old_connection_does_not_train_new_network(self):
        self.proxy.strategy_engine._current_network = 'phone'
        self.assertEqual(self.run_flow(100000, route_network='wifi'), 'progress')
        self.assertEqual(self.proxy.route_health.status('phone', 'surfshark.com', 443, '104.18.120.10'), 'unknown')
        self.proxy.strategy_engine.record_success.assert_not_called()
        self.assertIsNone(_WORKING_IP_CACHE.get('surfshark.com'))

    def test_handshake_only_does_not_cache_ip(self):
        self.proxy._whitelist_lock = threading.Lock()
        self.proxy.whitelist_domains = set()
        self.proxy.shadow_prober = None
        self.proxy._probe_socket_response = MagicMock(return_value=('success', b'\x16\x03\x03\x00\x50', 15))
        self.proxy._send_tls_client_hello_with_bypass = MagicMock(return_value=('combo_tlsrec_tcpsplit', 'surfshark.com'))
        upstream = MagicMock(spec=socket.socket)
        _set_socket_meta(upstream, '104.18.120.10', 0.02)
        with patch('flowguard.proxy.is_tls_client_hello', return_value=True):
            sock, _, _, _ = self.proxy._handshake_with_fast_fallback(
                MagicMock(), upstream, 'surfshark.com', 443, b'\x16\x03\x01\x00\x10')
        self.assertIs(sock, upstream)
        self.assertIsNone(_WORKING_IP_CACHE.get('surfshark.com'))

    def test_connect_handler_uses_tls_progress_path(self):
        import ssl
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        tls = ssl.create_default_context().wrap_bio(incoming, outgoing, server_hostname='example.com')
        with self.assertRaises(ssl.SSLWantReadError):
            tls.do_handshake()
        hello = outgoing.read()
        client, upstream = MagicMock(spec=socket.socket), MagicMock(spec=socket.socket)
        client.recv.return_value = b'CONNECT example.com:443 HTTP/1.1\r\n\r\n' + hello
        self.proxy._lock = threading.Lock()
        self.proxy._concurrency_sem = threading.BoundedSemaphore(1)
        self.proxy._concurrency_sem.acquire()
        self.proxy.active_connections = 1
        self.proxy._connect_target = MagicMock(return_value=upstream)
        self.proxy._handshake_with_fast_fallback = MagicMock(return_value=(upstream, 'combo_tlsrec_tcpsplit', 'example.com', b'hello'))
        self.proxy._pipe_sockets = MagicMock()
        self.proxy._handle_client(client, ('127.0.0.1', 12345))
        self.assertTrue(self.proxy._pipe_sockets.call_args.kwargs['tls_tunnel'])
        self.assertEqual(self.proxy._pipe_sockets.call_args.kwargs['target_port'], 443)
