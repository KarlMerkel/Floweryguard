"""Подбор продолжает исходный TLS-туннель, не повторяя данные приложения."""
import socket
import ssl
import threading
import time
import unittest
from unittest.mock import Mock, patch

from flowguard.proxy import DPIBypassProxy, _set_socket_meta
from flowguard.route_health import RouteHealth
from flowguard.tls_parser import is_replayable_client_hello, _parse_extensions_info


def hello():
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ssl.create_default_context().wrap_bio(incoming, outgoing, server_hostname='discord.com')
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        return outgoing.read()
    raise AssertionError('ClientHello не создан')


class TestHandshakeWait(unittest.TestCase):
    def setUp(self):
        self.browser, self.client = socket.socketpair()
        self.addCleanup(self.browser.close)
        self.addCleanup(self.client.close)
        self.proxy = object.__new__(DPIBypassProxy)
        self.proxy.is_running = True
        self.proxy.buffer_size = 65536
        self.proxy.config = None
        self.proxy.route_health = RouteHealth()
        self.proxy.strategy_engine = Mock(_current_network='wifi')
        self.proxy.strategy_engine.select_strategy.return_value = 'direct'
        self.proxy.strategy_engine.allowed_strategy.side_effect = lambda x: x
        self.proxy._fixed_strategy = Mock(return_value=None)
        self.proxy._strategy_after_stall = Mock(return_value='direct')
        self.proxy._discover_tls_route = Mock(return_value=None)
        self.data = hello()

    def continuation(self, budget=1):
        return self.proxy._continue_tls_selection(
            self.client, 'discord.com', 'discord.com', 443, self.data,
            'wifi', ['1.1.1.1'], 'direct', time.monotonic() + budget)

    def test_later_attempt_keeps_browser_socket_and_original_hello(self):
        server, upstream = socket.socketpair()
        self.addCleanup(server.close)
        self.addCleanup(upstream.close)
        _set_socket_meta(upstream, '1.1.1.1', 0.01)
        self.proxy._try_direct_connect = Mock(return_value=upstream)
        self.proxy._safe_execute_strategy = Mock(side_effect=lambda strategy, sock, data, **kw: sock.sendall(data) is None)
        server.sendall(b'\x16\x03\x03\x00\x02ok')
        sock, _, _, response = self.continuation()
        self.assertIs(sock, upstream)
        self.assertEqual(server.recv(len(self.data)), self.data)
        self.assertEqual(response, b'\x16\x03\x03\x00\x02ok')
        self.assertNotEqual(self.client.fileno(), -1)
        self.browser.settimeout(0.01)
        with self.assertRaises(socket.timeout):
            self.browser.recv(1)
        self.proxy.strategy_engine.record_success.assert_not_called()

    def test_closed_browser_does_not_start_more_connections(self):
        self.browser.close()
        self.proxy._try_direct_connect = Mock()
        self.assertIsNone(self.continuation()[0])
        self.proxy._try_direct_connect.assert_not_called()

    def test_wait_is_cancelled_when_browser_closes(self):
        server, upstream = socket.socketpair()
        self.addCleanup(server.close)
        self.addCleanup(upstream.close)
        self.proxy._try_direct_connect = Mock(return_value=upstream)
        self.proxy._safe_execute_strategy = Mock(return_value=True)
        timer = threading.Timer(0.1, self.browser.close)
        timer.start()
        self.addCleanup(timer.cancel)
        started = time.monotonic()
        self.assertIsNone(self.continuation(2)[0])
        self.assertLess(time.monotonic() - started, 0.8)
        self.assertEqual(upstream.fileno(), -1)

    def test_expired_budget_and_changed_network_do_not_connect(self):
        self.proxy._try_direct_connect = Mock()
        self.assertIsNone(self.continuation(0)[0])
        self.proxy.strategy_engine._current_network = 'phone'
        self.assertIsNone(self.continuation()[0])
        self.proxy._try_direct_connect.assert_not_called()

    def test_application_data_and_incomplete_hello_are_not_replayed(self):
        self.assertTrue(is_replayable_client_hello(self.data))
        self.assertTrue(is_replayable_client_hello(self.data + b'\x14\x03\x03\x00\x01\x01'))
        self.assertFalse(is_replayable_client_hello(self.data[:-1]))
        self.assertFalse(is_replayable_client_hello(self.data + b'\x17\x03\x03\x00\x03abc'))
        self.proxy._try_direct_connect = Mock()
        self.data += b'\x17\x03\x03\x00\x03abc'
        self.assertIsNone(self.continuation()[0])
        self.proxy._try_direct_connect.assert_not_called()

    def test_fragmented_hello_and_early_data_extension(self):
        payload = self.data[5:]
        fragments = [payload[:30], payload[30:]]
        fragmented = b''.join(b'\x16\x03\x03' + len(p).to_bytes(2, 'big') + p for p in fragments)
        self.assertTrue(is_replayable_client_hello(fragmented))
        modified = bytearray(self.data)
        pos, size, _ = _parse_extensions_info(modified)
        modified.extend(b'\x00\x2a\x00\x00')
        modified[pos:pos + 2] = (size + 4).to_bytes(2, 'big')
        modified[3:5] = (len(modified) - 5).to_bytes(2, 'big')
        modified[6:9] = (len(modified) - 9).to_bytes(3, 'big')
        self.assertFalse(is_replayable_client_hello(bytes(modified)))

    def test_pending_client_bytes_prevent_replay(self):
        self.browser.sendall(b'\x17\x03\x03\x00\x03abc')
        self.proxy._try_direct_connect = Mock()
        self.assertIsNone(self.continuation()[0])
        self.proxy._try_direct_connect.assert_not_called()
        self.assertEqual(self.client.recv(8), b'\x17\x03\x03\x00\x03abc')

    def test_silent_server_stops_at_deadline_and_closes_upstream(self):
        server, upstream = socket.socketpair()
        self.addCleanup(server.close)
        self.addCleanup(upstream.close)
        self.proxy._try_direct_connect = Mock(return_value=upstream)
        self.proxy._safe_execute_strategy = Mock(return_value=True)
        started = time.monotonic()
        self.assertIsNone(self.continuation(.15)[0])
        self.assertLess(time.monotonic() - started, .7)
        self.assertEqual(upstream.fileno(), -1)

    def test_fourth_attempt_recovers_original_tunnel(self):
        sockets = [socket.socketpair() for _ in range(4)]
        for pair in sockets:
            for sock in pair:
                self.addCleanup(sock.close)
        upstreams = [pair[1] for pair in sockets]
        for sock in upstreams:
            _set_socket_meta(sock, '1.1.1.1', .01)
        self.proxy.whitelist_domains = set()
        self.proxy._whitelist_lock = threading.Lock()
        self.proxy._send_tls_client_hello_with_bypass = Mock(return_value=('direct', 'example.org'))
        self.proxy.strategy_engine.get_fallback_strategy.return_value = 'direct'
        self.proxy._connect_target = Mock(side_effect=upstreams[1:3])
        self.proxy._probe_socket_response = Mock(return_value=('silent_drop', None, 1200))
        self.proxy._try_direct_connect = Mock(return_value=upstreams[3])
        self.proxy._safe_execute_strategy = Mock(side_effect=lambda strategy, sock, data, **kw: sock.sendall(data) is None)
        response = b'\x16\x03\x03\x00\x02ok'
        sockets[3][0].sendall(response)
        result = self.proxy._handshake_with_fast_fallback(
            self.client, upstreams[0], 'example.org', 443, self.data)
        self.assertIs(result[0], upstreams[3])
        self.assertEqual(result[3], response)
        self.assertEqual(sockets[3][0].recv(len(self.data)), self.data)
        self.assertEqual(self.proxy._probe_socket_response.call_count, 3)
        self.assertNotEqual(self.client.fileno(), -1)
        self.proxy.strategy_engine.record_success.assert_not_called()

    def test_first_response_never_starts_continuation(self):
        server, upstream = socket.socketpair()
        self.addCleanup(server.close)
        self.addCleanup(upstream.close)
        self.proxy._send_tls_client_hello_with_bypass = Mock(return_value=('direct', 'discord.com'))
        self.proxy._probe_socket_response = Mock(return_value=('success', b'\x16', 10))
        self.proxy._continue_tls_selection = Mock()
        result = self.proxy._handshake_with_fast_fallback(
            self.client, upstream, 'discord.com', 443, self.data)
        self.assertIs(result[0], upstream)
        self.proxy._continue_tls_selection.assert_not_called()

    def test_failed_early_data_is_never_replayed_by_initial_fallback(self):
        server, upstream = socket.socketpair()
        self.addCleanup(server.close)
        self.addCleanup(upstream.close)
        self.proxy._send_tls_client_hello_with_bypass = Mock(return_value=('direct', 'discord.com'))
        self.proxy._probe_socket_response = Mock(return_value=('silent_drop', None, 1200))
        self.proxy._continue_tls_selection = Mock()
        self.proxy._connect_target = Mock()
        result = self.proxy._handshake_with_fast_fallback(
            self.client, upstream, 'discord.com', 443,
            self.data + b'\x17\x03\x03\x00\x03abc')
        self.assertIsNone(result[0])
        self.proxy._continue_tls_selection.assert_not_called()
        self.proxy._connect_target.assert_not_called()
        self.proxy._discover_tls_route.assert_not_called()

    def test_stopping_proxy_cancels_wait(self):
        server, upstream = socket.socketpair()
        self.addCleanup(server.close)
        self.addCleanup(upstream.close)
        self.proxy._try_direct_connect = Mock(return_value=upstream)
        self.proxy._safe_execute_strategy = Mock(return_value=True)
        timer = threading.Timer(.1, setattr, args=(self.proxy, 'is_running', False))
        timer.start()
        self.addCleanup(timer.cancel)
        started = time.monotonic()
        self.assertIsNone(self.continuation(2)[0])
        self.assertLess(time.monotonic() - started, .8)
        self.assertEqual(upstream.fileno(), -1)

    def test_manual_strategy_and_disabled_ipv6_are_respected(self):
        self.proxy._fixed_strategy.return_value = 'tls_record_frag'
        self.proxy._strategy_after_stall.side_effect = lambda h, p, ip, method, excluded: method
        self.proxy._try_direct_connect = Mock(return_value=None)
        self.proxy._continue_tls_selection(self.client, 'discord.com', 'discord.com', 443,
            self.data, 'wifi', ['2606:4700::1111', '1.1.1.1'], 'direct', time.monotonic() + 1)
        self.proxy.strategy_engine.select_strategy.assert_not_called()
        self.assertEqual(self.proxy._try_direct_connect.call_count, 1)
        self.assertEqual(self.proxy._try_direct_connect.call_args.args[0], '1.1.1.1')
        self.assertEqual(self.proxy._strategy_after_stall.call_args.args[3], 'tls_record_frag')
