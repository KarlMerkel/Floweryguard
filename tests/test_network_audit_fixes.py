"""Регрессии адаптации из пользовательских логов 28 октября."""
import socket
import threading
import time
import unittest
from unittest.mock import Mock, patch

from flowguard.proxy import DPIBypassProxy, ShadowProber
from flowguard.profiles import ProfileManager
from flowguard.route_health import RouteHealth


class NetworkAuditTests(unittest.TestCase):
    def test_synthetic_probe_respects_permissions_and_never_rewards(self):
        probe = object.__new__(ShadowProber)
        probe.strategy_engine = Mock()
        probe.strategy_engine.select_strategy.return_value = 'direct'
        probe.strategy_engine.allowed_strategy.return_value = 'direct'
        sock = Mock()
        sock.recv.return_value = b'\x16' + bytes(15)
        with patch('flowguard.proxy.socket.socket', return_value=sock), \
                patch('flowguard.proxy.execute_strategy') as execute:
            probe._probe_host('audit.example', '192.0.2.1')
        self.assertEqual(execute.call_args.args[0], 'direct')
        probe.strategy_engine.record_success.assert_not_called()

    def make_proxy(self):
        proxy = object.__new__(DPIBypassProxy)
        proxy.route_health = RouteHealth()
        proxy.strategy_engine = Mock()
        proxy.strategy_engine._current_network = 'audit-network'
        proxy.strategy_engine.select_strategy.return_value = 'direct'
        proxy.strategy_engine.get_fallback_strategy.return_value = 'direct'
        proxy.strategy_engine.allowed_strategy.side_effect = lambda value: value
        proxy._fixed_strategy = Mock(return_value=None)
        proxy._strategy_after_stall = Mock(side_effect=lambda h, p, ip, s, excluded=(): s)
        proxy._send_tls_client_hello_with_bypass = Mock(return_value=('direct', 'rr1.googlevideo.com'))
        proxy._safe_execute_strategy = Mock(return_value=True)
        proxy.whitelist_domains = set()
        proxy._whitelist_lock = threading.Lock()
        proxy.shadow_prober = None
        return proxy

    def test_every_failed_attempt_is_remembered_without_global_penalty(self):
        for last_status in ('success', 'silent_drop'):
            with self.subTest(last_status=last_status):
                proxy = self.make_proxy()
                first, alternate = Mock(), Mock()
                proxy._connect_target = Mock(return_value=alternate)
                proxy._probe_socket_response = Mock(side_effect=[('silent_drop', None, 380),
                                                                 (last_status, b'\x16', 10)])
                def metadata(sock):
                    return {'target_ip': '192.0.2.1' if sock is first else '192.0.2.2', 'connect_rtt': .01}
                with patch('flowguard.proxy.is_tls_client_hello', return_value=True), \
                        patch('flowguard.proxy._get_socket_meta', side_effect=metadata), \
                        patch('flowguard.proxy._safe_close_socket'):
                    proxy._handshake_with_fast_fallback(Mock(), first, 'rr1.googlevideo.com', 443, b'hello')
                self.assertEqual(proxy.route_health.status('audit-network', 'rr1.googlevideo.com', 443, '192.0.2.1'), 'suspect')
                self.assertIn('direct', proxy.route_health.stalled_strategies('audit-network', 'rr1.googlevideo.com', 443, '192.0.2.1'))
                if last_status != 'success':
                    self.assertEqual(proxy.route_health.status('audit-network', 'rr1.googlevideo.com', 443, '192.0.2.2'), 'suspect')
                proxy.strategy_engine.record_failure.assert_not_called()

    def test_delayed_first_response_is_not_discarded(self):
        proxy = self.make_proxy()
        proxy.buffer_size = 4096
        proxy._connect_target = Mock(return_value=None)
        client, server = socket.socketpair()
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        sent = threading.Event()
        def reply():
            sent.wait(2)
            time.sleep(.65)
            try:
                server.sendall(b'\x16\x03\x03\x00\x01x')
            except OSError:
                return
        worker = threading.Thread(target=reply)
        worker.start()
        self.addCleanup(worker.join, 3)
        def hello(*args, **kwargs):
            sent.set()
            return 'direct', 'audit.example'
        proxy._send_tls_client_hello_with_bypass.side_effect = hello
        with patch('flowguard.proxy.is_tls_client_hello', return_value=True), \
                patch('flowguard.proxy._get_socket_meta', return_value={'target_ip': '192.0.2.1', 'connect_rtt': .01}):
            result = proxy._handshake_with_fast_fallback(Mock(), client, 'audit.example', 443, b'hello')
        self.assertIs(result[0], client)
        self.assertEqual(result[3], b'\x16\x03\x03\x00\x01x')

    def test_same_profile_notifies_network_change(self):
        manager = object.__new__(ProfileManager)
        manager._lock = threading.Lock()
        manager._monitor_running = False
        manager._last_fingerprint = 'wifi:old'
        manager.active_profile_id = 'home_wifi'
        manager.network_map = {'wifi:new': 'home_wifi'}
        manager.get_profile = Mock(return_value={'name': 'Дом'})
        callback = Mock()
        def changed():
            manager._monitor_running = False
            return 'wifi:new'
        def thread(*args, **kwargs):
            result = Mock()
            result.start.side_effect = kwargs['target']
            return result
        with patch('flowguard.profiles.threading.Thread', side_effect=thread), \
                patch('flowguard.profiles.time.sleep'), \
                patch('flowguard.profiles.get_network_fingerprint', side_effect=changed):
            manager.start_network_monitor(Mock(), callback)
        callback.assert_called_once_with('home_wifi', 'Дом', 'wifi:new')
