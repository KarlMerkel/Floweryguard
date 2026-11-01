"""Резервный маршрут проверяет TLS и не подменяет наблюдения о загрузке."""
from test_handshake_wait import hello as real_client_hello
import ssl
import socket
import threading
import unittest
from unittest.mock import Mock, patch

from flowguard.route_recovery import RecoveryRoutes, verify_tls_route
from flowguard.proxy import (DPIBypassProxy, _set_socket_meta, _get_socket_meta,
                             _RESOLVED_IPS_CACHE, _WORKING_IP_CACHE)
from flowguard.route_health import RouteHealth, TransferProgress


class TestRecoveryRoutes(unittest.TestCase):
    def manager(self, probe, clock=lambda: 0):
        manager = RecoveryRoutes(probe=probe, clock=clock)
        self.addCleanup(manager.close)
        return manager

    def test_parallel_probe_keeps_verified_result_scoped_and_expires(self):
        barrier = threading.Barrier(2)
        now = [0]

        def probe(host, port, ip, strategy, timeout):
            barrier.wait(timeout=1)
            return ip == '8.6.112.0'

        manager = self.manager(probe, lambda: now[0])
        result = manager.find('wifi', 'discord.com', 443,
                              [('1.1.1.1', 'direct'), ('8.6.112.0', 'tls_record_frag')], 2)
        self.assertEqual(result, ('8.6.112.0', 'tls_record_frag'))
        self.assertEqual(manager.get('wifi', 'DISCORD.COM.', 443), result)
        self.assertIsNone(manager.get('phone', 'discord.com', 443))
        self.assertIsNone(manager.get('wifi', 'cdn.discordapp.com', 443))
        self.assertIsNone(manager.get('wifi', 'discord.com', 8443))
        now[0] = 61
        self.assertIsNone(manager.get('wifi', 'discord.com', 443))

    def test_failure_rotates_pairs_and_rate_limits_probes(self):
        now = [0]
        probe = Mock(return_value=False)
        manager = self.manager(probe, lambda: now[0])
        pairs = [('1.1.1.1', s) for s in ('direct', 'tls_record_frag', 'multi_split')]
        self.assertIsNone(manager.find('wifi', 'discord.com', 443, pairs, 1))
        self.assertEqual(probe.call_count, 2)
        self.assertIsNone(manager.find('wifi', 'discord.com', 443, pairs, 1))
        self.assertEqual(probe.call_count, 2)
        now[0] = 6
        manager.find('wifi', 'discord.com', 443, pairs, 1)
        self.assertTrue(any(call.args[3] == 'multi_split' for call in probe.call_args_list))

    def test_actual_failure_invalidates_hint(self):
        manager = self.manager(Mock(return_value=True))
        manager.find('wifi', 'discord.com', 443, [('1.1.1.1', 'direct')], 1)
        manager.reject('wifi', 'discord.com', 443, '1.1.1.1')
        self.assertIsNone(manager.get('wifi', 'discord.com', 443))

    def test_close_prevents_late_result_and_new_work(self):
        entered, release = threading.Event(), threading.Event()

        def probe(*args):
            entered.set()
            release.wait(1)
            return True

        manager = self.manager(probe)
        worker = threading.Thread(target=lambda: manager.find(
            'wifi', 'discord.com', 443, [('1.1.1.1', 'direct')], 1))
        worker.start()
        self.assertTrue(entered.wait(1))
        manager.close()
        release.set()
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertIsNone(manager.get('wifi', 'discord.com', 443))
        self.assertIsNone(manager.find('wifi', 'discord.com', 443, [('1.1.1.1', 'direct')], 1))

    def test_certificate_error_rejects_candidate(self):
        context = Mock()
        context.wrap_bio.return_value.do_handshake.side_effect = ssl.SSLCertVerificationError('wrong host')
        sock = Mock()
        sock.__enter__ = Mock(return_value=sock)
        sock.__exit__ = Mock(return_value=False)
        with patch('flowguard.route_recovery.ssl.create_default_context', return_value=context), \
                patch('flowguard.route_recovery.socket.create_connection', return_value=sock):
            self.assertFalse(verify_tls_route('discord.com', 443, '1.1.1.1', 'direct', 1))
        self.assertEqual(context.wrap_bio.call_args.kwargs['server_hostname'], 'discord.com')

    def test_private_addresses_are_never_probed(self):
        for ip in ('127.0.0.1', '10.0.0.1', '::1', '198.18.0.1'):
            with patch('flowguard.route_recovery.socket.create_connection') as connect:
                self.assertFalse(verify_tls_route('discord.com', 443, ip, 'direct', 1))
                connect.assert_not_called()

    def test_background_work_is_bounded_and_close_rejects_new_tasks(self):
        entered, release = threading.Event(), threading.Event()
        manager = self.manager(Mock(return_value=False))

        def work():
            entered.set()
            release.wait(2)

        self.addCleanup(release.set)
        self.assertTrue(manager.schedule(work))
        self.assertTrue(entered.wait(1))
        for _ in range(20):
            self.assertFalse(manager.schedule(work))
        manager.close()
        self.assertFalse(manager.schedule(work))
        release.set()


class TestRecoveryIntegration(unittest.TestCase):
    def setUp(self):
        self.proxy = object.__new__(DPIBypassProxy)
        self.proxy.is_running = True
        self.proxy.config = None
        self.proxy.route_recovery = Mock()
        self.proxy.route_recovery.find.return_value = ('8.6.112.0', 'tls_record_frag')
        self.proxy.strategy_engine = Mock(_current_network='wifi')
        self.proxy.strategy_engine.allowed_strategy.side_effect = lambda name: name
        self.proxy._fixed_strategy = Mock(return_value=None)
        self.proxy.route_health = Mock()
        self.proxy.route_health.proven_ips.return_value = []
        self.proxy.route_health.stalled_strategies.return_value = set()

    def test_discovery_never_rewards_strategy(self):
        result = self.proxy._discover_tls_route('discord.com', 443, 'tls_record_frag', 2)
        self.assertEqual(result, ('8.6.112.0', 'tls_record_frag'))
        self.proxy.strategy_engine.record_success.assert_not_called()
        self.proxy.route_health.record.assert_not_called()

    def test_explicit_strategy_limits_probe_choices(self):
        self.proxy._fixed_strategy.return_value = 'direct'
        self.proxy._discover_tls_route('discord.com', 443, 'combo_tlsrec_tcpsplit', 2)
        pairs = self.proxy.route_recovery.find.call_args.args[3]
        self.assertTrue(pairs)
        self.assertTrue(all(strategy == 'direct' for _, strategy in pairs))

    def test_unrelated_domain_and_other_port_do_not_trigger_discovery(self):
        for host, port in [('discord.com.example', 443), ('discord.com', 8443),
                           ('finland14042.discord.media.example', 443),
                           ('finland14042.discord.media', 50000)]:
            self.assertIsNone(self.proxy._discover_tls_route(host, port, 'direct', 2))
        self.proxy.route_recovery.find.assert_not_called()

    def test_voice_signaling_host_uses_verified_tls_recovery(self):
        result = self.proxy._discover_tls_route('finland14042.discord.media', 443, 'tls_record_frag', 2)
        self.assertEqual(result, ('8.6.112.0', 'tls_record_frag'))
        self.proxy.route_recovery.find.assert_called_once()
        self.assertEqual(self.proxy.route_recovery.find.call_args.args[:3],
                         ('wifi', 'finland14042.discord.media', 443))

    def test_network_change_during_probe_discards_result(self):
        def switch(*args, **kwargs):
            self.proxy.strategy_engine._current_network = 'phone'
            return '8.6.112.0', 'direct'
        self.proxy.route_recovery.find.side_effect = switch
        self.assertIsNone(self.proxy._discover_tls_route('discord.com', 443, 'direct', 2))

    def test_failed_first_hello_recovers_with_original_client_bytes(self):
        first, recovered, client = Mock(), Mock(), Mock()
        _set_socket_meta(first, '162.159.128.233', 0.01)
        _set_socket_meta(recovered, '8.6.112.0', 0.02)
        self.proxy._send_tls_client_hello_with_bypass = Mock(return_value=('tls_record_frag', 'discord.com'))
        self.proxy._try_direct_connect = Mock(return_value=recovered)
        self.proxy._safe_execute_strategy = Mock()
        self.proxy._probe_socket_response = Mock(side_effect=[
            ('silent_drop', None, 1200), ('success', b'server hello', 20)])
        hello = real_client_hello()
        with patch('flowguard.proxy.is_tls_client_hello', return_value=True):
            sock, strategy, host, response = self.proxy._handshake_with_fast_fallback(
                client, first, 'discord.com', 443, hello)
        self.assertIs(sock, recovered)
        self.assertEqual((strategy, host, response), ('tls_record_frag', 'discord.com', b'server hello'))
        self.proxy._safe_execute_strategy.assert_called_once_with(
            'tls_record_frag', recovered, hello, host='discord.com')
        self.proxy.strategy_engine.record_success.assert_not_called()

    def test_manual_host_mapping_prevents_automatic_recovery(self):
        with patch('flowguard.proxy._configured_host_ip', return_value='1.1.1.1'):
            self.assertIsNone(self.proxy._discover_tls_route('discord.com', 443, 'direct', 2))
        self.proxy.route_recovery.find.assert_not_called()

    def test_connect_handler_recovers_before_returning_502(self):
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        tls = ssl.create_default_context().wrap_bio(incoming, outgoing, server_hostname='discord.com')
        with self.assertRaises(ssl.SSLWantReadError):
            tls.do_handshake()
        hello = outgoing.read()
        client, upstream = Mock(spec=socket.socket), Mock(spec=socket.socket)
        client.recv.return_value = b'CONNECT discord.com:443 HTTP/1.1\r\n\r\n' + hello
        self.proxy._lock = threading.Lock()
        self.proxy._concurrency_sem = threading.BoundedSemaphore(1)
        self.proxy._concurrency_sem.acquire()
        self.proxy.active_connections = 1
        self.proxy.timeout, self.proxy.buffer_size = 15, 65536
        self.proxy._connect_target = Mock(return_value=None)
        self.proxy._discover_tls_route = Mock(return_value=('8.6.112.0', 'tls_record_frag'))
        self.proxy._try_direct_connect = Mock(return_value=upstream)
        self.proxy._handshake_with_fast_fallback = Mock(return_value=(upstream, 'tls_record_frag', 'discord.com', b'hello'))
        self.proxy._pipe_sockets = Mock()
        self.proxy._handle_client(client, ('127.0.0.1', 12345))
        self.proxy._discover_tls_route.assert_called_once()
        self.proxy._handshake_with_fast_fallback.assert_called_once_with(
            client, upstream, 'discord.com', 443, hello)
        self.assertFalse(any(b'502' in call.args[0] for call in client.sendall.call_args_list))
        self.proxy._pipe_sockets.assert_called_once()

    def simulate_late_failure(self, *, complete=False, network='wifi'):
        self.proxy.route_health = RouteHealth()
        self.proxy.timeout, self.proxy.buffer_size = 15, 65536
        self.proxy.bytes_rx = self.proxy.bytes_tx = 0
        client, upstream = Mock(spec=socket.socket), Mock(spec=socket.socket)
        _set_socket_meta(upstream, '8.6.112.0', 0.01)
        progress = TransferProgress()
        progress.received(14000, 1, data=(b'\x17\x03\x03' +
                          (13995 if complete else 16384).to_bytes(2, 'big') + b'x' * 13995))

        def relay(*args, **kwargs):
            if not complete:
                kwargs['on_suspect'](progress, 'idle_timeout')
            return progress, 'idle_timeout'

        self.proxy._safe_execute_strategy = Mock()
        with patch('flowguard.proxy.relay_tls', side_effect=relay):
            self.proxy._pipe_tls(client, upstream, 'cdn.discordapp.com', 'tls_record_frag',
                                 443, False, network)
        return client, upstream

    def test_late_stall_schedules_once_and_does_not_replay_request(self):
        client, upstream = self.simulate_late_failure()
        self.proxy.route_recovery.reject.assert_called_with('wifi', 'cdn.discordapp.com', 443, '8.6.112.0')
        self.proxy.route_recovery.schedule.assert_called_once()
        self.proxy.route_recovery.find.assert_not_called()
        callback = self.proxy.route_recovery.schedule.call_args.args[0]
        callback()
        self.proxy.route_recovery.find.assert_called_once()
        pairs = self.proxy.route_recovery.find.call_args.args[3]
        self.assertNotIn(('8.6.112.0', 'tls_record_frag'), pairs)
        client.sendall.assert_not_called()
        upstream.sendall.assert_not_called()
        self.proxy._safe_execute_strategy.assert_not_called()
        self.proxy.strategy_engine.record_success.assert_not_called()

    def test_scheduled_probe_does_not_migrate_to_changed_network(self):
        self.simulate_late_failure()
        self.proxy.strategy_engine._current_network = 'phone'
        self.proxy.route_recovery.schedule.call_args.args[0]()
        self.proxy.route_recovery.find.assert_not_called()

    def test_complete_small_response_does_not_launch_recovery(self):
        self.simulate_late_failure(complete=True)
        self.proxy.route_recovery.schedule.assert_not_called()

    def test_old_connection_does_not_schedule_in_new_network(self):
        self.simulate_late_failure(network='old-wifi')
        self.proxy.route_recovery.schedule.assert_not_called()

    def test_verified_new_technique_can_reuse_suspect_ip_but_real_progress_wins(self):
        import time
        host, recovered_ip, dns_ip = 'cdn.discordapp.com', '8.6.112.0', '1.1.1.1'
        self.proxy.timeout = 2
        self.proxy.dns_failover = self.proxy.doh_harvester = None
        self.proxy.route_health = RouteHealth()
        self.proxy.route_recovery.get.return_value = (recovered_ip, 'tls_record_frag')
        self.proxy.route_health.record('wifi', host, 443, recovered_ip, 'suspect')
        self.proxy.route_health.record_strategy('wifi', host, 443, recovered_ip, 'direct', 'suspect')
        key = self.proxy._resolved_cache_key(host)
        _WORKING_IP_CACHE.pop(host, None)
        _RESOLVED_IPS_CACHE.set(key, (time.time(), [dns_ip]))
        self.addCleanup(_RESOLVED_IPS_CACHE.pop, key, None)
        self.addCleanup(_WORKING_IP_CACHE.pop, host, None)
        for proven, expected in [(False, recovered_ip), (True, dns_ip)]:
            if proven:
                self.proxy.route_health.record('wifi', host, 443, dns_ip, 'progress')
            sock = Mock(spec=socket.socket)
            sock.connect_ex.return_value = 0
            with self.subTest(proven=proven), patch('flowguard.proxy.socket.socket', return_value=sock):
                connected = self.proxy._connect_target(host, 443)
                self.assertEqual(_get_socket_meta(connected)['target_ip'], expected)
