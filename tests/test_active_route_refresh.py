"""Непрерывная передача сохраняет маршрут, простой не продлевает доверие."""

import socket
import unittest
from unittest.mock import Mock, patch

from flowguard.route_health import RouteHealth
from flowguard.tls_transport import relay_tls
from flowguard.proxy import DPIBypassProxy
from flowguard.route_health import TransferProgress


def records(count=5):
    return (b'\x17\x03\x03\x40\x00' + b'x' * 16384) * count


class TestActiveRouteRefresh(unittest.TestCase):
    def simulate(self, events):
        now = [0.0]
        health = RouteHealth(clock=lambda: now[0])
        scope = ('wifi', 'cdn.discordapp.com', 443, '192.0.2.1')
        client, upstream = Mock(spec=socket.socket), Mock(spec=socket.socket)
        client.send.side_effect = lambda data: len(data)
        incoming = iter(events)
        finished = [False]
        notifications = []
        delivered = []

        def ready(readers, writers, errors, timeout):
            if writers:
                return [], writers, []
            stamp, data = next(incoming)
            now[0] = stamp
            if data is None:
                finished[0] = True
                return [], [], []
            upstream.recv.return_value = data
            return [upstream], [], []

        def progress():
            notifications.append(now[0])
            health.record(*scope, 'progress')
            health.record_strategy(*scope, 'direct', 'progress')

        with patch('flowguard.tls_transport.time.monotonic', side_effect=lambda: now[0]), \
                patch('flowguard.tls_transport.select.select', side_effect=ready):
            relay_tls(client, upstream, lambda: not finished[0], 15, 131072,
                      lambda direction, count: delivered.append(count), progress)
        self.assertEqual(sum(delivered), sum(len(data) for _, data in events if data))
        return health, scope, notifications

    def test_active_route_survives_initial_five_minute_expiry(self):
        events = [(stamp, records()) for stamp in (1, 61, 121, 181, 241, 301)]
        health, scope, notifications = self.simulate(events + [(302, None)])
        self.assertEqual(health.status(*scope), 'progress')
        self.assertEqual(health.progressing_strategies(*scope), ['direct'])
        self.assertEqual(notifications, [1, 61, 121, 181, 241, 301])

    def test_idle_connection_does_not_refresh(self):
        health, scope, notifications = self.simulate([(1, records()), (302, None)])
        self.assertEqual(health.status(*scope), 'unknown')
        self.assertEqual(notifications, [1])

    def test_refresh_requires_fresh_volume_and_complete_record(self):
        health, scope, notifications = self.simulate([
            (1, records()), (61, records(1)), (121, records(1)),
            (181, records(1)), (241, records(1)[:-1]), (302, None)])
        self.assertEqual(health.status(*scope), 'unknown')
        self.assertEqual(notifications, [1])

    def test_burst_does_not_refresh_on_every_chunk(self):
        _, _, notifications = self.simulate([
            (1, records()), (2, records()), (3, records()), (4, None)])
        self.assertEqual(notifications, [1])

    def test_repeated_progress_does_not_multiply_strategy_rewards(self):
        proxy = object.__new__(DPIBypassProxy)
        proxy.timeout = 15
        proxy.buffer_size = 131072
        proxy.is_running = True
        proxy.bytes_rx = proxy.bytes_tx = 0
        proxy.route_health = Mock()
        proxy.strategy_engine = Mock()
        proxy.strategy_engine._current_network = 'wifi'
        client, upstream = Mock(spec=socket.socket), Mock(spec=socket.socket)
        upstream.getpeername.return_value = ('192.0.2.1', 443)

        def transfer(client, upstream, running, timeout, capacity, account, on_progress, **kwargs):
            progress = TransferProgress()
            for stamp in (1, 61, 121, 181, 241, 301):
                data = records()
                progress.received(len(data), stamp, data=data)
                account('rx', len(data))
                on_progress()
            proxy.strategy_engine.record_success.assert_not_called()
            return progress, 'server_eof'

        with patch('flowguard.proxy.relay_tls', side_effect=transfer), \
                patch('flowguard.proxy.mark_ip_working'):
            proxy._pipe_tls(client, upstream, 'cdn.discordapp.com', 'direct', 443, False, 'wifi')
        self.assertEqual(proxy.route_health.record.call_count, 6)
        self.assertEqual(proxy.route_health.record_strategy.call_count, 6)
        proxy.strategy_engine.record_success.assert_called_once_with(
            'cdn.discordapp.com', 'direct', ip='192.0.2.1')
