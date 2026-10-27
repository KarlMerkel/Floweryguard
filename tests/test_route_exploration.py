"""Перебор после зависания доходит до неизвестных узлов, даже когда истёк короткий штраф."""
import socket
import time
import unittest
from unittest.mock import Mock, patch

from flowguard.proxy import DPIBypassProxy, _RESOLVED_IPS_CACHE, _WORKING_IP_CACHE, _get_socket_meta
from flowguard.route_health import RouteHealth


class TestRouteExploration(unittest.TestCase):
    def setUp(self):
        for cache in (_RESOLVED_IPS_CACHE, _WORKING_IP_CACHE):
            cache.clear()
            self.addCleanup(cache.clear)
        self.now = 100.0
        self.proxy = object.__new__(DPIBypassProxy)
        self.proxy.config = None
        self.proxy.timeout = 2
        self.proxy.doh_harvester = self.proxy.dns_failover = None
        self.proxy.strategy_engine = Mock(_current_network='wifi')
        self.health = self.proxy.route_health = RouteHealth(clock=lambda: self.now)
        self.host = 'cdn.example.org'
        self.ips = ['192.0.2.' + str(i) for i in range(1, 7)]

    def connect(self, host=None, port=443):
        host = host or self.host
        _RESOLVED_IPS_CACHE.set(self.proxy._resolved_cache_key(host), (time.time(), self.ips))
        sock = Mock(spec=socket.socket)
        sock.connect_ex.return_value = 0
        with patch('flowguard.proxy.socket.socket', return_value=sock):
            connected = self.proxy._connect_target(host, port)
        self.assertIsNotNone(connected)
        return _get_socket_meta(connected)['target_ip']

    def test_expired_suspicion_does_not_restart_at_same_first_addresses(self):
        chosen = []
        for _ in self.ips:
            ip = self.connect()
            chosen.append(ip)
            self.now += 16
            self.health.record('wifi', self.host, 443, ip, 'suspect')
        self.assertEqual(chosen, self.ips)
        self.assertEqual(self.health.status('wifi', self.host, 443, self.ips[0]), 'unknown')
        self.health.record('wifi', self.host, 443, self.ips[-1], 'progress')
        self.assertEqual(self.connect(), self.ips[-1])

    def test_successful_connect_alone_does_not_force_rotation(self):
        self.assertEqual([self.connect() for _ in range(3)], [self.ips[0]] * 3)

    def test_exploration_is_scoped_and_expires(self):
        self.assertEqual(self.connect(), self.ips[0])
        self.health.record('wifi', self.host, 443, self.ips[0], 'suspect')
        self.now += 46
        self.assertEqual(self.connect(), self.ips[1])
        self.assertEqual(self.connect('other.example.org'), self.ips[0])
        self.assertEqual(self.connect(port=8443), self.ips[0])
        self.proxy.strategy_engine._current_network = 'phone'
        self.assertEqual(self.connect(), self.ips[0])
        self.proxy.strategy_engine._current_network = 'wifi'
        self.now += 301
        self.assertEqual(self.connect(), self.ips[0])

    def test_clear_resets_exploration(self):
        self.connect()
        self.health.record('wifi', self.host, 443, self.ips[0], 'suspect')
        self.health.clear()
        self.assertEqual(self.connect(), self.ips[0])
