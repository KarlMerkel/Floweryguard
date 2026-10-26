"""Следующее соединение учитывает передачу, даже когда TCP плохого узла доступен."""
import socket
import time
import unittest
from unittest.mock import MagicMock, patch

from flowguard.proxy import (DPIBypassProxy, _WORKING_IP_CACHE,
                             _RESOLVED_IPS_CACHE, _DEAD_IP_CACHE, _get_socket_meta)
from flowguard.route_health import RouteHealth


class TestRouteSelection(unittest.TestCase):
    def setUp(self):
        for cache in (_WORKING_IP_CACHE, _RESOLVED_IPS_CACHE, _DEAD_IP_CACHE):
            cache.clear()
            self.addCleanup(cache.clear)
        self.proxy = object.__new__(DPIBypassProxy)
        self.proxy.timeout = 5
        self.proxy.config = None
        self.proxy.dns_failover = self.proxy.doh_harvester = None
        self.proxy.strategy_engine = MagicMock()
        self.proxy.strategy_engine._current_network = 'wifi'
        self.proxy.route_health = RouteHealth()
        self.host = 'surfshark.com'
        self.bad, self.good = '104.18.1.1', '104.18.2.1'

    def connect(self, candidates, port=443):
        _RESOLVED_IPS_CACHE.set(self.host, (time.time(), candidates))
        sock = MagicMock(spec=socket.socket)
        sock.connect_ex.return_value = 0
        with patch('flowguard.proxy.socket.socket', return_value=sock):
            result = self.proxy._connect_target(self.host, port)
        self.assertIsNotNone(result)
        return _get_socket_meta(result)['target_ip']

    def test_suspect_cached_ip_yields_to_dns_alternative(self):
        _WORKING_IP_CACHE.set(self.host, self.bad)
        self.proxy.route_health.record('wifi', self.host, 443, self.bad, 'suspect')
        self.assertEqual(self.connect([self.bad, self.good]), self.good)

    def test_progress_has_priority_over_unknown_dns_address(self):
        self.proxy.route_health.record('wifi', self.host, 443, self.good, 'progress')
        self.assertEqual(self.connect([self.bad, self.good]), self.good)

    def test_only_address_is_still_available_and_not_banned(self):
        self.proxy.route_health.record('wifi', self.host, 443, self.bad, 'suspect')
        self.assertEqual(self.connect([self.bad]), self.bad)
        self.assertIsNone(_DEAD_IP_CACHE.get(self.bad))

    def test_different_network_or_port_does_not_inherit_preference(self):
        self.proxy.route_health.record('wifi', self.host, 443, self.good, 'progress')
        self.assertEqual(self.connect([self.bad, self.good], port=8443), self.bad)
        self.proxy.strategy_engine._current_network = 'phone'
        self.assertEqual(self.connect([self.bad, self.good]), self.bad)

    def test_global_fast_cache_does_not_leak_progress_to_other_network(self):
        _WORKING_IP_CACHE.set(self.host, self.good)
        self.proxy.route_health.record('wifi', self.host, 443, self.good, 'progress')
        self.assertEqual(self.connect([self.bad, self.good]), self.good)
        self.proxy.strategy_engine._current_network = 'phone'
        self.assertEqual(self.connect([self.bad, self.good]), self.bad)
        self.proxy.strategy_engine._current_network = 'wifi'
        self.assertEqual(self.connect([self.bad, self.good], port=8443), self.bad)

    def test_discord_initial_priority_yields_to_observed_stall(self):
        self.host = 'cdn.discordapp.com'
        self.proxy.route_health.record('wifi', self.host, 443, '162.159.136.232', 'suspect')
        self.assertNotEqual(self.connect([self.bad]), '162.159.136.232')
