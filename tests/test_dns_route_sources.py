"""Рабочие публичные DNS-ответы не отбрасываются по предположению о подсети."""
import socket
import unittest
from unittest.mock import Mock, patch

from flowguard.config import Config
from flowguard.proxy import (DPIBypassProxy, is_bogon_or_sinkhole_ip,
                             _get_socket_meta, _DNS_CACHE, _RESOLVED_IPS_CACHE,
                             _WORKING_IP_CACHE, _DEAD_IP_CACHE)


class TestDnsRouteSources(unittest.TestCase):
    def setUp(self):
        for cache in (_DNS_CACHE, _RESOLVED_IPS_CACHE, _WORKING_IP_CACHE, _DEAD_IP_CACHE):
            cache.clear()
            self.addCleanup(cache.clear)
        with patch('flowguard.proxy.ShadowProber'), patch('flowguard.proxy.WarmUpHarvester'):
            self.proxy = DPIBypassProxy(Config('_dns_route_test_missing.ini'))
        self.proxy.whitelist_domains = {'signal.org'}
        self.proxy._check_reload_whitelist = Mock()
        self.proxy.doh_harvester = Mock()
        self.proxy.doh_harvester.harvest.return_value = ['104.18.10.47']
        self.proxy.dns_failover = None

    def connect(self, system_ip, custom=False):
        self.proxy.config.set_override('enable_custom_dns', custom)
        sock = Mock(spec=socket.socket)
        sock.connect_ex.return_value = 0
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (system_ip, 443))]
        with patch('flowguard.proxy.socket.getaddrinfo', return_value=addresses), \
             patch('flowguard.proxy.socket.socket', return_value=sock):
            connected = self.proxy._connect_target('signal.org', 443)
        self.assertIsNotNone(connected)
        return _get_socket_meta(connected)['target_ip']

    def test_public_edges_are_not_permanently_banned(self):
        for ip in ('8.6.112.0', '8.6.112.50', '8.47.69.0', '8.47.69.254'):
            with self.subTest(ip=ip):
                self.assertFalse(is_bogon_or_sinkhole_ip(ip))

    def test_automatic_dns_keeps_system_candidate_before_doh(self):
        self.assertEqual(self.connect('8.6.112.0'), '8.6.112.0')
        self.proxy.doh_harvester.harvest.assert_called_once_with('signal.org')

    def test_explicit_custom_dns_keeps_priority(self):
        self.assertEqual(self.connect('8.6.112.0', custom=True), '104.18.10.47')

    def test_fake_ip_still_falls_back_to_doh(self):
        self.assertEqual(self.connect('198.18.0.10'), '104.18.10.47')
