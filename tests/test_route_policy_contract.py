"""Начальные подсказки не должны запрещать публичные адреса или вытеснять наблюдения."""
import json
import socket
import subprocess
import sys
import time
import unittest
from unittest.mock import Mock, patch

from flowguard.proxy import (DPIBypassProxy, is_bogon_or_sinkhole_ip,
                             is_discord_host, is_discord_network_host, is_discord_media_host,
                             is_google_or_youtube_host, is_googlevideo_host,
                             is_gaming_host, is_telegram_host,
                             _WORKING_IP_CACHE, _RESOLVED_IPS_CACHE, _DEAD_IP_CACHE,
                             _get_socket_meta, _set_socket_meta)
from flowguard.route_health import RouteHealth


class TestRoutePolicyContract(unittest.TestCase):
    def setUp(self):
        for cache in (_WORKING_IP_CACHE, _RESOLVED_IPS_CACHE, _DEAD_IP_CACHE):
            cache.clear()
            self.addCleanup(cache.clear)
        self.proxy = object.__new__(DPIBypassProxy)
        self.proxy.timeout = 2
        self.proxy.config = None
        self.proxy.dns_failover = self.proxy.doh_harvester = None
        self.proxy.strategy_engine = Mock(_current_network='wifi')
        self.proxy.route_health = RouteHealth()

    def connect(self, host, addresses):
        _RESOLVED_IPS_CACHE.set(self.proxy._resolved_cache_key(host), (time.time(), addresses))
        sock = Mock(spec=socket.socket)
        sock.connect_ex.return_value = 0
        with patch('flowguard.proxy.socket.socket', return_value=sock):
            connected = self.proxy._connect_target(host, 443)
        self.assertIsNotNone(connected)
        return _get_socket_meta(connected)['target_ip']

    def test_no_public_address_is_banned_without_observation(self):
        for ip in ('192.144.59.14', '94.232.43.149', '204.8.99.144', '204.8.99.146'):
            with self.subTest(ip=ip):
                self.assertFalse(is_bogon_or_sinkhole_ip(ip))

    def test_import_does_not_seed_dead_public_addresses(self):
        command = ('import json; from flowguard.proxy import is_ip_dead; '
                   'print(json.dumps([is_ip_dead(ip) for ip in '
                   '["204.8.99.144", "204.8.99.146"]]))')
        result = subprocess.run([sys.executable, '-c', command], capture_output=True,
                                text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout.strip().splitlines()[-1]), [False, False])

    def test_telemetry_domain_is_not_implicitly_blocked(self):
        self.assertEqual(self.connect('dc-telemetry.net', ['93.184.216.34']), '93.184.216.34')

    def test_discord_uses_dns_before_unproven_static_pool(self):
        self.assertEqual(self.connect('cdn.discordapp.com', ['8.6.112.0']), '8.6.112.0')

    def test_dns_member_of_static_pool_is_not_reordered(self):
        self.assertEqual(self.connect('cdn.discordapp.com', ['162.159.128.233', '8.6.112.0']),
                         '162.159.128.233')

    def test_unrelated_domains_are_not_assigned_service_routes(self):
        cases = [
            (is_discord_host, 'notdiscord.example'),
            (is_discord_network_host, 'cdn.discordapp.com.example'),
            (is_discord_media_host, 'images-ext.example'),
            (is_google_or_youtube_host, 'youtube.com.example'),
            (is_googlevideo_host, 'notgooglevideo.com'),
            (is_gaming_host, 'steampowered.com.example'),
            (is_telegram_host, 'telegram.example'),
        ]
        for classify, host in cases:
            with self.subTest(host=host):
                self.assertFalse(classify(host))

    def test_service_ranges_and_mapped_addresses_remain_filtered(self):
        for ip in ('127.0.0.1', '10.0.0.1', '198.18.0.1', '100.64.0.1',
                   '::1', '::', 'fc00::1', 'fe80::1', 'ff02::1', '::ffff:127.0.0.1'):
            with self.subTest(ip=ip):
                self.assertTrue(is_bogon_or_sinkhole_ip(ip))
        self.assertFalse(is_bogon_or_sinkhole_ip('2606:4700::1111'))
        self.assertFalse(is_bogon_or_sinkhole_ip('::ffff:8.6.112.0'))

    def test_ncsi_reply_does_not_replace_unrelated_domains(self):
        self.assertFalse(DPIBypassProxy._is_ncsi_request('msftncsi.com.example', '/'))
        self.assertFalse(DPIBypassProxy._is_ncsi_request('notmsftconnecttest.com', '/'))
        self.assertTrue(DPIBypassProxy._is_ncsi_request('www.msftconnecttest.com', '/connecttest.txt'))

    def test_observed_address_wins_even_outside_static_pool(self):
        for host in ('cdn.discordapp.com', 'media.discordapp.net', 'rr1.googlevideo.com'):
            with self.subTest(host=host):
                ip = '8.6.112.0' if 'discord' in host else '142.250.180.14'
                self.proxy.route_health.record('wifi', host, 443, ip, 'progress')
                _WORKING_IP_CACHE.set(host, ip)
                sock = Mock(spec=socket.socket)
                _set_socket_meta(sock, ip, 0.02)
                self.proxy._try_direct_connect = Mock(return_value=sock)
                result = self.proxy._connect_target(host, 443)
                self.assertIs(result, sock)
                self.assertEqual(_get_socket_meta(result)['target_ip'], ip)

    def test_discord_does_not_drop_dns_candidates_by_subnet(self):
        for ip in ('162.159.135.17', '162.159.134.17'):
            with self.subTest(ip=ip):
                self.assertEqual(self.connect('media.discordapp.net', [ip]), ip)
