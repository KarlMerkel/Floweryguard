"""Изменение маршрута и схемы запроса требует работающей явной настройки."""
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import Mock, patch

from flowguard.config import Config
from flowguard.proxy import (DPIBypassProxy, load_custom_hosts, set_use_hosts_file,
                             resolve_fallback_dns, _get_socket_meta, _DNS_CACHE,
                             _RESOLVED_IPS_CACHE, _WORKING_IP_CACHE)


class TestExplicitRoutingOptions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'config.ini').write_text('', encoding='utf-8')
        self.config = Config(str(self.root / 'config.ini'))
        with patch('flowguard.proxy.ShadowProber'), patch('flowguard.proxy.WarmUpHarvester'):
            self.proxy = DPIBypassProxy(self.config)
        self.proxy.dns_failover = self.proxy.doh_harvester = None
        self.proxy._check_reload_whitelist = Mock()
        self.proxy.whitelist_domains = set()
        for cache in (_DNS_CACHE, _RESOLVED_IPS_CACHE, _WORKING_IP_CACHE):
            cache.clear()
            self.addCleanup(cache.clear)
        set_use_hosts_file(False)
        self.addCleanup(set_use_hosts_file, False)

    def test_http_post_is_forwarded_without_unsolicited_redirect(self):
        self.assert_http_post_forwarded()

    def test_force_https_does_not_discard_post_body(self):
        self.config.set_override('force_https', True)
        self.assert_http_post_forwarded()

    def assert_http_post_forwarded(self):
        self.config.set_override('http_host_obfuscation', False)
        client, upstream = Mock(), Mock()
        request = b'POST http://example.org/form HTTP/1.1\r\nHost: example.org\r\nContent-Length: 3\r\n\r\nabc'
        self.proxy._connect_target = Mock(return_value=upstream)
        self.proxy._pipe_sockets = Mock()
        self.proxy._handle_http_request(client, request, 'http://example.org/form')
        self.proxy._connect_target.assert_called_once_with('example.org', 80)
        upstream.sendall.assert_called_once_with(request.replace(b'http://example.org/form', b'/form', 1))
        client.sendall.assert_not_called()

    def test_hosts_parser_reads_aliases_comments_and_ipv6(self):
        path = self.root / 'hosts.txt'
        path.write_text('8.6.112.0 Example.org alias.example.org # comment\n'
                        '2606:4700::1111 dns.example.org\n'
                        'not-an-ip broken.example.org\n', encoding='utf-8')
        self.assertEqual(load_custom_hosts(str(path)), {
            'example.org': '8.6.112.0', 'alias.example.org': '8.6.112.0',
            'dns.example.org': '2606:4700::1111'})

    def test_hosts_override_is_opt_in_and_precedes_learned_cache(self):
        (self.root / 'hosts.txt').write_text('8.6.112.0 example.org\n', encoding='utf-8')
        normal_ip = '93.184.216.34'
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (normal_ip, 443))]
        sock = Mock(spec=socket.socket)
        sock.connect_ex.return_value = 0
        with patch('flowguard.proxy.socket.getaddrinfo', return_value=addresses), \
             patch('flowguard.proxy.socket.socket', return_value=sock):
            normal = self.proxy._connect_target('example.org', 443)
            self.assertEqual(_get_socket_meta(normal)['target_ip'], normal_ip)
            _WORKING_IP_CACHE.set('example.org', normal_ip)
            self.proxy.route_health.record(self.proxy.strategy_engine._current_network,
                                           'example.org', 443, normal_ip, 'progress')
            self.config.set_override('use_hosts_file', True)
            manual = self.proxy._connect_target('example.org', 443)
            self.assertEqual(_get_socket_meta(manual)['target_ip'], '8.6.112.0')

    def test_legacy_hosts_switch_controls_fallback_resolution(self):
        manager = Mock()
        manager.resolve_one.return_value = '93.184.216.34'
        with patch('flowguard.proxy.load_custom_hosts', return_value={'example.org': '8.6.112.0'}), \
             patch('flowguard.proxy.get_dns_failover_manager', return_value=manager):
            self.assertEqual(resolve_fallback_dns('example.org'), '93.184.216.34')
            set_use_hosts_file(True)
            self.assertEqual(resolve_fallback_dns('example.org'), '8.6.112.0')

    def test_manual_hosts_respect_local_address_and_ipv6_policy(self):
        self.config.set_override('use_hosts_file', True)
        self.config.set_override('ipv6_mode', 'disabled')
        for ip in ('127.0.0.1', '198.18.0.1', '2606:4700::1111'):
            (self.root / 'hosts.txt').write_text(ip + ' example.org\n', encoding='utf-8')
            with self.subTest(ip=ip), patch('flowguard.proxy.socket.socket') as create_socket:
                self.assertIsNone(self.proxy._connect_target('example.org', 443))
                self.assertIsNone(resolve_fallback_dns('example.org', self.config))
                create_socket.assert_not_called()

    def test_empty_custom_dns_input_does_not_choose_a_third_party_server(self):
        from flowguard.main import FloweryApp
        app = object.__new__(FloweryApp)
        app.config = self.config
        self.config.set_override('server', '')
        self.config.set_override('primary', '')
        app.apply_setting = Mock()
        with patch('builtins.input', side_effect=['5', '', '']), \
             patch('builtins.print'), patch('flowguard.main.os.system'), \
             patch('flowguard.doh_resolver.auto_detect_dns_provider', side_effect=ValueError('Не ожидался запрос')) as detect:
            app.configure_custom_dns_interactive()
        detect.assert_not_called()
