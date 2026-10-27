"""Настройки должны влиять на реальные резолверы, сокеты и сохранение оценок."""

import os
import socket
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from flowguard.config import Config
from flowguard import proxy, doh_resolver, strategy


class TestRuntimeSettings(unittest.TestCase):
    def test_harvester_uses_one_deadline_for_all_workers(self):
        now = [0.0]
        waits = []

        def join(timeout):
            waits.append(timeout)
            now[0] += timeout

        worker = Mock()
        worker.join.side_effect = join
        harvester = doh_resolver.MultiDoHHarvester(Config('absent.ini'))
        with patch.object(doh_resolver.threading, 'Thread', return_value=worker), \
             patch.object(doh_resolver.time, 'monotonic', side_effect=lambda: now[0]):
            self.assertEqual(harvester.harvest('example.com'), [])
        self.assertEqual(sum(waits), 3.5)
        self.assertEqual(waits, [3.5, 0.0, 0.0])

    def test_custom_provider_reaches_proxy_and_harvester(self):
        cfg = Config('absent.ini')
        for name, value in [('server', 'my-resolver'), ('doh_name', 'my-resolver'),
                            ('doh_url', 'https://resolver.example/dns-query'),
                            ('primary', '192.0.2.53'), ('secondary', ''), ('enable_custom_dns', True)]:
            cfg.set_value('dns', name, value)
        manager = proxy.get_dns_failover_manager(cfg, force_new=True)
        self.assertEqual(manager.primary_provider.doh_host, 'resolver.example')
        harvester = doh_resolver.MultiDoHHarvester(cfg)
        self.assertEqual([p.doh_host for p in harvester.providers], ['resolver.example'])
        cfg.set_value('dns', 'doh_url', 'https://second.example/dns-query')
        self.assertNotEqual(proxy.get_dns_failover_manager(cfg).primary_provider, manager.primary_provider)

    def test_ipv6_disabled_filters_os_candidates(self):
        p = object.__new__(proxy.DPIBypassProxy)
        p.config = Config('absent.ini')
        p.timeout = 1
        p.route_health = proxy.RouteHealth()
        p.strategy_engine = Mock(_current_network='test')
        p.whitelist_domains = set()
        p._whitelist_lock = threading.Lock()
        p._check_reload_whitelist = Mock()
        p.doh_harvester = p.dns_failover = None
        p.flush_stale_caches()
        upstream = Mock()
        with patch.object(proxy.socket, 'getaddrinfo', return_value=[
            (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('2001:db8::1', 443, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.1', 443))]), \
             patch.object(proxy.socket, 'socket', return_value=upstream) as factory:
            p._connect_target('audit.example', 443)
        self.assertTrue(all(call.args[0] == socket.AF_INET for call in factory.call_args_list))
        upstream.connect.assert_called_once_with(('192.0.2.1', 443))

    def test_failed_save_remains_dirty_for_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'scores.json')
            selector = strategy.ThompsonStrategySelector(scores_file=path)
            selector._dirty = True
            with patch.object(strategy.os, 'replace', side_effect=PermissionError('отказ')):
                selector.save_scores(force=True)
            self.assertTrue(selector._dirty)
            selector.save_scores()
            self.assertTrue(os.path.exists(path))
            self.assertFalse(selector._dirty)

    def test_all_selection_paths_respect_disabled_techniques(self):
        with tempfile.TemporaryDirectory() as directory:
            selector = strategy.ThompsonStrategySelector(scores_file=os.path.join(directory, 'scores.json'))
            selector.configure_allowed(False, False, False)
            for host, kwargs in [('youtube.com', {}), ('cdn.discordapp.com', {}), ('example.com', {'is_whitelisted': True})]:
                self.assertEqual(selector.select_strategy(host, **kwargs), 'direct')
                self.assertEqual(selector.get_fallback_strategy(host, failed_strategy='combo_tlsrec_tcpsplit', **kwargs), 'direct')
