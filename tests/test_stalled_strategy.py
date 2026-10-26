"""После зависания меняется техника конкретного сайта, а не только его адрес."""
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from flowguard.config import Config
from flowguard.proxy import DPIBypassProxy
from flowguard.route_health import RouteHealth
from flowguard.strategy import ThompsonStrategySelector


class TestStalledStrategy(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.now = 100.0
        self.proxy = object.__new__(DPIBypassProxy)
        self.proxy.config = Config(str(Path(directory.name) / 'missing.ini'))
        self.proxy.route_health = RouteHealth(clock=lambda: self.now, max_entries=4)
        self.proxy.strategy_engine = ThompsonStrategySelector(scores_file=str(Path(directory.name) / 'scores.json'))
        self.proxy.strategy_engine.set_network_context('wifi')
        self.proxy.whitelist_domains = {'*.sndcdn.com'}
        self.proxy._whitelist_lock = threading.Lock()
        self.host = 'a-v2.sndcdn.com'

    def record(self, strategy='combo_tlsrec_tcpsplit', outcome='suspect', host=None):
        self.proxy.route_health.record_strategy('wifi', host or self.host, 443, strategy, outcome)

    def choose(self, host=None, port=443):
        return self.proxy._strategy_after_stall(host or self.host, port, '192.0.2.1', 'combo_tlsrec_tcpsplit')

    def test_next_connection_tries_alternative_without_training_global_scores(self):
        self.proxy.strategy_engine.select_strategy(self.host)
        before = self.proxy.strategy_engine.get_domain_scores(self.host)
        self.record()
        self.assertNotEqual(self.choose(), 'combo_tlsrec_tcpsplit')
        self.assertEqual(self.proxy.strategy_engine.get_domain_scores(self.host), before)

    def test_hint_is_scoped_and_expires(self):
        self.record()
        self.assertEqual(self.choose('other.sndcdn.com'), 'combo_tlsrec_tcpsplit')
        self.assertEqual(self.choose(port=8443), 'combo_tlsrec_tcpsplit')
        self.proxy.strategy_engine.set_network_context('phone')
        self.assertEqual(self.choose(), 'combo_tlsrec_tcpsplit')
        self.proxy.strategy_engine.set_network_context('wifi')
        self.now += 46
        self.assertEqual(self.choose(), 'combo_tlsrec_tcpsplit')

    def test_success_keeps_alternative_after_suspicion_expires(self):
        self.record()
        self.record('tcp_split_sni_mid', 'progress')
        self.now += 46
        self.assertEqual(self.choose(), 'tcp_split_sni_mid')
        self.now += 300
        self.assertEqual(self.choose(), 'combo_tlsrec_tcpsplit')

    def test_manual_strategy_and_disabled_techniques_take_priority(self):
        self.record()
        self.proxy.config.set_override('auto_strategy', False)
        self.assertEqual(self.choose(), 'combo_tlsrec_tcpsplit')
        self.proxy.config.set_override('auto_strategy', True)
        self.proxy.strategy_engine.configure_allowed(False, False, False)
        self.assertEqual(self.choose(), 'direct')

    def test_domain_override_is_not_replaced(self):
        self.record()
        self.proxy.strategy_engine._strategy_overrides[self.host] = 'combo_tlsrec_tcpsplit'
        self.assertEqual(self.choose(), 'combo_tlsrec_tcpsplit')

    def test_storage_is_bounded_and_clear_removes_hints(self):
        self.record()
        for i in range(4):
            self.record(host=str(i) + '.example')
        self.assertEqual(self.choose(), 'combo_tlsrec_tcpsplit')
        self.record()
        self.proxy.route_health.clear()
        self.assertEqual(self.choose(), 'combo_tlsrec_tcpsplit')

    def test_client_hello_uses_alternative(self):
        self.record()
        self.proxy._check_reload_whitelist = Mock()
        self.proxy._logged_whitelisted_lock = threading.Lock()
        self.proxy._logged_whitelisted = set()
        self.proxy._safe_execute_strategy = Mock()
        with patch('flowguard.proxy.is_tls_client_hello', return_value=True), \
             patch('flowguard.proxy.parse_sni', return_value=(self.host,)), \
             patch('flowguard.proxy.is_winws_tcp_filtering_active', return_value=False):
            selected, _ = self.proxy._send_tls_client_hello_with_bypass(Mock(), b'hello', self.host)
        self.assertNotEqual(selected, 'combo_tlsrec_tcpsplit')
        self.assertEqual(self.proxy._safe_execute_strategy.call_args.args[0], selected)
