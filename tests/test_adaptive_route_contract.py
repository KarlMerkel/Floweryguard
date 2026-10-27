"""Обучение и отказы отделяются от случайно соседних маршрутов."""
import os
import tempfile
import unittest
from unittest.mock import Mock, patch
from flowguard.config import Config
from flowguard.proxy import DPIBypassProxy, is_ip_dead, _DEAD_IP_CACHE
from flowguard.route_health import RouteHealth
from flowguard.strategy import ThompsonStrategySelector


class TestAdaptiveRouteContract(unittest.TestCase):
    def test_known_service_can_learn_another_strategy(self):
        with tempfile.TemporaryDirectory() as directory:
            engine = ThompsonStrategySelector(scores_file=os.path.join(directory, 'scores.json'))
            host = 'cdn.discordapp.com'
            self.assertEqual(engine.select_strategy(host), 'combo_tlsrec_tcpsplit')
            for _ in range(4):
                engine.record_failure(host, 'combo_tlsrec_tcpsplit', is_tspu=True)
                engine.record_success(host, 'multi_split')
            self.assertEqual(engine.select_strategy(host), 'multi_split')

    def test_synthetic_probe_does_not_train_transfer_scores(self):
        with tempfile.TemporaryDirectory() as directory:
            engine = ThompsonStrategySelector(scores_file=os.path.join(directory, 'scores.json'))
            engine.select_strategy('youtube.com')
            before = engine.get_domain_scores('youtube.com')
            engine.record_success('youtube.com', 'direct', is_calibration=True)
            engine.record_failure('youtube.com', 'combo_tlsrec_tcpsplit', is_calibration=True)
            self.assertEqual(engine.get_domain_scores('youtube.com'), before)

    def test_connect_failure_does_not_ban_ip_of_other_site(self):
        _DEAD_IP_CACHE.clear()
        self.addCleanup(_DEAD_IP_CACHE.clear)
        with patch('flowguard.proxy.ShadowProber'), patch('flowguard.proxy.WarmUpHarvester'):
            proxy = DPIBypassProxy(Config())
        proxy.dns_failover = proxy.doh_harvester = None
        proxy.route_health = RouteHealth()
        proxy.strategy_engine._current_network = 'audit'
        sock = Mock()
        sock.connect.side_effect = OSError('соединение отклонено')
        with patch('flowguard.proxy.socket.socket', return_value=sock), patch('flowguard.proxy.resolve_fallback_dns', return_value=None):
            self.assertIsNone(proxy._connect_target('site.example', 8443, target_ip='192.0.2.80'))
        self.assertFalse(is_ip_dead('192.0.2.80'))
        self.assertEqual(proxy.route_health.status('audit', 'site.example', 8443, '192.0.2.80'), 'suspect')
        self.assertEqual(proxy.route_health.status('audit', 'other.example', 443, '192.0.2.80'), 'unknown')
