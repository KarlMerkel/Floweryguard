"""Модульные тесты для модуля «Калибровка» (flowguard/calibration.py).
"""

import unittest
from unittest.mock import patch, MagicMock
from Floweryguard.calibration import (
    FAST_CALIBRATION_DOMAINS,
    FULL_CALIBRATION_DOMAINS,
    CALIBRATION_CANDIDATE_STRATEGIES,
    StrategyCalibrator,
    probe_tls_strategy,
)
from Floweryguard.strategy import ThompsonStrategySelector


class TestCalibrationTargets(unittest.TestCase):
    """Проверка списков сайтов калибровки."""

    def test_fast_targets_present(self):
        self.assertGreaterEqual(len(FAST_CALIBRATION_DOMAINS), 10)
        self.assertIn("www.youtube.com", FAST_CALIBRATION_DOMAINS)
        self.assertIn("discord.com", FAST_CALIBRATION_DOMAINS)

    def test_full_targets_count_and_domains(self):
        self.assertGreaterEqual(len(FULL_CALIBRATION_DOMAINS), 90)
        self.assertIn("instagram.com", FULL_CALIBRATION_DOMAINS)
        self.assertIn("rutracker.org", FULL_CALIBRATION_DOMAINS)
        self.assertIn("torproject.org", FULL_CALIBRATION_DOMAINS)
        self.assertIn("proton.me", FULL_CALIBRATION_DOMAINS)
        self.assertIn("meduza.io", FULL_CALIBRATION_DOMAINS)


class TestStrategyCalibrator(unittest.TestCase):
    """Тесты диспетчера калибровки и обучения модели."""

    def setUp(self):
        self.mock_engine = MagicMock(spec=ThompsonStrategySelector)
        self.calibrator = StrategyCalibrator(engine=self.mock_engine, max_workers=4)

    @patch("Floweryguard.calibration.probe_tls_strategy")
    def test_run_fast_calibration_success_flow(self, mock_probe):
        # Эмулируем: combo_tlsrec_tcpsplit всегда успешен, direct сбоит
        def fake_probe(domain, strategy, **kwargs):
            if strategy == "combo_tlsrec_tcpsplit":
                return True, 45.0, "TLS ServerHello OK"
            else:
                return False, 120.0, "TSPU TCP RST"

        mock_probe.side_effect = fake_probe

        report = self.calibrator.run_calibration(mode="fast")

        self.assertEqual(report["mode"], "fast")
        self.assertEqual(report["total_domains"], len(FAST_CALIBRATION_DOMAINS))
        self.assertEqual(report["winning_strategy"], "combo_tlsrec_tcpsplit")

        # Проверяем, что ML-движок вызывался для фиксации успехов и неудач с флагом is_calibration=True
        self.assertTrue(self.mock_engine.record_success.called)
        self.assertTrue(self.mock_engine.record_failure.called)
        # Проверяем передачу аргумента is_calibration=True
        _, last_fail_kwargs = self.mock_engine.record_failure.call_args
        self.assertTrue(last_fail_kwargs.get("is_calibration", False))
        self.assertTrue(self.mock_engine.save_scores.called)

    @patch("Floweryguard.calibration.probe_tls_strategy")
    def test_cancellation(self, mock_probe):
        mock_probe.return_value = (True, 50.0, "OK")
        self.calibrator.cancel()
        report = self.calibrator.run_calibration(mode="fast")
        # При установленном флаге отмены completed_probes должен быть 0 или минимальным
        self.assertLessEqual(report["completed_probes"], 2)

    def test_tcp_overlap_sni_registered_and_dispatched(self):
        """Проверка присутствия Ptacek-Newsham tcp_overlap_sni в калибровке и диспетчере."""
        from Floweryguard.strategy import STRATEGY_DISPATCH
        self.assertIn("tcp_overlap_sni", CALIBRATION_CANDIDATE_STRATEGIES)
        self.assertIn("tcp_overlap_sni", STRATEGY_DISPATCH)
        self.assertTrue(callable(STRATEGY_DISPATCH["tcp_overlap_sni"]))

    def test_soften_calibration_priors_preserves_variance(self):
        """Проверка защиты от зацементирования: смягчение весов перед повторной калибровкой."""
        selector = ThompsonStrategySelector(enabled=True)
        domain = "test-overfit.org"
        strat = "tcp_split_sni_mid"

        # Искусственно накачиваем веса до экстремума (симулируем многократные проверки)
        for _ in range(15):
            selector.record_success(domain, strat, rtt_ms=40.0, is_calibration=False)
        
        scores_before = selector.get_domain_scores(domain)[strat]
        self.assertGreater(scores_before["alpha"], 10.0)

        # Вызываем смягчение
        selector.soften_calibration_priors(factor=0.75)
        scores_after = selector.get_domain_scores(domain)[strat]

        # Вес должен быть плавно уменьшен (pulling), но остаться >= 0.5
        self.assertLess(scores_after["alpha"], scores_before["alpha"])
        self.assertGreaterEqual(scores_after["alpha"], 0.5)

    def test_calibration_damping_limits_penalty(self):
        """Проверка демпфирования: штраф при калибровке в разы мягче, чем при боевом сбое."""
        selector = ThompsonStrategySelector(enabled=True)
        domain_prod = "prod-fail.org"
        domain_cal = "cal-fail.org"
        strat = "tcp_split_sni_mid"

        # Боевой сбой (браузер)
        selector.record_failure(domain_prod, strat, is_tspu=True, is_calibration=False)
        prod_beta = selector.get_domain_scores(domain_prod)[strat]["beta"]

        # Калибровочный сбой (синтетический зонд)
        selector.record_failure(domain_cal, strat, is_tspu=True, is_calibration=True)
        cal_beta = selector.get_domain_scores(domain_cal)[strat]["beta"]

        # Калибровочный штраф (2.5) значительно меньше боевого (15.0)
        self.assertLess(cal_beta, prod_beta)


if __name__ == "__main__":
    unittest.main()
