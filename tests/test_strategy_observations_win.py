"""Наблюдаемый результат важнее предположения о стратегии по имени сервиса."""
import tempfile
import unittest
from pathlib import Path
from flowguard.strategy import ThompsonStrategySelector


class TestStrategyObservationsWin(unittest.TestCase):
    def test_observed_technique_can_win_initial_and_fallback_selection(self):
        for host, winner in [('youtube.com', 'tls_record_frag'),
                             ('cdn.discordapp.com', 'tcp_split_sni_mid'),
                             ('surfshark.com', 'multi_split'),
                             ('discord.com', 'direct')]:
            with self.subTest(host=host), tempfile.TemporaryDirectory() as directory:
                engine = ThompsonStrategySelector(scores_file=str(Path(directory) / 'scores.json'))
                for _ in range(40):
                    engine.record_success(host, winner, rtt_ms=25)
                    engine.record_failure(host, 'combo_tlsrec_tcpsplit', is_tspu=False)
                self.assertEqual(engine.select_strategy(host), winner)
                self.assertEqual(engine.get_fallback_strategy(host, failed_strategy='tcp_split_sni_start',
                                                              is_whitelisted=True), winner)

    def test_fallback_respects_explicit_exclusions(self):
        with tempfile.TemporaryDirectory() as directory:
            engine = ThompsonStrategySelector(scores_file=str(Path(directory) / 'scores.json'))
            for _ in range(40):
                engine.record_success('cdn.discordapp.com', 'multi_split', rtt_ms=25)
            selected = engine.get_fallback_strategy('cdn.discordapp.com', failed_strategy='multi_split',
                                                     failed_strategies={'combo_tlsrec_tcpsplit'})
            self.assertNotIn(selected, {'multi_split', 'combo_tlsrec_tcpsplit'})

    def test_cluster_observations_are_not_overwritten_by_domain_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            engine = ThompsonStrategySelector(scores_file=str(Path(directory) / 'scores.json'))
            for _ in range(40):
                engine.record_success('cdn.discordapp.com', 'tcp_split_sni_mid', rtt_ms=25)
                engine.record_failure('cdn.discordapp.com', 'combo_tlsrec_tcpsplit', is_tspu=False)
            self.assertEqual(engine.select_strategy('media.discordapp.net'), 'tcp_split_sni_mid')
