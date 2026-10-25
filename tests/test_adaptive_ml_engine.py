"""Тесты для улучшенного ML-движка Thompson Sampling (Transfer Learning, CDN Clusters, Network Context)."""

import os
import unittest
import tempfile
import time
from Floweryguard.strategy import (
    ThompsonStrategySelector,
    classify_cdn_cluster,
    CDN_CLUSTERS,
    ALL_STRATEGIES
)


class TestAdaptiveMLEngine(unittest.TestCase):
    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        self.temp_file.close()
        self.scores_path = self.temp_file.name

    def tearDown(self):
        if os.path.exists(self.scores_path):
            try:
                os.remove(self.scores_path)
            except Exception:
                pass

    def test_cdn_cluster_classification(self):
        """Проверка точности классификации CDN кластеров."""
        # Google / BoringSSL
        self.assertEqual(classify_cdn_cluster("rr2---sn-4g5edn6r.googlevideo.com"), "google")
        self.assertEqual(classify_cdn_cluster("youtu.be"), "google")
        self.assertEqual(classify_cdn_cluster("play.google.com"), "google")

        # Discord
        self.assertEqual(classify_cdn_cluster("gateway.discord.gg"), "discord")
        self.assertEqual(classify_cdn_cluster("cdn.discordapp.com"), "discord")

        # Cloudflare
        self.assertEqual(classify_cdn_cluster("fandom.com"), "cloudflare")
        self.assertEqual(classify_cdn_cluster("medium.com"), "cloudflare")
        self.assertEqual(classify_cdn_cluster("unknown.com", ip="104.21.35.12"), "cloudflare")
        self.assertEqual(classify_cdn_cluster("unknown.com", ip="172.67.150.1"), "cloudflare")

        # Akamai / Fastly
        self.assertEqual(classify_cdn_cluster("github.com"), "akamai_fastly")
        self.assertEqual(classify_cdn_cluster("reddit.com"), "akamai_fastly")

        # Неизвестный хост
        self.assertIsNone(classify_cdn_cluster("my-private-server.local", ip="192.168.1.1"))

    def test_continuous_rtt_reward(self):
        """Проверка непрерывной функции полезности RTT."""
        selector = ThompsonStrategySelector(scores_file=self.scores_path)
        domain = "speedtest.example.com"
        strat = "multi_split"

        # Быстрый RTT (30 мс) -> высокий вес (alpha delta > 1.2)
        scores_before = selector.get_domain_scores(domain)
        a_before = scores_before[strat]["alpha"]
        selector.record_success(domain, strat, rtt_ms=30.0)
        scores_fast = selector.get_domain_scores(domain)
        a_fast = scores_fast[strat]["alpha"]
        fast_reward = a_fast - a_before
        self.assertGreater(fast_reward, 1.2)

        # Медленный RTT (500 мс) -> низкий вес (alpha delta < 0.8)
        selector.record_success(domain, strat, rtt_ms=500.0)
        scores_slow = selector.get_domain_scores(domain)
        a_slow = scores_slow[strat]["alpha"]
        slow_reward = a_slow - a_fast
        self.assertLess(slow_reward, 0.8)
        self.assertGreater(fast_reward, slow_reward)

    def test_transfer_learning_cdn_cluster(self):
        """Проверка Transfer Learning: новый домен CDN кластера наследует опыт кластера."""
        selector = ThompsonStrategySelector(scores_file=self.scores_path)
        domain1 = "video1.googlevideo.com"
        domain2 = "video2.googlevideo.com"
        winning_strat = "boringssl_split"

        # Обучаем кластер google через домен 1
        for _ in range(8):
            selector.record_success(domain1, winning_strat, rtt_ms=45.0)

        # Проверяем, что в кластере 'google' стратегия winning_strat получила буст
        cluster_data = selector._cluster_scores[selector._current_network]["google"]
        self.assertGreater(cluster_data[winning_strat][0], 2.5)

        # Теперь обращаемся к совершенно новому домену из этого же кластера
        new_priors = selector.get_domain_scores(domain2)
        # Prior inheritance должен дать новому домену преимущество для winning_strat
        self.assertGreater(new_priors[winning_strat]["alpha"], new_priors["direct"]["alpha"])

    def test_network_context_separation(self):
        """Проверка контекстного разделения моделей при смене сети (Network Context Matrix)."""
        selector = ThompsonStrategySelector(scores_file=self.scores_path)
        domain = "instagram.com"

        # Сеть 1: Мобильный оператор A (работает tcp_split_sni_start)
        selector.set_network_context("profile_mts_lte")
        selector.record_success(domain, "tcp_split_sni_start", rtt_ms=50.0)
        selector.record_success(domain, "tcp_split_sni_start", rtt_ms=50.0)

        # Сеть 2: Домашний Wi-Fi (работает combo_tlsrec_tcpsplit, а tcp_split_sni_start сбрасывается)
        selector.set_network_context("profile_home_wifi")
        selector.record_success(domain, "combo_tlsrec_tcpsplit", rtt_ms=25.0)
        selector.record_failure(domain, "tcp_split_sni_start", is_tspu=True)

        # Проверяем изоляцию весов
        selector.set_network_context("profile_mts_lte")
        mts_scores = selector.get_domain_scores(domain)
        self.assertGreater(mts_scores["tcp_split_sni_start"]["alpha"], 2.0)

        selector.set_network_context("profile_home_wifi")
        wifi_scores = selector.get_domain_scores(domain)
        self.assertGreater(wifi_scores["combo_tlsrec_tcpsplit"]["alpha"], 2.0)
        self.assertGreater(wifi_scores["tcp_split_sni_start"]["beta"], 2.0)

    def test_temporal_decay(self):
        """Проверка дисконтирования старых весов (Temporal Decay)."""
        selector = ThompsonStrategySelector(scores_file=self.scores_path)
        domain = "rutracker.org"
        strat = "combo_tlsrec_tcpsplit"

        # Накапливаем веса
        for _ in range(10):
            selector.record_success(domain, strat, rtt_ms=40.0)

        alpha_high = selector.get_domain_scores(domain)[strat]["alpha"]
        self.assertGreater(alpha_high, 8.0)

        # Симулируем прошедшее время (например, 7 часов)
        selector._last_decay_time = time.time() - 25200
        selector._apply_temporal_decay_locked()

        alpha_decayed = selector.get_domain_scores(domain)[strat]["alpha"]
        self.assertLess(alpha_decayed, alpha_high)
        # Но не меньше минимума (0.1)
        self.assertGreaterEqual(alpha_decayed, 0.1)

    def test_persistence_backwards_compatible(self):
        """Проверка сохранения и загрузки весов с сохранением обратной совместимости."""
        selector = ThompsonStrategySelector(scores_file=self.scores_path)
        domain = "test.org"
        selector.record_success(domain, "direct", rtt_ms=50.0)
        selector.save_scores(force=True)

        # Проверяем, что новый экземпляр корректно вычитывает сохраненную модель
        selector_loaded = ThompsonStrategySelector(scores_file=self.scores_path)
        domain_data = selector_loaded.get_domain_scores(domain)
        self.assertIn("direct", domain_data)
        self.assertGreater(domain_data["direct"]["alpha"], 1.5)

    def test_youtube_priors_prioritize_safe_splits(self):
        """Проверка, что для YouTube априори выбирается эффективная фрагментация (boringssl_split), а не direct."""
        selector = ThompsonStrategySelector(scores_file=self.scores_path)
        priors = selector._init_domain_priors("rr1---sn-4g5ednks.googlevideo.com", is_youtube=True, is_discord=False)
        # boringssl_split должен иметь высокий приоритет среди безопасных сплитов
        self.assertGreater(priors["boringssl_split"][0], 5.0)
        self.assertGreater(priors["boringssl_split"][0], priors["direct"][0])
        # B1: слабые априорные веса (alpha + beta <= 10.0)
        self.assertLessEqual(priors["boringssl_split"][0] + priors["boringssl_split"][1], 10.0)
        # direct не должен быть основным для YouTube
        self.assertLess(priors["direct"][0], 5.0)

    def test_get_fallback_strategy_adaptive_for_youtube(self):
        """Проверка адаптивного выбора fallback стратегии для YouTube при сбросе ТСПУ."""
        selector = ThompsonStrategySelector(scores_file=self.scores_path)
        host = "rr1---sn-aj5go5-5i.googlevideo.com"

        # Симулируем, что упала стратегия boringssl_split
        strat = selector.get_fallback_strategy(host, failed_strategy="boringssl_split", is_youtube=True)
        self.assertNotEqual(strat, "boringssl_split")
        self.assertIn(strat, ["combo_tlsrec_tcpsplit", "tcp_split_sni_mid", "tcp_split_sni_start", "multi_split", "direct"])

        # Симулируем серию успешных соединений для multi_split
        for _ in range(70):
            selector.record_success(host, "multi_split")

        # Теперь fallback должен предпочитать наиболее успешную подтвержденную стратегию
        strat_after_wins = selector.get_fallback_strategy(host, failed_strategy="tcp_split_sni_mid", is_youtube=True)
        self.assertEqual(strat_after_wins, "multi_split")


if __name__ == "__main__":
    unittest.main()
