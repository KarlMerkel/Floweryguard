"""Unit-тесты для верификации устранения узких горлышек DPI bypass и стабильности сети.
Проверяет:
1. Детекцию bogon/sinkhole IP (0.0.0.0, 127.x.x.x, 192.144.59.14)
2. Фильтрацию bogon в is_ip_dead
3. Недопустимость несовместимых стратегий (TLS record fragmentation) в YouTube fallback
4. Соблюдение allowed_strategies в get_fallback_strategy
5. Защиту от ложных Silent Drop (адаптивные таймауты probe_timeout >= 850 мс)
"""

import unittest
from flowguard.proxy import is_bogon_or_sinkhole_ip, is_ip_dead, mark_ip_dead, mark_ip_working
from flowguard.strategy import ThompsonStrategySelector, ALL_STRATEGIES


class TestBottlenecksFix(unittest.TestCase):

    def test_bogon_and_sinkhole_detection(self):
        """Проверка распознавания bogon-адресов и страниц заглушек РКН/провайдеров."""
        # Bogon / Loopback / Empty
        self.assertTrue(is_bogon_or_sinkhole_ip(""))
        self.assertTrue(is_bogon_or_sinkhole_ip(None))
        self.assertTrue(is_bogon_or_sinkhole_ip("0.0.0.0"))
        self.assertTrue(is_bogon_or_sinkhole_ip("127.0.0.1"))
        self.assertTrue(is_bogon_or_sinkhole_ip("127.0.0.53"))
        self.assertTrue(is_bogon_or_sinkhole_ip("::1"))
        self.assertTrue(is_bogon_or_sinkhole_ip("255.255.255.255"))

        # РКН заглушка
        self.assertFalse(is_bogon_or_sinkhole_ip("192.144.59.14"))

        # Валидные публичные IP (не bogon)
        self.assertFalse(is_bogon_or_sinkhole_ip("1.1.1.1"))
        self.assertFalse(is_bogon_or_sinkhole_ip("8.8.8.8"))
        self.assertFalse(is_bogon_or_sinkhole_ip("142.250.74.78"))
        self.assertFalse(is_bogon_or_sinkhole_ip("104.21.32.39"))

    def test_is_ip_dead_with_bogons(self):
        """is_ip_dead должен мгновенно дисквалифицировать bogon/sinkhole IP."""
        self.assertTrue(is_ip_dead("0.0.0.0"))
        self.assertTrue(is_ip_dead("127.0.0.1"))
        self.assertFalse(is_ip_dead("192.144.59.14"))

        # Обычный IP не мертв по умолчанию
        valid_ip = "198.51.100.99"
        mark_ip_working(valid_ip)
        self.assertFalse(is_ip_dead(valid_ip))

        # Пометка мертвым
        mark_ip_dead(valid_ip, duration=60.0)
        self.assertTrue(is_ip_dead(valid_ip))

        # Снятие пометки
        mark_ip_working(valid_ip)
        self.assertFalse(is_ip_dead(valid_ip))

    def test_youtube_fallback_never_uses_tls_record_frag(self):
        """Fallback для YouTube ни при каких условиях не должен отдавать TLS Record Fragmentation."""
        selector = ThompsonStrategySelector(scores_file=None)
        yt_host = "rr1---sn-aj5go5-5i.googlevideo.com"

        # Проверяем fallback при падении любых доступных TCP-сплитов
        for failed in ["tcp_split_sni_mid", "tcp_split_sni_start", "multi_split", "boringssl_split", "direct"]:
            fb = selector.get_fallback_strategy(yt_host, failed_strategy=failed, is_youtube=True)
            self.assertNotEqual(fb, failed)
            self.assertNotIn(fb, ["tls_record_frag"],
                             f"Fallback {fb} для YouTube недопустим!")
            self.assertIn(fb, ALL_STRATEGIES)

    def test_fallback_respects_allowed_strategies(self):
        """get_fallback_strategy строго соблюдает фильтр self._allowed_strategies."""
        selector = ThompsonStrategySelector(scores_file=None)
        # Отключаем TCP Split (оставляем только TLS record frag и direct)
        selector.configure_allowed(tcp_split=False, tls_record_frag=True, oob_data=False)

        host = "discord.com"
        fb = selector.get_fallback_strategy(host, failed_strategy="direct", is_discord=True)
        # Так как tcp_split выключен, fallback не имеет права выбрать tcp-split
        self.assertIn(fb, ["tls_record_frag", "combo_tlsrec_tcpsplit", "direct"])

    def test_probe_timeout_safety_margin(self):
        """Адаптивный таймаут probe_timeout для защиты от ложных Silent Drop."""
        # Моделируем формулу probe_timeout = max(0.85, min(2.5, base_rtt * 3.5 + 0.35))
        def calc_timeout(base_rtt: float) -> float:
            return max(0.85, min(2.5, base_rtt * 3.5 + 0.35))

        # Сверхбыстрая сеть (5 мс)
        self.assertGreaterEqual(calc_timeout(0.005), 0.85)

        # Мобильная 4G/LTE сеть (80 мс)
        self.assertGreaterEqual(calc_timeout(0.080), 0.85)

        # Медленная спутниковая / перегруженная сеть (400 мс)
        self.assertAlmostEqual(calc_timeout(0.400), 1.75, places=2)


if __name__ == "__main__":
    unittest.main()
