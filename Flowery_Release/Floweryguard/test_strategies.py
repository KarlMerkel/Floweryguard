"""Модульный тест новых DPI-bypass техник и алгоритма Thompson Sampling."""

import socket
import unittest
from Floweryguard.tls_parser import (
    is_tls_client_hello,
    parse_sni,
    get_sni_offsets,
    create_tls_record_fragments,
    create_multi_tls_record_fragments,
    create_dummy_tls_record,
)
from Floweryguard.sni_spoofer import build_fake_client_hello
from Floweryguard.strategy import (
    ThompsonStrategySelector,
    execute_strategy,
    ALL_STRATEGIES,
)


class TestDPIStrategies(unittest.TestCase):
    def setUp(self):
        # Реальный сгенерированный TLS ClientHello с SNI "discord.com"
        self.sample_ch = build_fake_client_hello("discord.com")
        self.yt_ch = build_fake_client_hello("www.youtube.com")

    def test_tls_parsing_and_offsets(self):
        self.assertTrue(is_tls_client_hello(self.sample_ch))
        parsed = parse_sni(self.sample_ch)
        self.assertIsNotNone(parsed)
        hostname, start, length = parsed
        self.assertEqual(hostname, "discord.com")

        offsets = get_sni_offsets(self.sample_ch)
        self.assertIsNotNone(offsets)
        start_pos, mid_pos, end_pos = offsets
        self.assertEqual(start_pos, start)
        self.assertEqual(end_pos, start + length)
        self.assertTrue(start_pos < mid_pos <= end_pos)
        self.assertEqual(self.sample_ch[start_pos:end_pos].decode("ascii"), "discord.com")

    def test_dummy_records(self):
        alert_rec = create_dummy_tls_record("alert")
        self.assertEqual(len(alert_rec), 7)
        self.assertEqual(alert_rec[0], 0x15)  # Alert

        app_rec = create_dummy_tls_record("appdata")
        self.assertEqual(len(app_rec), 5)
        self.assertEqual(app_rec[0], 0x17)  # Application Data

    def test_multi_tls_record_fragments(self):
        frags = create_multi_tls_record_fragments(self.sample_ch)
        self.assertTrue(len(frags) >= 2)
        total_payload = b""
        for f in frags:
            self.assertEqual(f[0], 0x16)
            total_payload += f[5:]
        self.assertEqual(total_payload, self.sample_ch[5:])

    def test_thompson_sampling_and_penalties(self):
        selector = ThompsonStrategySelector(enabled=True)

        # 1. YouTube должен выбрать split-стратегии, совместимые с BoringSSL
        strat_yt = selector.select_strategy("www.youtube.com", is_youtube=True)
        self.assertIn(strat_yt, ["boringssl_split", "tcp_split_sni_mid", "tcp_split_sni_start", "multi_split", "disoob_sni"])
        self.assertNotIn(strat_yt, ["tls_record_frag", "combo_tlsrec_tcpsplit"])

        # 2. Discord должен предпочесть проверенные техники (direct, combo, tlsrec), исключая disoob_sni
        strat_dc = selector.select_strategy("gateway.discord.gg", is_discord=True)
        self.assertIn(strat_dc, ["direct", "combo_tlsrec_tcpsplit", "tls_record_frag", "multi_split", "tcp_split_sni_mid"])
        self.assertNotEqual(strat_dc, "disoob_sni")

        # 3. Проверка обучения: штрафуем стратегию и смотрим реакцию
        domain = "test-domain.org"
        for _ in range(50):
            selector.record_failure(domain, "disoob_sni")
        for _ in range(50):
            selector.record_failure(domain, "tcp_split_sni_mid")
        for _ in range(50):
            selector.record_success(domain, "combo_tlsrec_tcpsplit")

        # После 50 успехов для combo и 50 штрафов для tcp_split_sni_mid, combo должна побеждать почти всегда
        combo_wins = sum(1 for _ in range(20) if selector.select_strategy(domain) == "combo_tlsrec_tcpsplit")
        self.assertTrue(combo_wins >= 18)

    def test_execute_strategy_mock_socket(self):
        # Проверяем, что все стратегии выполняются без падений сокета
        class MockSocket:
            def __init__(self):
                self.sent = []
                self.oob = []

            def sendall(self, data):
                self.sent.append(data)

            def send(self, data, flags=0):
                if flags == socket.MSG_OOB:
                    self.oob.append(data)
                else:
                    self.sent.append(data)

        for strat in ALL_STRATEGIES:
            mock = MockSocket()
            execute_strategy(strat, mock, self.sample_ch, delay=0.0)
            self.assertTrue(len(mock.sent) >= 1 or len(mock.oob) >= 1)

    def test_whitelist_wildcards(self):
        from Floweryguard.config import is_host_in_whitelist
        wl = {
            "discord.com",
            "*.discord.gg",
            "rotterdam*.discord.media",
            "*.googlevideo.com",
        }
        # Точное совпадение
        self.assertTrue(is_host_in_whitelist("discord.com", wl))
        # Поддомен *.discord.gg
        self.assertTrue(is_host_in_whitelist("gateway.discord.gg", wl))
        self.assertTrue(is_host_in_whitelist("sub.gateway.discord.gg", wl))
        # Произвольный wildcard в префиксе
        self.assertTrue(is_host_in_whitelist("rotterdam1234.discord.media", wl))
        self.assertTrue(is_host_in_whitelist("rotterdam-voice.discord.media", wl))
        self.assertFalse(is_host_in_whitelist("frankfurt1234.discord.media", wl))
        # Не в вайтлисте
        self.assertFalse(is_host_in_whitelist("example.org", wl))

    def test_thread_safe_bounded_cache(self):
        from Floweryguard.proxy import ThreadSafeBoundedCache
        cache = ThreadSafeBoundedCache(maxsize=3)
        cache.set("a", 1)
        cache.set("b", 2)
        cache.set("c", 3)
        self.assertEqual(cache.get("a"), 1)
        self.assertEqual(cache.get("b"), 2)
        self.assertEqual(cache.get("c"), 3)

        # Добавление 4-го элемента вытесняет самый старый ('a')
        cache.set("d", 4)
        self.assertIsNone(cache.get("a"))
        self.assertEqual(cache.get("d"), 4)
        self.assertIn("b", cache)
        self.assertNotIn("a", cache)

        # Удаление через pop
        val = cache.pop("b")
        self.assertEqual(val, 2)
        self.assertNotIn("b", cache)

    def test_strategy_scores_persistence(self):
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            tmp_cache_file = tf.name

        try:
            sel1 = ThompsonStrategySelector(enabled=True, cache_file=tmp_cache_file)
            sel1.record_success("persisted-test.com", "boringssl_split")
            sel1.save_scores(force=True)

            # Создаем второй экземпляр, который читает тот же файл
            sel2 = ThompsonStrategySelector(enabled=True, cache_file=tmp_cache_file)
            key = sel2._get_domain_key("persisted-test.com")
            self.assertIn(key, sel2._scores)
            self.assertIn("boringssl_split", sel2._scores[key])
            self.assertGreater(sel2._scores[key]["boringssl_split"][0], 1.0)
        finally:
            if os.path.exists(tmp_cache_file):
                os.remove(tmp_cache_file)

    def test_betavariate_non_positive_safety(self):
        # Проверяем, что движок не падает при alpha/beta <= 0 (коррумпированный кэш)
        selector = ThompsonStrategySelector(enabled=True)
        domain = "corrupted-test.com"
        key = selector._get_domain_key(domain)
        with selector._lock:
            selector._scores[key] = {"disoob_sni": [0.0, 0.0]}
        strat = selector.select_strategy(domain)
        self.assertEqual(strat, "disoob_sni")

    def test_safe_close_socket(self):
        from Floweryguard.proxy import _safe_close_socket
        # Закрытие None не вызывает исключений
        _safe_close_socket(None)

        # Создаем пару сокетов и корректно закрываем
        s1, s2 = socket.socketpair()
        try:
            _safe_close_socket(s1)
            _safe_close_socket(s2)
        finally:
            try:
                s1.close()
                s2.close()
            except Exception:
                pass

    def test_dns_netsh_decoding(self):
        from Floweryguard.dns_config import _decode_netsh
        raw_utf8 = "Подключен Ethernet 2".encode("utf-8")
        decoded = _decode_netsh(raw_utf8)
        self.assertEqual(decoded, "Подключен Ethernet 2")

    def test_flowery_app_lifecycle(self):
        from Floweryguard.main import FloweryApp
        app = FloweryApp()
        self.assertFalse(app._is_active)
        self.assertFalse(app._cleaned_up)
        # cleanup без force при неактивном приложении выходит без изменений
        app.cleanup()
        self.assertFalse(app._cleaned_up)
        # cleanup с force=True гарантированно выполняется
        app.cleanup(force=True)
        self.assertTrue(app._cleaned_up)


if __name__ == "__main__":
    unittest.main()
