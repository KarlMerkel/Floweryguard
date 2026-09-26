import os
import sys
import socket
import unittest

# Обеспечиваем импорт Floweryguard при автономном запуске файла
_project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

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
        app.config.set_override("auto_system_proxy", False)
        app.config.set_override("fix_ttl", False)
        app.config.set_override("block_quic", False)
        app.config.set_override("enable_custom_dns", False)
        self.assertFalse(app._is_active)
        self.assertFalse(app._cleaned_up)
        # cleanup без force при неактивном приложении выходит без изменений
        app.cleanup()
        self.assertFalse(app._cleaned_up)
        # cleanup с force=True гарантированно выполняется без сброса настроек пользователя
        app.cleanup(force=True)
        self.assertTrue(app._cleaned_up)

    def test_composite_key_subnet(self):
        selector = ThompsonStrategySelector(enabled=True)
        self.assertEqual(selector._get_composite_key("sub.example.com", "1.2.3.4"), "example.com:1.2.3.0/24")
        self.assertEqual(selector._get_composite_key("example.com", None), "example.com")
        self.assertEqual(selector._get_composite_key("example.com", "invalid-ip"), "example.com")

    def test_fallback_strategy_selection(self):
        selector = ThompsonStrategySelector(enabled=True)
        # Для YouTube сбой disoob_sni должен дать другую стратегию
        fb_yt = selector.get_fallback_strategy("youtube.com", failed_strategy="disoob_sni", is_youtube=True)
        self.assertNotEqual(fb_yt, "disoob_sni")
        self.assertIn(fb_yt, ["tcp_split_sni_mid", "boringssl_split", "multi_split"])

        # Для Discord сбой combo_tlsrec_tcpsplit должен дать direct или tls_record_frag
        fb_dc = selector.get_fallback_strategy("discord.gg", failed_strategy="combo_tlsrec_tcpsplit", is_discord=True)
        self.assertNotEqual(fb_dc, "combo_tlsrec_tcpsplit")
        self.assertIn(fb_dc, ["direct", "tls_record_frag", "tcp_split_sni_mid"])

        # Для общего домена сбой combo_tlsrec_tcpsplit должен дать альтернативу
        fb_gen = selector.get_fallback_strategy("rutracker.org", failed_strategy="combo_tlsrec_tcpsplit")
        self.assertNotEqual(fb_gen, "combo_tlsrec_tcpsplit")

    def test_tspu_penalty_distinction(self):
        selector = ThompsonStrategySelector(enabled=True)
        domain = "penalty-test.org"
        ip = "93.184.216.34"
        key = selector._get_composite_key(domain, ip)

        # Мягкий штраф (реальный сбой сети)
        selector.record_failure(domain, "combo_tlsrec_tcpsplit", ip=ip, is_tspu=False)
        beta_soft = selector._scores[key]["combo_tlsrec_tcpsplit"][1]
        self.assertAlmostEqual(beta_soft, 1.0 + 3.0, places=1)

        # Жесткий штраф (ТСПУ блокировка)
        selector.record_failure(domain, "combo_tlsrec_tcpsplit", ip=ip, is_tspu=True)
        beta_hard = selector._scores[key]["combo_tlsrec_tcpsplit"][1]
        self.assertAlmostEqual(beta_hard, beta_soft + 20.0, places=1)

    def test_socket_meta_lifecycle(self):
        from Floweryguard.proxy import _set_socket_meta, _get_socket_meta, _safe_close_socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            _set_socket_meta(s, "104.21.55.2", 0.038)
            meta = _get_socket_meta(s)
            self.assertEqual(meta.get("target_ip"), "104.21.55.2")
            self.assertAlmostEqual(meta.get("connect_rtt", 0.0), 0.038, places=3)
        finally:
            _safe_close_socket(s)

        # После safe_close сокет должен быть очищен из метаданных
        meta_after = _get_socket_meta(s)
        self.assertEqual(meta_after, {})

    def test_shadow_prober_filtering_and_throttling(self):
        from Floweryguard.proxy import ShadowProber
        selector = ThompsonStrategySelector(enabled=True)
        prober = ShadowProber(selector)

        # 1. Телеметрия и метрики должны отсеиваться
        prober.maybe_enqueue("telemetry.discord.com")
        self.assertEqual(prober.task_queue.qsize(), 0)
        prober.maybe_enqueue("analytics.google.com")
        self.assertEqual(prober.task_queue.qsize(), 0)

        # 2. Хосты с уже высокой статистикой успеха (alpha >= 3) должны отсеиваться
        known_host = "known-good-site.com"
        known_key = selector._get_composite_key(known_host, "1.1.1.1")
        with selector._lock:
            selector._scores[known_key] = {"combo_tlsrec_tcpsplit": [5.0, 1.0]}
        prober.maybe_enqueue(known_host, ip="1.1.1.1")
        self.assertEqual(prober.task_queue.qsize(), 0)

        # 3. Новый хост должен успешно ставиться в очередь
        new_host = "unknown-test-probe.org"
        prober.maybe_enqueue(new_host)
        # Должен попасть в очередь (1 элемент)
        self.assertEqual(prober.task_queue.qsize(), 1)

        # 4. Повторный enqueue того же хоста блокируется кулдауном 15 минут
        prober.maybe_enqueue(new_host)
        self.assertEqual(prober.task_queue.qsize(), 1)


if __name__ == "__main__":
    unittest.main()

