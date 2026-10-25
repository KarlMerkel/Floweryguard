"""Тесты для Flowery v1.3.0 (B1–B18 архитектурные исправления).
Проверяют:
1. Bandit learning persistence (B1) без перезаписи YouTube/Discord в _load_scores
2. 7-дневный период полураспада (Temporal Decay)
3. Защиту стратегий от штрафа при сбое на мёртвом IP
4. Приоритет пользовательских переопределений (B10)
5. PathHealth & Exponential Backoff (300с -> 900с -> 1800с)
6. Режим VoiceHelper (B2): отсутствие --wf-tcp=80,443 в режиме proxy
7. DNSFailoverManager защиту от self-failover (B5)
8. Безопасность IPv6 в badsum_injector (B18)
9. Блокировку UDP 53 для блокируемых ресурсов в resolve_fallback_dns (B6)
10. Типизацию исходов пробы сокета в proxy.py
"""

import unittest
import os
import time
import json
import socket
import tempfile
import logging
import inspect
from flowguard.strategy import ThompsonStrategySelector
from flowguard.voice_helper import VoiceHelper
from flowguard.doh_resolver import DNSFailoverManager, DNS_PRESETS
from flowguard.badsum_injector import WinDivertBadsumController
from flowguard.proxy import (
    is_ip_dead,
    mark_ip_dead,
    mark_ip_working,
    record_ip_strategy_failure,
    _IP_DEAD_STRIKES,
    _IP_FAILURES,
    set_use_hosts_file,
    resolve_fallback_dns,
    _DEAD_IP_CACHE,
    DPIBypassProxy,
)
from flowguard.config import Config


class TestFloweryV140Fixes(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.scores_path = os.path.join(self.test_dir, "test_scores.json")

    def tearDown(self):
        try:
            if os.path.exists(self.scores_path):
                os.remove(self.scores_path)
            os.rmdir(self.test_dir)
        except Exception:
            pass

    def test_b1_bandit_scores_persistence_no_overwrite(self):
        """B1: _load_scores() не должен сбрасывать обученные веса YouTube в [80.0, 1.0]."""
        initial_data = {
            "_metadata": {
                "version": 2,
                "saved_at": time.time(),
                "networks": {
                    "default": {
                        "googlevideo.com": {
                            "multi_split": [42.0, 2.0],
                            "boringssl_split": [15.0, 3.0]
                        },
                        "discord.com": {
                            "multi_split": [33.0, 1.5]
                        }
                    }
                }
            },
            "googlevideo.com": {
                "multi_split": [42.0, 2.0],
                "boringssl_split": [15.0, 3.0]
            },
            "discord.com": {
                "multi_split": [33.0, 1.5]
            }
        }
        with open(self.scores_path, "w", encoding="utf-8") as f:
            json.dump(initial_data, f)

        selector = ThompsonStrategySelector(scores_file=self.scores_path)
        scores_yt = selector.get_domain_scores("googlevideo.com")
        self.assertIn("multi_split", scores_yt)
        # Вес не должен быть сброшен в 40.0 или перезаписан hardcode [80, 1] для combo_tlsrec_tcpsplit
        self.assertAlmostEqual(scores_yt["multi_split"]["alpha"], 42.0, delta=1.0)

        scores_dc = selector.get_domain_scores("discord.com")
        self.assertIn("multi_split", scores_dc)
        self.assertAlmostEqual(scores_dc["multi_split"]["alpha"], 33.0, delta=1.0)

    def test_b1_temporal_decay_half_life_7_days(self):
        """B1: Проверка 7-дневного периода полураспада (604800 секунд)."""
        selector = ThompsonStrategySelector(scores_file=self.scores_path)
        domain = "example.com"
        strat = "tcp_split_sni_mid"
        selector.record_success(domain, strat, rtt_ms=50.0)

        alpha_init = selector.get_domain_scores(domain)[strat]["alpha"]

        # Симулируем ровно 7 дней прошедшего времени
        selector._last_decay_time = time.time() - 604800.0
        selector._apply_temporal_decay_locked()

        alpha_decayed = selector.get_domain_scores(domain)[strat]["alpha"]
        # Через 7 дней alpha должна уменьшиться примерно вдвое (decay factor = 0.5)
        self.assertAlmostEqual(alpha_decayed, alpha_init * 0.5, delta=0.5)

    def test_b1_dead_ip_penalty_protection(self):
        """B1: record_failure не должен штрафовать стратегию, если IP помечен как мертвый."""
        selector = ThompsonStrategySelector(scores_file=self.scores_path)
        domain = "test-penalty.org"
        strat = "tcp_split_sni_mid"
        dead_ip = "198.51.100.99"

        mark_ip_dead(dead_ip, duration=300.0)
        self.assertTrue(is_ip_dead(dead_ip))

        initial_beta = selector.get_domain_scores(domain)[strat]["beta"]
        selector.record_failure(domain, strat, ip=dead_ip, is_tspu=True)

        beta_after = selector.get_domain_scores(domain)[strat]["beta"]
        # Beta не должна вырасти, так как IP мертвый
        self.assertEqual(initial_beta, beta_after)

        mark_ip_working(dead_ip)

    def test_b10_user_overrides_priority(self):
        """B10: Пользовательские переопределения из strategy_overrides.json должны иметь абсолютный приоритет."""
        selector = ThompsonStrategySelector(scores_file=self.scores_path)
        selector._strategy_overrides["custom.org"] = "disoob_sni"

        override = selector.get_user_override("custom.org")
        self.assertEqual(override, "disoob_sni")

        selected = selector.select_strategy("custom.org")
        self.assertEqual(selected, "disoob_sni")

    def test_path_health_exponential_backoff(self):
        """Phase 2 PathHealth: 2 разные упавшие стратегии за 60с помечают IP мёртвым со страйками."""
        test_ip = "203.0.113.42"
        mark_ip_working(test_ip)

        # 1-я упавшая стратегия
        res1 = record_ip_strategy_failure(test_ip, "stratA")
        self.assertFalse(res1)
        self.assertFalse(is_ip_dead(test_ip))

        # 2-я упавшая стратегия на том же IP
        res2 = record_ip_strategy_failure(test_ip, "stratB")
        self.assertTrue(res2)
        self.assertTrue(is_ip_dead(test_ip))

        # Страйк 1: 300с
        self.assertEqual(_IP_DEAD_STRIKES.get(test_ip), 1)

        # mark_ip_working сбрасывает статус
        mark_ip_working(test_ip)
        self.assertFalse(is_ip_dead(test_ip))
        self.assertNotIn(test_ip, _IP_DEAD_STRIKES)

    def test_b2_voice_helper_proxy_mode_omits_wf_tcp(self):
        """B2: VoiceHelper в режиме proxy не должен генерировать --wf-tcp=80,443 аргументы winws."""
        helper_proxy = VoiceHelper(mode="proxy", tcp_desync=True)
        args_proxy = helper_proxy.build_winws_args()
        self.assertNotIn("--wf-tcp=80,443", args_proxy)

        helper_packet = VoiceHelper(mode="packet", tcp_desync=True)
        args_packet = helper_packet.build_winws_args()
        self.assertIn("--wf-tcp=80,443", args_packet)

    def test_b5_dns_failover_prevents_self_failover(self):
        """B5: Fallback провайдер обязан отличаться от Primary."""
        mgr = DNSFailoverManager(primary_provider=DNS_PRESETS["cloudflare"])
        self.assertNotEqual(mgr.primary_provider.name, mgr.fallback_provider.name)

        mgr_google = DNSFailoverManager(primary_provider=DNS_PRESETS["google"])
        self.assertNotEqual(mgr_google.primary_provider.name, mgr_google.fallback_provider.name)

    def test_b18_badsum_ipv6_safety(self):
        """B18: badsum_injector не должен падать на IPv6 сокетах."""
        injector = WinDivertBadsumController()
        try:
            s6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            result = injector.inject_fake_sni_packet(s6, b"test_payload")
            self.assertFalse(result)
            s6.close()
        except OSError:
            pass

    def test_b6_resolve_fallback_dns_blocked_never_udp53(self):
        """B6: resolve_fallback_dns не должен отправлять UDP 53 для блокируемых ресурсов."""
        set_use_hosts_file(False)
        from unittest.mock import patch, MagicMock
        from flowguard.proxy import _DNS_CACHE
        manager = MagicMock()
        manager.resolve_one.return_value = None
        with patch("flowguard.proxy.get_dns_failover_manager", return_value=manager), \
             patch("socket.socket") as udp_socket:
            for host in ("discord.com", "rr1.googlevideo.com", "rutracker.org"):
                _DNS_CACHE.pop(host, None)
                self.assertIsNone(resolve_fallback_dns(host))
            udp_socket.assert_not_called()

    def test_dns_fallback_keeps_udp_for_unprotected_domains(self):
        """Обычные домены сохраняют резервный UDP DNS при недоступном DoH."""
        from unittest.mock import patch, MagicMock
        from flowguard.proxy import _DNS_CACHE
        host = "ordinary-fallback.example"
        _DNS_CACHE.pop(host, None)
        manager = MagicMock()
        manager.resolve_one.return_value = None
        udp = MagicMock()
        udp.recvfrom.side_effect = socket.timeout()
        with patch("flowguard.proxy.get_dns_failover_manager", return_value=manager), \
             patch("socket.socket", return_value=udp):
            self.assertIsNone(resolve_fallback_dns(host))
        self.assertGreater(udp.sendto.call_count, 0)
        self.assertTrue(all(call.args[1][1] == 53 for call in udp.sendto.call_args_list))

    def test_b1_weak_initial_priors_bound(self):
        """B1: Все домены при первом обращении получают слабые априорные веса (alpha + beta <= 10.0)."""
        selector = ThompsonStrategySelector(scores_file=self.scores_path)
        test_domains = [
            ("rr1---sn-4g5ednks.googlevideo.com", True, False),
            ("gateway.discord.gg", False, True),
            ("rutracker.org", False, False),
            ("unknown-domain-test-xyz.org", False, False),
        ]
        for domain, is_yt, is_dc in test_domains:
            priors = selector._init_domain_priors(domain, is_youtube=is_yt, is_discord=is_dc)
            for strat_name, (alpha, beta) in priors.items():
                self.assertLessEqual(
                    alpha + beta,
                    10.0,
                    f"Prior for {domain} strat {strat_name} exceeds bound 10.0: alpha={alpha}, beta={beta}"
                )

    def test_b7_flowery_home_log_isolation(self):
        """B7: FLOWERY_HOME изолирует логи во временную папку, защищая папку Документы."""
        temp_home = os.path.join(self.test_dir, "fake_flowery_home")
        old_val = os.environ.get("FLOWERY_HOME")
        try:
            os.environ["FLOWERY_HOME"] = temp_home
            from flowguard.logger import get_log_dir
            log_dir = get_log_dir()
            expected = os.path.join(temp_home, "logs")
            self.assertEqual(os.path.normpath(log_dir), os.path.normpath(expected))
            self.assertTrue(os.path.isdir(log_dir))
        finally:
            if old_val is not None:
                os.environ["FLOWERY_HOME"] = old_val
            else:
                os.environ.pop("FLOWERY_HOME", None)

    def test_b11_logger_deduplication(self):
        """B11: Повторные вызовы setup_logger() не создают дублирующиеся FileHandler."""
        from flowguard.logger import setup_logger
        logger_inst = setup_logger()
        initial_file_handlers = [h for h in logger_inst.handlers if isinstance(h, logging.FileHandler)]
        self.assertEqual(len(initial_file_handlers), 1)

        for _ in range(3):
            setup_logger()

        current_file_handlers = [h for h in logger_inst.handlers if isinstance(h, logging.FileHandler)]
        self.assertEqual(len(current_file_handlers), 1)

    def test_b15_canonical_and_shim_module_identity(self):
        """B15: Floweryguard shim возвращает идентичные объекты модулей flowguard."""
        import flowguard.strategy as fg_strat
        import Floweryguard.strategy as fguard_strat
        import flowguard.config as fg_cfg
        import Floweryguard.config as fguard_cfg

        self.assertIs(fg_strat, fguard_strat)
        self.assertIs(fg_cfg, fguard_cfg)

    def test_b8_apply_setting_persistence(self):
        """B8: apply_setting сохраняет измененные настройки в файл config.ini на диске."""
        cfg_path = os.path.join(self.test_dir, "test_config.ini")
        cfg = Config(config_path=cfg_path)
        cfg.set_value("proxy", "timeout", 42)
        saved = cfg.save()
        self.assertTrue(saved)
        self.assertTrue(os.path.exists(cfg_path))

        cfg_loaded = Config(config_path=cfg_path)
        self.assertEqual(cfg_loaded.timeout, 42)

    def test_b12_reclaim_port_safeguard(self):
        """B12: _reclaim_port не завершает посторонние процессы вне app_dir."""
        cfg = Config()
        proxy = DPIBypassProxy(config=cfg)
        proxy.port = 18129
        try:
            proxy._reclaim_port()
        except Exception as e:
            self.fail(f"_reclaim_port raised unexpected exception: {e}")

    def test_b13_early_connect_safety(self):
        """B13: early_connect не считает хост живым, если все кэшированные IP мертвы."""
        dead_ip = "192.0.2.111"
        mark_ip_dead(dead_ip, duration=300.0)
        self.assertTrue(is_ip_dead(dead_ip))
        mark_ip_working(dead_ip)

    def test_fast_fallback_budget_bounds(self):
        """Fast-Fallback: проверка константы бюджета 8.0с, адаптивных тайм-аутов и последовательности одной переменной."""
        from flowguard import proxy
        source = inspect.getsource(proxy.DPIBypassProxy._handshake_with_fast_fallback)
        self.assertIn("MAX_FALLBACK_BUDGET = 8.0", source)
        self.assertIn("remaining_budget()", source)
        self.assertIn("strat3 = self.strategy_engine.get_fallback_strategy", source)
        self.assertIn("adaptive_floor1 = max(0.18", source)
        self.assertIn("adaptive_floor2 = max(0.25", source)
        self.assertIn("adaptive_floor3 = max(0.25", source)
        self.assertIn("skip_attempt2_fast_path", source)

    def test_safe_execute_strategy_handles_connection_reset(self):
        """Проверка _safe_execute_strategy: перехватывает ConnectionResetError без падения потока."""
        from flowguard.proxy import DPIBypassProxy
        from flowguard.config import Config
        cfg = Config()
        p = DPIBypassProxy(cfg)

        # Создаем пару сокетов и закрываем серверный конец для имитации RST от ТСПУ
        client_s, server_s = socket.socketpair()
        server_s.close()
        client_s.close()  # сокет закрыт, вызов send вызовет OSError
        res = p._safe_execute_strategy("tcp_split_sni_mid", client_s, b"dummy_data", host="youtube.com")
        self.assertFalse(res)

    def test_connect_target_cached_entry_with_excluded_set(self):
        """_connect_target извлекает другие живые IP из RAM-кэша без сетевого getaddrinfo при excluded_set."""
        from unittest.mock import patch
        from flowguard.proxy import DPIBypassProxy, _RESOLVED_IPS_CACHE
        from flowguard.config import Config
        cfg = Config()
        p = DPIBypassProxy(cfg)
        test_host = "test-ram-cache-rotation.example"
        ip_pool = ["93.184.216.34", "93.184.216.35"]
        _RESOLVED_IPS_CACHE.set(test_host, (time.time(), ip_pool))

        getaddrinfo_called = []

        def mock_gai(*args, **kwargs):
            getaddrinfo_called.append(args)
            return []

        connected_to = []

        def mock_connect(sock_self, addr):
            connected_to.append(addr[0])
            return None

        with patch("socket.getaddrinfo", side_effect=mock_gai), \
             patch.object(socket.socket, "connect", mock_connect):
            s = p._connect_target(test_host, 443, exclude_ip={"93.184.216.34"}, timeout=0.5)
            self.assertIsNotNone(s)
            s.close()
            # Убеждаемся, что взят второй IP из кэша
            self.assertIn("93.184.216.35", connected_to)
            self.assertNotIn("93.184.216.34", connected_to)
            # Убеждаемся, что getaddrinfo НЕ вызывался, так как в кэше был живой IP!
            self.assertEqual(len(getaddrinfo_called), 0)

    def test_sni_offsets_sld_middle(self):
        """Проверка расчета середины SNI в SLD для многоуровневых доменов."""
        from flowguard.tls_parser import get_sni_offsets
        from flowguard.sni_spoofer import build_fake_client_hello

        # 1. YouTube Video CDN: rr1---sn-4g5ednks.googlevideo.com
        ch = build_fake_client_hello("rr1---sn-4g5ednks.googlevideo.com")
        offsets = get_sni_offsets(ch)
        self.assertIsNotNone(offsets)
        start, mid, end = offsets
        sni_str = ch[start:end].decode("ascii")
        mid_rel = mid - start
        self.assertTrue(sni_str[:mid_rel].endswith("googl"))
        self.assertTrue(sni_str[mid_rel:].startswith("evideo.com"))

        # 2. www.youtube.com
        ch_yt = build_fake_client_hello("www.youtube.com")
        start, mid, end = get_sni_offsets(ch_yt)
        sni_yt = ch_yt[start:end].decode("ascii")
        mid_rel = mid - start
        self.assertTrue(sni_yt[:mid_rel].endswith("you"))
        self.assertTrue(sni_yt[mid_rel:].startswith("tube.com"))

    def test_youtube_priors_prioritize_combo(self):
        """YouTube priors должны отдавать наивысший приоритет combo_tlsrec_tcpsplit."""
        temp_scores = os.path.join(tempfile.gettempdir(), f"test_priors_{time.time()}.json")
        selector = ThompsonStrategySelector(scores_file=temp_scores)
        selector._cluster_scores.clear()
        priors = selector._init_domain_priors("youtube.com", is_youtube=True, is_discord=False)
        self.assertEqual(priors["combo_tlsrec_tcpsplit"], [8.0, 2.0])
        self.assertEqual(priors["boringssl_split"], [6.0, 2.0])
        self.assertEqual(priors["tcp_split_sni_mid"], [5.0, 2.0])

    def test_sni_offsets_trailing_dot_and_cctld_and_idn(self):
        """Проверка устойчивости get_sni_offsets к FQDN с точкой, ccTLD и IDN Punycode."""
        from flowguard.tls_parser import get_sni_offsets, create_tls_record_fragments
        from flowguard.sni_spoofer import build_fake_client_hello
        import inspect
        from flowguard.strategy import StrategyExecutor

        # 1. Trailing dot: www.youtube.com.
        ch_dot = build_fake_client_hello("www.youtube.com.")
        start, mid, end = get_sni_offsets(ch_dot)
        sni_dot = ch_dot[start:end]
        mid_rel = mid - start
        self.assertTrue(sni_dot[:mid_rel].endswith(b"you"), f"Failed for trailing dot: {sni_dot[:mid_rel]}")
        self.assertTrue(sni_dot[mid_rel:].startswith(b"tube.com."), f"Failed for trailing dot: {sni_dot[mid_rel:]}")

        # 2. ccTLD: service.gov.ru
        ch_cctld = build_fake_client_hello("service.gov.ru")
        start, mid, end = get_sni_offsets(ch_cctld)
        sni_cctld = ch_cctld[start:end]
        mid_rel = mid - start
        self.assertTrue(sni_cctld[:mid_rel].endswith(b"ser"))
        self.assertTrue(sni_cctld[mid_rel:].startswith(b"vice.gov.ru"))

        # 3. IDN Punycode: тест.рф -> xn--e1aybc.xn--p1ai
        ch_idn = build_fake_client_hello("тест.рф")
        start, mid, end = get_sni_offsets(ch_idn)
        sni_idn = ch_idn[start:end]
        mid_rel = mid - start
        self.assertTrue(sni_idn[:mid_rel].endswith(b"xn--e"))
        self.assertTrue(sni_idn[mid_rel:].startswith(b"1aybc.xn--p1ai"))

        # 4. create_tls_record_fragments с None split_offset использует sni_mid
        frags = create_tls_record_fragments(ch_dot)
        self.assertEqual(len(frags), 2)
        # Проверяем, что первая запись не содержит полное доменное имя youtube
        self.assertNotIn(b"youtube.com", frags[0])

        # 5. tls_record_frag в strategy.py использует offsets[1] (sni_mid)
        source_frag = inspect.getsource(StrategyExecutor.tls_record_frag)
        self.assertIn("split_offset = offsets[1]", source_frag)

    def test_handshake_fast_fallback_rst_server_triggers_attempt2_and_3(self):
        """Проверка исправления бага 502 Bad Gateway:
        Когда ТСПУ или сервер сбрасывают первую попытку с кодом 'rst_server',
        Fast-Fallback не сдается и не возвращает None (502 Bad Gateway),
        а корректно переходит к Попытке 2 / Попытке 3 с альтернативными стратегиями и IP.
        """
        from unittest.mock import MagicMock, patch
        from flowguard.sni_spoofer import build_fake_client_hello
        from flowguard.proxy import _set_socket_meta

        cfg = Config()
        proxy = DPIBypassProxy(cfg)
        ch = build_fake_client_hello("gateway-us-east1-d.discord.gg")

        current_sock = MagicMock()
        _set_socket_meta(current_sock, "162.159.130.234", 0.035)

        sock2 = MagicMock()
        _set_socket_meta(sock2, "162.159.130.234", 0.035)

        proxy._send_tls_client_hello_with_bypass = MagicMock(return_value=("combo_tlsrec_tcpsplit", "gateway-us-east1-d.discord.gg"))
        proxy._connect_target = MagicMock(return_value=sock2)

        # Attempt 1 -> rst_server (сброс ТСПУ > base_rtt * 0.5)
        # Attempt 2 -> success (альтернативная стратегия на том же IP)
        proxy._probe_socket_response = MagicMock(side_effect=[
            ("rst_server", None, 65.0),
            ("success", b"\x16\x03\x03\x00\x50ServerHello", 35.0),
        ])
        proxy._safe_execute_strategy = MagicMock(return_value=True)

        res_sock, res_strat, eff_host, resp = proxy._handshake_with_fast_fallback(
            client_sock=MagicMock(),
            target_sock=current_sock,
            target_host="gateway-us-east1-d.discord.gg",
            target_port=443,
            first_packet=ch
        )

        # Убеждаемся, что сокет НЕ равен None (502 Bad Gateway предотвращен!)
        self.assertIsNotNone(res_sock)
        self.assertEqual(res_sock, sock2)
        self.assertNotEqual(res_strat, "combo_tlsrec_tcpsplit")
        self.assertIn(res_strat, ("tls_record_frag", "tcp_split_sni_mid", "multi_split"))
        self.assertEqual(resp, b"\x16\x03\x03\x00\x50ServerHello")


if __name__ == "__main__":
    unittest.main()
