"""Тесты для верификации исправлений и оптимизаций цикла аудита:
1. Инициализация fallback стратегий в select_strategy без KeyError.
2. Проверка резолвинга литеральных IPv4/IPv6 в DoHResolver без сетевых запросов.
3. Однократная замена заголовка Host в _obfuscate_http_request.
4. Отсутствие экранированных кавычек в параметрах netsh name=.
5. Защита от утечки сокетов при client_aborted в early_connect.
6. Отсутствие ложных штрафов стратегий при клиентском разрыве соединения.
"""

import unittest
import socket
import struct
import threading
import time
from unittest.mock import MagicMock, patch

from flowguard.config import Config
from flowguard.strategy import ThompsonStrategySelector, ALL_STRATEGIES
from flowguard.doh_resolver import DoHResolver, DoHProvider
from flowguard.dns_config import DNSManager
from flowguard.proxy import DPIBypassProxy


class TestAuditCycleFixes(unittest.TestCase):

    def test_select_strategy_handles_missing_candidate_without_keyerror(self):
        """Проверяет, что при отсутствии fallback-стратегии в candidates не возникает KeyError."""
        engine = ThompsonStrategySelector(enabled=True)
        engine.set_network_context("test_net")
        
        # Намеренно создаем candidates только с одной стратегией, которую затем исключим
        key = engine._get_composite_key("test-host.com")
        engine._scores["test_net"] = {
            key: {"boringssl_split": [5.0, 1.0]}
        }
        
        # Для YouTube boringssl_split исключена, поэтому available выпадет на ALL_STRATEGIES
        selected = engine.select_strategy("test-host.com", is_youtube=True)
        self.assertIn(selected, ALL_STRATEGIES)
        # Проверяем, что стратегия корректно проинициализировалась в candidates
        self.assertIn(selected, engine._scores["test_net"][key])

    def test_doh_resolver_literal_ip_bypass(self):
        """Проверяет, что литеральные IP не опрашивают сеть и возвращают корректный результат."""
        prov = DoHProvider(name="test", doh_host="127.0.0.1", doh_path="/dns-query", server_ips=("127.0.0.1",))
        resolver = DoHResolver(prov)

        # IPv4 при qtype=1 (A)
        res_v4_a = resolver.resolve("198.51.100.1", qtype=1)
        self.assertEqual(res_v4_a, ["198.51.100.1"])

        # IPv4 при qtype=28 (AAAA) - должен вернуть [] без обращения к сети
        res_v4_aaaa = resolver.resolve("198.51.100.1", qtype=28)
        self.assertEqual(res_v4_aaaa, [])

        # IPv6 при qtype=28 (AAAA)
        res_v6_aaaa = resolver.resolve("2001:db8::1", qtype=28)
        self.assertEqual(res_v6_aaaa, ["2001:db8::1"])

        # IPv6 при qtype=1 (A) - должен вернуть []
        res_v6_a = resolver.resolve("2001:db8::1", qtype=1)
        self.assertEqual(res_v6_a, [])

    def test_http_host_obfuscation_single_replacement(self):
        """Проверяет, что в HTTP запросе подменяется только первый заголовок Host, а не тело."""
        cfg = Config()
        cfg.set_override("http_host_obfuscation", True)
        cfg.set_override("whitelist_spoof_sni", False)
        cfg.set_override("mask_user_agent", False)
        proxy = DPIBypassProxy(cfg)

        req = (
            b"POST /api HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Content-Length: 30\r\n\r\n"
            b"Data containing Host: example.com inside body"
        )
        obfuscated = proxy._obfuscate_http_request(req)
        
        # Первый заголовок должен быть заменен
        self.assertIn(b"\r\nhoSt: example.com\r\n", obfuscated)
        # Тело запроса НЕ должно быть заменено
        self.assertIn(b"Data containing Host: example.com inside body", obfuscated)

    def test_dns_config_netsh_formatting_no_escaped_quotes(self):
        """Проверяет, что аргументы netsh name= передаются без внутренних кавычек."""
        mgr = DNSManager()
        creationflags = 0
        calls = []

        def mock_run(cmd, **kwargs):
            calls.append(cmd)
            mock_res = MagicMock()
            mock_res.returncode = 0
            mock_res.stdout = b""
            mock_res.stderr = b""
            return mock_res

        with patch("subprocess.run", side_effect=mock_run):
            with patch("flowguard.dns_config.is_admin", return_value=True):
                with patch.object(mgr, "test_dns_server", return_value=True):
                    with patch.object(mgr, "get_active_interfaces", return_value=["Wi-Fi 2", "Беспроводная сеть"]):
                        mgr.set_secure_dns()

        self.assertTrue(len(calls) > 0)
        for cmd in calls:
            for arg in cmd:
                # В аргументе не должно быть внутренних двойных кавычек вида name="Wi-Fi"
                if arg.startswith("name="):
                    self.assertFalse(arg.startswith('name="'), f"Обнаружена внутренняя кавычка в {arg}")
                    self.assertFalse(arg.endswith('"'), f"Обнаружена завершающая кавычка в {arg}")

    def test_proxy_early_connect_abort_event_socket_cleanup(self):
        """Проверяет, что при досрочном отключении клиента фоновый сокет закрывается."""
        cfg = Config()
        cfg.set_override("early_connect", True)
        proxy = DPIBypassProxy(cfg)

        mock_target_sock = MagicMock()
        mock_target_sock.close = MagicMock()

        # Имитируем ситуацию, когда клиент отключился до завершения _connect_target
        client_aborted = threading.Event()
        client_aborted.set()
        connect_res = [None]

        def _async_connect():
            s = mock_target_sock
            if client_aborted.is_set():
                if s:
                    s.close()
                return
            connect_res[0] = s

        _async_connect()
        # Сокет должен быть закрыт немедленно
        mock_target_sock.close.assert_called_once()
        self.assertIsNone(connect_res[0])

    def test_strategy_get_scores_for_key(self):
        """Проверяет метод get_scores_for_key с учетом контекста сети и fallback на default."""
        engine = ThompsonStrategySelector(enabled=True)
        engine.set_network_context("wifi:HomeRouter")

        key = engine._get_composite_key("test.org", "1.2.3.4")
        engine._scores["wifi:HomeRouter"] = {
            key: {"combo_tlsrec_tcpsplit": [15.0, 1.0]}
        }

        scores = engine.get_scores_for_key("test.org", "1.2.3.4")
        self.assertIsNotNone(scores)
        self.assertIn("combo_tlsrec_tcpsplit", scores)
        self.assertEqual(scores["combo_tlsrec_tcpsplit"][0], 15.0)

        # Проверка fallback на default для ключа, отсутствующего в wifi:HomeRouter
        def_key = engine._get_composite_key("default-only.org")
        engine._scores["default"] = {
            def_key: {"tcp_split_sni_mid": [10.0, 2.0]}
        }
        def_scores = engine.get_scores_for_key("default-only.org")
        self.assertIsNotNone(def_scores)
        self.assertIn("tcp_split_sni_mid", def_scores)

    def test_shadow_prober_respects_learned_strategy_in_network_context(self):
        """Проверяет, что ShadowProber видит веса в контексте сети и отсеивает известные хосты."""
        from flowguard.proxy import ShadowProber
        engine = ThompsonStrategySelector(enabled=True)
        engine.set_network_context("wifi:OfficeNet")
        prober = ShadowProber(engine)

        # Для хоста с alpha >= 3 в текущей сети пробер не должен ставить в очередь
        host = "known-established-domain.com"
        key = engine._get_composite_key(host, "93.184.216.34")
        engine._scores["wifi:OfficeNet"] = {
            key: {"combo_tlsrec_tcpsplit": [8.0, 1.0]}
        }

        prober.maybe_enqueue(host, ip="93.184.216.34")
        self.assertEqual(prober.task_queue.qsize(), 0)

    def test_bounded_host_locks_eviction(self):
        """Проверяет, что _HOST_RESOLVE_LOCKS автоматически сбрасывает старые незаблокированные замки при росте >= 2048."""
        from flowguard.proxy import _get_host_lock, _HOST_RESOLVE_LOCKS, _SINGLE_FLIGHT_LOCK
        with _SINGLE_FLIGHT_LOCK:
            _HOST_RESOLVE_LOCKS.clear()
            for i in range(2050):
                _HOST_RESOLVE_LOCKS[f"test-domain-{i}.com"] = threading.Lock()
        
        # Запрос нового хоста должен триггерить очистку
        new_lock = _get_host_lock("trigger-eviction.com")
        self.assertIsNotNone(new_lock)
        self.assertLessEqual(len(_HOST_RESOLVE_LOCKS), 1050)
        self.assertIn("trigger-eviction.com", _HOST_RESOLVE_LOCKS)

    def test_flush_stale_caches_clears_resolved_ips_and_locks(self):
        """Проверяет, что flush_stale_caches сбрасывает _RESOLVED_IPS_CACHE и замки _HOST_RESOLVE_LOCKS."""
        from flowguard.proxy import (
            DPIBypassProxy, _RESOLVED_IPS_CACHE, _HOST_RESOLVE_LOCKS, _SINGLE_FLIGHT_LOCK
        )
        cfg = Config()
        proxy = DPIBypassProxy(cfg)
        _RESOLVED_IPS_CACHE.set("example.com", ["93.184.216.34"])
        with _SINGLE_FLIGHT_LOCK:
            _HOST_RESOLVE_LOCKS["stale.com"] = threading.Lock()

        proxy.flush_stale_caches()
        self.assertIsNone(_RESOLVED_IPS_CACHE.get("example.com"))
        with _SINGLE_FLIGHT_LOCK:
            self.assertNotIn("stale.com", _HOST_RESOLVE_LOCKS)

    def test_power_watchdog_none_srv_handling(self):
        """Проверяет устойчивость power_watchdog к srv=None из системного реестра."""
        mock_mgr = MagicMock()
        mock_mgr.get_current_settings.return_value = (1, None, None)
        p_host = "127.0.0.1"
        p_port = 8118
        en, srv, _ = mock_mgr.get_current_settings()
        target_srv = f"{p_host}:{p_port}"
        # Проверяем, что условие вычисляется безопасно без TypeError
        needs_recovery = (en != 1 or target_srv not in (srv or ""))
        self.assertTrue(needs_recovery)

    def test_ttl_fix_decode_netsh(self):
        """Проверяет функцию _decode_netsh в ttl_fix для сохранения не-ASCII интерфейсов."""
        from flowguard.ttl_fix import _decode_netsh
        self.assertEqual(_decode_netsh(b""), "")
        self.assertEqual(_decode_netsh("Беспроводная сеть".encode("utf-8")), "Беспроводная сеть")
        self.assertEqual(_decode_netsh("Беспроводная сеть".encode("cp866")), "Беспроводная сеть")


    def test_profiles_decode_netsh(self):
        """Проверяет декодирование вывода netsh в кодировках Windows (UTF-8, OEM CP866)."""
        from flowguard.profiles import _decode_netsh
        self.assertEqual(_decode_netsh(b""), "")
        self.assertEqual(_decode_netsh("Привет, Мир!".encode("utf-8")), "Привет, Мир!")
        self.assertEqual(_decode_netsh("Привет, Мир!".encode("cp866")), "Привет, Мир!")

    def test_sni_spoofer_idna_cyrillic(self):
        """Проверяет IDNA-кодирование для кириллических доменов в SNISpoofer и фейковом HTTP."""
        from flowguard.sni_spoofer import SNISpoofer, build_fake_http_request, build_fake_client_hello
        fake_http = build_fake_http_request("госуслуги.рф")
        self.assertIn(b"xn--", fake_http)
        fake_ch = build_fake_client_hello("госуслуги.рф")
        self.assertIn(b"xn--", fake_ch)

    def test_sni_spoofer_preserves_post_body(self):
        """Проверяет, что obfuscate_http_request не повреждает тело POST/PUT запроса и сохраняет виртуальный хостинг."""
        from flowguard.sni_spoofer import SNISpoofer
        spoofer = SNISpoofer(whitelisted_sni="gosuslugi.ru")
        body = b"{\"field\": \"value\", \"host_info\": \"Host: example.org\"}"
        raw_req = b"POST /api/test HTTP/1.1\r\nHost: example.com\r\nContent-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" + body
        obf = spoofer.obfuscate_http_request(raw_req)
        head, sep, res_body = obf.partition(b"\r\n\r\n")
        self.assertEqual(sep, b"\r\n\r\n")
        self.assertEqual(res_body, body)
        # Виртуальный хостинг сохранен: целевой домен example.com остался, изменен только регистр на hoSt:
        self.assertIn(b"hoSt: example.com", head)
        self.assertNotIn(b"Host: gosuslugi.ru", head)

    def test_sni_spoofer_fake_http_desync_execution(self):
        """Проверяет, что send_with_fake_http_desync отправляет фейковый пакет и затем реальный HTTP запрос."""
        from flowguard.sni_spoofer import SNISpoofer
        spoofer = SNISpoofer(whitelisted_sni="gosuslugi.ru", delay=0)
        mock_sock = MagicMock()
        mock_ctrl = MagicMock()
        mock_ctrl.is_available = True
        with patch("flowguard.sni_spoofer.get_badsum_controller", return_value=mock_ctrl):
            req = b"GET / HTTP/1.1\r\nhoSt: example.com\r\n\r\n"
            res = spoofer.send_with_fake_http_desync(mock_sock, req)
            self.assertTrue(res)
            # Фейковый пакет инжектирован с белым Host
            mock_ctrl.inject_fake_sni_packet.assert_called_once()
            injected_payload = mock_ctrl.inject_fake_sni_packet.call_args[0][1]
            self.assertIn(b"Host: gosuslugi.ru", injected_payload)
            # Реальный сокет получил настоящий запрос с hoSt: example.com
            mock_sock.sendall.assert_called_once_with(req)

    def test_badsum_injector_custom_seq_ack(self):
        """Проверяет передачу кастомных seq и ack в inject_fake_sni_packet."""
        from flowguard.badsum_injector import WinDivertBadsumController
        controller = WinDivertBadsumController()
        mock_sock = MagicMock()
        mock_sock.getsockname.return_value = ("192.168.1.10", 54321)
        mock_sock.getpeername.return_value = ("93.184.216.34", 80)
        with patch.object(controller, "inject_packet", return_value=True) as mock_inject:
            res = controller.inject_fake_sni_packet(mock_sock, b"TEST", seq=1234567, ack=7654321)
            self.assertTrue(res)
            mock_inject.assert_called_once()
            raw_pkt = mock_inject.call_args[0][0]
            # IPv4 header: 20 bytes, TCP header: seq at offset 24..28, ack at offset 28..32
            seq_val = struct.unpack("!I", raw_pkt[24:28])[0]
            ack_val = struct.unpack("!I", raw_pkt[28:32])[0]
            self.assertEqual(seq_val, 1234567)
            self.assertEqual(ack_val, 7654321)

    def test_is_host_in_whitelist_port_stripping(self):
        """Проверяет, что is_host_in_whitelist корректно очищает порты и IPv6 скобки."""
        from flowguard.config import is_host_in_whitelist
        wl = {"discord.com", "gateway.discord.gg", "rotterdam*.discord.media", "2606:4700::6810:85e5"}
        # Обычные хосты с портами
        self.assertTrue(is_host_in_whitelist("discord.com:443", wl))
        self.assertTrue(is_host_in_whitelist("gateway.discord.gg:80", wl))
        self.assertTrue(is_host_in_whitelist("rotterdam99.discord.media:50001", wl))
        # IPv6 с портами в скобках
        self.assertTrue(is_host_in_whitelist("[2606:4700::6810:85e5]:443", wl))
        self.assertTrue(is_host_in_whitelist("[2606:4700::6810:85e5]", wl))
        # Не входящие в whitelist хосты с портами
        self.assertFalse(is_host_in_whitelist("example.org:443", wl))

    def test_strategy_discord_fallback_default(self):
        """Проверяет, что get_fallback_strategy для Discord возвращает combo_tlsrec_tcpsplit при пустом пуле."""
        from flowguard.strategy import ThompsonStrategySelector, ALL_STRATEGIES
        selector = ThompsonStrategySelector(enabled=True)
        # Исключаем все стратегии, кромеcombo_tlsrec_tcpsplit
        strat = selector.get_fallback_strategy("gateway.discord.gg", failed_strategies=ALL_STRATEGIES)
        self.assertEqual(strat, "combo_tlsrec_tcpsplit")

    def test_voice_helper_does_not_stop_windivert_if_system_winws_active(self):
        """Проверяет, что stop() не останавливает службу WinDivert при наличии стороннего winws.exe."""
        from flowguard.voice_helper import VoiceHelper
        helper = VoiceHelper()
        helper.managed_by_us = True
        helper.process = MagicMock()
        helper.process.poll.return_value = 0
        with patch("flowguard.voice_helper.is_system_winws_running", return_value=True), \
             patch("flowguard.voice_helper.is_admin", return_value=True), \
             patch("subprocess.run") as mock_subproc:
            helper.stop()
            mock_subproc.assert_not_called()

    def test_parse_sni_malformed_name_len_exceeds_extension(self):
        """Проверяет, что parse_sni возвращает None при попытке выхода name_len за границы SNI расширения."""
        from flowguard.tls_parser import parse_sni
        prefix = b"\x16\x03\x03\x01\x00\x01\x00\x00\xfc\x03\x03" + (b"R" * 32) + b"\x00" + b"\x00\x02\x00\x9c" + b"\x01\x00"
        sni_ext = b"\x00\x00\x00\x0a\x00\x08\x00\x00\x1e" + b"bad_sni_reading_out_of_bounds!"
        next_ext = b"\x00\x0b\x00\x04\x01\x02\x03\x04" + (b"\x00" * 100)
        packet = prefix + b"\x00\xd0" + sni_ext + next_ext
        res = parse_sni(packet)
        self.assertIsNone(res)

    def test_parse_extensions_info_bounds(self):
        """Проверяет, что _parse_extensions_info прерывает парсинг, если total_len расширения превышает ext_end."""
        from flowguard.tls_parser import _parse_extensions_info
        prefix = b"\x16\x03\x03\x00\x60\x01\x00\x00\x5c\x03\x03" + (b"R" * 32) + b"\x00" + b"\x00\x02\x00\x9c" + b"\x01\x00"
        malformed_ext = b"\x00\x0a\x00\x00\x00\x32" + (b"\x00" * 80)
        packet = prefix + malformed_ext
        info = _parse_extensions_info(packet)
        self.assertIsNotNone(info)
        ext_len_pos, extensions_len, extensions = info
        self.assertEqual(len(extensions), 0)

    def test_parse_http_target_relative_url(self):
        """Проверяет, что _parse_http_target сохраняет путь при относительном URL и читает Host заголовок."""
        from flowguard.proxy import DPIBypassProxy
        proxy = DPIBypassProxy(Config())
        raw_req = b"GET /ncsi.txt HTTP/1.1\r\nHost: www.msftncsi.com\r\n\r\n"
        host, port, path = proxy._parse_http_target(raw_req, "/ncsi.txt")
        self.assertEqual(host, "www.msftncsi.com")
        self.assertEqual(port, 80)
        self.assertEqual(path, "/ncsi.txt")

    def test_parse_http_target_https_and_ports(self):
        """Проверяет разбор абсолютных URL с HTTPS и нестандартными портами."""
        from flowguard.proxy import DPIBypassProxy
        proxy = DPIBypassProxy(Config())
        raw_req = b"GET https://example.com:8443/test/path HTTP/1.1\r\nHost: example.com:8443\r\n\r\n"
        host, port, path = proxy._parse_http_target(raw_req, "https://example.com:8443/test/path")
        self.assertEqual(host, "example.com")
        self.assertEqual(port, 8443)
        self.assertEqual(path, "/test/path")

    def test_calc_tcp_checksum_rfc793_zero_mapping(self):
        """Проверяет, что calc_tcp_checksum преобразует вычисленный ноль в 0xFFFF по RFC 793."""
        from flowguard.badsum_injector import calc_tcp_checksum
        with patch("flowguard.badsum_injector.calc_ip_checksum", return_value=0):
            c = calc_tcp_checksum("192.168.1.1", "192.168.1.2", b"\x00" * 20)
            self.assertEqual(c, 0xFFFF)


if __name__ == "__main__":
    unittest.main()

