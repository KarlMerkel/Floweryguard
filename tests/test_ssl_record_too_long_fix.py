"""Тест исправления SSL_ERROR_RX_RECORD_TOO_LONG.

Проверяет:
1. Запрет отправки открытого HTTP 502 Bad Gateway в клиентский TLS-сокет после '200 Connection Established' (RFC 2817/9110).
2. Гарантированный выбор 'combo_tlsrec_tcpsplit' на Попытке 3 в _handshake_with_fast_fallback.
3. Экспертные стартовые априорные веса в Strategy Engine (combo [8.0, 2.0], tcp_split_sni_mid [4.0, 2.0]).
4. Приоритет combo_tlsrec_tcpsplit в get_fallback_strategy при сбросе ТСПУ.
"""

import socket
import struct
import unittest
from unittest.mock import MagicMock, patch

from flowguard.config import Config
from flowguard.proxy import DPIBypassProxy, _safe_close_socket
from flowguard.strategy import ThompsonStrategySelector, ALL_STRATEGIES
from flowguard.sni_spoofer import build_fake_client_hello


class TestSSLRecordTooLongFix(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.proxy = DPIBypassProxy(self.config)
        self.proxy.shadow_prober = MagicMock()

    def test_no_502_bad_gateway_sent_over_tls_tunnel(self):
        """После отправки '200 Connection Established' прокси находится в TLS-режиме
        и НИКОГДА не должен отправлять HTTP 502 Bad Gateway в клиентский сокет при сбое рукопожатия."""
        client_sock = MagicMock()
        client_sock.recv.side_effect = [
            b"CONNECT rutracker.org:443 HTTP/1.1\r\nHost: rutracker.org:443\r\n\r\n",
            build_fake_client_hello("rutracker.org")
        ]

        target_sock = MagicMock()
        # Имитируем успешное TCP-подключение к цели, но сбой рукопожатия
        with patch.object(self.proxy, "_connect_target", return_value=target_sock), \
             patch.object(self.proxy, "_handshake_with_fast_fallback", return_value=(None, "tcp_split_sni_mid", "rutracker.org", None)):

            self.proxy._handle_client(client_sock, ("127.0.0.1", 54321))

            # Проверяем, что 200 Connection Established был отправлен
            sent_payloads = [call[0][0] for call in client_sock.sendall.call_args_list]
            self.assertTrue(any(b"200 Connection Established" in p for p in sent_payloads))

            # КРИТИЧЕСКАЯ ПРОВЕРКА: 502 Bad Gateway НЕ ДОЛЖЕН быть отправлен в TLS сессию!
            for p in sent_payloads:
                self.assertNotIn(b"502 Bad Gateway", p, "Обнаружена отправка plaintext 502 в TLS туннель!")
                self.assertNotIn(b"HTTP/1.1 502", p, "Обнаружен HTTP 502 в TLS сессии!")

            # Клиентский сокет должен быть безопасно закрыт
            client_sock.close.assert_called()

    def test_handshake_attempt3_falls_back_to_combo_tlsrec_tcpsplit(self):
        """Если Попытка 1 (напр. tcp_split_sni_mid) и Попытка 2 завершились неудачей,
        Попытка 3 обязана использовать 'combo_tlsrec_tcpsplit' на новом IP."""
        client_hello = build_fake_client_hello("rutracker.org")
        current_sock = MagicMock()
        sock2 = MagicMock()
        new_sock = MagicMock()

        executed = []
        def fake_exec(strat, s, data, host=""):
            executed.append(strat)
            return True

        with patch.object(self.proxy, "_connect_target", side_effect=[sock2, new_sock]), \
             patch.object(self.proxy, "_send_tls_client_hello_with_bypass", return_value=("tcp_split_sni_mid", "rutracker.org")), \
             patch.object(self.proxy.strategy_engine, "get_fallback_strategy", return_value="tcp_split_sni_start"), \
             patch.object(self.proxy, "_probe_socket_response", side_effect=[
                 ("silent_drop", None, 600.0),                     # Attempt 1 failed
                 ("silent_drop", None, 600.0),                     # Attempt 2 failed
                 ("success", b"\x16\x03\x03\x00\x10serverhello", 50.0)  # Attempt 3 success
             ]), \
             patch.object(self.proxy, "_safe_execute_strategy", side_effect=fake_exec), \
             patch("flowguard.proxy._get_socket_meta", side_effect=[
                 {"target_ip": "104.21.55.1", "connect_rtt": 0.050},  # current_sock
                 {"target_ip": "104.21.55.1", "connect_rtt": 0.050},  # sock2
                 {"target_ip": "172.67.180.2", "connect_rtt": 0.045}, # new_sock
             ]):

            live_sock, strat_used, eff_host, resp = self.proxy._handshake_with_fast_fallback(
                client_sock=MagicMock(),
                target_sock=current_sock,
                target_host="rutracker.org",
                target_port=443,
                first_packet=client_hello
            )

            self.assertEqual(live_sock, new_sock)
            self.assertEqual(strat_used, "combo_tlsrec_tcpsplit")
            self.assertEqual(executed, ["tcp_split_sni_start", "combo_tlsrec_tcpsplit"])

    def test_strategy_priors_combo_champion(self):
        """Проверяет, что для зарубежных ресурсов combo_tlsrec_tcpsplit имеет приоритет чемпиона [8.0, 2.0]."""
        selector = ThompsonStrategySelector(scores_file=":memory:")
        priors = selector._init_domain_priors("example.org")

        self.assertEqual(priors["combo_tlsrec_tcpsplit"], [8.0, 2.0])
        self.assertEqual(priors["tcp_split_sni_mid"], [4.0, 2.0])
        # Математическое ожидание combo_tlsrec_tcpsplit строго выше остальных кандидатов
        combo_exp = priors["combo_tlsrec_tcpsplit"][0] / sum(priors["combo_tlsrec_tcpsplit"])
        mid_exp = priors["tcp_split_sni_mid"][0] / sum(priors["tcp_split_sni_mid"])
        self.assertGreater(combo_exp, mid_exp)

    def test_get_fallback_strategy_prioritizes_combo_on_tspu(self):
        """get_fallback_strategy при сбросе ТСПУ отдает combo_tlsrec_tcpsplit, если он не был опробован."""
        selector = ThompsonStrategySelector(scores_file=None)
        fb = selector.get_fallback_strategy("rutracker.org", failed_strategy="tcp_split_sni_mid", is_tspu=True)
        self.assertEqual(fb, "combo_tlsrec_tcpsplit")

        # Если combo_tlsrec_tcpsplit уже пробовали, выбирается следующая лучшая альтернатива
        fb2 = selector.get_fallback_strategy(
            "rutracker.org",
            failed_strategy="tcp_split_sni_mid",
            failed_strategies={"tcp_split_sni_mid", "combo_tlsrec_tcpsplit"},
            is_tspu=True
        )
        self.assertNotEqual(fb2, "combo_tlsrec_tcpsplit")
        self.assertNotEqual(fb2, "tcp_split_sni_mid")

    def test_ssl_record_too_long_vector_analysis(self):
        """Математическое доказательство природы ошибки SSL_ERROR_RX_RECORD_TOO_LONG:
        Символ 'H' (0x48) интерпретируется браузером как тип записи, а 'P/' (0x502F) как длина > 16384."""
        http_502 = b"HTTP/1.1 502 Bad Gateway\r\n\r\n"
        first_byte = http_502[0]
        # В TLS записи байты 3:5 определяют длину полезной нагрузки
        record_len = struct.unpack("!H", http_502[3:5])[0]

        self.assertEqual(first_byte, ord("H"))
        self.assertEqual(record_len, 0x502F)  # 20527 байт
        self.assertGreater(record_len, 16384, "Длина превышает максимальный размер TLS Record (16 КБ)")


    def test_handshake_attempt3_uses_combo_on_new_ip_when_attempt1_was_combo(self):
        """Когда Попытка 1 уже использовала чемпионский combo_tlsrec_tcpsplit на IP 1 (напр. Cloudflare drop),
        Попытка 3 при подключении к новому IP 2 обязана использовать combo_tlsrec_tcpsplit на новом IP!"""
        client_hello = build_fake_client_hello("rutracker.org")
        current_sock = MagicMock()
        sock2 = MagicMock()
        new_sock = MagicMock()

        executed = []
        def fake_exec(strat, s, data, host=""):
            executed.append(strat)
            return True

        with patch.object(self.proxy, "_connect_target", side_effect=[sock2, new_sock]), \
             patch.object(self.proxy, "_send_tls_client_hello_with_bypass", return_value=("combo_tlsrec_tcpsplit", "rutracker.org")), \
             patch.object(self.proxy, "_probe_socket_response", side_effect=[
                 ("silent_drop", None, 600.0),                     # Attempt 1 failed (combo on IP 1)
                 ("silent_drop", None, 600.0),                     # Attempt 2 failed (fallback on IP 1)
                 ("success", b"\x16\x03\x03\x00\x10serverhello", 50.0)  # Attempt 3 on IP 2
             ]), \
             patch.object(self.proxy, "_safe_execute_strategy", side_effect=fake_exec), \
             patch("flowguard.proxy._get_socket_meta", side_effect=[
                 {"target_ip": "104.21.55.1", "connect_rtt": 0.050},  # current_sock (IP 1)
                 {"target_ip": "104.21.55.1", "connect_rtt": 0.050},  # sock2 (IP 1)
                 {"target_ip": "172.67.180.2", "connect_rtt": 0.045}, # new_sock (IP 2)
             ]):

            live_sock, strat_used, eff_host, resp = self.proxy._handshake_with_fast_fallback(
                client_sock=MagicMock(),
                target_sock=current_sock,
                target_host="rutracker.org",
                target_port=443,
                first_packet=client_hello
            )

            self.assertEqual(live_sock, new_sock)
            self.assertEqual(strat_used, "combo_tlsrec_tcpsplit")
            self.assertIn("combo_tlsrec_tcpsplit", executed)
            self.assertEqual(executed[-1], "combo_tlsrec_tcpsplit")

    def test_handshake_attempt3_discord_uses_new_ip_observations(self):
        """После смены IP используется проверенная на нём техника, включая TLS-фрагментацию."""
        for _ in range(40):
            self.proxy.strategy_engine.record_success(
                'discord.com', 'tls_record_frag', ip='162.159.133.233', rtt_ms=25)
        client_hello = build_fake_client_hello("discord.com")
        current_sock = MagicMock()
        sock2 = MagicMock()
        new_sock = MagicMock()

        executed = []
        def fake_exec(strat, s, data, host=""):
            executed.append(strat)
            return True

        with patch.object(self.proxy, "_connect_target", side_effect=[sock2, new_sock]), \
             patch.object(self.proxy, "_send_tls_client_hello_with_bypass", return_value=("combo_tlsrec_tcpsplit", "discord.com")), \
             patch.object(self.proxy, "_probe_socket_response", side_effect=[
                 ("silent_drop", None, 600.0),
                 ("silent_drop", None, 600.0),
                 ("success", b"\x16\x03\x03\x00\x10serverhello", 50.0)
             ]), \
             patch.object(self.proxy, "_safe_execute_strategy", side_effect=fake_exec), \
             patch("flowguard.proxy._get_socket_meta", side_effect=[
                 {"target_ip": "162.159.130.233", "connect_rtt": 0.050},
                 {"target_ip": "162.159.130.233", "connect_rtt": 0.050},
                 {"target_ip": "162.159.133.233", "connect_rtt": 0.045},
             ]):

            live_sock, strat_used, eff_host, resp = self.proxy._handshake_with_fast_fallback(
                client_sock=MagicMock(),
                target_sock=current_sock,
                target_host="discord.com",
                target_port=443,
                first_packet=client_hello
            )

            self.assertEqual(live_sock, new_sock)
            self.assertEqual(strat_used, "tls_record_frag")
            self.assertEqual(executed[-1], "tls_record_frag")

    def test_handshake_attempt3_same_ip_falls_back_when_combo_failed(self):
        """Если новый IP недоступен (new_ip == current_ip) и combo_tlsrec_tcpsplit уже завершился неудачей,
        Попытка 3 обращается к get_fallback_strategy для выбора другой стратегии."""
        client_hello = build_fake_client_hello("rutracker.org")
        current_sock = MagicMock()
        sock2 = MagicMock()
        new_sock = MagicMock()

        executed = []
        def fake_exec(strat, s, data, host=""):
            executed.append(strat)
            return True

        with patch.object(self.proxy, "_connect_target", side_effect=[sock2, new_sock]), \
             patch.object(self.proxy, "_send_tls_client_hello_with_bypass", return_value=("combo_tlsrec_tcpsplit", "rutracker.org")), \
             patch.object(self.proxy.strategy_engine, "get_fallback_strategy", return_value="multi_split"), \
             patch.object(self.proxy, "_probe_socket_response", side_effect=[
                 ("silent_drop", None, 600.0),
                 ("silent_drop", None, 600.0),
                 ("success", b"\x16\x03\x03\x00\x10serverhello", 50.0)
             ]), \
             patch.object(self.proxy, "_safe_execute_strategy", side_effect=fake_exec), \
             patch("flowguard.proxy._get_socket_meta", side_effect=[
                 {"target_ip": "104.21.55.1", "connect_rtt": 0.050},
                 {"target_ip": "104.21.55.1", "connect_rtt": 0.050},
                 {"target_ip": "104.21.55.1", "connect_rtt": 0.050},  # Тот же самый IP
             ]):

            live_sock, strat_used, eff_host, resp = self.proxy._handshake_with_fast_fallback(
                client_sock=MagicMock(),
                target_sock=current_sock,
                target_host="rutracker.org",
                target_port=443,
                first_packet=client_hello
            )

            self.assertEqual(strat_used, "multi_split")
            self.assertEqual(executed[-1], "multi_split")


if __name__ == "__main__":
    unittest.main()

