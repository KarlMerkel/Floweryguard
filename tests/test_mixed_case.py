"""Unit-тесты для техники обхода Mixed-Case SNI и стратегии mixed_case_tcpsplit."""

import unittest
from unittest.mock import MagicMock
from Floweryguard.tls_parser import randomize_sni_case, parse_sni, get_sni_offsets
from Floweryguard.sni_spoofer import build_fake_client_hello
from Floweryguard.strategy import StrategyExecutor, ALL_STRATEGIES, STRATEGY_DISPATCH


class TestMixedCaseSNI(unittest.TestCase):
    """Проверка корректности модификации регистра SNI без изменения длины пакета."""

    def test_randomize_sni_case_preserves_length(self):
        domain = "discord.com"
        ch = build_fake_client_hello(domain)
        self.assertGreater(len(ch), 0)

        mod = randomize_sni_case(ch)

        # Длина модифицированного пакета должна быть СТРОГО идентична исходному
        self.assertEqual(len(mod), len(ch))

        # Смещения SNI должны сохраняться
        offsets = get_sni_offsets(mod)
        self.assertIsNotNone(offsets)
        start, mid, end = offsets

        original_sni = ch[start:end]
        modified_sni = mod[start:end]

        # Должен измениться регистр части символов
        self.assertNotEqual(original_sni, modified_sni)
        # При этом строка в нижнем регистре должна быть идентична исходному домену
        self.assertEqual(modified_sni.decode("ascii").lower(), domain)

    def test_randomize_sni_case_non_tls_noop(self):
        non_tls = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        res = randomize_sni_case(non_tls)
        self.assertEqual(res, non_tls)

    def test_mixed_case_tcpsplit_execution(self):
        domain = "instagram.com"
        ch = build_fake_client_hello(domain)
        mock_sock = MagicMock()

        StrategyExecutor.mixed_case_tcpsplit(mock_sock, ch, delay=0.0)

        # Должно быть ровно 2 вызова sendall (TCP Split)
        self.assertEqual(mock_sock.sendall.call_count, 2)

        call_args = [call[0][0] for call in mock_sock.sendall.call_args_list]
        combined = call_args[0] + call_args[1]

        # Суммарная длина должна совпадать с длиной ClientHello
        self.assertEqual(len(combined), len(ch))

        # Домен внутри отправленных пакетов должен парситься обратно
        sni_parsed = parse_sni(combined)
        self.assertIsNotNone(sni_parsed)
        self.assertEqual(sni_parsed[0].lower(), domain)

    def test_strategy_registered(self):
        self.assertIn("mixed_case_tcpsplit", STRATEGY_DISPATCH)
        self.assertTrue(hasattr(StrategyExecutor, "mixed_case_tcpsplit"))


if __name__ == "__main__":
    unittest.main()
