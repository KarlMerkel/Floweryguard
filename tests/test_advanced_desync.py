"""Тесты для расширенных техник DPI Bypass:
- Ptacek-Newsham Overlapping TCP Segments (seqovl)
- Profile-aware IPv6 Management (disabled / prefer / auto)
- Multi-DoH Anycast IP Harvester
"""

import unittest
from unittest.mock import MagicMock, patch
import socket
from Floweryguard.config import Config
from Floweryguard.profiles import BUILTIN_PROFILES
from Floweryguard.voice_helper import VoiceHelper
from Floweryguard.strategy import StrategyExecutor, ALL_STRATEGIES
from Floweryguard.doh_resolver import MultiDoHHarvester, DoHProvider


class TestAdvancedDesync(unittest.TestCase):
    """Тестирование передовых техник десинхронизации."""

    def test_voice_helper_split_seqovl_args(self):
        """Проверка аргументов winws с Ptacek-Newsham sequence overlap (seqovl)."""
        helper = VoiceHelper(fooling="badsum", autottl=True, split_seqovl=16, repeats=4)
        args = helper.build_winws_args()
        self.assertIn("--dpi-desync-split-seqovl=16", args)
        self.assertIn("--dpi-desync-fooling=badsum", args)

    def test_tcp_overlap_sni_strategy_registered(self):
        """Проверка наличия безопасного алиаса tcp_overlap_sni в StrategyExecutor."""
        self.assertTrue(hasattr(StrategyExecutor, "tcp_overlap_sni"))

    def test_tcp_overlap_sni_execution(self):
        """Проверка исполнения безопасного алиаса tcp_overlap_sni на сокете."""
        fake_sock = MagicMock()
        client_hello = (
            b"\x16\x03\x01\x00\x30\x01\x00\x00\x2c\x03\x03"
            + (b"\x00" * 28)
            + b"\x00\x00\x02\x00\x9c\x01\x00\x00\x00"
            + b"\x00\x00\x00\x0a\x00\x08\x00\x00\x05target"
        )
        StrategyExecutor.tcp_overlap_sni(fake_sock, client_hello, delay=0.0)
        self.assertTrue(fake_sock.sendall.called)

    def test_profiles_ipv6_and_seqovl(self):
        """Проверка сетевых профилей на наличие настроек ipv6_mode и split_seqovl."""
        tethering = BUILTIN_PROFILES["tethering"]["settings"]
        self.assertEqual(tethering.get("ipv6_mode"), "disabled")
        self.assertEqual(tethering.get("packet_desync_split_seqovl"), 16)

        home_wifi = BUILTIN_PROFILES["home_wifi"]["settings"]
        self.assertEqual(home_wifi.get("ipv6_mode"), "disabled")
        self.assertEqual(home_wifi.get("packet_desync_fooling"), "badsum")
        self.assertEqual(home_wifi.get("packet_desync_split_seqovl"), 16)

        strict_whitelist = BUILTIN_PROFILES["strict_whitelist"]["settings"]
        self.assertEqual(strict_whitelist.get("ipv6_mode"), "disabled")
        self.assertEqual(strict_whitelist.get("packet_desync_fooling"), "badsum")

    def test_multi_doh_harvester_aggregation(self):
        """Проверка агрегации альтернативных Anycast IP через MultiDoHHarvester."""
        mock_p1 = DoHProvider("P1", "doh1.test", "/dns", ("1.1.1.1",))
        mock_p2 = DoHProvider("P2", "doh2.test", "/dns", ("2.2.2.2",))

        harvester = MultiDoHHarvester(providers=[mock_p1, mock_p2], timeout=1.0)
        
        # Мокаем resolve у резолверов
        harvester.resolvers[0].resolve = MagicMock(return_value=["104.16.1.1", "104.16.1.2"])
        harvester.resolvers[1].resolve = MagicMock(return_value=["172.64.1.1", "104.16.1.1"])

        results = harvester.harvest("test-domain.com")
        self.assertIn("104.16.1.1", results)
        self.assertIn("104.16.1.2", results)
        self.assertIn("172.64.1.1", results)
        # Проверка дедупликации: 104.16.1.1 должен быть ровно один раз
        self.assertEqual(results.count("104.16.1.1"), 1)
        self.assertEqual(len(results), 3)


if __name__ == "__main__":
    unittest.main()
