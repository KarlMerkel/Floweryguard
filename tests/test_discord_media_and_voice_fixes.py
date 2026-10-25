"""Тесты для проверки исправлений Discord Media (загрузка картинок) и Discord Voice (микрофон)."""

import unittest
from unittest.mock import patch, MagicMock
import os
import time

from flowguard.config import Config
from flowguard.strategy import ThompsonStrategySelector
from flowguard.proxy import DPIBypassProxy
from flowguard.voice_helper import VoiceHelper


class TestDiscordMediaAndVoiceFixes(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.selector = ThompsonStrategySelector(scores_file="test_discord_scores.json")
        self.proxy = DPIBypassProxy(self.config)

    def tearDown(self):
        if os.path.exists("test_discord_scores.json"):
            try:
                os.remove("test_discord_scores.json")
            except Exception:
                pass

    def test_media_discord_selects_combo_tlsrec_tcpsplit(self):
        """cdn.discordapp.com и media.discordapp.net выбирают combo_tlsrec_tcpsplit для надежного обхода ТСПУ."""
        strat_cdn = self.selector.select_strategy("cdn.discordapp.com")
        self.assertEqual(strat_cdn, "combo_tlsrec_tcpsplit")

        strat_media = self.selector.select_strategy("media.discordapp.net")
        self.assertEqual(strat_media, "combo_tlsrec_tcpsplit")

        strat_img = self.selector.select_strategy("images-ext-1.discordapp.net")
        self.assertEqual(strat_img, "combo_tlsrec_tcpsplit")

        scores = self.selector.get_scores_for_key("cdn.discordapp.com")
        self.assertIsNotNone(scores)
        self.assertEqual(scores["combo_tlsrec_tcpsplit"], [12.0, 1.0])

    def test_core_discord_forces_combo_tlsrec_tcpsplit(self):
        """discord.com и gateway.discord.gg жестко фиксируют стратегию combo_tlsrec_tcpsplit."""
        strat_core = self.selector.select_strategy("discord.com")
        self.assertEqual(strat_core, "combo_tlsrec_tcpsplit")

        strat_gw = self.selector.select_strategy("gateway.discord.gg")
        self.assertEqual(strat_gw, "combo_tlsrec_tcpsplit")

    def test_discord_media_stall_detection_records_failure(self):
        """Если соединение cdn.discordapp.com зависает без ответа сервера (0 байт) и клиент
        закрывает сокет после ожидания, фиксируется record_failure.
        """
        self.proxy.is_running = True
        client_sock = MagicMock()
        target_sock = MagicMock()
        target_ip = "162.159.135.233"
        target_sock.getpeername.return_value = (target_ip, 443)

        client_sock.recv.side_effect = [b"GET /attachments/123/img.png HTTP/1.1\r\n\r\n", b""]
        target_sock.recv.side_effect = [b""]  # 0 байт - полный дроп ТСПУ

        call_cnt = [0]
        def fake_select(r, w, x, timeout):
            call_cnt[0] += 1
            if call_cnt[0] == 1:
                return ([client_sock], [], [])
            elif call_cnt[0] == 2:
                return ([], [], [])
            elif call_cnt[0] == 3:
                return ([client_sock], [], [])
            return ([], [], [])

        with patch("select.select", side_effect=fake_select), \
             patch.object(self.proxy.strategy_engine, "record_success") as mock_success, \
             patch.object(self.proxy.strategy_engine, "record_failure") as mock_failure:

            self.proxy._pipe_sockets(
                client_sock,
                target_sock,
                host="cdn.discordapp.com",
                strategy="combo_tlsrec_tcpsplit"
            )

            mock_failure.assert_called_with("cdn.discordapp.com", "combo_tlsrec_tcpsplit", ip=target_ip, is_tspu=False)
            mock_success.assert_not_called()

    def test_voice_helper_uses_active_discord_udp(self):
        """VoiceHelper использует ACTIVE_DISCORD_UDP.bin для предотвращения ошибки NO_ROUTE (SSRC mismatch)."""
        vh = VoiceHelper(autottl=True, autottl_delta=2, repeats=2)
        args = vh.build_winws_args()

        self.assertTrue(vh.fake_discord.endswith("ACTIVE_DISCORD_UDP.bin"))
        self.assertTrue(vh.fake_stun.endswith("stun.bin") or vh.fake_stun.endswith("ACTIVE_DISCORD_UDP.bin"))
        self.assertIn(f"--dpi-desync-fake-discord={vh.fake_discord}", args)
        self.assertIn("--dpi-desync-autottl=2", args)
        self.assertIn("--dpi-desync-repeats=2", args)


if __name__ == "__main__":
    unittest.main()
