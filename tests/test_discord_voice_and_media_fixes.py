"""Unit tests for Discord voice outgoing audio (WebRTC Opus unknown L7) and media/GIF fixes."""

import os
import unittest
from unittest.mock import MagicMock, patch

from flowguard.config import Config
from flowguard.proxy import (
    DPIBypassProxy,
    is_discord_media_host,
    DISCORD_CLOUDFLARE_ANYCAST_IPS,
    DISCORD_CDN_ANYCAST_IPS,
    DISCORD_MEDIA_ANYCAST_IPS,
)
from flowguard.voice_helper import (
    VoiceHelper,
    is_winws_tcp_filtering_active,
)


class TestDiscordVoiceAndMediaFixes(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.proxy = DPIBypassProxy(self.config)

    def test_voice_helper_webrtc_unknown_protocol_desync(self):
        """VoiceHelper обязан десинхронизировать WebRTC Opus (L7 unknown) с fake_unknown_udp, any-protocol=1 и cutoff=n4."""
        vh = VoiceHelper()
        args = vh.build_winws_args()

        self.assertIn("--filter-l7=discord,stun,unknown", args)
        self.assertIn("--dpi-desync-any-protocol=1", args)
        self.assertIn("--dpi-desync-cutoff=n4", args)
        self.assertTrue(any(a.startswith("--dpi-desync-fake-unknown-udp=") for a in args))
        self.assertIn("--dpi-desync-repeats=6", args)
        # В UDP Discord Voice autottl строго исключен
        self.assertFalse(any("--dpi-desync-autottl" in a for a in args))

    def test_winws_tcp_filtering_uac_windivert_fallback(self):
        """Когда UAC блокирует чтение командной строки winws.exe, проверяется статус службы WinDivert."""
        ext_vh = VoiceHelper(mode="proxy")
        ext_vh.managed_by_us = False

        with patch("flowguard.voice_helper.is_system_winws_running", return_value=True), \
             patch("flowguard.voice_helper.get_winws_command_lines", return_value=[]), \
             patch("flowguard.voice_helper.is_windivert_driver_running", return_value=True):
            self.assertTrue(is_winws_tcp_filtering_active(voice_helper=ext_vh, force_refresh=True))

        with patch("flowguard.voice_helper.is_system_winws_running", return_value=True), \
             patch("flowguard.voice_helper.get_winws_command_lines", return_value=[]), \
             patch("flowguard.voice_helper.is_windivert_driver_running", return_value=False):
            self.assertFalse(is_winws_tcp_filtering_active(voice_helper=ext_vh, force_refresh=True))

    def test_anycast_ip_pools_prioritize_unthrottled_subnets(self):
        """Не замедляемые в РФ подсети (128, 129, 130, 136) должны стоять во главе пулов перед 134 и 135."""
        head_expected = ["162.159.128.232", "162.159.129.232", "162.159.130.232", "162.159.136.232"]

        # Проверка DISCORD_CDN_ANYCAST_IPS
        self.assertEqual(DISCORD_CDN_ANYCAST_IPS[:4], head_expected)

        # Проверка DISCORD_MEDIA_ANYCAST_IPS
        self.assertEqual(DISCORD_MEDIA_ANYCAST_IPS[:4], head_expected)

        # Проверка DISCORD_CLOUDFLARE_ANYCAST_IPS
        self.assertEqual(DISCORD_CLOUDFLARE_ANYCAST_IPS[:4], head_expected)

        # 134.x и 135.x должны идти строго ПОСЛЕ head_expected
        for pool in (DISCORD_CDN_ANYCAST_IPS, DISCORD_MEDIA_ANYCAST_IPS, DISCORD_CLOUDFLARE_ANYCAST_IPS):
            for ip in pool:
                if "162.159.134." in ip or "162.159.135." in ip:
                    self.assertGreaterEqual(pool.index(ip), 4)

    def test_discord_media_hosts_select_media_pools(self):
        """Хосты Discord media и аватарок (cdn, media, images-ext, attachments) направляются в Anycast пулы."""
        media_hosts = [
            "cdn.discordapp.com",
            "media.discordapp.net",
            "attachments.discord.net",
            "images-ext-1.discordapp.net",
            "dl.discordapp.net",
        ]
        for h in media_hosts:
            self.assertTrue(is_discord_media_host(h))

    def test_whitelist_contains_all_gif_domains(self):
        """Файл whitelist.txt содержит все необходимые домены Tenor и Giphy (включая media0-media4)."""
        whitelist_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "whitelist.txt")
        with open(whitelist_path, "r", encoding="utf-8") as f:
            lines = {line.strip() for line in f if line.strip() and not line.startswith("#")}

        required_gif = [
            "tenor.com",
            "*.tenor.com",
            "c.tenor.com",
            "media.tenor.com",
            "api.tenor.com",
            "t.tenor.com",
            "tenor.googleapis.com",
            "giphy.com",
            "*.giphy.com",
            "media.giphy.com",
            "media0.giphy.com",
            "media1.giphy.com",
            "media2.giphy.com",
            "media3.giphy.com",
            "media4.giphy.com",
        ]
        for domain in required_gif:
            self.assertIn(domain, lines, f"Domain {domain} must be in whitelist.txt")

    def test_is_windivert_driver_running_localization(self):
        """Проверка распознавания статуса службы WinDivert при различных локалях (RUNNING, РАБОТАЕТ, код 4)."""
        from flowguard.voice_helper import is_windivert_driver_running

        with patch("sys.platform", "win32"), \
             patch("subprocess.check_output", return_value=b"STATE : 4  RUNNING"):
            self.assertTrue(is_windivert_driver_running())

        with patch("sys.platform", "win32"), \
             patch("subprocess.check_output", return_value="СОСТОЯНИЕ : 4  РАБОТАЕТ".encode("utf-8")):
            self.assertTrue(is_windivert_driver_running())

        with patch("sys.platform", "win32"), \
             patch("subprocess.check_output", return_value=b"STATE : 1  STOPPED"):
            self.assertFalse(is_windivert_driver_running())

    def test_release_whitelist_contains_all_gif_domains(self):
        """Flowery_Release/whitelist.txt также содержит все необходимые домены Tenor и Giphy."""
        release_whitelist_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Flowery_Release", "whitelist.txt"
        )
        with open(release_whitelist_path, "r", encoding="utf-8") as f:
            lines = {line.strip() for line in f if line.strip() and not line.startswith("#")}

        required_gif = [
            "tenor.com",
            "*.tenor.com",
            "c.tenor.com",
            "media.tenor.com",
            "api.tenor.com",
            "t.tenor.com",
            "tenor.googleapis.com",
            "giphy.com",
            "*.giphy.com",
            "media.giphy.com",
            "media0.giphy.com",
            "media1.giphy.com",
            "media2.giphy.com",
            "media3.giphy.com",
            "media4.giphy.com",
        ]
        for domain in required_gif:
            self.assertIn(domain, lines, f"Domain {domain} must be in Flowery_Release/whitelist.txt")


if __name__ == "__main__":
    unittest.main()
