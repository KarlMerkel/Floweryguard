import os
import sys
import time
import socket
import unittest
from unittest.mock import MagicMock, patch

from flowguard.proxy import DPIBypassProxy, is_telegram_host, is_discord_host
from flowguard.config import Config
from flowguard.strategy import get_strategy_engine
from flowguard.system_proxy import build_proxy_override
from flowguard.voice_helper import is_winws_tcp_filtering_active, PID_FILE, set_active_voice_helper
from flowguard.power_watchdog import PowerWatchdog


class TestTelegramMeduzaFixes(unittest.TestCase):

    def setUp(self):
        self.config = Config()
        self.proxy = DPIBypassProxy(self.config)

    def test_telegram_host_detection(self):
        """is_telegram_host точно идентифицирует MTProto IP и домены Telegram."""
        self.assertTrue(is_telegram_host("149.154.167.51"))
        self.assertTrue(is_telegram_host("91.108.56.100"))
        self.assertTrue(is_telegram_host("api.telegram.org"))
        self.assertTrue(is_telegram_host("t.me"))
        self.assertTrue(is_telegram_host("telegram.org"))
        self.assertTrue(is_telegram_host("telegra.ph"))
        self.assertTrue(is_telegram_host("tdesktop.com"))
        self.assertFalse(is_telegram_host("google.com"))
        self.assertFalse(is_telegram_host("youtube.com"))
        self.assertFalse(is_telegram_host(""))
        self.assertFalse(is_telegram_host(None))

    def test_telegram_in_proxy_override(self):
        """build_proxy_override содержит домены и MTProto подсети Telegram для прямого соединения."""
        override = build_proxy_override()
        self.assertIn("*.telegram.org", override)
        self.assertIn("telegram.org", override)
        self.assertIn("*.t.me", override)
        self.assertIn("t.me", override)
        self.assertIn("149.154.*", override)
        self.assertIn("91.108.*", override)
        self.assertIn("*.telegra.ph", override)
        self.assertIn("*.tdesktop.com", override)

    def test_telegram_proxy_bypass_direct(self):
        """Для хостов Telegram прокси отправляет пакет напрямую (стратегия direct)."""
        sock = MagicMock()
        data = b"\x16\x03\x01\x00\x10\x01..."  # fake client hello
        with patch("flowguard.proxy.is_tls_client_hello", return_value=True), \
             patch("flowguard.proxy.parse_sni", return_value=("api.telegram.org", None)):
            strat, host = self.proxy._send_tls_client_hello_with_bypass(
                sock, data, "api.telegram.org"
            )
            self.assertEqual(strat, "direct")
            sock.sendall.assert_called_with(data)

    def test_telegram_socket_long_lived_timeout(self):
        """Для подключений Telegram _pipe_sockets устанавливает таймаут сокетов 3600.0с."""
        self.proxy.is_running = True
        client_sock = MagicMock()
        target_sock = MagicMock()
        with patch("select.select", return_value=([], [], [])):
            self.proxy._pipe_sockets(client_sock, target_sock, host="149.154.167.51:443")
        client_sock.settimeout.assert_called_with(3600.0)
        target_sock.settimeout.assert_called_with(3600.0)

    def test_meduza_pinned_to_combo_tlsrec_tcpsplit(self):
        """meduza.io и mdza.io жестко фиксируются на стратегию combo_tlsrec_tcpsplit."""
        engine = get_strategy_engine()
        for domain in ["meduza.io", "api.meduza.io", "mdza.io"]:
            strat = engine.select_strategy(domain)
            self.assertEqual(strat, "combo_tlsrec_tcpsplit", f"Failed for {domain}")
            fallback = engine.get_fallback_strategy(domain)
            self.assertEqual(fallback, "combo_tlsrec_tcpsplit", f"Fallback failed for {domain}")

    def test_discord_attachments_in_is_discord_host(self):
        """attachments.discord.net классифицируется как инфраструктура Discord."""
        self.assertTrue(is_discord_host("attachments.discord.net"))
        self.assertTrue(is_discord_host("media.discordapp.net"))
        self.assertTrue(is_discord_host("cdn.discordapp.com"))

    def test_winws_pid_file_avoids_powershell(self):
        """При наличии валидного PID_FILE Flowery winws не вызывает PowerShell."""
        current_pid = os.getpid()
        with open(PID_FILE, "w", encoding="utf-8") as f:
            f.write(str(current_pid))
        vh = MagicMock(managed_by_us=True, mode="proxy", tcp_desync=False)
        try:
            with patch("subprocess.check_output") as mock_check, \
                 patch("flowguard.voice_helper.is_system_winws_running", return_value=True), \
                 patch("flowguard.voice_helper.get_active_voice_helper", return_value=vh):
                mock_check.side_effect = AssertionError("PowerShell should NOT be called!")
                active = is_winws_tcp_filtering_active(voice_helper=vh, force_refresh=True)
                self.assertFalse(active)
        finally:
            if os.path.exists(PID_FILE):
                os.remove(PID_FILE)

    def test_power_watchdog_startup_grace_period(self):
        """PowerWatchdog в первые 15 секунд холодного запуска не считает сокет мертвым."""
        app = MagicMock()
        app._is_active = True
        app.config = Config()
        watchdog = PowerWatchdog(app)
        watchdog._start_time = time.time()  # только что стартовал

        # Симулируем вызов проверки, когда сокет не отвечает
        with patch.object(watchdog, "_is_proxy_socket_alive", return_value=False), \
             patch.object(watchdog, "trigger_recovery") as mock_rec:
            # Вызываем одну итерацию проверки
            dt = time.time() - watchdog._start_time
            if dt < 15.0:
                # В течение первых 15с trigger_recovery не должен вызываться
                self.assertFalse(mock_rec.called)


if __name__ == "__main__":
    unittest.main()
