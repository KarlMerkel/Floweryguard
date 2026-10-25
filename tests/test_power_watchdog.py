"""Unit-тесты для модуля PowerWatchdog (Flowery v1.3.0).
Проверяют детекцию спящего режима, гибернации (S4 / Modern Standby),
дебаунсинг восстановления, реанимацию сокетов и сброс кэшей.
"""

import time
import unittest
from unittest.mock import MagicMock, patch

from Floweryguard.power_watchdog import PowerWatchdog
from Floweryguard.proxy import DPIBypassProxy, _WORKING_IP_CACHE, _DEAD_IP_CACHE, _DNS_CACHE
from Floweryguard.system_proxy import SystemProxyManager
from Floweryguard.config import Config


class DummyApp:
    """Мок главного оркестратора FloweryApp."""
    def __init__(self):
        self._is_active = True
        self.config = Config()
        self.proxy_server = MagicMock()
        self.proxy_mgr = MagicMock()
        self.ttl_mgr = MagicMock()
        self.quic_blocker = MagicMock()
        self.dns_mgr = MagicMock()
        self.profile_mgr = MagicMock()
        self.profile_mgr.auto_detect_and_apply.return_value = ("Мобильная раздача", "test_fp")
        self.voice_helper = MagicMock()
        self.tray_icon = MagicMock()
        self.active_profile_name = "default"
        self.current_network_fp = "default_network"


class TestPowerWatchdog(unittest.TestCase):

    def setUp(self):
        self.app = DummyApp()
        self.watchdog = PowerWatchdog(self.app, check_interval=0.1, time_jump_threshold=0.5)

    def tearDown(self):
        self.watchdog.stop()

    def test_init_and_state(self):
        self.assertFalse(self.watchdog.is_running)
        self.assertEqual(self.watchdog.recoveries_count, 0)
        self.assertFalse(self.watchdog._in_suspend)

    def test_start_and_stop(self):
        self.watchdog.start()
        self.assertTrue(self.watchdog.is_running)
        self.assertIsNotNone(self.watchdog._thread)
        self.assertTrue(self.watchdog._thread.is_alive())
        self.watchdog.stop()
        self.assertFalse(self.watchdog.is_running)
        self.assertIsNone(self.watchdog._thread)

    def test_trigger_recovery_debouncing(self):
        """Проверка дебаунсинга: повторные вызовы в пределах кулдауна блокируются."""
        with patch.object(self.watchdog, "_execute_recovery_sequence"):
            first = self.watchdog.trigger_recovery("Test Event 1")
            self.assertTrue(first)
            self.assertEqual(self.watchdog.recoveries_count, 1)

            # Мгновенный повторный вызов должен быть отсечен кулдауном
            second = self.watchdog.trigger_recovery("Test Event 2")
            self.assertFalse(second)
            self.assertEqual(self.watchdog.recoveries_count, 1)

    def test_on_power_broadcast_suspend(self):
        """PBT_APMSUSPEND (0x0004) переводит флаг в _in_suspend и сохраняет веса."""
        # Мокаем strategy_engine
        engine_mock = MagicMock()
        self.app.proxy_server.strategy_engine = engine_mock

        self.watchdog.on_power_broadcast(0x0004)
        self.assertTrue(self.watchdog._in_suspend)
        engine_mock.save_scores.assert_called_once_with(force=True)

    def test_on_power_broadcast_resume(self):
        """PBT_APMRESUMEAUTOMATIC (0x0012) и PBT_APMRESUMESUSPEND (0x0007) запускают восстановление."""
        with patch.object(self.watchdog, "trigger_recovery") as mock_trig:
            self.watchdog.on_power_broadcast(0x0012)
            mock_trig.assert_called_with(reason="Win32 Power Event 0x0012")

            self.watchdog.on_power_broadcast(0x0007)
            mock_trig.assert_called_with(reason="Win32 Power Event 0x0007")

    def test_recovery_sequence_execution(self):
        """Проверка цепочки вызовов реанимации компонентов."""
        with patch("time.sleep"):  # Ускоряем тайминги сна в тесте
            self.watchdog._execute_recovery_sequence("Unit Test")

            # Проверка вызова методов прокси
            self.app.proxy_server.revive_if_needed.assert_called_once()
            self.app.proxy_server.flush_stale_caches.assert_called_once()

            # Проверка системного прокси
            self.app.proxy_mgr.ensure_active.assert_called_once()

            # Проверка адаптации профиля
            self.app.profile_mgr.auto_detect_and_apply.assert_called_once()

    def test_proxy_flush_stale_caches(self):
        """Проверка полного сброса кэшей IP и DNS в DPIBypassProxy."""
        cfg = Config()
        proxy = DPIBypassProxy(cfg)

        _WORKING_IP_CACHE.set("discord.com", "162.159.130.233")
        _DEAD_IP_CACHE.set("1.2.3.4", time.time() + 300)
        _DNS_CACHE.set("test.org", ["1.1.1.1"])

        self.assertIn("discord.com", _WORKING_IP_CACHE)
        self.assertIn("test.org", _DNS_CACHE)

        proxy.flush_stale_caches()

        self.assertNotIn("discord.com", _WORKING_IP_CACHE)
        self.assertNotIn("test.org", _DNS_CACHE)
        self.assertNotIn("1.2.3.4", _DEAD_IP_CACHE)


if __name__ == "__main__":
    unittest.main()
