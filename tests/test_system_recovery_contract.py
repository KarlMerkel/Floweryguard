"""Отказы системных команд не должны терять исходные настройки Windows."""

import os
import tempfile
import threading
import unittest
from unittest.mock import Mock, MagicMock, patch

from flowguard import dns_config, ttl_fix, main, power_watchdog, syscmd


class TestRecoveryContract(unittest.TestCase):
    def test_system_command_has_deadline(self):
        with patch.object(syscmd.subprocess, 'run', side_effect=syscmd.subprocess.TimeoutExpired('netsh', 10)) as run:
            self.assertIsNone(syscmd.run_command(['netsh', 'test']))
        self.assertEqual(run.call_args.kwargs['timeout'], 10)

    def test_dns_write_requires_persisted_snapshot(self):
        manager = dns_config.DNSManager()
        with patch.object(dns_config, 'is_admin', return_value=True), \
             patch.object(manager, 'test_dns_server', return_value=True), \
             patch.object(manager, 'get_active_interfaces', return_value=['Ethernet']), \
             patch.object(manager, '_get_adapter_dns_registry', return_value=['192.0.2.53']), \
             patch.object(manager, '_save_backup_file', return_value=False), \
             patch.object(dns_config, 'run_command') as run:
            self.assertFalse(manager.set_secure_dns())
        run.assert_not_called()

    def test_failed_dns_restore_can_be_retried(self):
        manager = dns_config.DNSManager()
        manager._changed_adapters = ['Ethernet']
        manager._original_dns = {'Ethernet': ['192.0.2.53']}
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(manager, '_get_backup_filepath', return_value=os.path.join(directory, 'dns.json')), \
             patch.object(dns_config, 'is_admin', return_value=True), \
             patch.object(dns_config, 'run_command', return_value=Mock(returncode=1)) as run:
            manager._save_backup_file()
            self.assertFalse(manager.restore_dns())
            self.assertEqual(manager._original_dns['Ethernet'], ['192.0.2.53'])
            run.return_value = Mock(returncode=0)
            self.assertTrue(manager.restore_dns())
            self.assertFalse(manager.has_pending_restore())

    def test_disconnected_interface_is_not_selected(self):
        with patch.object(dns_config, 'run_command', return_value=Mock(returncode=0, stdout=b'Enabled Disconnected Dedicated Ethernet\nEnabled Connected Dedicated Wi-Fi\n')):
            self.assertEqual(dns_config.DNSManager().get_active_interfaces(), ['Wi-Fi'])

    def test_mtu_timeout_still_requires_restore(self):
        manager = ttl_fix.MTUManager()
        with patch.object(ttl_fix, 'is_admin', return_value=True), \
             patch.object(manager, 'get_active_interfaces', return_value=[('Wi-Fi', 1500)]), \
             patch.object(manager, 'get_default_gateway_interfaces', return_value=['Wi-Fi']), \
             patch.object(manager, '_get_ipv6_mtu', return_value=1500), \
             patch.object(ttl_fix, 'run_command', return_value=None) as run:
            self.assertFalse(manager.apply_mtu())
            self.assertTrue(manager._applied)
            self.assertFalse(manager.restore_mtu())
            self.assertEqual(manager.original_mtus['Wi-Fi'], 1500)
            run.return_value = Mock(returncode=0)
            self.assertTrue(manager.restore_mtu())
            self.assertFalse(manager._applied)

    def test_construction_does_not_write_system_settings(self):
        with patch.multiple(main, ProfileManager=MagicMock(), TTLManager=MagicMock(), MTUManager=MagicMock(),
                            SystemProxyManager=MagicMock(), QUICBlocker=MagicMock(), DNSManager=MagicMock(),
                            DPIBypassProxy=MagicMock(), NetworkDetector=MagicMock(), VoiceHelper=MagicMock(),
                            PowerWatchdog=MagicMock(), FloweryTrayIcon=MagicMock()), \
             patch.object(main, 'is_admin', return_value=True), patch.object(main.ctypes.windll.winmm, 'timeBeginPeriod') as timer:
            main.ProfileManager.return_value.auto_detect_and_apply.return_value = ('test', 'test')
            app = main.FloweryApp()
            app.dns_mgr.restore_dns.assert_not_called()
            app.dns_mgr.heal_stale_dns.assert_not_called()
            app.dns_mgr.set_secure_dns.assert_not_called()
            app.ttl_mgr.apply_ttl.assert_not_called()
            app.proxy_mgr.force_cleanup.assert_not_called()
            timer.assert_not_called()

    def test_cleanup_retries_failed_proxy_restore(self):
        app = object.__new__(main.FloweryApp)
        app._cleanup_lock = threading.Lock()
        app._is_active = True
        app._cleaned_up = False
        app._timer_period_active = False
        for name in ('proxy_mgr', 'power_watchdog', 'tray_icon', 'profile_mgr', 'proxy_server', 'voice_helper', 'quic_blocker', 'ttl_mgr', 'mtu_mgr', 'dns_mgr', 'config'):
            setattr(app, name, Mock())
        app.proxy_mgr._is_active = True
        app.proxy_mgr.disable.side_effect = [False, True]
        app.dns_mgr.has_pending_restore.return_value = False
        with patch.object(main, 'is_admin', return_value=False), patch.object(main, 'release_single_instance_mutex'):
            self.assertFalse(app.cleanup(force=True))
            self.assertFalse(app._cleaned_up)
            self.assertTrue(app.cleanup(force=True))
        self.assertEqual(app.proxy_mgr.disable.call_count, 2)

    def test_recovery_cannot_write_after_stop(self):
        app = Mock()
        app._is_active = True
        watchdog = power_watchdog.PowerWatchdog(app)
        watchdog.stop()
        with patch.object(power_watchdog.time, 'sleep'), patch.object(power_watchdog, 'is_admin', return_value=False):
            watchdog._execute_recovery_sequence('test')
        app.proxy_mgr.ensure_active.assert_not_called()
