"""Восстановление исходных параметров без вмешательства в настройки компьютера."""

import threading
import unittest
from unittest.mock import MagicMock, patch

from flowguard.system_proxy import SystemProxyManager
from flowguard.dns_config import DNSManager
from flowguard.ttl_fix import TTLManager
from flowguard.main import FloweryApp


class TestSettingsRestore(unittest.TestCase):
    def test_repeated_proxy_enable_preserves_original(self):
        manager = SystemProxyManager()
        manager.get_current_settings = MagicMock(side_effect=[
            (1, 'proxy.example:8080', '<local>'),
            (1, manager.proxy_address, manager.proxy_override),
        ])
        with patch('flowguard.system_proxy.winreg'), patch('flowguard.system_proxy.refresh_system_proxy_settings'):
            self.assertTrue(manager.enable())
            self.assertTrue(manager.enable())
        self.assertEqual((manager.original_enable, manager.original_server, manager.original_override),
                         (1, 'proxy.example:8080', '<local>'))

    def test_repeated_ttl_apply_preserves_original(self):
        manager = TTLManager(enable_timestamps=False)
        manager.get_current_ttl = MagicMock(side_effect=[(128, None), (65, 65)])
        with patch('flowguard.ttl_fix.is_admin', return_value=True), patch('flowguard.ttl_fix.winreg'):
            self.assertTrue(manager.apply_ttl())
            self.assertTrue(manager.apply_ttl())
        self.assertEqual((manager.original_ttl_v4, manager.original_ttl_v6), (128, None))

    def test_dns_restore_without_changes_does_not_reset_adapters(self):
        manager = DNSManager()
        with patch('flowguard.dns_config.is_admin', return_value=True), \
             patch.object(manager, '_load_backup_file', return_value=False), \
             patch.object(manager, 'get_active_interfaces', return_value=['Ethernet']), \
             patch('flowguard.dns_config.subprocess.run') as run, \
             patch('flowguard.dns_config.os.remove'):
            self.assertTrue(manager.restore_dns())
        run.assert_not_called()

    def test_cleanup_restores_proxy_once_without_forced_reset(self):
        app = object.__new__(FloweryApp)
        app._cleanup_lock = threading.Lock()
        app._cleaned_up = False
        app._is_active = True
        app._timer_period_active = False
        for name in ('proxy_mgr', 'power_watchdog', 'tray_icon', 'profile_mgr', 'proxy_server',
                     'voice_helper', 'quic_blocker', 'ttl_mgr', 'mtu_mgr', 'dns_mgr', 'config'):
            setattr(app, name, MagicMock())
        app.config.auto_system_proxy = True
        app.config.enable_custom_dns = False
        app.dns_mgr._changed_adapters = []
        with patch('flowguard.main.is_admin', return_value=False), \
             patch('flowguard.main.release_single_instance_mutex'):
            app.cleanup()
        app.proxy_mgr.disable.assert_called_once_with()
