"""Ручные настройки сохраняются при запуске и смене сетевого профиля."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from flowguard.config import Config
from flowguard.profiles import ProfileManager


class TestProfilePrecedence(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'config.ini'
        self.manager = ProfileManager(str(self.path.with_suffix('.json')))

    def test_explicit_ini_values_survive_profile(self):
        self.path.write_text('[proxy]\nproxy_discord = false\n'
                             '[tethering]\nfix_ttl = false\ndefault_ttl = 67\n'
                             '[strategy]\ndefault_strategy = multi_split\n', encoding='utf-8')
        config = Config(str(self.path))
        self.manager.apply_profile('tethering', config)
        self.assertFalse(config.proxy_discord)
        self.assertFalse(config.fix_ttl)
        self.assertEqual(config.default_ttl, 67)
        self.assertEqual(config.default_strategy, 'multi_split')

    def test_menu_choices_survive_switch_and_restart(self):
        config = Config(str(self.path))
        self.manager.apply_profile('home_wifi', config)
        config.set_value('quic', 'block_quic', False)
        config.set_value('proxy', 'discord_voice_udp', False)
        self.assertTrue(config.save())
        for candidate in (config, Config(str(self.path))):
            self.manager.apply_profile('tethering', candidate)
            self.assertFalse(candidate.block_quic)
            self.assertFalse(candidate.discord_voice_udp)

    def test_profile_supplies_missing_settings_without_persisting_them(self):
        config = Config(str(self.path))
        self.manager.apply_profile('clean_gaming', config)
        self.assertEqual(config.default_strategy, 'tcp_split_sni_mid')
        self.assertTrue(config.save())
        self.assertNotIn('default_strategy', self.path.read_text(encoding='utf-8'))

    def test_switch_discards_settings_absent_from_new_profile(self):
        self.manager.custom_profiles['temporary'] = {
            'settings': {'fragment_delay': 0.5, 'tcp_split': False}}
        config = Config(str(self.path))
        self.manager.apply_profile('temporary', config)
        self.assertEqual(config.fragment_delay, 0.5)
        self.assertFalse(config.tcp_split)
        self.manager.apply_profile('home_wifi', config)
        self.assertEqual(config.fragment_delay, 0.001)
        self.assertTrue(config.tcp_split)

    def test_command_line_override_survives_profile_change(self):
        config = Config(str(self.path))
        config.set_override('auto_strategy', False)
        config.set_override('default_strategy', 'multi_split')
        self.manager.apply_profile('home_wifi', config)
        self.assertFalse(config.auto_strategy)
        self.assertEqual(config.default_strategy, 'multi_split')

    def test_detector_cannot_override_user_choice(self):
        config = Config(str(self.path))
        config.set_value('fragmentation', 'fragment_delay', 0.025)
        config.apply_profile({'fragment_delay': 0.1})
        self.assertEqual(config.fragment_delay, 0.025)

    def test_desync_profile_alias_reaches_actual_setting(self):
        config = Config(str(self.path))
        self.manager.apply_profile('tethering', config)
        self.assertEqual(config.packet_desync_split_seqovl, 16)
        config.set_value('desync', 'split_seqovl', 8)
        self.manager.apply_profile('home_wifi', config)
        self.assertEqual(config.packet_desync_split_seqovl, 8)

    def test_switch_updates_tcp_policy_without_changing_voice_policy(self):
        from flowguard import main
        app = object.__new__(main.FloweryApp)
        app.config = Config(str(self.path))
        self.manager.apply_profile('home_wifi', app.config)
        app._is_active = True
        app.proxy_server = Mock()
        app.proxy_mgr = Mock()
        app.tray_icon = Mock()
        app.voice_helper = Mock(tcp_fooling='none', fooling='none')
        app.voice_helper.is_running.return_value = False
        with patch.object(main, 'is_admin', return_value=False):
            app._on_profile_switched('home_wifi', 'Домашняя сеть', 'test-network')
        self.assertEqual(app.voice_helper.tcp_fooling, 'badsum')
        self.assertEqual(app.voice_helper.fooling, 'none')
