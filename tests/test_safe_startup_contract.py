"""Занятый порт и повторный запуск не дают права завершать чужие процессы."""

from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from flowguard.proxy import DPIBypassProxy


class TestSafeStartup(unittest.TestCase):
    def test_bind_failure_never_reclaims_another_process(self):
        proxy = object.__new__(DPIBypassProxy)
        proxy.host = '127.0.0.1'
        proxy.port = 8118
        error = OSError('занято')
        error.winerror = 10048
        sock = Mock()
        sock.bind.side_effect = error
        proxy._reclaim_port = Mock()
        with patch('flowguard.proxy.socket.socket', return_value=sock):
            with self.assertRaises(OSError):
                proxy.start()
        proxy._reclaim_port.assert_not_called()
        sock.close.assert_called_once()
        self.assertIsNone(proxy.server_sock)

    def test_startup_batches_do_not_kill_or_reset_proxy(self):
        for directory in (Path('.'), Path('Flowery_Release')):
            for filename in ('start.bat', 'menu.bat'):
                with self.subTest(path=directory / filename):
                    source = (directory / filename).read_text(encoding='utf-8').lower()
                    self.assertNotIn('taskkill', source)
                    self.assertNotIn('/v proxyenable', source)

    def test_main_does_not_kill_previous_instance(self):
        source = Path('flowguard/main.py').read_text(encoding='utf-8')
        self.assertNotIn('["taskkill"', source)
