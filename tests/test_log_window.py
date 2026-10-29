"""Отдельный просмотр журнала не запускает службы и не блокирует меню."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from flowguard import log_viewer


class LogWindowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'журнал с пробелами.log'
        self.path.write_text('старое\nначало\n', encoding='utf-8')

    def test_tail_shows_history_once_and_follows_append(self):
        with log_viewer.LogTail(self.path, history_lines=1) as tail:
            self.assertEqual(tail.read_updates(), 'начало\n')
            self.assertEqual(tail.read_updates(), '')
            with self.path.open('ab') as stream:
                stream.write('новое\n'.encode('utf-8'))
            self.assertEqual(tail.read_updates(), 'новое\n')

    def test_large_file_starts_at_recent_lines_without_control_sequences(self):
        self.path.write_bytes(b'old\n' * 100000 + b'\x1b[31mrecent\x00\n')
        with log_viewer.LogTail(self.path, history_lines=2) as tail:
            self.assertEqual(tail.read_updates(), 'old\nrecent\n')

    def test_closed_viewer_can_be_opened_again(self):
        previous = Mock()
        previous.poll.return_value = 0
        with patch.object(log_viewer, '_window_process', previous), \
                patch.object(log_viewer.sys, 'platform', 'win32'), \
                patch('subprocess.Popen') as launch:
            self.assertTrue(log_viewer.open_log_window(str(self.path)))
        launch.assert_called_once()

    def test_split_utf8_and_truncation(self):
        self.path.write_bytes(b'')
        with log_viewer.LogTail(self.path) as tail:
            tail.read_updates()
            with self.path.open('ab') as stream:
                stream.write(b'\xd0')
            self.assertEqual(tail.read_updates(), '')
            with self.path.open('ab') as stream:
                stream.write(b'\x96\n')
            self.assertEqual(tail.read_updates(), 'Ж\n')
            self.path.write_bytes(b'x\n')
            self.assertEqual(tail.read_updates(), 'x\n')

    def test_source_window_uses_argument_list_and_reuses_process(self):
        process = Mock()
        process.poll.return_value = None
        with patch.object(log_viewer, '_window_process', None), \
                patch.object(log_viewer.sys, 'platform', 'win32'), \
                patch.object(log_viewer.sys, 'frozen', False, create=True), \
                patch('subprocess.Popen', return_value=process) as launch:
            self.assertTrue(log_viewer.open_log_window(str(self.path)))
            self.assertTrue(log_viewer.open_log_window(str(self.path)))
        launch.assert_called_once()
        args, kwargs = launch.call_args
        self.assertEqual(args[0][-1], str(self.path))
        self.assertEqual(kwargs['creationflags'], subprocess.CREATE_NEW_CONSOLE)
        self.assertFalse(kwargs.get('shell', False))

    def test_frozen_command_does_not_start_normal_application(self):
        with patch.object(log_viewer, '_window_process', None), \
                patch.object(log_viewer.sys, 'platform', 'win32'), \
                patch.object(log_viewer.sys, 'frozen', True, create=True), \
                patch('subprocess.Popen') as launch:
            log_viewer.open_log_window(str(self.path))
        self.assertEqual(launch.call_args.args[0], [sys.executable, '--log-window', str(self.path)])

    def test_viewer_entrypoint_reads_only_and_does_not_create_session(self):
        before = sorted(Path(self.temp.name).rglob('*'))
        env = dict(os.environ, FLOWERY_HOME=self.temp.name, PYTHONIOENCODING='utf-8')
        result = subprocess.run([sys.executable, str(Path('flowguard/main.py').resolve()),
                                 '--log-window', str(self.path), '--once'],
                                capture_output=True, env=env, timeout=10,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        self.assertEqual(result.returncode, 0, result.stderr.decode('utf-8', errors='replace'))
        self.assertIn('начало', result.stdout.decode('utf-8'))
        self.assertEqual(sorted(Path(self.temp.name).rglob('*')), before)

    def test_start_failure_is_returned_to_menu(self):
        with patch.object(log_viewer, '_window_process', None), \
                patch.object(log_viewer.sys, 'platform', 'win32'), \
                patch('subprocess.Popen', side_effect=OSError('blocked')):
            self.assertFalse(log_viewer.open_log_window(str(self.path)))
