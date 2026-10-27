"""EXE использует настройки рядом с собой, а не в каталоге распаковки."""

import contextlib
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from flowguard import main
from flowguard.config import Config


class TestFrozenStartup(unittest.TestCase):
    def test_help_selects_executable_directory_and_external_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / 'bundle'
            executable = root / 'portable'
            (bundle / 'flowguard').mkdir(parents=True)
            executable.mkdir()
            (bundle / 'config.ini').write_text('[proxy]\nport=8118\n', encoding='utf-8')
            (executable / 'config.ini').write_text('[proxy]\nport=9191\n', encoding='utf-8')
            previous = os.getcwd()
            try:
                with patch.object(sys, 'frozen', True, create=True), \
                     patch.object(sys, '_MEIPASS', str(bundle), create=True), \
                     patch.object(sys, 'executable', str(executable / 'Flowery.exe')), \
                     patch.object(sys, 'argv', ['Flowery.exe', '--help']), \
                     patch.object(sys, 'stderr', sys.stderr), \
                     patch.object(sys, 'excepthook', sys.excepthook), \
                     patch.object(main, '__file__', str(bundle / 'flowguard/main.py')), \
                     patch.object(main, 'init_terminal'), patch.object(main, 'set_app_icon'), \
                     contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaises(SystemExit) as result:
                        main.main()
                    self.assertEqual(result.exception.code, 0)
                    self.assertEqual(Path.cwd(), executable)
                    self.assertEqual(Config().proxy_port, 9191)
            finally:
                os.chdir(previous)
