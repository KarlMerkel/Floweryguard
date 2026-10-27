"""Импорт модулей не должен перенастраивать консоль вызывающего процесса."""

import subprocess
import sys
import unittest


class TestImportSafety(unittest.TestCase):
    def test_main_import_preserves_error_stream_and_console(self):
        code = '''
import sys
from unittest.mock import patch, MagicMock
stderr, excepthook = sys.stderr, sys.excepthook
kernel, user = MagicMock(), MagicMock()
with patch("ctypes.windll.kernel32", kernel), patch("ctypes.windll.user32", user):
    import flowguard.main
    assert sys.stderr is stderr, "Импорт заменил stderr"
    assert sys.excepthook is excepthook, "Импорт заменил обработчик исключений"
    kernel.SetConsoleTitleW.assert_not_called()
    user.LoadImageW.assert_not_called()
'''
        result = subprocess.run([sys.executable, "-c", code], capture_output=True,
                                text=True, encoding="utf-8", timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
