"""Неудачная загрузка списка не должна повреждать действующую базу."""
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from flowguard.domain_list import fetch_domains, save_domains


class DomainListTests(unittest.TestCase):
    def test_download_validates_and_normalizes_domains(self):
        with patch('urllib.request.urlopen', return_value=io.BytesIO(b'# list\nExample.COM\n*.cdn.example.com\n')):
            self.assertEqual(fetch_domains('https://example.com/list.txt'), {'example.com', 'cdn.example.com'})

    def test_html_and_oversize_are_rejected(self):
        for data in (b'<html>404</html>', b'example.com\ninvalid/path', b'a' * (1048576 + 1)):
            with patch('urllib.request.urlopen', return_value=io.BytesIO(data)):
                with self.assertRaises(ValueError):
                    fetch_domains('https://example.com/list.txt')

    def test_atomic_write_keeps_old_file_on_replace_error(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'whitelist.txt'
            target.write_text('old.example\n', encoding='utf-8')
            with patch('os.replace', side_effect=PermissionError('busy')):
                with self.assertRaises(PermissionError):
                    save_domains(target, {'new.example'})
            self.assertEqual(target.read_text(encoding='utf-8'), 'old.example\n')
            self.assertEqual(sorted(p.name for p in Path(folder).iterdir()), ['whitelist.txt', 'whitelist.txt.bak'])
