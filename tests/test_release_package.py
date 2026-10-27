"""Чистые настройки и проверяемая целостность локальных архивов выпуска."""
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from prepare_release import collect_portable, write_bundle, verify_bundle, verify_build, digest


class TestReleasePackage(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_portable_uses_templates_without_user_data(self):
        for name in ('start.bat', 'menu.bat', 'test.bat', 'whitelist.txt', 'LICENSE'):
            (self.root / name).write_text('public', encoding='utf-8')
        templates = self.root / 'packaging'
        templates.mkdir()
        for name in ('config.ini', 'hosts.txt', 'PORTABLE_README.md', 'RELEASE_NOTES.md', 'THIRD_PARTY.md'):
            (templates / name).write_text('clean', encoding='utf-8')
        (templates / 'network_profiles.json').write_text('{"network_map": {}, "custom_profiles": {}}')
        (templates / 'licenses').mkdir()
        (templates / 'licenses/vendor.txt').write_text('license')
        for name in ('config.ini', 'hosts.txt', 'network_profiles.json', 'strategy_scores.json', 'stop.bat', 'session.log'):
            (self.root / name).write_text('private-user-data', encoding='utf-8')
        exe = self.root / 'candidate.exe'
        exe.write_bytes(b'MZ-test')
        files = collect_portable(self.root, exe)
        self.assertEqual(files['config.ini'], b'clean')
        self.assertEqual(files['hosts.txt'], b'clean')
        self.assertEqual(json.loads(files['network_profiles.json'])['network_map'], {})
        self.assertEqual(files['Flowery.exe'], b'MZ-test')
        self.assertIn('licenses/vendor.txt', files)
        for name in ('strategy_scores.json', 'stop.bat', 'session.log'):
            self.assertNotIn(name, files)
        self.assertFalse(any(b'private-user-data' in data for data in files.values()))

    def test_manifest_verifies_every_payload(self):
        archive = write_bundle(self.root, 'test-bundle', {'file.txt': b'payload'}, 'abc123', 'portable')
        manifest = verify_bundle(archive)
        self.assertEqual(manifest['source_commit'], 'abc123')
        self.assertEqual(manifest['files']['file.txt']['size'], 7)
        with zipfile.ZipFile(archive) as source:
            entries = {name: source.read(name) for name in source.namelist()}
        entries['test-bundle/file.txt'] = b'tampered'
        with zipfile.ZipFile(archive, 'w') as target:
            for name, data in entries.items():
                target.writestr(name, data)
        with self.assertRaises(ValueError):
            verify_bundle(archive)

    def test_archive_rejects_unsafe_paths_and_user_state(self):
        for name in ('../escape', '/absolute', 'C:/absolute', 'folder\\escape',
                     'strategy_scores.json', 'logs/session.log'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                write_bundle(self.root, 'bad', {name: b'data'}, 'abc123', 'portable')

    def test_existing_archive_is_not_overwritten(self):
        path = write_bundle(self.root, 'existing', {'file.txt': b'original'}, 'abc123', 'portable')
        original = path.read_bytes()
        with self.assertRaises(FileExistsError):
            write_bundle(self.root, 'existing', {'file.txt': b'new'}, 'abc123', 'portable')
        self.assertEqual(path.read_bytes(), original)

    def test_build_rejects_changed_executable_or_source(self):
        exe = self.root / 'Flowery.exe'
        exe.write_bytes(b'MZ-build')
        source = self.root / 'main.py'
        source.write_bytes(b'original')
        (self.root / 'BUILD_INFO.json').write_text(json.dumps({
            'version': '1.3.0', 'exe_sha256': digest(exe.read_bytes()),
            'inputs': {'main.py': digest(source.read_bytes())},
        }), encoding='utf-8')
        verify_build(self.root, exe)
        source.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'Исходник изменился'):
            verify_build(self.root, exe)
        source.write_bytes(b'original')
        exe.write_bytes(b'MZ-other')
        with self.assertRaisesRegex(ValueError, 'EXE не соответствует'):
            verify_build(self.root, exe)
