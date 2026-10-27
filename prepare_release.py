"""Создаёт чистые локальные ZIP-комплекты и проверяет их; ничего не публикует."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import zipfile

VERSION = '1.3.0'
USER_FILES = {'strategy_scores.json', 'strategy_overrides.json', 'dns_snapshot.json',
              'mtu_snapshot.json', '.env'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def validate_name(name):
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or '..' in path.parts or '\\' in name or ':' in name
            or path.as_posix() != name or path.name in USER_FILES
            or path.suffix in ('.log', '.pyc') or '__pycache__' in path.parts
            or any(part in ('.git', '.agents', 'logs', 'scratch') for part in path.parts)):
        raise ValueError('Недопустимый файл комплекта: ' + name)


def collect_portable(root, executable):
    root, executable = Path(root), Path(executable)
    files = {'Flowery.exe': executable.read_bytes()}
    for name in ('start.bat', 'menu.bat', 'test.bat', 'whitelist.txt', 'LICENSE'):
        files[name] = (root / name).read_bytes()
    for name in ('config.ini', 'network_profiles.json', 'hosts.txt', 'RELEASE_NOTES.md', 'THIRD_PARTY.md'):
        files[name] = (root / 'packaging' / name).read_bytes()
    files['README.md'] = (root / 'packaging/PORTABLE_README.md').read_bytes()
    for path in (root / 'packaging/licenses').glob('*.txt'):
        files['licenses/' + path.name] = path.read_bytes()
    info = executable.with_name('BUILD_INFO.json')
    if info.exists():
        files['BUILD_INFO.json'] = info.read_bytes()
    return files


def collect_source(root):
    files = {}
    folders = {
        'flowguard': {'.py'}, 'Floweryguard': {'.py'}, 'tests': {'.py'},
        'Flowery_Release/flowguard': {'.py'}, 'Flowery_Release/Floweryguard': {'.py'},
        'packaging': {'.ini', '.json', '.txt', '.md'},
        'relay': {'.js', '.mjs', '.md'}, 'zapret_bin': {'.exe', '.dll', '.sys', '.bin'},
    }
    for folder, suffixes in folders.items():
        for path in sorted((root / folder).rglob('*')):
            if path.is_file() and path.suffix.lower() in suffixes:
                if path.is_symlink():
                    raise ValueError('Символическая ссылка в исходниках: ' + str(path))
                files[path.relative_to(root).as_posix()] = path.read_bytes()
    for name in ('README.md', 'LICENSE', 'Flowery.spec', 'build_local.py', 'prepare_release.py',
                 'icon.ico', 'icon.png', 'start.bat', 'menu.bat', 'test.bat', 'stop.bat', 'whitelist.txt'):
        files[name] = (root / name).read_bytes()
    for name in ('config.ini', 'network_profiles.json', 'hosts.txt'):
        files[name] = (root / 'packaging' / name).read_bytes()
        files['Flowery_Release/' + name] = files[name]
    for name in ('start.bat', 'menu.bat', 'test.bat', 'stop.bat', 'whitelist.txt'):
        files['Flowery_Release/' + name] = files[name]
    for name in ('RELEASE_NOTES.md', 'THIRD_PARTY.md'):
        files[name] = (root / 'packaging' / name).read_bytes()
    return files


def write_bundle(output, name, files, revision, kind):
    validate_name(name)
    if '/' in name:
        raise ValueError('Имя комплекта должно состоять из одного компонента')
    for relative in files:
        validate_name(relative)
        if relative in ('manifest.json', 'SHA256SUMS.txt'):
            raise ValueError('Служебное имя комплекта: ' + relative)
    manifest = {'version': VERSION, 'kind': kind, 'source_commit': revision,
                'status': 'local-candidate', 'files': {
                    path: {'sha256': digest(data), 'size': len(data)}
                    for path, data in sorted(files.items())}}
    payload = dict(files)
    payload['manifest.json'] = (json.dumps(manifest, indent=2, ensure_ascii=False) + '\n').encode('utf-8')
    payload['SHA256SUMS.txt'] = ''.join(
        digest(data) + '  ' + path + '\n' for path, data in sorted(payload.items())).encode('utf-8')
    archive = Path(output) / (name + '.zip')
    with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for path, data in sorted(payload.items()):
            info = zipfile.ZipInfo(name + '/' + path, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            bundle.writestr(info, data)
    verify_bundle(archive)
    return archive


def verify_bundle(archive):
    with zipfile.ZipFile(archive) as bundle:
        names = bundle.namelist()
        if not names or len(names) != len(set(names)):
            raise ValueError('Пустой архив или повторяющиеся записи')
        for name in names:
            validate_name(name)
        roots = {PurePosixPath(name).parts[0] for name in names}
        if len(roots) != 1:
            raise ValueError('У архива должен быть один корневой каталог')
        prefix = roots.pop() + '/'
        manifest = json.loads(bundle.read(prefix + 'manifest.json'))
        expected = set(manifest['files']) | {'manifest.json', 'SHA256SUMS.txt'}
        if {name[len(prefix):] for name in names} != expected:
            raise ValueError('Состав архива не соответствует манифесту')
        for path, metadata in manifest['files'].items():
            data = bundle.read(prefix + path)
            if len(data) != metadata['size'] or digest(data) != metadata['sha256']:
                raise ValueError('Не совпала контрольная сумма: ' + path)
        sums = ''.join(digest(bundle.read(prefix + path)) + '  ' + path + '\n'
                       for path in sorted(expected - {'SHA256SUMS.txt'}))
        if bundle.read(prefix + 'SHA256SUMS.txt') != sums.encode('utf-8'):
            raise ValueError('Не совпал файл контрольных сумм')
        return manifest


def verify_build(root, executable):
    info = json.loads(executable.with_name('BUILD_INFO.json').read_text(encoding='utf-8'))
    if info['version'] != VERSION or info['exe_sha256'] != digest(executable.read_bytes()):
        raise ValueError('EXE не соответствует сведениям о сборке')
    for path, checksum in info['inputs'].items():
        validate_name(path)
        if digest((root / path).read_bytes()) != checksum:
            raise ValueError('Исходник изменился после сборки: ' + path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exe', type=Path, default=Path('dist/Flowery.exe'))
    parser.add_argument('--output', type=Path)
    parser.add_argument('--verify', type=Path, help='Проверить существующий архив')
    args = parser.parse_args()
    if args.verify:
        manifest = verify_bundle(args.verify)
        print('Архив проверен, файлов: ' + str(len(manifest['files'])))
        return 0
    root = Path(__file__).resolve().parent
    executable = args.exe.resolve()
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    verify_build(root, executable)
    output = (args.output or root / 'dist/release-candidate' / revision[:12]).resolve()
    output.mkdir(parents=True, exist_ok=False)
    archives = []
    for kind, files in (('windows-x64', collect_portable(root, executable)), ('source', collect_source(root))):
        archive = write_bundle(output, 'Flowery-v' + VERSION + '-' + kind, files, revision, kind)
        archives.append({'file': archive.name, 'sha256': digest(archive.read_bytes()), 'size': archive.stat().st_size})
    (output / 'SHA256SUMS.txt').write_text(''.join(r['sha256'] + '  ' + r['file'] + '\n' for r in archives), encoding='utf-8')
    (output / 'release_manifest.json').write_text(json.dumps({
        'version': VERSION, 'source_commit': revision, 'published': False,
        'archives': archives}, indent=2) + '\n', encoding='utf-8')
    print('Подготовлены локальные архивы: ' + str(output))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
