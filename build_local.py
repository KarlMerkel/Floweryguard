"""Сборка локального комплекта v1.3.0; ничего не публикует и не меняет настройки."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def build_inputs(root):
    """Фиксирует исходники и ресурсы, из которых собирается исполняемый файл."""
    paths = [root / name for name in ('Flowery.spec', 'build_local.py', 'whitelist.txt', 'icon.ico', 'icon.png')]
    for folder in ('flowguard', 'Floweryguard'):
        paths.extend((root / folder).glob('*.py'))
    paths.extend(root / 'packaging' / name for name in
                 ('config.ini', 'network_profiles.json', 'hosts.txt', 'version_info.txt'))
    paths.extend(path for path in (root / 'zapret_bin').iterdir()
                 if path.suffix.lower() in ('.exe', '.dll', '.sys', '.bin'))
    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(paths)}


def main():
    root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package-dir', type=Path, help='Отдельная папка комплекта, если прежний EXE запущен')
    args = parser.parse_args()
    dist = root / 'dist'
    package = (args.package_dir or dist / 'Flowery-v1.3.0-portable').resolve()
    env = os.environ.copy()
    env['FLOWERY_HOME'] = str(root / 'build/user-data')
    env['PYTHONIOENCODING'] = 'utf-8'
    inputs = build_inputs(root)
    result = subprocess.run(
        [sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean',
         '--distpath', str(dist), '--workpath', str(root / 'build'), str(root / 'Flowery.spec')],
        cwd=root, env=env,
    )
    if result.returncode:
        return result.returncode
    if inputs != build_inputs(root):
        raise RuntimeError('Исходники изменились во время сборки. Повторите сборку.')

    package.mkdir(parents=True, exist_ok=True)
    shutil.copy2(dist / 'Flowery.exe', package / 'Flowery.exe')
    for name in ('start.bat', 'menu.bat', 'test.bat', 'README.md', 'whitelist.txt'):
        shutil.copy2(root / name, package / name)
    # При повторной сборке сохраняем параметры уже протестированного комплекта.
    for name in ('config.ini', 'network_profiles.json', 'hosts.txt'):
        if not (package / name).exists():
            shutil.copy2(root / 'packaging' / name, package / name)
    digest = hashlib.sha256((package / 'Flowery.exe').read_bytes()).hexdigest()
    import PyInstaller
    info = json.dumps({'version': '1.3.0', 'exe_sha256': digest,
                       'python': sys.version, 'pyinstaller': PyInstaller.__version__,
                       'inputs': inputs}, indent=2, ensure_ascii=False) + '\n'
    for target in (dist, package):
        (target / 'BUILD_INFO.json').write_text(info, encoding='utf-8')
    (package / 'SHA256SUMS.txt').write_text(digest + '  Flowery.exe\n', encoding='utf-8')
    print('Локальный комплект: ' + str(package))
    print('SHA-256 Flowery.exe: ' + digest)
    return 0


if __name__ == '__main__':
    sys.exit(main())
