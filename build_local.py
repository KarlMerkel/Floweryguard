"""Сборка локального комплекта v1.3.0; ничего не публикует и не меняет настройки."""

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys


def main():
    root = Path(__file__).resolve().parent
    dist = root / 'dist'
    package = dist / 'Flowery-v1.3.0-portable'
    env = os.environ.copy()
    env['FLOWERY_HOME'] = str(root / 'build/user-data')
    env['PYTHONIOENCODING'] = 'utf-8'
    result = subprocess.run(
        [sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean',
         '--distpath', str(dist), '--workpath', str(root / 'build'), str(root / 'Flowery.spec')],
        cwd=root, env=env,
    )
    if result.returncode:
        return result.returncode

    package.mkdir(parents=True, exist_ok=True)
    shutil.copy2(dist / 'Flowery.exe', package / 'Flowery.exe')
    for name in ('start.bat', 'menu.bat', 'stop.bat', 'test.bat', 'README.md', 'whitelist.txt', 'hosts.txt'):
        shutil.copy2(root / name, package / name)
    # При повторной сборке сохраняем параметры уже протестированного комплекта.
    for name in ('config.ini', 'network_profiles.json'):
        if not (package / name).exists():
            shutil.copy2(root / 'packaging' / name, package / name)
    digest = hashlib.sha256((package / 'Flowery.exe').read_bytes()).hexdigest()
    (package / 'SHA256SUMS.txt').write_text(digest + '  Flowery.exe\n', encoding='utf-8')
    print('Локальный комплект: ' + str(package))
    print('SHA-256 Flowery.exe: ' + digest)
    return 0


if __name__ == '__main__':
    sys.exit(main())
