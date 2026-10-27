# -*- mode: python ; coding: utf-8 -*-
"""Локальная сборка из основного пакета без пользовательских данных."""
from pathlib import Path

root = Path(SPECPATH)
modules = ['flowguard.' + path.stem for path in (root / 'flowguard').glob('*.py')
           if path.stem != '__init__']
assets = [(str(root / name), '.') for name in ('whitelist.txt', 'icon.ico', 'icon.png')]
assets += [(str(root / 'packaging' / name), '.') for name in ('config.ini', 'network_profiles.json', 'hosts.txt')]
assets += [(str(path), 'zapret_bin') for path in (root / 'zapret_bin').iterdir()
           if path.suffix.lower() in ('.exe', '.dll', '.sys', '.bin')]

a = Analysis(
    [str(root / 'flowguard/main.py')],
    pathex=[str(root)], binaries=[], datas=assets,
    hiddenimports=['flowguard', 'Floweryguard'] + modules,
    hookspath=[], hooksconfig={}, runtime_hooks=[],
    excludes=[], noarchive=False, optimize=0,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name='Flowery', debug=False, bootloader_ignore_signals=False,
    strip=False, upx=False, console=True,
    # Повышение прав выполняется приложением только для режимов, которым оно нужно.
    uac_admin=False, icon=str(root / 'icon.ico'),
    version=str(root / 'packaging/version_info.txt'),
)
