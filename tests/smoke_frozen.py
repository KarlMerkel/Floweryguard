"""Проверка готового EXE во временной папке без включения системных настроек."""

import argparse
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile


def system_settings():
    """Снимок только чтением: значения прокси, TTL и DNS, без вывода адресов."""
    if os.name != 'nt':
        return {}
    import winreg
    result = {}
    locations = [
        (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Internet Settings',
         ('ProxyEnable', 'ProxyServer', 'ProxyOverride', 'AutoConfigURL')),
        (winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters', ('DefaultTTL',)),
        (winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters', ('DefaultTTL',)),
    ]
    for protocol in ('Tcpip', 'Tcpip6'):
        base = 'SYSTEM\\CurrentControlSet\\Services\\' + protocol + '\\Parameters\\Interfaces'
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as key:
            for index in range(winreg.QueryInfoKey(key)[0]):
                locations.append((winreg.HKEY_LOCAL_MACHINE, base + '\\' + winreg.EnumKey(key, index),
                                  ('NameServer', 'DhcpNameServer')))
    for hive, path, names in locations:
        with winreg.OpenKey(hive, path) as key:
            for name in names:
                try:
                    value = winreg.QueryValueEx(key, name)
                except FileNotFoundError:
                    value = None
                result[(hive, path, name)] = value
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('executable', type=Path)
    parser.add_argument('--network', action='store_true', help='Запустить встроенную проверку сайтов через временный прокси')
    args = parser.parse_args()
    source = args.executable.resolve(strict=True)
    before = system_settings()
    with tempfile.TemporaryDirectory(prefix='flowery-exe-') as directory:
        root = Path(directory)
        portable = root / 'portable'
        portable.mkdir()
        exe = portable / 'Flowery.exe'
        shutil.copy2(source, exe)
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        config = portable / 'config.ini'
        config.write_text('[proxy]\nport = ' + str(port) + '\nauto_system_proxy = false\n'
                          'ipv6_mode = preferred\ndiscord_voice_udp = false\n'
                          '[dns]\nenable_custom_dns = false\n'
                          '[tethering]\nfix_ttl = false\nclamp_mss = false\n'
                          '[quic]\nblock_quic = false\n', encoding='utf-8')
        original_config = config.read_bytes()
        env = dict(os.environ, FLOWERY_HOME=str(root / 'user-data'), PYTHONIOENCODING='utf-8')
        flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0

        def run(option, timeout=40):
            result = subprocess.run([str(exe), option], cwd=root, env=env,
                                    capture_output=True, timeout=timeout, creationflags=flags)
            output = (result.stdout + result.stderr).decode('utf-8', errors='replace')
            print(output)
            if result.returncode or 'Traceback (most recent call last)' in output:
                raise RuntimeError('EXE ' + option + ': код ' + str(result.returncode))
            print('EXE ' + option + ': код 0')
            return output

        help_output = run('--help')
        if '--profile' not in help_output:
            raise RuntimeError('EXE не показал справку')
        status = run('--status')
        if 'PREFERRED' not in status:
            raise RuntimeError('EXE не прочитал внешний config.ini')
        if config.read_bytes() != original_config:
            raise RuntimeError('Проверка статуса изменила config.ini')

        if args.network:
            config.write_text(config.read_text(encoding='utf-8').replace('preferred', 'disabled'), encoding='utf-8')
            output = run('--test', timeout=180)
            if f'127.0.0.1:{port}' not in output or 'Прокси-сервер остановлен' not in output:
                raise RuntimeError('Не подтверждён запуск и остановка отдельного прокси')
            with socket.socket() as probe:
                probe.settimeout(1)
                if probe.connect_ex(('127.0.0.1', port)) == 0:
                    raise RuntimeError('После завершения EXE порт остался открыт')
        if system_settings() != before:
            raise RuntimeError('Настройки Windows изменились во время проверки')
        print('Проверка EXE завершена; прокси, TTL и DNS Windows не изменились. Временные данные удаляются.')


if __name__ == '__main__':
    main()
