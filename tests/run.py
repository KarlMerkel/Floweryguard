"""Запуск тестов в отдельной копии проекта без изменения пользовательских данных."""

import argparse
import ipaddress
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import traceback
import unittest


def run_worker(integration, pattern):
    sys.path.insert(0, str(Path.cwd()))
    blocked = []

    def audit(event, args):
        if event in ('winreg.SetValue', 'winreg.DeleteValue', 'winreg.DeleteKey', 'winreg.CreateKey'):
            message = f"Запись реестра в автономном тесте: {event}"
            blocked.append(message)
            raise OSError(message)
        if event == 'subprocess.Popen':
            command = args[1]
            words = [str(word).lower() for word in command] if isinstance(command, (list, tuple)) else str(command).lower().split()
            executable = Path(str(args[0])).name.lower()
            mutating = (executable in ('taskkill', 'taskkill.exe') or
                        executable in ('netsh', 'netsh.exe', 'reg', 'reg.exe', 'sc', 'sc.exe') and
                        bool(set(words) & {'set', 'add', 'delete', 'stop', 'start'}))
            if mutating:
                message = f"Системная запись без подмены в тесте: {executable}"
                blocked.append(message)
                raise OSError(message)
        dns_events = ("socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr")
        if event not in ("socket.connect", "socket.sendto") + dns_events:
            return
        address = args[0] if event in dns_events else args[-1]
        host = address[0] if isinstance(address, tuple) else address
        if host in (None, "", "localhost"):
            return
        try:
            local = ipaddress.ip_address(host).is_loopback
        except ValueError:
            local = False
        if not local:
            origin = " <- ".join(frame.name for frame in traceback.extract_stack(limit=7)[:-1])
            message = f"Внешняя сеть в автономном тесте: {event} {host} ({origin})"
            blocked.append(message)
            raise OSError(message)

    if not integration:
        sys.addaudithook(audit)
    directory = "tests/integration" if integration else "tests"
    suite = unittest.defaultTestLoader.discover(directory, pattern=pattern)
    # Собственный поток не теряется при перенастройке консоли тестируемым main.py.
    with open("test-results.log", "w", encoding="utf-8") as stream:
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    print(Path("test-results.log").read_text(encoding="utf-8"))
    for message in sorted(set(blocked)):
        print(message, file=sys.stderr)
    return int(not result.wasSuccessful() or bool(blocked))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--integration", action="store_true", help="Проверки с доступом к интернету")
    parser.add_argument("--pattern", default="test_*.py", help="Маска имён тестовых модулей")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        return run_worker(args.integration, args.pattern)

    source = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="flowery-tests-") as directory:
        root = Path(directory)
        for name in ("flowguard", "Floweryguard", "tests", "zapret_bin"):
            shutil.copytree(source / name, root / name, ignore=shutil.ignore_patterns("__pycache__", "*.log"))
        release = root / "Flowery_Release"
        release.mkdir()
        for name in ("Floweryguard", "flowguard"):
            shutil.copytree(source / "Flowery_Release" / name, release / name,
                            ignore=shutil.ignore_patterns("__pycache__", "*.log"))
        for base, target in ((source, root), (source / "Flowery_Release", release)):
            for pattern in ("*.bat", "config.ini", "whitelist.txt", "hosts.txt"):
                for path in base.glob(pattern):
                    shutil.copy2(path, target / path.name)
        env = os.environ.copy()
        env.update(FLOWERY_HOME=str(root / "user-data"), PYTHONIOENCODING="utf-8")
        command = [sys.executable, str(root / "tests/run.py"), "--worker", "--pattern", args.pattern]
        if args.integration:
            command.append("--integration")
        try:
            result = subprocess.run(command, cwd=root, env=env, timeout=180)
            if result.returncode == 120 and (root / "test-results.log").exists():
                print((root / "test-results.log").read_text(encoding="utf-8"))
            return result.returncode
        except subprocess.TimeoutExpired:
            print("Тесты не завершились за 180 секунд.", file=sys.stderr)
            return 1


if __name__ == "__main__":
    sys.exit(main())
