"""Модуль интеграции Discord Voice (UDP WebRTC DPI Bypass).
Запускает точечную десинхронизацию zapret winws.exe только для UDP портов Discord (19294-19344, 50000-50100),
не затрагивая TCP трафик и гармонично дополняя локальный прокси Flowery.
"""

import os
import sys
import subprocess
from typing import Optional
from Floweryguard.ttl_fix import is_admin


def is_system_winws_running() -> bool:
    """Проверяет, запущен ли процесс winws.exe в системе (например, внешний zapret)."""
    try:
        creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        output = subprocess.check_output(
            ["tasklist", "/FI", "IMAGENAME eq winws.exe", "/NH"],
            creationflags=creationflags,
        )
        return b"winws.exe" in output.lower()
    except Exception:
        return False


class VoiceHelper:
    """Управление точечным запуском WinDivert/winws для голосовых каналов Discord."""

    def __init__(self, bin_dir: Optional[str] = None):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.bin_dir = bin_dir or os.path.join(base_dir, "zapret_bin")
        self.winws_path = os.path.join(self.bin_dir, "winws.exe")
        self.fake_discord = os.path.join(self.bin_dir, "ACTIVE_DISCORD_UDP.bin")
        self.process: Optional[subprocess.Popen] = None
        self.managed_by_us = False

    def is_available(self) -> bool:
        """Проверяет наличие бинарников winws.exe и фейковых пакетов."""
        return os.path.exists(self.winws_path) and os.path.exists(self.fake_discord)

    def is_running(self) -> bool:
        """Проверяет, активен ли winws (наш или внешний)."""
        if self.process is not None and self.process.poll() is None:
            return True
        return is_system_winws_running()

    def start(self) -> bool:
        """Запускает winws с точечным фильтром Discord UDP или подключается к существующему."""
        # 1. Если zapret уже запущен в системе — не плодим дубликаты
        if is_system_winws_running():
            print("\033[92m[+] Обнаружен активный zapret (winws) — Discord Voice UDP защищён\033[0m")
            self.managed_by_us = False
            return True

        if not self.is_available():
            print("\033[90m[-] Бинарники zapret_bin не найдены (пропуск автозапуска UDP войса)\033[0m")
            return False

        if not is_admin():
            print("\033[93m[!] Требуются права Администратора для загрузки драйвера WinDivert (UDP войс)\033[0m")
            return False

        stun_bin = os.path.join(self.bin_dir, "stun.bin")
        fake_stun = stun_bin if os.path.exists(stun_bin) else self.fake_discord

        args = [
            self.winws_path,
            "--wf-udp=19294-19344,50000-50100",
            "--filter-udp=19294-19344,50000-50100",
            "--filter-l7=discord,stun",
            "--dpi-desync=fake",
            f"--dpi-desync-fake-discord={self.fake_discord}",
            f"--dpi-desync-fake-stun={fake_stun}",
            "--dpi-desync-repeats=6",
        ]

        try:
            creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

            self.process = subprocess.Popen(
                args,
                cwd=self.bin_dir,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creationflags,
            )
            self.managed_by_us = True
            print("\033[92m[+] Discord Voice UDP Helper запущен в фоне (точечная десинхронизация портов 50000-50100)\033[0m")
            return True
        except Exception as e:
            print(f"\033[91m[!] Ошибка запуска winws UDP voice: {e}\033[0m")
            return False

    def stop(self) -> None:
        """Останавливает процесс winws, только если мы его запускали."""
        if self.process and self.managed_by_us:
            print("  [*] Остановка фонового процесса Discord Voice (winws)...")
            try:
                self.process.terminate()
                self.process.wait(timeout=2)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
            self.process = None
            self.managed_by_us = False

            # Выгрузка драйвера WinDivert, если он остался активным
            if sys.platform == "win32" and is_admin():
                for svc in ["WinDivert", "WinDivert14"]:
                    try:
                        creationflags = subprocess.CREATE_NO_WINDOW
                        subprocess.run(
                            ["sc", "stop", svc],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            creationflags=creationflags,
                            check=False
                        )
                    except Exception:
                        pass
