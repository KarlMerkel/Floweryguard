"""Модуль управления TTL (Time to Live) и TCP Timestamps для Windows.
Обход ограничений операторов связи при мобильном тетеринге.
"""

import sys
import os
import ctypes
import subprocess
import winreg
from typing import Optional, Tuple

TCPIP_PARAMS_KEY = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
TCPIP6_PARAMS_KEY = r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
DEFAULT_WINDOWS_TTL = 128


def is_admin() -> bool:
    """Проверяет, запущен ли скрипт с правами администратора."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


class TTLManager:
    """Класс управления TTL и TCP Timestamps."""

    def __init__(self, target_ttl: int = 65, enable_timestamps: bool = True):
        self.target_ttl = target_ttl
        self.enable_timestamps = enable_timestamps
        self.original_ttl_v4: Optional[int] = None
        self.original_ttl_v6: Optional[int] = None
        self._applied = False

    def get_current_ttl(self) -> Tuple[Optional[int], Optional[int]]:
        """Возвращает текущие значения DefaultTTL для IPv4 и IPv6 из реестра."""
        ttl_v4 = None
        ttl_v6 = None

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, TCPIP_PARAMS_KEY, 0, winreg.KEY_READ) as key:
                ttl_v4, _ = winreg.QueryValueEx(key, "DefaultTTL")
        except FileNotFoundError:
            ttl_v4 = None
        except Exception:
            ttl_v4 = None

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, TCPIP6_PARAMS_KEY, 0, winreg.KEY_READ) as key:
                ttl_v6, _ = winreg.QueryValueEx(key, "DefaultTTL")
        except FileNotFoundError:
            ttl_v6 = None
        except Exception:
            ttl_v6 = None

        return ttl_v4, ttl_v6

    def apply_ttl(self) -> bool:
        """Устанавливает целевое значение DefaultTTL (например, 65) и включает TCP timestamps."""
        if not is_admin():
            print("[!] Требуются права Администратора для установки TTL!")
            return False

        try:
            self.original_ttl_v4, self.original_ttl_v6 = self.get_current_ttl()

            with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, TCPIP_PARAMS_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "DefaultTTL", 0, winreg.REG_DWORD, self.target_ttl)

            try:
                with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, TCPIP6_PARAMS_KEY, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, "DefaultTTL", 0, winreg.REG_DWORD, self.target_ttl)
            except Exception:
                pass

            if self.enable_timestamps:
                creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                subprocess.run(
                    ["netsh", "interface", "tcp", "set", "global", "timestamps=enabled"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=creationflags,
                    check=False
                )

            self._applied = True
            return True
        except Exception as e:
            print(f"[!] Ошибка установки TTL в реестре: {e}")
            return False

    def restore_ttl(self) -> bool:
        """Восстанавливает исходные значения TTL."""
        if not self._applied or not is_admin():
            return False

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, TCPIP_PARAMS_KEY, 0, winreg.KEY_SET_VALUE) as key:
                if self.original_ttl_v4 is not None:
                    winreg.SetValueEx(key, "DefaultTTL", 0, winreg.REG_DWORD, self.original_ttl_v4)
                else:
                    try:
                        winreg.DeleteValue(key, "DefaultTTL")
                    except FileNotFoundError:
                        pass

            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, TCPIP6_PARAMS_KEY, 0, winreg.KEY_SET_VALUE) as key:
                    if self.original_ttl_v6 is not None:
                        winreg.SetValueEx(key, "DefaultTTL", 0, winreg.REG_DWORD, self.original_ttl_v6)
                    else:
                        try:
                            winreg.DeleteValue(key, "DefaultTTL")
                        except FileNotFoundError:
                            pass
            except Exception:
                pass

            self._applied = False
            return True
        except Exception as e:
            print(f"[!] Ошибка восстановления TTL: {e}")
            return False
