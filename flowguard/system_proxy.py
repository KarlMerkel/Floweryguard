"""Модуль автоматической настройки системного прокси Windows (WinINet / Registry).
Позволяет всем браузерам и программам мгновенно направлять трафик через локальный прокси
без необходимости ручной настройки.
"""

import winreg
import ctypes
from typing import Optional, Tuple

INTERNET_SETTINGS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
INTERNET_OPTION_SETTINGS_CHANGED = 39
INTERNET_OPTION_REFRESH = 37


def refresh_system_proxy_settings() -> None:
    """Уведомляет подсистему WinINet о смене настроек прокси."""
    try:
        wininet = ctypes.windll.wininet
        wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
    except Exception as e:
        print(f"[!] Не удалось обновить WinINet настройки: {e}")


def build_proxy_override(proxy_discord: bool = True, proxy_youtube: bool = True) -> str:
    """Формирует список исключений ProxyOverride в зависимости от режима."""
    overrides = []

    # Если Discord НЕ проксируется через Flowery, исключаем его (отдаем в zapret)
    if not proxy_discord:
        overrides.extend([
            "*.discord.com", "*.discord.gg", "*.discord.media", "*.discordapp.com", "*.discordapp.net",
            "discord.com", "discord.gg", "discord.media", "discordapp.com", "discordapp.net",
            "*.discord.co", "*.discordcdn.com", "*.discord.dev", "*.discord.new", "*.discord.gift",
            "*.discord-activities.com", "*.discordactivities.com", "*.dis.gd",
            "discord.co", "discordcdn.com", "discord.dev", "discord.new", "discord.gift",
            "discord-activities.com", "discordactivities.com", "dis.gd"
        ])

    # Если YouTube НЕ проксируется через Flowery, исключаем его (отдаем в zapret)
    if not proxy_youtube:
        overrides.extend([
            "*.youtube.com", "youtube.com", "*.googlevideo.com", "googlevideo.com",
            "*.ytimg.com", "ytimg.com", "youtu.be"
        ])

    overrides.extend(["127.0.0.1", "127.*", "localhost", "::1", "<local>"])
    return ";".join(overrides)


class SystemProxyManager:
    """Управляет состоянием системного HTTP прокси Windows."""

    def __init__(self, proxy_address: str = "127.0.0.1:8118", proxy_override: Optional[str] = None):
        self.proxy_address = proxy_address
        self.proxy_override = proxy_override or build_proxy_override(proxy_discord=True, proxy_youtube=True)
        self.original_enable: Optional[int] = None
        self.original_server: Optional[str] = None
        self.original_override: Optional[str] = None
        self._is_active = False

    def get_current_settings(self) -> Tuple[int, str, str]:
        """Считывает текущие настройки прокси из реестра."""
        enable = 0
        server = ""
        override = ""
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_READ) as key:
                try:
                    enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
                except FileNotFoundError:
                    pass
                try:
                    server, _ = winreg.QueryValueEx(key, "ProxyServer")
                except FileNotFoundError:
                    pass
                try:
                    override, _ = winreg.QueryValueEx(key, "ProxyOverride")
                except FileNotFoundError:
                    pass
        except Exception as e:
            print(f"[!] Ошибка чтения настроек прокси: {e}")
        return enable, server, override

    def is_stale_proxy_present(self) -> bool:
        """Проверяет, остались ли настройки прокси от предыдущего некорректно завершенного сеанса."""
        enable, server, _ = self.get_current_settings()
        if enable != 1 or not server or self.proxy_address not in server:
            return False
        # Проверяем, запущен ли реальный процесс прокси на этом адресе:порту
        try:
            import socket
            host, port_str = self.proxy_address.split(":")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            res = s.connect_ex((host, int(port_str)))
            s.close()
            if res == 0:
                # Прокси активен и принимает соединения — он не брошен!
                return False
        except Exception:
            pass
        return True

    def enable(self) -> bool:
        """Включает системный прокси и перенаправляет трафик."""
        try:
            cur_enable, cur_server, cur_override = self.get_current_settings()

            # Защита от сохранения нашего же прокси как 'оригинального' при падении прошлой сессии
            if cur_server and self.proxy_address in cur_server:
                self.original_enable = 0
                self.original_server = None
                self.original_override = None
            else:
                self.original_enable = cur_enable
                self.original_server = cur_server
                self.original_override = cur_override

            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, self.proxy_address)
                winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, self.proxy_override)

            refresh_system_proxy_settings()
            self._is_active = True
            return True
        except Exception as e:
            print(f"[!] Ошибка включения системного прокси: {e}")
            return False

    def disable(self, force: bool = False) -> bool:
        """Отключает системный прокси и возвращает оригинальные настройки."""
        if not self._is_active and not force:
            return False

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_SET_VALUE) as key:
                prev_enable = self.original_enable if (self.original_enable is not None and not force) else 0
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, prev_enable)

                if self.original_server and self.proxy_address not in self.original_server:
                    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, self.original_server)
                else:
                    try:
                        winreg.DeleteValue(key, "ProxyServer")
                    except FileNotFoundError:
                        pass

                if self.original_override:
                    winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, self.original_override)
                else:
                    try:
                        winreg.DeleteValue(key, "ProxyOverride")
                    except FileNotFoundError:
                        pass

            refresh_system_proxy_settings()
            self._is_active = False
            return True
        except Exception as e:
            print(f"[!] Ошибка отключения системного прокси: {e}")
            return False

    def force_cleanup(self) -> bool:
        """Принудительно сбрасывает настройки прокси Windows до состояния по умолчанию."""
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                try:
                    cur_server, _ = winreg.QueryValueEx(key, "ProxyServer")
                    if cur_server and self.proxy_address in cur_server:
                        winreg.DeleteValue(key, "ProxyServer")
                except Exception:
                    pass
            refresh_system_proxy_settings()
            self._is_active = False
            return True
        except Exception as e:
            print(f"[!] Ошибка принудительного сброса прокси: {e}")
            return False
