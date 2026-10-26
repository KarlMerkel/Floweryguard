"""Модуль автоматической настройки системного прокси Windows (WinINet / Registry).
Позволяет всем браузерам и программам мгновенно направлять трафик через локальный прокси
без необходимости ручной настройки.
"""

import winreg
import ctypes
from typing import Optional, Tuple

from flowguard.logger import get_logger

logger = get_logger("SystemProxy")

INTERNET_SETTINGS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
INTERNET_OPTION_SETTINGS_CHANGED = 39
INTERNET_OPTION_REFRESH = 37


def refresh_system_proxy_settings() -> None:
    """Уведомляет подсистему WinINet о смене настроек прокси."""
    try:
        wininet = ctypes.windll.wininet
        wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
        logger.debug("Настройки WinINet успешно обновлены")
    except Exception as e:
        logger.warning(f"Не удалось обновить WinINet настройки: {e}")
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

    # Игровые платформы, Steam, Sony PlayStation, PlayFab и GameGuard (в обход прокси)
    overrides.extend([
        "*.steampowered.com", "steampowered.com",
        "*.steamcommunity.com", "steamcommunity.com",
        "*.steamcontent.com", "steamcontent.com",
        "*.steamstatic.com", "steamstatic.com",
        "*.steamserver.net", "steamserver.net",
        "*.steam-chat.com", "steam-chat.com",
        "*.steamgames.com", "steamgames.com",
        "*.steamusercontent.com", "steamusercontent.com",
        "*.valve.net", "valve.net",
        "*.valvesoftware.com", "valvesoftware.com",
        "*.playstation.com", "playstation.com",
        "*.playstation.net", "playstation.net",
        "*.playstationnetwork.com", "playstationnetwork.com",
        "*.sony.com", "sony.com",
        "*.sonyentertainmentnetwork.com", "sonyentertainmentnetwork.com",
        "*.playfabapi.com", "playfabapi.com",
        "*.playfab.com", "playfab.com",
        "*.playfab.net", "playfab.net",
        "*.trafficmanager.net", "trafficmanager.net",
        "*.arrowheadgs.com", "arrowheadgs.com",
        "*.helldivers2.dev", "helldivers2.dev",
        "*.nprotect.net", "nprotect.net",
        "*.nprotect.com", "nprotect.com",
        "*.inca.co.kr", "inca.co.kr",
        "*.gameguard.des", "gameguard.des",
        "*.gameguard.co.kr", "gameguard.co.kr",
        "*.battleye.com", "battleye.com",
        "*.easyanticheat.net", "easyanticheat.net",
        "*.epicgames.com", "epicgames.com",
        "*.ea.com", "ea.com",
        "*.ubisoft.com", "ubisoft.com",
        "*.riotgames.com", "riotgames.com",
        "*.battle.net", "battle.net",
    ])

    # Telegram (MTProto DC, Web, API - не блокируется, идет напрямую без прокси)
    overrides.extend([
        "*.telegram.org", "telegram.org",
        "*.t.me", "t.me",
        "*.telegra.ph", "telegra.ph",
        "*.tdesktop.com", "tdesktop.com",
        "149.154.*", "91.108.*"
    ])

    # Приватные адреса локальных сетей (RFC 1918) и loopback:
    overrides.extend([
        "127.0.0.1", "127.*", "localhost", "::1", "<local>",
        "10.*", "192.168.*",
        "172.16.*", "172.17.*", "172.18.*", "172.19.*", "172.20.*", "172.21.*",
        "172.22.*", "172.23.*", "172.24.*", "172.25.*", "172.26.*", "172.27.*",
        "172.28.*", "172.29.*", "172.30.*", "172.31.*"
    ])
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
                    logger.debug("Значение ProxyEnable не найдено в реестре (используется 0)")
                except Exception as e:
                    logger.debug(f"Ошибка чтения ProxyEnable: {e}")
                try:
                    server, _ = winreg.QueryValueEx(key, "ProxyServer")
                except FileNotFoundError:
                    logger.debug("Значение ProxyServer не найдено в реестре (пустая строка)")
                except Exception as e:
                    logger.debug(f"Ошибка чтения ProxyServer: {e}")
                try:
                    override, _ = winreg.QueryValueEx(key, "ProxyOverride")
                except FileNotFoundError:
                    logger.debug("Значение ProxyOverride не найдено в реестре (пустая строка)")
                except Exception as e:
                    logger.debug(f"Ошибка чтения ProxyOverride: {e}")
        except Exception as e:
            logger.error(f"Ошибка чтения настроек прокси: {e}")
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
            host, port_str = self.proxy_address.rsplit(":", 1)
            host = host.strip("[]")
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            s = socket.socket(family, socket.SOCK_STREAM)
            s.settimeout(0.2)
            res = s.connect_ex((host, int(port_str)))
            s.close()
            if res == 0:
                # Прокси активен и принимает соединения — он не брошен!
                return False
        except Exception as e:
            logger.debug(f"is_stale_proxy_present socket check error: {e}")
        logger.warning(f"Обнаружен зависший системный прокси: {server}")
        return True

    def enable(self) -> bool:
        """Включает системный прокси и перенаправляет трафик."""
        try:
            cur_enable, cur_server, cur_override = self.get_current_settings()

            # Защита от сохранения нашего же прокси как 'оригинального' при падении прошлой сессии
            if not self._is_active:
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
            logger.info(f"Системный прокси Windows включен: {self.proxy_address}")
            return True
        except Exception as e:
            logger.error(f"Ошибка включения системного прокси: {e}")
            print(f"[!] Ошибка включения системного прокси: {e}")
            return False

    def ensure_active(self) -> bool:
        """Проверяет и восстанавливает активность системного прокси, если Windows или сторонний софт отключили его (например, при выходе из сна/гибернации)."""
        enable, server, override = self.get_current_settings()
        if enable != 1 or not server or self.proxy_address not in server:
            logger.info("ensure_active: прокси был отключен внешним событием, повторное включение")
            return self.enable()
        # Даже если флаг в реестре стоит, освежаем кэш WinINet после пробуждения
        refresh_system_proxy_settings()
        return True

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
                        logger.debug("ProxyServer уже отсутствует в реестре")
                    except Exception as e:
                        logger.debug(f"Ошибка удаления ProxyServer: {e}")

                if self.original_override:
                    winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, self.original_override)
                else:
                    try:
                        winreg.DeleteValue(key, "ProxyOverride")
                    except FileNotFoundError:
                        logger.debug("ProxyOverride уже отсутствует в реестре")
                    except Exception as e:
                        logger.debug(f"Ошибка удаления ProxyOverride: {e}")

            refresh_system_proxy_settings()
            self._is_active = False
            logger.info("Системный прокси Windows успешно отключен")
            return True
        except Exception as e:
            logger.error(f"Ошибка отключения системного прокси: {e}")
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
                except FileNotFoundError:
                    logger.debug("force_cleanup: ProxyServer уже отсутствует в реестре")
                except Exception as e:
                    logger.debug(f"force_cleanup: ошибка удаления ProxyServer: {e}")
            refresh_system_proxy_settings()
            self._is_active = False
            logger.info("Принудительный сброс настроек системного прокси выполнен успешно")
            return True
        except Exception as e:
            logger.error(f"Ошибка принудительного сброса прокси: {e}")
            print(f"[!] Ошибка принудительного сброса прокси: {e}")
            return False
