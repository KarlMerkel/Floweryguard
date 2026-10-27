"""Модуль блокировки протокола QUIC (UDP/443) через Windows Firewall.
Принуждает веб-браузеры (Chrome, Firefox, Edge, Yandex, Brave, Opera)
переключаться на TCP/TLS, где работают техники DPI bypass и zapret.
ВАЖНО: Правило создается ИСКЛЮЧИТЕЛЬНО для браузеров (через параметр program=),
чтобы никогда не блокировать сетевые онлайн-игры (Steam, сетевой мультиплеер, PlayFab Party DTLS).
"""

import os
import sys
import subprocess
from typing import Dict
from flowguard.ttl_fix import is_admin
from flowguard.logger import get_logger

logger = get_logger("QUIC")

RULE_PREFIX = "Flowery_Block_QUIC"
NETSH_TIMEOUT = 10.0
KNOWN_BROWSER_KEYS = (
    "chrome", "firefox", "msedge", "yandex", "brave", "opera", "operagx", "vivaldi", "discord"
)


def _decode_netsh_output(raw_bytes: bytes) -> str:
    """Универсальное безопасное декодирование вывода системных утилит Windows."""
    if not raw_bytes:
        return ""
    try:
        return raw_bytes.decode("utf-8")
    except (UnicodeDecodeError, LookupError) as e:
        logger.debug(f"netsh firewall вывод не является UTF-8 ({e}), перебор альтернативных кодировок")

    import locale
    candidates = []
    enc_list = ["cp866", "cp1251"]
    pref = locale.getpreferredencoding()
    if pref and pref.lower() not in ("cp866", "cp1251", "utf-8"):
        enc_list.append(pref)

    for enc in enc_list:
        try:
            txt = raw_bytes.decode(enc)
            ru_letters = sum(1 for c in txt if 'а' <= c.lower() <= 'я' or c.lower() == 'ё')
            bad_chars = sum(1 for c in txt if c in '─│┌┐└┘├┤┬┴┼═║╒╓╔╕╖╗╘╙╚╛╜╝╞╟╠╡╢╣╤╥╦╧╨╩╪╫╬█▄▌▐▀ЃҐЇў¤­ №')
            candidates.append((ru_letters - bad_chars * 2, enc, txt))
        except Exception as e:
            logger.debug(f"Ошибка декодирования firewall в {enc}: {e}")

    if candidates:
        candidates.sort(key=lambda x: x[0], reverse=True)
        return candidates[0][2]
    return raw_bytes.decode("latin1", errors="replace")


def get_installed_browsers() -> Dict[str, str]:
    """Автоматически находит исполняемые файлы установленных веб-браузеров и Discord Desktop.
    Использует системный реестр Windows (App Paths) и стандартные пути установки.
    """
    browsers: Dict[str, str] = {}
    if sys.platform != "win32":
        return browsers

    known_exes = {
        "chrome.exe": "chrome",
        "firefox.exe": "firefox",
        "msedge.exe": "msedge",
        "browser.exe": "yandex",
        "brave.exe": "brave",
        "opera.exe": "opera",
        "vivaldi.exe": "vivaldi",
    }

    # 1. Поиск в реестре HKLM и HKCU App Paths
    try:
        import winreg
        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"
        for root in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            try:
                with winreg.OpenKey(root, key_path) as k:
                    for exe_name, b_key in known_exes.items():
                        try:
                            with winreg.OpenKey(k, exe_name) as sk:
                                val, _ = winreg.QueryValueEx(sk, "")
                                if val:
                                    cleaned = val.strip(' \t\r\n"\'')
                                    if os.path.isfile(cleaned):
                                        browsers[b_key] = os.path.abspath(cleaned)
                        except Exception:
                            pass
            except Exception:
                pass
    except Exception as e:
        logger.debug(f"get_installed_browsers registry error: {e}")

    # 2. Файловые пути по умолчанию для веб-браузеров
    fallback_paths = [
        (r"%ProgramFiles%\Google\Chrome\Application\chrome.exe", "chrome"),
        (r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe", "chrome"),
        (r"%LocalAppData%\Google\Chrome\Application\chrome.exe", "chrome"),
        (r"%ProgramFiles%\Mozilla Firefox\firefox.exe", "firefox"),
        (r"%ProgramFiles(x86)%\Mozilla Firefox\firefox.exe", "firefox"),
        (r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe", "msedge"),
        (r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe", "msedge"),
        (r"%LocalAppData%\Yandex\YandexBrowser\Application\browser.exe", "yandex"),
        (r"%ProgramFiles%\BraveSoftware\Brave-Browser\Application\brave.exe", "brave"),
        (r"%LocalAppData%\BraveSoftware\Brave-Browser\Application\brave.exe", "brave"),
        (r"%LocalAppData%\Programs\Opera\opera.exe", "opera"),
        (r"%LocalAppData%\Programs\Opera GX\opera.exe", "operagx"),
        (r"%LocalAppData%\Vivaldi\Application\vivaldi.exe", "vivaldi"),
    ]

    for raw_p, b_key in fallback_paths:
        if b_key not in browsers:
            expanded = os.path.expandvars(raw_p)
            if os.path.isfile(expanded):
                browsers[b_key] = os.path.abspath(expanded)

    # 3. Динамический поиск Discord (Electron клиент: app-*\Discord.exe, ProgramFiles, LocalAppData)
    # ВАЖНО: сетевые запросы QUIC выполняет дочерний процесс Electron из каталога app-*\Discord.exe.
    # Лаунчер-заглушка %LocalAppData%\Discord\Discord.exe не выполняет веб-запросы Chromium,
    # поэтому правило Windows Firewall обязано нацеливаться на реальный исполняемый файл app-*\Discord.exe.
    import glob
    discord_candidates = []
    for d_pattern in (
        r"%LocalAppData%\Discord\app-*\Discord.exe",
        r"%LocalAppData%\DiscordCanary\app-*\DiscordCanary.exe",
        r"%LocalAppData%\DiscordPTB\app-*\DiscordPTB.exe",
        r"%ProgramFiles%\Discord\Discord.exe",
        r"%ProgramFiles(x86)%\Discord\Discord.exe",
        r"%LocalAppData%\Discord\Discord.exe",
    ):
        found = glob.glob(os.path.expandvars(d_pattern))
        if found:
            discord_candidates.extend(found)
    if discord_candidates:
        app_candidates = [c for c in discord_candidates if "\\app-" in c or "/app-" in c]
        if app_candidates:
            app_candidates.sort(reverse=True)
            browsers["discord"] = os.path.abspath(app_candidates[0])
        else:
            discord_candidates.sort(reverse=True)
            browsers["discord"] = os.path.abspath(discord_candidates[0])

    # Дедупликация браузеров по нормализованному пути исполняемого файла
    seen_paths = set()
    unique_browsers = {}
    for b_key, b_path in browsers.items():
        norm_p = os.path.normcase(os.path.abspath(b_path))
        if norm_p not in seen_paths:
            seen_paths.add(norm_p)
            unique_browsers[b_key] = b_path
    browsers = unique_browsers

    logger.debug(f"Обнаружено браузеров для QUIC-изоляции: {list(browsers.keys())}")
    return browsers


class QUICBlocker:
    """Управление точечной блокировкой протокола QUIC (UDP 443) для веб-браузеров и Discord.
    Игры, Steam и голосовой трафик Discord (UDP 19294-19344, 50000-50100) не затрагиваются.
    """

    def __init__(self):
        self._blocked = False

    def is_rule_present(self) -> bool:
        """Проверяет наличие хотя бы одного правила блокировки QUIC в брандмауэре."""
        try:
            creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            # Проверяем старое глобальное правило и браузерные правила
            res = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", f"name={RULE_PREFIX}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=creationflags,
                timeout=NETSH_TIMEOUT,
                check=False
            )
            out_str = _decode_netsh_output(res.stdout)
            if res.returncode == 0 and RULE_PREFIX.lower() in out_str.lower():
                return True

            for b_key in KNOWN_BROWSER_KEYS:
                r_name = f"{RULE_PREFIX}_{b_key}"
                res_b = subprocess.run(
                    ["netsh", "advfirewall", "firewall", "show", "rule", f"name={r_name}"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=creationflags,
                    timeout=NETSH_TIMEOUT,
                    check=False
                )
                if res_b.returncode == 0:
                    out_b = _decode_netsh_output(res_b.stdout)
                    if r_name.lower() in out_b.lower():
                        return True
            return False
        except Exception as e:
            logger.debug(f"is_rule_present check failed: {e}")
            return False

    def block_quic(self) -> bool:
        """Добавляет правила блокировки исходящего UDP 443 ТОЧЕЧНО для браузеров."""
        if not is_admin():
            logger.warning("block_quic: требуются права Администратора")
            return False

        try:
            # Сначала очищаем любые старые/глобальные правила
            self.unblock_quic()

            browsers = get_installed_browsers()
            if not browsers:
                logger.warning("Браузеры не найдены для QUIC-блокировки. Глобальное правило не создается (защита онлайн-игр).")
                return False

            creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            success_count = 0

            for b_key, exe_path in browsers.items():
                r_name = f"{RULE_PREFIX}_{b_key}"
                logger.info(f"Добавление правила QUIC (UDP 443) для браузера {b_key} ({exe_path})...")
                res = subprocess.run(
                    [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={r_name}",
                        "dir=out",
                        "action=block",
                        "protocol=UDP",
                        "remoteport=443",
                        f"program={exe_path}",
                        "enable=yes",
                        "profile=any",
                        f"description=Flowery DPI Bypass QUIC block for {b_key}"
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=creationflags,
                    timeout=NETSH_TIMEOUT,
                    check=False
                )

                if res.returncode == 0:
                    success_count += 1
                else:
                    err_str = _decode_netsh_output(res.stderr).strip()
                    logger.warning(f"Не удалось добавить правило QUIC для {b_key}: {err_str}")

            if success_count > 0:
                self._blocked = True
                logger.info(f"QUIC успешно заблокирован для {success_count} браузеров (онлайн-игры и Steam не затронуты)")
                return True
            return False
        except Exception as e:
            logger.error(f"Ошибка вызова netsh advfirewall add rule: {e}")
            return False

    def unblock_quic(self) -> bool:
        """Удаляет все правила блокировки QUIC из Windows Firewall."""
        if not is_admin():
            logger.debug("unblock_quic: пропуск (нет прав администратора)")
            return False

        try:
            creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            logger.info("Удаление правил блокировки QUIC из Windows Firewall...")

            # 1. Удаление старого глобального правила
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={RULE_PREFIX}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creationflags,
                timeout=NETSH_TIMEOUT,
                check=False
            )

            # 2. Удаление браузерных правил
            for b_key in KNOWN_BROWSER_KEYS:
                r_name = f"{RULE_PREFIX}_{b_key}"
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={r_name}"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=creationflags,
                    timeout=NETSH_TIMEOUT,
                    check=False
                )

            # 3. Дополнительная гарантия через PowerShell Remove-NetFirewallRule
            try:
                ps_cmd = "Get-NetFirewallRule -DisplayName 'Flowery_Block_QUIC*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule"
                subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=creationflags,
                    timeout=3
                )
            except Exception:
                pass

            if self.is_rule_present():
                logger.warning("Правила блокировки QUIC остались в брандмауэре после удаления")
                return False
            self._blocked = False
            logger.info("Все правила блокировки QUIC удалены из брандмауэра")
            return True
        except Exception as e:
            logger.error(f"Ошибка удаления правил QUIC: {e}")
            return False
