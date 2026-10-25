"""Модуль управления TTL (Time to Live) и TCP Timestamps для Windows.
Обход ограничений операторов связи при мобильном тетеринге.
"""

import sys
import os
import ctypes
import subprocess
import winreg
from typing import Optional, Tuple, List, Dict

try:
    from Floweryguard.logger import get_logger
except ImportError:
    from flowguard.logger import get_logger

logger = get_logger("TTL")

TCPIP_PARAMS_KEY = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
TCPIP6_PARAMS_KEY = r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
DEFAULT_WINDOWS_TTL = 128


def is_admin() -> bool:
    """Проверяет, запущен ли скрипт с правами администратора."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception as e:
        logger.debug(f"Ошибка проверки IsUserAnAdmin: {e}")
        return False


def check_admin_or_elevate(auto_elevate: bool = True) -> bool:
    """Проверяет наличие прав администратора.
    Если прав нет:
    - Запрашивает повышение прав через ShellExecuteW 'runas'.
    - Если пользователь нажал 'Нет' / отказался от UAC, или права не получены:
      выводит предупреждение и ЗАВЕРШАЕТ процесс. Приложение не открывается без прав админа!
    """
    if is_admin():
        logger.debug("Права администратора подтверждены")
        return True

    logger.warning("Процесс запущен без прав администратора")
    if auto_elevate and sys.platform == "win32":
        try:
            if getattr(sys, "frozen", False):
                exe = sys.executable
                params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
            else:
                exe = sys.executable
                params = f'"{os.path.abspath(sys.argv[0])}" ' + " ".join([f'"{arg}"' for arg in sys.argv[1:]])

            app_base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            work_dir = os.path.dirname(exe) if getattr(sys, "frozen", False) else app_base
            logger.info(f"Запрос повышения UAC (ShellExecuteW runas): {exe} {params} (cwd={work_dir})")
            # 1 = SW_SHOWNORMAL
            ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, work_dir, 1)
            if ret > 32:
                # Повышенный процесс успешно запущен, непривилегированный родитель немедленно закрывается
                logger.info(f"Elevated процесс успешно запущен (ret={ret}), родительский процесс завершается")
                sys.exit(0)
            else:
                logger.warning(f"ShellExecuteW runas вернул {ret} (пользователь отклонил UAC или ошибка)")
        except Exception as e:
            logger.error(f"Ошибка вызова ShellExecuteW runas: {e}")

    # Если права не получены или пользователь отклонил UAC запрос:
    err_title = "Flowery (Glue) — Доступ запрещён"
    err_text = (
        "Flowery требует обязательных прав Администратора для работы:\n\n"
        " • Установка DefaultTTL в реестре (обход ограничений тетеринга)\n"
        " • Блокировка QUIC в Windows Firewall\n"
        " • Управление DNS и системным прокси\n\n"
        "Запустите программу от имени Администратора!"
    )
    print(f"\n\033[91m[X] ОШИБКА: {err_text}\033[0m\n")
    if sys.platform == "win32" and not os.environ.get("FLOWERY_NO_POPUP"):
        try:
            is_tty = bool(sys.stdin and hasattr(sys.stdin, "isatty") and sys.stdin.isatty())
            if not is_tty:
                if hasattr(ctypes.windll.user32, "MessageBoxTimeoutW"):
                    ctypes.windll.user32.MessageBoxTimeoutW(0, err_text, err_title, 0x10 | 0x0 | 0x10000, 0, 4000)
                else:
                    ctypes.windll.user32.MessageBoxW(0, err_text, err_title, 0x10 | 0x0 | 0x10000)
            else:
                try:
                    input("Нажмите Enter для выхода...")
                except Exception as e:
                    logger.debug(f"Ошибка ожидания ввода пользователя: {e}")
                    try:
                        os.system("pause")
                    except Exception as e2:
                        logger.debug(f"Ошибка вызова pause: {e2}")
        except Exception as e:
            logger.debug(f"Ошибка отображения окна ошибки: {e}")
    sys.exit(1)


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
        except Exception as e:
            logger.debug(f"Ошибка чтения IPv4 DefaultTTL: {e}")
            ttl_v4 = None

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, TCPIP6_PARAMS_KEY, 0, winreg.KEY_READ) as key:
                ttl_v6, _ = winreg.QueryValueEx(key, "DefaultTTL")
        except FileNotFoundError:
            ttl_v6 = None
        except Exception as e:
            logger.debug(f"Ошибка чтения IPv6 DefaultTTL: {e}")
            ttl_v6 = None

        return ttl_v4, ttl_v6

    def apply_ttl(self) -> bool:
        """Устанавливает целевое значение DefaultTTL (например, 65) и включает TCP timestamps."""
        if not is_admin():
            logger.warning("apply_ttl: требуются права Администратора")
            print("[!] Требуются права Администратора для установки TTL!")
            return False

        try:
            self.original_ttl_v4, self.original_ttl_v6 = self.get_current_ttl()
            logger.info(f"Текущие значения TTL: IPv4={self.original_ttl_v4}, IPv6={self.original_ttl_v6}")

            with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, TCPIP_PARAMS_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "DefaultTTL", 0, winreg.REG_DWORD, self.target_ttl)
            logger.info(f"Установлен IPv4 DefaultTTL = {self.target_ttl}")

            try:
                with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, TCPIP6_PARAMS_KEY, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, "DefaultTTL", 0, winreg.REG_DWORD, self.target_ttl)
                logger.info(f"Установлен IPv6 DefaultTTL = {self.target_ttl}")
            except Exception as e:
                logger.debug(f"Ошибка записи IPv6 DefaultTTL: {e}")

            if self.enable_timestamps:
                creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                res = subprocess.run(
                    ["netsh", "interface", "tcp", "set", "global", "timestamps=enabled"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=creationflags,
                    check=False
                )
                logger.info(f"Включение TCP Timestamps: exit_code={res.returncode}")

            self._applied = True
            return True
        except Exception as e:
            logger.error(f"Ошибка установки TTL в реестре: {e}")
            print(f"[!] Ошибка установки TTL в реестре: {e}")
            return False

    def restore_ttl(self) -> bool:
        """Восстанавливает исходные значения TTL."""
        if not self._applied or not is_admin():
            logger.debug("restore_ttl: пропуск (не было применено или нет прав админа)")
            return False

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, TCPIP_PARAMS_KEY, 0, winreg.KEY_SET_VALUE) as key:
                if self.original_ttl_v4 is not None:
                    winreg.SetValueEx(key, "DefaultTTL", 0, winreg.REG_DWORD, self.original_ttl_v4)
                    logger.info(f"Восстановлен IPv4 DefaultTTL = {self.original_ttl_v4}")
                else:
                    try:
                        winreg.DeleteValue(key, "DefaultTTL")
                        logger.info("Удален ключ IPv4 DefaultTTL (возврат к дефолту)")
                    except FileNotFoundError:
                        logger.debug("Ключ IPv4 DefaultTTL уже отсутствует в реестре")
                    except Exception as e:
                        logger.debug(f"Ошибка удаления IPv4 DefaultTTL: {e}")

            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, TCPIP6_PARAMS_KEY, 0, winreg.KEY_SET_VALUE) as key:
                    if self.original_ttl_v6 is not None:
                        winreg.SetValueEx(key, "DefaultTTL", 0, winreg.REG_DWORD, self.original_ttl_v6)
                        logger.info(f"Восстановлен IPv6 DefaultTTL = {self.original_ttl_v6}")
                    else:
                        try:
                            winreg.DeleteValue(key, "DefaultTTL")
                            logger.info("Удален ключ IPv6 DefaultTTL (возврат к дефолту)")
                        except FileNotFoundError:
                            logger.debug("Ключ IPv6 DefaultTTL уже отсутствует в реестре")
                        except Exception as e:
                            logger.debug(f"Ошибка удаления IPv6 DefaultTTL: {e}")
            except Exception as e:
                logger.debug(f"Ошибка доступа к ветке IPv6 параметров реестра: {e}")

            self._applied = False
            return True
        except Exception as e:
            logger.error(f"Ошибка восстановления TTL: {e}")
            print(f"[!] Ошибка восстановления TTL: {e}")
            return False


def _decode_netsh(raw_bytes: bytes) -> str:
    """Безопасное декодирование системного вывода Windows (netsh)."""
    if not raw_bytes:
        return ""
    try:
        return raw_bytes.decode("utf-8")
    except (UnicodeDecodeError, LookupError) as e:
        logger.debug(f"netsh вывод не является UTF-8 ({e}), перебор альтернативных кодировок")

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
            logger.debug(f"Ошибка декодирования netsh через {enc}: {e}")

    if candidates:
        candidates.sort(key=lambda x: x[0], reverse=True)
        return candidates[0][2]
    return raw_bytes.decode("latin1", errors="replace")


class MTUManager:
    """Управление MTU (Maximum Transmission Unit) для предотвращения фрагментации
    и потерь пакетов при мобильной раздаче интернета (GTP/CGNAT tunnels).
    """

    def __init__(self, target_mtu: int = 1380):
        self.target_mtu = target_mtu
        self.original_mtus: Dict[str, int] = {}
        self.original_mtus_v6: Dict[str, int] = {}
        self._applied = False

    def get_active_interfaces(self) -> List[Tuple[str, int]]:
        """Определяет список активных подключенных интерфейсов и их текущий MTU."""
        interfaces: List[Tuple[str, int]] = []
        if sys.platform != "win32":
            return interfaces

        try:
            creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            proc = subprocess.run(
                ["netsh", "interface", "ipv4", "show", "subinterfaces"],
                capture_output=True,
                creationflags=creationflags,
                check=False
            )
            raw = proc.stdout or b""
            text_out = _decode_netsh(raw)

            for line in text_out.splitlines():
                line = line.strip()
                if not line or line.startswith("---") or "MTU" in line:
                    continue
                parts = line.split(maxsplit=4)
                if len(parts) >= 5:
                    try:
                        mtu = int(parts[0])
                        media_state = int(parts[1])
                        name = parts[4].strip()
                        # media_state == 1 означает подключенное состояние
                        if media_state == 1 and not name.lower().startswith("loopback"):
                            interfaces.append((name, mtu))
                    except (ValueError, IndexError) as e:
                        logger.debug(f"Ошибка парсинга строки MTU '{line}': {e}")
                        continue
            logger.info(f"Обнаружено активных сетевых интерфейсов: {len(interfaces)}: {interfaces}")
        except Exception as e:
            logger.error(f"Ошибка получения списка сетевых интерфейсов: {e}")
        return interfaces

    def _get_ipv6_mtu(self, iface_name: str) -> Optional[int]:
        """Определяет текущий MTU IPv6 для интерфейса."""
        if sys.platform != "win32":
            return None
        try:
            creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            proc = subprocess.run(
                ["netsh", "interface", "ipv6", "show", "subinterfaces"],
                capture_output=True,
                creationflags=creationflags,
                check=False
            )
            raw = proc.stdout or b""
            text_out = _decode_netsh(raw)
            for line in text_out.splitlines():
                parts = line.strip().split(maxsplit=4)
                if len(parts) >= 5 and parts[4].strip().lower() == iface_name.lower():
                    return int(parts[0])
        except Exception as e:
            logger.debug(f"_get_ipv6_mtu for '{iface_name}' failed: {e}")
        return None

    def get_default_gateway_interfaces(self) -> List[str]:
        """Определяет имена интерфейсов с активным маршрутом по умолчанию (Default Gateway / 0.0.0.0/0)."""
        if sys.platform != "win32":
            return []

        default_names: List[str] = []
        creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

        # Способ 1: через netsh interface ipv4 show route (префикс 0.0.0.0/0) + netsh show interfaces (индекс -> имя)
        try:
            proc_route = subprocess.run(
                ["netsh", "interface", "ipv4", "show", "route"],
                capture_output=True,
                creationflags=creationflags,
                check=False
            )
            route_text = _decode_netsh(proc_route.stdout or b"")
            default_idxs = set()
            for line in route_text.splitlines():
                parts = line.split()
                if len(parts) >= 6 and "0.0.0.0/0" in parts:
                    try:
                        idx_val = parts[parts.index("0.0.0.0/0") + 1]
                        default_idxs.add(idx_val)
                    except (IndexError, ValueError):
                        pass

            if default_idxs:
                proc_ifaces = subprocess.run(
                    ["netsh", "interface", "ipv4", "show", "interfaces"],
                    capture_output=True,
                    creationflags=creationflags,
                    check=False
                )
                iface_text = _decode_netsh(proc_ifaces.stdout or b"")
                for line in iface_text.splitlines():
                    parts = line.split(maxsplit=4)
                    if len(parts) >= 5 and parts[0] in default_idxs:
                        name = parts[4].strip()
                        if name and name not in default_names:
                            default_names.append(name)
        except Exception as e:
            logger.debug(f"get_default_gateway_interfaces: ошибка парсинга netsh route: {e}")

        if default_names:
            return default_names

        # Способ 2: определение локального IP через UDP connect к 8.8.8.8 + поиск интерфейса по netsh ipaddresses
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.0)
            try:
                s.connect(("8.8.8.8", 53))
                local_ip = s.getsockname()[0]
            finally:
                s.close()

            if local_ip and local_ip != "127.0.0.1":
                proc_ips = subprocess.run(
                    ["netsh", "interface", "ipv4", "show", "ipaddresses"],
                    capture_output=True,
                    creationflags=creationflags,
                    check=False
                )
                ips_text = _decode_netsh(proc_ips.stdout or b"")
                current_iface = None
                for line in ips_text.splitlines():
                    line_s = line.strip()
                    if line_s.lower().startswith("interface ") or line_s.lower().startswith("интерфейс "):
                        parts = line_s.split(":", 1)
                        if len(parts) == 2:
                            current_iface = parts[1].strip()
                    elif current_iface and local_ip in line_s:
                        if current_iface not in default_names:
                            default_names.append(current_iface)
                        break
        except Exception as e:
            logger.debug(f"get_default_gateway_interfaces: ошибка проверки через socket local IP: {e}")

        return default_names

    def apply_mtu(self, target_mtu: Optional[int] = None) -> bool:
        """Устанавливает target_mtu (по умолчанию 1380) для сотовых/модемных адаптеров
        и основного адаптера шлюза по умолчанию (в т.ч. тетеринг через Ethernet/RNDIS).
        """
        if not is_admin() or sys.platform != "win32":
            logger.debug("apply_mtu: пропуск (не Windows или нет прав админа)")
            return False

        if target_mtu is not None:
            self.target_mtu = target_mtu

        active = self.get_active_interfaces()
        if not active:
            logger.warning("apply_mtu: активные интерфейсы не найдены")
            return False

        default_gateways = set(self.get_default_gateway_interfaces())
        logger.info(f"MTUManager: Обнаружены основные интерфейсы шлюза по умолчанию: {default_gateways}")

        creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        success = False
        for name, current_mtu in active:
            n_low = name.lower()
            # Проводные Ethernet-адаптеры и виртуальные адаптеры не должны урезаться по MTU,
            # если они не являются основным шлюзом интернета / тетеринга,
            # иначе сетевые онлайн-игры (Steam, сетевой мультиплеер) сбрасывают UDP-пакеты лобби (WSAEMSGSIZE).
            is_cellular = any(m in n_low for m in ("rndis", "cell", "сотов", "lte", "modem", "broadband", "tether"))
            is_virtual = any(v in n_low for v in (
                "virtual", "vmware", "vbox", "hyper-v", "loopback", "wsl",
                "radmin", "hamachi", "tap-", "tailscale", "zerotier", "wireguard", "vpn"
            ))
            is_wired = any(w in n_low for w in ("ethernet", "локальн"))
            is_primary_gateway = name in default_gateways

            # Виртуальные адаптеры никогда не урезаем
            if is_virtual:
                logger.debug(f"MTUManager: Пропуск интерфейса '{name}' (виртуальный адаптер, MTU={current_mtu} сохранен)")
                continue

            # Для проводных Ethernet-адаптеров: разрешаем MTU только если это основной шлюз (тетеринг через провод)
            # или сотовый/модемный адаптер
            if is_wired and not (is_cellular or is_primary_gateway):
                logger.debug(f"MTUManager: Пропуск интерфейса '{name}' (второстепенный проводной Ethernet без шлюза, MTU={current_mtu} сохранен)")
                continue

            orig_v6 = self._get_ipv6_mtu(name)
            needs_v4 = (current_mtu != self.target_mtu)
            needs_v6 = (orig_v6 is not None and orig_v6 != self.target_mtu)

            if needs_v4 or needs_v6:
                self.original_mtus[name] = current_mtu
                if orig_v6 is not None:
                    self.original_mtus_v6[name] = orig_v6
                cmd_v4 = ["netsh", "interface", "ipv4", "set", "subinterface", name, f"mtu={self.target_mtu}", "store=active"]
                cmd_v6 = ["netsh", "interface", "ipv6", "set", "subinterface", name, f"mtu={self.target_mtu}", "store=active"]
                try:
                    res_v4 = subprocess.run(cmd_v4, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=creationflags, check=False)
                    res_v6 = subprocess.run(cmd_v6, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=creationflags, check=False)
                    if res_v4.returncode == 0 or res_v6.returncode == 0:
                        success = True
                        logger.info(f"Установлен MTU={self.target_mtu} (IPv4/IPv6) для интерфейса '{name}' (было: v4={current_mtu}, v6={orig_v6})")
                    else:
                        logger.warning(f"Ошибка netsh set MTU для '{name}': exit_v4={res_v4.returncode}, exit_v6={res_v6.returncode}")
                except Exception as e:
                    logger.error(f"Исключение при установке MTU для '{name}': {e}")

        self._applied = success
        return success

    def restore_mtu(self) -> bool:
        """Восстанавливает исходный MTU для модифицированных интерфейсов."""
        if not self._applied or sys.platform != "win32" or not is_admin():
            logger.debug("restore_mtu: пропуск (не было применено или нет прав админа)")
            return False

        creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        restored = False
        for name, orig_mtu in list(self.original_mtus.items()):
            orig_v6 = self.original_mtus_v6.get(name, orig_mtu)
            cmd_v4 = ["netsh", "interface", "ipv4", "set", "subinterface", name, f"mtu={orig_mtu}", "store=active"]
            cmd_v6 = ["netsh", "interface", "ipv6", "set", "subinterface", name, f"mtu={orig_v6}", "store=active"]
            try:
                res_v4 = subprocess.run(cmd_v4, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=creationflags, check=False)
                res_v6 = subprocess.run(cmd_v6, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=creationflags, check=False)
                if res_v4.returncode == 0 or res_v6.returncode == 0:
                    restored = True
                    logger.info(f"Восстановлен MTU v4={orig_mtu}, v6={orig_v6} для интерфейса '{name}'")
                else:
                    logger.warning(f"Ошибка netsh restore MTU для '{name}': exit_v4={res_v4.returncode}, exit_v6={res_v6.returncode}")
            except Exception as e:
                logger.error(f"Исключение при восстановлении MTU для '{name}': {e}")

        self.original_mtus.clear()
        self.original_mtus_v6.clear()
        self._applied = False
        return restored
