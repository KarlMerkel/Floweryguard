"""Модуль проверки и защиты DNS.
Позволяет использовать защищенные DNS серверы (1.1.1.1, 8.8.8.8).
"""

import os
import sys
import subprocess
import socket
import tempfile
import json
import threading
from typing import Optional, List, Union
try:
    from Floweryguard.ttl_fix import is_admin
    from Floweryguard.logger import get_logger
except ImportError:
    from flowguard.ttl_fix import is_admin
    from flowguard.logger import get_logger

logger = get_logger("DNS")


VIRTUAL_ADAPTER_KEYWORDS = (
    "radmin", "hamachi", "virtual", "vmware", "vbox", "tap-", "wsl", "tailscale", "zerotier", "wireguard"
)


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
            logger.debug(f"Ошибка декодирования netsh в {enc}: {e}")

    if candidates:
        candidates.sort(key=lambda x: x[0], reverse=True)
        return candidates[0][2]
    return raw_bytes.decode("latin1", errors="replace")


class DNSManager:
    """Управление настройками DNS в Windows."""

    def __init__(self, primary_dns: str = "1.1.1.1", secondary_dns: str = "8.8.8.8"):
        self.primary_dns = primary_dns
        self.secondary_dns = secondary_dns
        self._changed_adapters: List[str] = []
        self._original_dns: dict = {}

    @staticmethod
    def test_resolution(domain: str = "cloudflare.com", timeout: float = 0.8) -> bool:
        """Проверяет работоспособность текущего DNS резолвера с жестким таймаутом."""
        result = [False]

        def _worker():
            try:
                socket.gethostbyname(domain)
                result[0] = True
            except Exception as e:
                logger.debug(f"DNS test_resolution({domain}) exception: {e}")

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        t.join(timeout=timeout)
        return result[0]

    @staticmethod
    def test_dns_server(ip: str, timeout: float = 1.0) -> bool:
        """Проверяет реальную отзывчивость конкретного DNS-сервера по UDP:53."""
        if not ip:
            return False
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            # Запрос типа A для домена cloudflare.com (RFC 1035)
            query = b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0a\x63\x6c\x6f\x75\x64\x66\x6c\x61\x72\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01"
            sock.sendto(query, (ip, 53))
            resp, _ = sock.recvfrom(512)
            is_ok = len(resp) >= 12 and resp[:2] == b"\xaa\xbb"
            logger.debug(f"test_dns_server({ip}): {'OK' if is_ok else 'Invalid response'}")
            return is_ok
        except Exception as e:
            logger.debug(f"test_dns_server({ip}) failed: {e}")
            return False
        finally:
            if sock:
                try:
                    sock.close()
                except Exception as e:
                    logger.debug(f"Error closing socket test_dns_server({ip}): {e}")

    @staticmethod
    def _get_backup_filepath() -> str:
        return os.path.join(tempfile.gettempdir(), "flowery_dns_backup.json")

    def _save_backup_file(self) -> None:
        try:
            with open(self._get_backup_filepath(), "w", encoding="utf-8") as f:
                json.dump({"original": self._original_dns, "changed": self._changed_adapters}, f)
            logger.debug(f"DNS backup сохранен в {self._get_backup_filepath()}")
        except Exception as e:
            logger.debug(f"Ошибка сохранения DNS backup: {e}")

    def _load_backup_file(self) -> bool:
        p = self._get_backup_filepath()
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        orig = data.get("original", {})
                        changed = data.get("changed", [])
                        if isinstance(orig, dict) and orig:
                            self._original_dns.update(orig)
                        if isinstance(changed, list) and changed:
                            for c in changed:
                                if c not in self._changed_adapters:
                                    self._changed_adapters.append(c)
                        logger.debug(f"DNS backup загружен из {p}: {len(self._changed_adapters)} адаптеров")
                        return True
            except Exception as e:
                logger.debug(f"Ошибка чтения DNS backup {p}: {e}")
        return False

    def get_active_interfaces(self) -> List[str]:
        """Получает имена активных физических сетевых интерфейсов (исключая VPN и виртуальные)."""
        interfaces = []
        try:
            creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            res = subprocess.run(
                ["netsh", "interface", "show", "interface"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=creationflags,
                check=False
            )
            out_str = _decode_netsh(res.stdout)
            for line in out_str.splitlines():
                line_lower = line.lower()
                if "connected" in line_lower or "подключен" in line_lower:
                    parts = line.split()
                    if len(parts) >= 4:
                        iface_name = " ".join(parts[3:])
                        if any(k in iface_name.lower() for k in VIRTUAL_ADAPTER_KEYWORDS):
                            continue
                        if iface_name not in interfaces:
                            interfaces.append(iface_name)
            logger.info(f"Обнаружены активные сетевые адаптеры: {interfaces}")
        except Exception as e:
            logger.error(f"Ошибка получения интерфейсов: {e}")
        return interfaces

    def _get_adapter_dns_registry(self, iface_name: str) -> Optional[Union[str, List[str]]]:
        """Определяет текущие настройки DNS адаптера напрямую через реестр Windows.
        100% не зависит от языка операционной системы и вывода netsh.
        """
        if sys.platform != "win32":
            return None
        try:
            import winreg
            net_key = r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, net_key) as parent:
                num_subkeys = winreg.QueryInfoKey(parent)[0]
                for i in range(num_subkeys):
                    guid = winreg.EnumKey(parent, i)
                    try:
                        with winreg.OpenKey(parent, rf"{guid}\Connection") as conn:
                            name, _ = winreg.QueryValueEx(conn, "Name")
                            if name.strip().lower() == iface_name.strip().lower():
                                tcp_key = rf"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{guid}"
                                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, tcp_key) as tcp:
                                    try:
                                        ns, _ = winreg.QueryValueEx(tcp, "NameServer")
                                    except FileNotFoundError:
                                        ns = ""
                                    if ns and ns.strip():
                                        ips = [ip.strip() for ip in ns.replace(",", " ").split() if ip.strip()]
                                        if ips:
                                            return ips
                                    return "dhcp"
                    except FileNotFoundError:
                        # Служебные подразделы реестра (Descriptions, Configuration) не имеют ключа Connection
                        continue
                    except Exception as e:
                        logger.debug(f"Ошибка чтения ветки GUID {guid}: {e}")
                        continue
        except Exception as e:
            logger.debug(f"Ошибка доступа к ветке Network в реестре: {e}")
        return None

    def _backup_dns(self, iface: str, creationflags: int) -> None:
        """Считывает и сохраняет текущие DNS настройки адаптера перед их заменой.
        Корректно определяет статику и DHCP на любых языковых версиях Windows (RU/EN).
        """
        if iface in self._original_dns:
            return

        # 1. Первичный метод: прямое чтение реестра Windows (мгновенно и не зависит от языка консоли)
        reg_result = self._get_adapter_dns_registry(iface)
        if reg_result is not None:
            self._original_dns[iface] = reg_result
            logger.info(f"Бэкап DNS (реестр) для '{iface}': {reg_result}")
            return

        # 2. Резервный метод: мультиязычный парсер вывода netsh
        try:
            res = subprocess.run(
                ["netsh", "interface", "ipv4", "show", "dns", f"name={iface}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=creationflags,
                check=False
            )
            out_str = _decode_netsh(res.stdout)
            import re

            static_ips = []
            in_static_section = False
            for line in out_str.splitlines():
                line_lower = line.lower()
                # Определяем секцию статических адресов (RU/EN)
                if "static" in line_lower or "статич" in line_lower:
                    in_static_section = True
                elif "dhcp" in line_lower:
                    in_static_section = False

                if in_static_section:
                    found = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
                    for ip in found:
                        if ip not in static_ips and not ip.startswith("255.") and not ip.startswith("0."):
                            static_ips.append(ip)

            if static_ips:
                self._original_dns[iface] = static_ips
            else:
                self._original_dns[iface] = "dhcp"
            logger.info(f"Бэкап DNS (netsh) для '{iface}': {self._original_dns[iface]}")
        except Exception as e:
            logger.debug(f"Ошибка бэкапа DNS через netsh для '{iface}': {e}")
            self._original_dns[iface] = "dhcp"

    def set_secure_dns(self) -> bool:
        """Настраивает защищенные DNS на подключенных интерфейсах с предварительной проверкой доступности."""
        if not is_admin():
            logger.warning("set_secure_dns: требуются права Администратора")
            return False

        # Pre-flight проверка доступности DNS-сервера по сети
        effective_primary = self.primary_dns
        effective_secondary = self.secondary_dns

        if not self.test_dns_server(effective_primary):
            # Проверяем secondary, если primary недоступен
            if effective_secondary and self.test_dns_server(effective_secondary):
                effective_primary, effective_secondary = effective_secondary, "1.1.1.1"
                logger.info(f"Основной DNS {self.primary_dns} недоступен, переключено на {effective_primary}")
            elif self.test_dns_server("1.1.1.1"):
                effective_primary = "1.1.1.1"
                effective_secondary = "77.88.8.8"
                logger.info("Основной DNS недоступен, переключено на фолбэк Cloudflare 1.1.1.1")
            else:
                logger.warning(f"DNS сервер {self.primary_dns} не отвечает на UDP 53. Системные DNS оставлены без изменений.")
                return False

        interfaces = self.get_active_interfaces()
        success = False
        creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

        logger.info(f"Установка защищённых DNS ({effective_primary} / {effective_secondary}) на адаптерах: {interfaces}")

        for iface in interfaces:
            try:
                self._backup_dns(iface, creationflags)
                res1 = subprocess.run(
                    ["netsh", "interface", "ipv4", "set", "dns", f"name={iface}", "static", effective_primary],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=creationflags,
                    check=False
                )
                logger.info(f"netsh set dns '{iface}' static {effective_primary}: exit_code={res1.returncode}")
                if effective_secondary:
                    res2 = subprocess.run(
                        ["netsh", "interface", "ipv4", "add", "dns", f"name={iface}", effective_secondary, "index=2"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        creationflags=creationflags,
                        check=False
                    )
                    logger.info(f"netsh add dns '{iface}' {effective_secondary}: exit_code={res2.returncode}")
                if iface not in self._changed_adapters:
                    self._changed_adapters.append(iface)
                success = True
            except Exception as e:
                logger.error(f"Ошибка установки DNS на интерфейсе '{iface}': {e}")

        if success:
            self._save_backup_file()
            subprocess.run(["ipconfig", "/flushdns"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=creationflags, check=False)
            logger.info("ipconfig /flushdns выполнен после установки DNS")

        return success

    def restore_dns(self, force_all: bool = False) -> bool:
        """Восстанавливает исходные настройки DNS (DHCP или статические IP пользователя)."""
        if not is_admin():
            logger.debug("restore_dns: пропуск (нет прав администратора)")
            return False

        if not self._changed_adapters:
            self._load_backup_file()

        creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        adapters_to_restore = list(self._changed_adapters)

        if not adapters_to_restore and not force_all:
            return True

        # Если запрошен принудительный сброс (например при --clean / stop.bat) или список пуст
        if force_all:
            for iface in self.get_active_interfaces():
                if iface not in adapters_to_restore:
                    adapters_to_restore.append(iface)

        logger.info(f"Восстановление DNS для адаптеров: {adapters_to_restore}")

        for iface in adapters_to_restore:
            orig = self._original_dns.get(iface, "dhcp")
            try:
                if orig == "dhcp" or not isinstance(orig, list) or not orig:
                    res = subprocess.run(
                        ["netsh", "interface", "ipv4", "set", "dns", f"name={iface}", "dhcp"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        creationflags=creationflags,
                        check=False
                    )
                    logger.info(f"Восстановлен DNS (DHCP) для '{iface}': exit_code={res.returncode}")
                else:
                    # Восстанавливаем сохранённые статические адреса пользователя
                    res = subprocess.run(
                        ["netsh", "interface", "ipv4", "set", "dns", f"name={iface}", "static", orig[0]],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        creationflags=creationflags,
                        check=False
                    )
                    logger.info(f"Восстановлен статический DNS {orig[0]} для '{iface}': exit_code={res.returncode}")
                    for i, extra_ip in enumerate(orig[1:]):
                        subprocess.run(
                            ["netsh", "interface", "ipv4", "add", "dns", f"name={iface}", extra_ip, f"index={i+2}"],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            creationflags=creationflags,
                            check=False
                        )
            except Exception as e:
                logger.error(f"Ошибка восстановления DNS для '{iface}': {e}")

        self._changed_adapters.clear()
        self._original_dns.clear()
        try:
            p = self._get_backup_filepath()
            if os.path.exists(p):
                os.remove(p)
                logger.debug(f"Файл бэкапа DNS удален: {p}")
        except Exception as e:
            logger.debug(f"Ошибка удаления файла бэкапа DNS: {e}")

        subprocess.run(["ipconfig", "/flushdns"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=creationflags, check=False)
        return True

    def heal_stale_dns(self) -> List[str]:
        """Автоматическое самовосстановление DNS при старте (Zero-Config / Auto-Heal).
        Если с прошлого аварийного сеанса остался мертвый статический DNS (например, 192.144.59.14)
        или если текущие статические DNS адаптера не отвечают на запросы —
        автоматически сбрасывает настройки адаптера в DHCP и сбрасывает локальный кэш Windows.
        Возвращает список восстановленных интерфейсов.
        """
        if not is_admin() or sys.platform != "win32":
            return []

        # Обеспечиваем включенное состояние активного зондирования Windows NCSI
        try:
            import winreg
            ncsi_key = r"SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ncsi_key, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "EnableActiveProbing", 0, winreg.REG_DWORD, 1)
            logger.debug("EnableActiveProbing установлен в 1")
        except Exception as e:
            logger.debug(f"Ошибка записи EnableActiveProbing в реестре: {e}")

        healed_interfaces = []
        interfaces = self.get_active_interfaces()
        creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

        # Список известных нерабочих адресов прошлых версий и зависших локальных заглушек
        KNOWN_DEAD_DNS = {"192.144.59.14", "94.232.43.149", "127.0.0.1", "127.0.0.53"}

        for iface in interfaces:
            current_dns = self._get_adapter_dns_registry(iface)
            need_reset = False

            if isinstance(current_dns, list) and current_dns:
                # 1. Если прописаны известные нерабочие адреса
                if any(ip in KNOWN_DEAD_DNS for ip in current_dns):
                    need_reset = True
                    logger.warning(f"На интерфейсе '{iface}' обнаружен устаревший мертвый DNS: {current_dns}")
                else:
                    # 2. Проверяем, отвечает ли хоть один из прописанных статических серверов
                    any_alive = any(self.test_dns_server(ip, timeout=0.8) for ip in current_dns)
                    if not any_alive:
                        need_reset = True
                        logger.warning(f"На интерфейсе '{iface}' статические DNS {current_dns} не отвечают")

            if need_reset:
                try:
                    res = subprocess.run(
                        ["netsh", "interface", "ipv4", "set", "dns", f"name={iface}", "dhcp"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        creationflags=creationflags,
                        check=False
                    )
                    healed_interfaces.append(iface)
                    logger.info(f"Сброшен в DHCP проблемный DNS интерфейса '{iface}': exit_code={res.returncode}")
                except Exception as e:
                    logger.error(f"Ошибка сброса DNS в DHCP для '{iface}': {e}")

        if healed_interfaces:
            subprocess.run(["ipconfig", "/flushdns"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=creationflags, check=False)
            try:
                p = self._get_backup_filepath()
                if os.path.exists(p):
                    os.remove(p)
            except Exception as e:
                logger.debug(f"Ошибка удаления файла бэкапа: {e}")

        return healed_interfaces

