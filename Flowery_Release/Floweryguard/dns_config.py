"""Модуль проверки и защиты DNS.
Позволяет использовать защищенные DNS серверы (1.1.1.1, 8.8.8.8).
"""

import sys
import subprocess
import socket
from typing import Optional, List, Union
from Floweryguard.ttl_fix import is_admin


def _decode_netsh(raw_bytes: bytes) -> str:
    """Безопасное декодирование системного вывода Windows (netsh)."""
    if not raw_bytes:
        return ""
    import locale
    for enc in ["utf-8", locale.getpreferredencoding(), "cp866", "cp1251"]:
        try:
            return raw_bytes.decode(enc)
        except Exception:
            continue
    return raw_bytes.decode("latin1", errors="replace")


class DNSManager:
    """Управление настройками DNS в Windows."""

    def __init__(self, primary_dns: str = "1.1.1.1", secondary_dns: str = "8.8.8.8"):
        self.primary_dns = primary_dns
        self.secondary_dns = secondary_dns
        self._changed_adapters: List[str] = []
        self._original_dns: dict = {}

    @staticmethod
    def test_resolution(domain: str = "cloudflare.com") -> bool:
        """Проверяет работоспособность текущего DNS резолвера."""
        try:
            socket.gethostbyname(domain)
            return True
        except Exception:
            return False

    def get_active_interfaces(self) -> List[str]:
        """Получает имена активных сетевых интерфейсов."""
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
                        if iface_name not in interfaces:
                            interfaces.append(iface_name)
        except Exception as e:
            print(f"[!] Ошибка получения интерфейсов: {e}")
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
                    except Exception:
                        continue
        except Exception:
            pass
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
            return

        # 2. Резервный метод: мультиязычный парсер вывода netsh
        try:
            res = subprocess.run(
                ["netsh", "interface", "ipv4", "show", "dns", f'name="{iface}"'],
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
        except Exception:
            self._original_dns[iface] = "dhcp"

    def set_secure_dns(self) -> bool:
        """Настраивает защищенные DNS на подключенных интерфейсах с бэкапом старых."""
        if not is_admin():
            print("[!] Требуются права Администратора для изменения DNS.")
            return False

        interfaces = self.get_active_interfaces()
        success = False
        creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

        for iface in interfaces:
            try:
                self._backup_dns(iface, creationflags)
                subprocess.run(
                    ["netsh", "interface", "ipv4", "set", "dns", f'name="{iface}"', "static", self.primary_dns],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=creationflags,
                    check=False
                )
                subprocess.run(
                    ["netsh", "interface", "ipv4", "add", "dns", f'name="{iface}"', self.secondary_dns, "index=2"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=creationflags,
                    check=False
                )
                if iface not in self._changed_adapters:
                    self._changed_adapters.append(iface)
                success = True
            except Exception:
                pass

        return success

    def restore_dns(self) -> bool:
        """Восстанавливает исходные настройки DNS (DHCP или статические IP пользователя)."""
        if not is_admin() or not self._changed_adapters:
            return False

        creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        for iface in self._changed_adapters:
            orig = self._original_dns.get(iface, "dhcp")
            try:
                if orig == "dhcp" or not isinstance(orig, list) or not orig:
                    subprocess.run(
                        ["netsh", "interface", "ipv4", "set", "dns", f'name="{iface}"', "dhcp"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        creationflags=creationflags,
                        check=False
                    )
                else:
                    # Восстанавливаем сохранённые статические адреса пользователя
                    subprocess.run(
                        ["netsh", "interface", "ipv4", "set", "dns", f'name="{iface}"', "static", orig[0]],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        creationflags=creationflags,
                        check=False
                    )
                    for i, extra_ip in enumerate(orig[1:]):
                        subprocess.run(
                            ["netsh", "interface", "ipv4", "add", "dns", f'name="{iface}"', extra_ip, f"index={i+2}"],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            creationflags=creationflags,
                            check=False
                        )
            except Exception:
                pass

        self._changed_adapters.clear()
        self._original_dns.clear()
        return True
