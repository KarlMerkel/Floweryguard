"""Модуль проверки и защиты DNS.
Позволяет использовать защищенные DNS серверы (1.1.1.1, 8.8.8.8).
"""

import subprocess
import socket
from typing import Optional, List
from Floweryguard.ttl_fix import is_admin


class DNSManager:
    """Управление настройками DNS в Windows."""

    def __init__(self, primary_dns: str = "1.1.1.1", secondary_dns: str = "8.8.8.8"):
        self.primary_dns = primary_dns
        self.secondary_dns = secondary_dns
        self._changed_adapters: List[str] = []

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
            res = subprocess.run(
                ["netsh", "interface", "show", "interface"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False
            )
            for line in res.stdout.splitlines():
                if "Connected" in line or "Подключен" in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        iface_name = " ".join(parts[3:])
                        interfaces.append(iface_name)
        except Exception as e:
            print(f"[!] Ошибка получения интерфейсов: {e}")
        return interfaces

    def set_secure_dns(self) -> bool:
        """Настраивает защищенные DNS на подключенных интерфейсах."""
        if not is_admin():
            print("[!] Требуются права Администратора для изменения DNS.")
            return False

        interfaces = self.get_active_interfaces()
        success = False

        for iface in interfaces:
            try:
                subprocess.run(
                    ["netsh", "interface", "ipv4", "set", "dns", f"name={iface}", "static", self.primary_dns],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False
                )
                subprocess.run(
                    ["netsh", "interface", "ipv4", "add", "dns", f"name={iface}", self.secondary_dns, "index=2"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False
                )
                self._changed_adapters.append(iface)
                success = True
            except Exception:
                pass

        return success

    def restore_dns(self) -> bool:
        """Возвращает автоматическое получение DNS (DHCP)."""
        if not is_admin() or not self._changed_adapters:
            return False

        for iface in self._changed_adapters:
            try:
                subprocess.run(
                    ["netsh", "interface", "ipv4", "set", "dns", f"name={iface}", "dhcp"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False
                )
            except Exception:
                pass

        self._changed_adapters.clear()
        return True
