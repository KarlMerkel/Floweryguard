"""Модуль блокировки протокола QUIC (UDP/443) через Windows Firewall.
Принуждает браузеры и плееры (например, YouTube) переключаться на TCP/TLS,
где работают техники DPI bypass и zapret.
"""

import subprocess
from Floweryguard.ttl_fix import is_admin

RULE_NAME = "Flowery_Block_QUIC"


class QUICBlocker:
    """Управление правилом брандмауэра для блокировки UDP 443."""

    def __init__(self):
        self._blocked = False

    def is_rule_present(self) -> bool:
        """Проверяет наличие правила в брандмауэре."""
        try:
            res = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", f"name={RULE_NAME}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False
            )
            return RULE_NAME in res.stdout
        except Exception:
            return False

    def block_quic(self) -> bool:
        """Добавляет правило блокировки исходящего UDP 443."""
        if not is_admin():
            print("[!] Требуются права Администратора для блокировки QUIC в Windows Firewall.")
            return False

        try:
            if self.is_rule_present():
                self.unblock_quic()

            res = subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={RULE_NAME}",
                    "dir=out",
                    "action=block",
                    "protocol=UDP",
                    "remoteport=443",
                    "description=Flowery DPI Bypass QUIC block"
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False
            )

            if res.returncode == 0:
                self._blocked = True
                return True
            else:
                print(f"[!] Не удалось добавить правило QUIC: {res.stderr.strip()}")
                return False
        except Exception as e:
            print(f"[!] Ошибка вызова netsh advfirewall: {e}")
            return False

    def unblock_quic(self) -> bool:
        """Удаляет правило блокировки QUIC."""
        if not is_admin():
            return False

        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={RULE_NAME}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False
            )
            self._blocked = False
            return True
        except Exception:
            return False
