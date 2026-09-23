"""Модуль блокировки протокола QUIC (UDP/443) через Windows Firewall.
Принуждает браузеры и плееры (например, YouTube) переключаться на TCP/TLS,
где работают техники DPI bypass и zapret.
"""

import sys
import subprocess
from Floweryguard.ttl_fix import is_admin

RULE_NAME = "Flowery_Block_QUIC"


def _decode_netsh_output(raw_bytes: bytes) -> str:
    """Универсальное безопасное декодирование вывода системных утилит Windows."""
    if not raw_bytes:
        return ""
    import locale
    encodings = ["utf-8", locale.getpreferredencoding(), "cp866", "cp1251"]
    for enc in encodings:
        try:
            return raw_bytes.decode(enc)
        except Exception:
            continue
    return raw_bytes.decode("latin1", errors="replace")


class QUICBlocker:
    """Управление правилом брандмауэра для блокировки UDP 443."""

    def __init__(self):
        self._blocked = False

    def is_rule_present(self) -> bool:
        """Проверяет наличие правила в брандмауэре."""
        try:
            creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            res = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", f"name={RULE_NAME}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=creationflags,
                check=False
            )
            out_str = _decode_netsh_output(res.stdout)
            return res.returncode == 0 and RULE_NAME.lower() in out_str.lower()
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

            creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            res = subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={RULE_NAME}",
                    "dir=out",
                    "action=block",
                    "protocol=UDP",
                    "remoteport=443",
                    "enable=yes",
                    "profile=any",
                    "description=Flowery DPI Bypass QUIC block"
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=creationflags,
                check=False
            )

            if res.returncode == 0:
                self._blocked = True
                return True
            else:
                err_str = _decode_netsh_output(res.stderr).strip()
                print(f"[!] Не удалось добавить правило QUIC: {err_str}")
                return False
        except Exception as e:
            print(f"[!] Ошибка вызова netsh advfirewall: {e}")
            return False

    def unblock_quic(self) -> bool:
        """Удаляет правило блокировки QUIC."""
        if not is_admin():
            return False

        try:
            creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={RULE_NAME}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creationflags,
                check=False
            )
            self._blocked = False
            return True
        except Exception:
            return False
