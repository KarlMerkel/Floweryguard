"""Модуль подмены SNI и внедрения фейковых TLS-записей (SNI Spoofing & Desync).
Используется для обхода L7 белых списков без внешних серверов.
Строго стандартная библиотека Python.
"""

import socket
import struct
import time
from typing import List, Optional
from Floweryguard.tls_parser import is_tls_client_hello, parse_sni


def build_fake_client_hello(whitelisted_sni: str) -> bytes:
    """Генерирует валидный минимальный TLS ClientHello с указанным доверенным SNI (например, gosuslugi.ru)."""
    try:
        host_bytes = whitelisted_sni.encode("idna")
    except Exception:
        host_bytes = whitelisted_sni.encode("ascii", errors="ignore")
    # SNI extension (Type 0x0000)
    sni_data = (
        b"\x00"  # host_name type
        + struct.pack("!H", len(host_bytes))
        + host_bytes
    )
    sni_ext_payload = struct.pack("!H", len(sni_data)) + sni_data
    sni_ext = struct.pack("!H", 0x0000) + struct.pack("!H", len(sni_ext_payload)) + sni_ext_payload

    # Extensions block
    extensions_block = struct.pack("!H", len(sni_ext)) + sni_ext

    # Handshake body: Version 0x0303, Random (32b), SessionID len 0, Ciphers len 2 (0x009c), Comp len 1 (0x00)
    ch_body = (
        b"\x03\x03"
        + (b"\x77" * 32)
        + b"\x00"
        + struct.pack("!H", 2)
        + b"\x00\x9c"
        + b"\x01\x00"
        + extensions_block
    )

    # Handshake header: Type 1 (ClientHello), Length (24-bit)
    ch_len = len(ch_body)
    ch_msg = bytes([0x01, (ch_len >> 16) & 0xFF, (ch_len >> 8) & 0xFF, ch_len & 0xFF]) + ch_body

    # TLS Record Header: Type 0x16 (Handshake), Version 0x0301, Length (16-bit)
    record = b"\x16\x03\x01" + struct.pack("!H", len(ch_msg)) + ch_msg
    return record


class SNISpoofer:
    """Управление подменой SNI и отправкой спаренных TLS записей."""

    def __init__(self, whitelisted_sni: str = "gosuslugi.ru", delay: float = 0.008):
        self.whitelisted_sni = whitelisted_sni
        self.delay = delay
        self._cached_fake_record = build_fake_client_hello(whitelisted_sni)

    def send_with_fake_sni_desync(self, target_sock: socket.socket, real_client_hello: bytes) -> bool:
        """Отправляет сначала фейковый ClientHello с разрешённым SNI, чтобы DPI перевел сессию в 'allowed',
        затем через микрозадержку отправляет реальный ClientHello."""
        try:
            # 1. Отправляем фейковый ClientHello с доверенным SNI (DPI видит разрешенный ресурс)
            target_sock.sendall(self._cached_fake_record)

            if self.delay > 0:
                time.sleep(self.delay)

            # 2. Отправляем реальный ClientHello к целевому серверу
            target_sock.sendall(real_client_hello)
            return True
        except Exception:
            return False

    def obfuscate_http_request(self, raw_req: bytes) -> bytes:
        """Подменяет заголовки Host для обычного незашифрованного HTTP трафика под белый сайт."""
        try:
            lines = raw_req.split(b"\r\n")
            new_lines = []
            has_host = False
            for line in lines:
                if line.lower().startswith(b"host:"):
                    # Дублируем Host: белый сайт в первом заголовке, реальный во втором
                    new_lines.append(f"Host: {self.whitelisted_sni}".encode("ascii"))
                    new_lines.append(b"X-Forwarded-Host: " + line[5:].strip())
                    has_host = True
                else:
                    new_lines.append(line)
            return b"\r\n".join(new_lines)
        except Exception:
            return raw_req
