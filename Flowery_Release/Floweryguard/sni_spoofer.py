"""Модуль генерации фейковых TLS ClientHello и подмены SNI.

ВАЖНОЕ АРХИТЕКТУРНОЕ ПРИМЕЧАНИЕ:
На уровне пользовательского TCP-прокси (socket.SOCK_STREAM) без драйвера перехвата пакетов 
(WinDivert / NFQUEUE) отправка фейкового ClientHello в реальное TCP-соединение приводит к 
разрыву сессии сервером из-за нарушения TLS RFC (два ClientHello подряд).

В Flowery v1.3.0 для безопасной подмены SNI реализована технология Bad Checksum Injection
(см. badsum_injector.py и voice_helper.py):
Фейковый пакет отправляется с заведомо испорченной контрольной суммой (badsum).
Аппаратный стек сетевой карты целевого сервера мгновенно отбрасывает его без разрыва 
соединения, а пассивный ТСПУ-инспектор (не проверяющий чексумму) захватывает поддельный
SNI и успешно десинхронизируется!
"""

import logging
import socket
import struct
import time

logger = logging.getLogger("Flowery.SNISpoofer")


def build_fake_client_hello(whitelisted_sni: str) -> bytes:
    """Генерирует валидный современный TLS ClientHello (TLS 1.3 / 1.2) с указанным SNI."""
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

    # Supported Groups extension (Type 0x000a) - x25519 (0x001d), secp256r1 (0x0017), secp384r1 (0x0018)
    groups_payload = struct.pack("!H", 6) + b"\x00\x1d\x00\x17\x00\x18"
    groups_ext = struct.pack("!H", 0x000a) + struct.pack("!H", len(groups_payload)) + groups_payload

    # EC Point Formats extension (Type 0x000b) - uncompressed (0x00)
    ec_payload = b"\x01\x00"
    ec_ext = struct.pack("!H", 0x000b) + struct.pack("!H", len(ec_payload)) + ec_payload

    # Signature Algorithms extension (Type 0x000d)
    sig_payload = struct.pack("!H", 8) + b"\x04\x03\x08\x04\x04\x01\x05\x01"
    sig_ext = struct.pack("!H", 0x000d) + struct.pack("!H", len(sig_payload)) + sig_payload

    # Supported Versions extension (Type 0x002b) - TLS 1.3 (0x0304), TLS 1.2 (0x0303)
    versions_payload = b"\x04\x03\x04\x03\x03"
    versions_ext = struct.pack("!H", 0x002b) + struct.pack("!H", len(versions_payload)) + versions_payload

    # Key Share extension (Type 0x0033) - x25519 with 32-byte key
    key_bytes = b"\x2a" * 32
    key_share_entry = struct.pack("!H", 0x001d) + struct.pack("!H", 32) + key_bytes
    key_share_payload = struct.pack("!H", len(key_share_entry)) + key_share_entry
    key_share_ext = struct.pack("!H", 0x0033) + struct.pack("!H", len(key_share_payload)) + key_share_payload

    # Modern ciphers (TLS 1.3 + modern TLS 1.2 ECDHE + fallback RSA)
    ciphers_data = b"\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9\xcc\xa8\x00\x9c"
    ciphers_block = struct.pack("!H", len(ciphers_data)) + ciphers_data

    # Extensions block
    extensions = sni_ext + groups_ext + ec_ext + sig_ext + versions_ext + key_share_ext
    extensions_block = struct.pack("!H", len(extensions)) + extensions

    # Handshake body: Version 0x0303, Random (32b), SessionID len 0, Ciphers, Comp len 1 (0x00)
    ch_body = (
        b"\x03\x03"
        + (b"\x77" * 32)
        + b"\x00"
        + ciphers_block
        + b"\x01\x00"
        + extensions_block
    )

    # Handshake header: Type 1 (ClientHello), Length (24-bit)
    ch_len = len(ch_body)
    ch_msg = bytes([0x01, (ch_len >> 16) & 0xFF, (ch_len >> 8) & 0xFF, ch_len & 0xFF]) + ch_body

    # TLS Record Header: Type 0x16 (Handshake), Version 0x0301, Length (16-bit)
    record = b"\x16\x03\x01" + struct.pack("!H", len(ch_msg)) + ch_msg
    return record


def build_fake_http_request(whitelisted_sni: str) -> bytes:
    """Генерирует минимальный фейковый HTTP GET-запрос с указанным доверенным Host (например, gosuslugi.ru)."""
    try:
        host_ascii = whitelisted_sni.encode("idna").decode("ascii")
    except Exception:
        host_ascii = whitelisted_sni.encode("ascii", errors="ignore").decode("ascii")
    return (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host_ascii}\r\n"
        f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        f"Accept: */*\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode("ascii")


try:
    from Floweryguard.badsum_injector import get_badsum_controller
except ImportError:
    from flowguard.badsum_injector import get_badsum_controller


class SNISpoofer:
    """Управление подменой SNI и отправкой спаренных TLS/HTTP записей."""

    def __init__(self, whitelisted_sni: str = "gosuslugi.ru", delay: float = 0.008):
        self.whitelisted_sni = whitelisted_sni
        self.delay = delay
        self._cached_fake_record = build_fake_client_hello(whitelisted_sni)
        self._cached_fake_http = build_fake_http_request(whitelisted_sni)

    def send_with_fake_sni_desync(self, target_sock: socket.socket, real_client_hello: bytes) -> bool:
        """Отправляет фейковый ClientHello с разрешённым SNI через WinDivert Badsum инъекцию
        (чтобы DPI увидел белый SNI и разблокировал сессию, а сервер отбросил пакет из-за битой чексуммы),
        после чего отправляет настоящий ClientHello в сокет соединения.
        Возвращает False, если WinDivert недоступен или инъекция не удалась (B9).
        """
        try:
            controller = get_badsum_controller()
            if not controller or not controller.is_available:
                logger.debug("WinDivert badsum controller недоступен для fake SNI desync")
                return False

            injected = controller.inject_fake_sni_packet(target_sock, self._cached_fake_record)
            if not injected:
                logger.debug("WinDivert inject_fake_sni_packet вернул False")
                return False

            if self.delay > 0:
                time.sleep(self.delay)

            target_sock.sendall(real_client_hello)
            return True
        except Exception as e:
            logger.warning("Failed to send TLS with fake SNI desync: %s", e)
            return False

    def send_with_fake_http_desync(self, target_sock: socket.socket, real_http_req: bytes) -> bool:
        """Отправляет фейковый HTTP GET-запрос с белым Host через WinDivert Badsum инъекцию
        (DPI видит белый Host gosuslugi.ru и десинхронизируется, а реальный веб-сервер отбрасывает пакет
        из-за битой чексуммы), после чего отправляет настоящий HTTP-запрос в сокет соединения."""
        try:
            try:
                controller = get_badsum_controller()
                if controller and controller.is_available:
                    controller.inject_fake_sni_packet(target_sock, self._cached_fake_http)
            except Exception as e:
                logger.debug("WinDivert badsum HTTP injection skipped/failed: %s", e)

            if self.delay > 0:
                time.sleep(self.delay)

            target_sock.sendall(real_http_req)
            return True
        except Exception as e:
            logger.warning("Failed to send HTTP with fake desync: %s", e)
            return False

    def obfuscate_http_request(self, raw_req: bytes) -> bytes:
        """Обфусцирует регистр заголовка Host (hoSt:) с сохранением реального хоста (RFC 7230 / RFC 9110).
        Предотвращает поломку виртуального хостинга на удаленных веб-серверах."""
        try:
            if b"\r\n\r\n" in raw_req:
                head_part, body_part = raw_req.split(b"\r\n\r\n", 1)
                has_separator = True
            else:
                head_part, body_part = raw_req, b""
                has_separator = False

            lines = head_part.split(b"\r\n")
            new_lines = []
            replaced_host = False
            for line in lines:
                if not replaced_host and line.lower().startswith(b"host:"):
                    # Меняем регистр заголовка Host: на hoSt:, оставляя реальное имя хоста целевого сайта!
                    host_val = line[5:].strip()
                    new_lines.append(b"hoSt: " + host_val)
                    replaced_host = True
                else:
                    new_lines.append(line)

            new_head = b"\r\n".join(new_lines)
            if has_separator:
                return new_head + b"\r\n\r\n" + body_part
            return new_head
        except Exception as e:
            logger.debug("Failed to obfuscate HTTP request, using raw: %s", e)
            return raw_req
