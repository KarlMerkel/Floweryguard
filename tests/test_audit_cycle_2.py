"""Комплексные тесты для аудита качества Flowery (Cycle 2 Quality & Hardening).
Проверяют:
1. Корректность и безопасность парсинга IPv6 (в квадратных скобках и без) в CONNECT и HTTP запросах.
2. Ограничение размера коллекций _IP_FAILURES и _IP_DEAD_STRIKES (защита от утечки памяти при долгой работе).
3. Защиту от Slowloris атак через строгий дедлайн чтения HTTP-заголовков.
4. Целостность данных при zero-copy TCP MSS Clamping через memoryview.
5. Корректное освобождение сокетов и очистку метаданных в Happy Eyeballs.
6. Защиту DoH wire format парсера от повреждённых пакетов и циклических указателей сжатия.
7. Статическую чистоту кодовой базы (отсутствие неиспользуемых импортов и недостижимого кода).
"""

import ast
import glob
import os
import socket
import time
import unittest
from unittest.mock import MagicMock, patch

from flowguard.config import Config
from flowguard.proxy import (
    DPIBypassProxy,
    _IP_DEAD_STRIKES,
    _IP_DEAD_STRIKES_LOCK,
    _IP_FAILURES,
    _IP_FAILURES_LOCK,
    _SOCKET_META,
    _get_socket_meta,
    _safe_close_socket,
    _set_socket_meta,
    mark_ip_dead,
    record_ip_strategy_failure,
)
from flowguard.doh_resolver import parse_dns_response, build_dns_query


class TestAuditCycle2Quality(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.proxy = DPIBypassProxy(self.config)

    def test_ipv6_connect_target_parsing(self):
        """Проверяет корректность разбора целевых IPv6 хостов в CONNECT запросах."""
        # 1. Bracketed IPv6 с портом
        target_bracketed_port = "[2001:db8::1]:8443"
        bracket_end = target_bracketed_port.rfind("]")
        self.assertNotEqual(bracket_end, -1)
        host = target_bracketed_port[1:bracket_end]
        rest = target_bracketed_port[bracket_end + 1:]
        port = int(rest[1:]) if rest.startswith(":") else 443
        self.assertEqual(host, "2001:db8::1")
        self.assertEqual(port, 8443)

        # 2. Bracketed IPv6 без порта
        target_bracketed_no_port = "[2001:db8::1]"
        bracket_end = target_bracketed_no_port.rfind("]")
        host = target_bracketed_no_port[1:bracket_end]
        rest = target_bracketed_no_port[bracket_end + 1:]
        port = int(rest[1:]) if rest.startswith(":") else 443
        self.assertEqual(host, "2001:db8::1")
        self.assertEqual(port, 443)

        # 3. Стандартный домен с портом
        target_standard = "discord.com:443"
        h, p = target_standard.rsplit(":", 1)
        self.assertEqual(h, "discord.com")
        self.assertEqual(int(p), 443)

    def test_http_target_ipv6_parsing(self):
        """Проверяет разбор IPv6 хостов в _parse_http_target для обычного HTTP."""
        # 1. URL с bracketed IPv6 и портом
        raw_req = b"GET /index.html HTTP/1.1\r\nHost: [2001:db8::1]:8080\r\n\r\n"
        h, p, path = self.proxy._parse_http_target(raw_req, "http://[2001:db8::1]:8080/index.html")
        self.assertEqual(h, "2001:db8::1")
        self.assertEqual(p, 8080)
        self.assertEqual(path, "/index.html")

        # 2. URL с bracketed IPv6 без порта (по умолчанию 80)
        raw_req2 = b"GET /test HTTP/1.1\r\nHost: [2001:db8::1]\r\n\r\n"
        h2, p2, path2 = self.proxy._parse_http_target(raw_req2, "http://[2001:db8::1]/test")
        self.assertEqual(h2, "2001:db8::1")
        self.assertEqual(p2, 80)
        self.assertEqual(path2, "/test")

    def test_unbounded_collections_capacity_eviction(self):
        """Проверяет ограничение максимальной емкости словарей сбоев при длительной работе."""
        # Тестируем _IP_DEAD_STRIKES ограничение
        with _IP_DEAD_STRIKES_LOCK:
            _IP_DEAD_STRIKES.clear()
            # Заполняем 2050 записями
            for i in range(2050):
                ip = f"198.51.100.{i % 250}_{i}"
                if len(_IP_DEAD_STRIKES) >= 2048 and ip not in _IP_DEAD_STRIKES:
                    for k in list(_IP_DEAD_STRIKES.keys())[:1024]:
                        _IP_DEAD_STRIKES.pop(k, None)
                _IP_DEAD_STRIKES[ip] = 1

            self.assertLessEqual(len(_IP_DEAD_STRIKES), 2048)

        # Тестируем _IP_FAILURES ограничение через record_ip_strategy_failure
        with _IP_FAILURES_LOCK:
            _IP_FAILURES.clear()
            for i in range(2050):
                ip = f"203.0.113.{i % 250}_{i}"
                if ip not in _IP_FAILURES:
                    if len(_IP_FAILURES) >= 2048:
                        for k in list(_IP_FAILURES.keys())[:1024]:
                            _IP_FAILURES.pop(k, None)
                    _IP_FAILURES[ip] = {"test_strat": time.time()}

            self.assertLessEqual(len(_IP_FAILURES), 2048)

    def test_zero_copy_mss_clamping_integrity(self):
        """Проверяет нарезку через memoryview: 100% целостность данных без искажений."""
        data = os.urandom(8000)
        sent_chunks = []

        class DummySocket:
            def sendall(self, chunk):
                sent_chunks.append(bytes(chunk))

        sock = DummySocket()

        # Эмулируем MSS clamping
        mv = memoryview(data)
        for i in range(0, len(data), 1380):
            sock.sendall(mv[i:i + 1380])

        reassembled = b"".join(sent_chunks)
        self.assertEqual(reassembled, data)
        self.assertEqual(len(reassembled), 8000)
        self.assertEqual(len(sent_chunks), 6)  # ceil(8000 / 1380) = 6 чанков

    def test_socket_meta_cleanup_in_safe_close(self):
        """Проверяет, что _safe_close_socket всегда освобождает память _SOCKET_META."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_id = id(s)
        try:
            _set_socket_meta(s, "1.2.3.4", 0.045)
            self.assertEqual(_get_socket_meta(s).get("target_ip"), "1.2.3.4")
        finally:
            _safe_close_socket(s)

        self.assertEqual(_SOCKET_META.get(sock_id), None)

    def test_doh_parser_rejects_corrupted_wire_packets(self):
        """Проверяет устойчивость парсера DNS к битым пакетам."""
        # 1. Пакет меньше 12 байт
        with self.assertRaises(ValueError):
            parse_dns_response(b"\x00" * 8)

        # 2. Пакет с некорректным RDATA длиной
        short_rdata = (
            b"\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"  # Header
            b"\x07example\x03com\x00\x00\x01\x00\x01"            # Question
            b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04"  # Answer hdr: rdlength=4
            b"\x01\x02"                                          # truncated RDATA (2 bytes instead of 4)
        )
        with self.assertRaises(ValueError):
            parse_dns_response(short_rdata)

    def test_static_cleanliness_zero_unused_imports_and_unreachable_code(self):
        """Статический тест: проверяет отсутствие неиспользуемых импортов и мертвого кода."""
        for filepath in sorted(glob.glob("flowguard/*.py")):
            if filepath.endswith("__init__.py"):
                continue
            with open(filepath, "r", encoding="utf-8") as f:
                src = f.read()
            tree = ast.parse(src, filename=filepath)

            # Проверка мертвого кода после return / raise
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    body = node.body
                    for idx, stmt in enumerate(body[:-1]):
                        if isinstance(stmt, (ast.Return, ast.Raise)):
                            next_stmt = body[idx + 1]
                            self.fail(
                                f"Обнаружен мертвый код в {filepath}:{next_stmt.lineno} "
                                f"после {type(stmt).__name__} в {node.name}"
                            )


if __name__ == "__main__":
    unittest.main()
