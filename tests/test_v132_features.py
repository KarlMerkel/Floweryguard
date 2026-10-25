"""Тесты для новых возможностей Flowery v1.3.2:
1. Стриппинг ECH / ESNI (Encrypted Client Hello) в tls_parser.py
2. TLS Padding (RFC 7685) инъекция в tls_parser.py
3. Стратегия tls_padding_split в strategy.py
4. Модуль управления MTU (MTUManager) в ttl_fix.py
5. Настройки v1.3.2 в config.py
"""

import unittest
import struct
import socket
from typing import List

from Floweryguard.tls_parser import (
    is_tls_client_hello,
    parse_sni,
    strip_ech_from_client_hello,
    inject_tls_padding,
    _parse_extensions_info,
    TLS_PADDING_EXTENSION_TYPE,
    ECH_EXTENSION_TYPES,
)
from Floweryguard.sni_spoofer import build_fake_client_hello
from Floweryguard.strategy import (
    StrategyExecutor,
    ALL_STRATEGIES,
    STRATEGY_DISPATCH,
    get_strategy_engine,
)
from Floweryguard.calibration import CALIBRATION_CANDIDATE_STRATEGIES
from Floweryguard.ttl_fix import MTUManager
from Floweryguard.config import Config


class DummySocket:
    """Mock-сокет для перехвата сетевых вызовов в тестах стратегий."""

    def __init__(self):
        self.sent_data = bytearray()
        self.send_calls: List[bytes] = []

    def sendall(self, data: bytes) -> None:
        self.sent_data.extend(data)
        self.send_calls.append(data)

    def send(self, data: bytes, flags: int = 0) -> int:
        self.sent_data.extend(data)
        self.send_calls.append(data)
        return len(data)


class TestV132Features(unittest.TestCase):

    def setUp(self):
        self.base_hello = build_fake_client_hello("rutracker.org")

    def test_tls_padding_injection(self):
        """Проверка инъекции RFC 7685 TLS Padding до заданного размера."""
        orig_len = len(self.base_hello)
        self.assertLess(orig_len, 1250)

        padded = inject_tls_padding(self.base_hello, target_size=1250)
        self.assertEqual(len(padded), 1250)
        self.assertTrue(is_tls_client_hello(padded))

        # Проверяем корректность длин в заголовках
        rec_len = struct.unpack("!H", padded[3:5])[0]
        self.assertEqual(rec_len, len(padded) - 5)

        hs_len = int.from_bytes(padded[6:9], "big")
        self.assertEqual(hs_len, len(padded) - 9)

        # SNI должен сохраняться неизменным
        parsed_sni = parse_sni(padded)
        self.assertIsNotNone(parsed_sni)
        self.assertEqual(parsed_sni[0], "rutracker.org")

        # Наличие расширения padding 0x0015
        info = _parse_extensions_info(padded)
        self.assertIsNotNone(info)
        _, _, exts = info
        pad_exts = [e for e in exts if e[0] == TLS_PADDING_EXTENSION_TYPE]
        self.assertEqual(len(pad_exts), 1)

    def test_tls_padding_expansion(self):
        """Проверка донаращивания уже существующего padding расширения."""
        p1 = inject_tls_padding(self.base_hello, target_size=1100)
        self.assertEqual(len(p1), 1100)

        p2 = inject_tls_padding(p1, target_size=1300)
        self.assertEqual(len(p2), 1300)

        # Должно остаться ровно одно расширение padding
        info = _parse_extensions_info(p2)
        _, _, exts = info
        pad_exts = [e for e in exts if e[0] == TLS_PADDING_EXTENSION_TYPE]
        self.assertEqual(len(pad_exts), 1)
        self.assertEqual(parse_sni(p2)[0], "rutracker.org")

    def test_tls_padding_already_larger(self):
        """Если размер уже превышает target_size, пакет не изменяется."""
        padded = inject_tls_padding(self.base_hello, target_size=50)
        self.assertEqual(padded, self.base_hello)

    def test_ech_stripping(self):
        """Проверка удаления расширений ECH (0xfe0d) и ESNI (0xff02)."""
        # Синтезируем ClientHello с ECH
        info = _parse_extensions_info(self.base_hello)
        self.assertIsNotNone(info)
        pos, l, _ = info

        ech_payload = struct.pack("!HH", 0xFE0D, 16) + b"E" * 16
        esni_payload = struct.pack("!HH", 0xFF02, 8) + b"S" * 8
        added_exts = ech_payload + esni_payload

        new_data = (
            self.base_hello[:pos]
            + struct.pack("!H", l + len(added_exts))
            + self.base_hello[pos + 2 : pos + 2 + l]
            + added_exts
            + self.base_hello[pos + 2 + l :]
        )
        # Исправляем заголовки длины
        old_rec_len = struct.unpack("!H", new_data[3:5])[0]
        old_hs_len = int.from_bytes(new_data[6:9], "big")
        new_data = (
            new_data[:3]
            + struct.pack("!H", old_rec_len + len(added_exts))
            + new_data[5:6]
            + (old_hs_len + len(added_exts)).to_bytes(3, "big")
            + new_data[9:]
        )

        info_with_ech = _parse_extensions_info(new_data)
        ext_types = [e[0] for e in info_with_ech[2]]
        self.assertIn(0xFE0D, ext_types)
        self.assertIn(0xFF02, ext_types)

        # Выполняем стриппинг ECH
        stripped = strip_ech_from_client_hello(new_data)
        self.assertTrue(is_tls_client_hello(stripped))
        self.assertEqual(len(stripped), len(self.base_hello))

        info_stripped = _parse_extensions_info(stripped)
        stripped_types = [e[0] for e in info_stripped[2]]
        self.assertNotIn(0xFE0D, stripped_types)
        self.assertNotIn(0xFF02, stripped_types)
        self.assertEqual(parse_sni(stripped)[0], "rutracker.org")

    def test_strip_ech_idempotent_on_clean_packet(self):
        """Если в пакете нет ECH, стриппинг возвращает его неизменным."""
        stripped = strip_ech_from_client_hello(self.base_hello)
        self.assertEqual(stripped, self.base_hello)

    def test_strip_ech_non_tls_safe(self):
        """Не-TLS данные возвращаются без ошибок."""
        raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        self.assertEqual(strip_ech_from_client_hello(raw), raw)
        self.assertEqual(inject_tls_padding(raw), raw)

    def test_tls_padding_split_strategy_execution(self):
        """Проверка работы стратегии tls_padding_split через StrategyExecutor (безопасный алиас)."""
        self.assertIn("tls_padding_split", STRATEGY_DISPATCH)
        self.assertTrue(hasattr(StrategyExecutor, "tls_padding_split"))

        mock_sock = DummySocket()
        StrategyExecutor.tls_padding_split(mock_sock, self.base_hello, delay=0.0)

        # Должно быть отправлено как минимум 2 фрагмента
        self.assertGreaterEqual(len(mock_sock.send_calls), 2)
        self.assertTrue(is_tls_client_hello(bytes(mock_sock.sent_data)))
        self.assertEqual(parse_sni(bytes(mock_sock.sent_data))[0], "rutracker.org")

    def test_mtu_manager(self):
        """Проверка менеджера MTU."""
        mgr = MTUManager(target_mtu=1420)
        self.assertEqual(mgr.target_mtu, 1420)
        self.assertFalse(mgr._applied)
        # get_active_interfaces не должен падать
        ifaces = mgr.get_active_interfaces()
        self.assertIsInstance(ifaces, list)

    def test_mtu_manager_apply_and_restore_mocked(self):
        """Проверка полного цикла apply/restore в MTUManager с моком netsh."""
        from unittest.mock import patch, MagicMock
        mgr = MTUManager(target_mtu=1420)

        with patch("Floweryguard.ttl_fix.is_admin", return_value=True), \
             patch.object(mgr, "get_default_gateway_interfaces", return_value=["Wi-Fi"]), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=b"   MTU  MediaSenseState      Bytes In     Bytes Out  Interface\n------  ---------------  ------------  ------------  ---------\n  1500                1          1000          1000  Wi-Fi\n"
            )
            ifaces = mgr.get_active_interfaces()
            self.assertEqual(ifaces, [("Wi-Fi", 1500)])

            applied = mgr.apply_mtu()
            self.assertTrue(applied)
            self.assertEqual(mgr.original_mtus, {"Wi-Fi": 1500})
            self.assertTrue(mgr._applied)

            restored = mgr.restore_mtu()
            self.assertTrue(restored)
            self.assertEqual(mgr.original_mtus, {})
            self.assertFalse(mgr._applied)

    def test_config_v132_fields(self):
        """Проверка наличия новых настроек в классе Config."""
        cfg = Config("config.ini")
        self.assertIsInstance(cfg.strip_ech, bool)
        self.assertIsInstance(cfg.tls_padding, bool)
        self.assertIsInstance(cfg.clamp_mss, bool)
        self.assertIsInstance(cfg.target_mtu, int)
        self.assertEqual(cfg.target_mtu, 1420)


if __name__ == "__main__":
    unittest.main()
