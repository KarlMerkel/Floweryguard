"""Тесты для модуля инъекции битой контрольной суммы (Bad Checksum Injection) и VoiceHelper."""

import os
import unittest
import socket
import struct
import ctypes
from unittest.mock import MagicMock, patch
from Floweryguard.badsum_injector import (
    calc_ip_checksum,
    calc_tcp_checksum,
    calc_udp_checksum,
    corrupt_checksum,
    craft_fake_tcp_segment,
    craft_fake_ipv4_packet,
    WinDivertBadsumController,
    WinDivertAddress,
    get_badsum_controller,
)
from Floweryguard.sni_spoofer import SNISpoofer, build_fake_client_hello
from Floweryguard.voice_helper import VoiceHelper
from Floweryguard.config import Config


class TestBadsumInjector(unittest.TestCase):
    """Тестирование RFC 1071 чексумм и алгоритмов искажения (Badsum)."""

    def test_rfc791_ip_checksum(self):
        """Проверка контрольной суммы IPv4 по эталонному примеру RFC 791."""
        # 4500003c1c46400040060000ac100a63ac100a0c
        hdr_zero_sum = bytes.fromhex("4500003c1c46400040060000ac100a63ac100a0c")
        expected_sum = 0xB1E6
        actual_sum = calc_ip_checksum(hdr_zero_sum)
        self.assertEqual(actual_sum, expected_sum)

    def test_odd_length_ip_checksum(self):
        """Проверка расчета контрольной суммы для данных нечетной длины."""
        data = b"\x12\x34\x56"
        c = calc_ip_checksum(data)
        self.assertIsInstance(c, int)
        self.assertTrue(0 <= c <= 0xFFFF)

    def test_tcp_checksum_calculation(self):
        """Проверка расчета контрольной суммы TCP сегмента."""
        src_ip = "192.168.1.10"
        dst_ip = "93.184.216.34"
        tcp_hdr = struct.pack("!HHIIBBHHH", 12345, 443, 1000, 0, (5 << 4), 0x02, 64240, 0, 0)
        c = calc_tcp_checksum(src_ip, dst_ip, tcp_hdr)
        self.assertEqual(c, 0x8788)

    def test_udp_checksum_calculation(self):
        """Проверка расчета контрольной суммы UDP."""
        src_ip = "192.168.1.10"
        dst_ip = "1.1.1.1"
        payload = b"PING"
        udp_hdr = struct.pack("!HHHH", 50000, 53, 8 + len(payload), 0)
        c = calc_udp_checksum(src_ip, dst_ip, udp_hdr + payload)
        self.assertTrue(0 <= c <= 0xFFFF)

    def test_corrupt_checksum(self):
        """Проверка инъекции битой контрольной суммы."""
        valid_sum = 0xB1E6
        bad = corrupt_checksum(valid_sum, xor_mask=0x1234)
        self.assertNotEqual(bad, valid_sum)
        self.assertNotEqual(bad, 0)
        self.assertTrue(0 <= bad <= 0xFFFF)

        # Проверка крайнего случая, когда результат равен нулю
        zero_case = corrupt_checksum(0x1234, xor_mask=0x1234)
        self.assertNotEqual(zero_case, 0)

    def test_craft_fake_tcp_segment(self):
        """Проверка сборки фейкового TCP сегмента со сбитой чексуммой."""
        src_ip = "10.0.0.2"
        dst_ip = "104.16.123.96"
        payload = b"\x16\x03\x01\x00\x05DUMMY"

        # 1. Сегмент со сбитой суммой (corrupt_sum=True)
        seg_bad = craft_fake_tcp_segment(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=54321,
            dst_port=443,
            seq=1000,
            ack=2000,
            payload=payload,
            corrupt_sum=True,
            xor_mask=0x1234,
        )
        self.assertEqual(len(seg_bad), 20 + len(payload))
        actual_bad_sum = struct.unpack("!H", seg_bad[16:18])[0]

        # 2. Сегмент с валидной суммой (corrupt_sum=False)
        seg_good = craft_fake_tcp_segment(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=54321,
            dst_port=443,
            seq=1000,
            ack=2000,
            payload=payload,
            corrupt_sum=False,
        )
        actual_good_sum = struct.unpack("!H", seg_good[16:18])[0]

        self.assertNotEqual(actual_bad_sum, actual_good_sum)
        self.assertEqual(seg_bad[20:], payload)

    def test_craft_fake_ipv4_packet(self):
        """Проверка сборки полного пакета IPv4."""
        src_ip = "192.168.1.50"
        dst_ip = "8.8.8.8"
        payload = b"TEST"
        pkt = craft_fake_ipv4_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            transport_payload=payload,
            ttl=12,
        )
        self.assertEqual(len(pkt), 20 + len(payload))
        self.assertEqual(pkt[8], 12)  # Поле TTL

    def test_windivert_address_structure(self):
        """Проверка размера и полей структуры WinDivertAddress (WinDivert 2.x, 80 байт)."""
        self.assertEqual(ctypes.sizeof(WinDivertAddress), 80)
        addr = WinDivertAddress()
        addr.Timestamp = 123456789
        addr.Bitfields = (1 << 17)  # Outbound
        addr.Reserved2 = 0
        self.assertEqual(addr.Timestamp, 123456789)
        self.assertEqual(addr.Bitfields, (1 << 17))
        self.assertEqual(addr.Reserved2, 0)

    def test_windivert_controller_lifecycle(self):
        """Проверка инициализации контроллера и безопасного управления дескриптором."""
        ctrl = WinDivertBadsumController()
        self.assertIsInstance(ctrl.is_available, bool)
        # Вызов close на закрытом контроллере не должен вызывать исключений
        ctrl.close()
        self.assertIsNone(ctrl._handle)

    def test_inject_fake_sni_packet_mock(self):
        """Проверка сборки и отправки фейкового пакета в inject_fake_sni_packet."""
        ctrl = WinDivertBadsumController()
        mock_sock = MagicMock()
        mock_sock.getsockname.return_value = ("192.168.1.100", 55555)
        mock_sock.getpeername.return_value = ("93.184.216.34", 443)

        with patch.object(ctrl, "inject_packet", return_value=True) as mock_inject:
            result = ctrl.inject_fake_sni_packet(mock_sock, b"FAKE_TLS", corrupt_sum=True, ttl=64)
            self.assertTrue(result)
            mock_inject.assert_called_once()
            raw_pkt = mock_inject.call_args[0][0]
            self.assertIsInstance(raw_pkt, bytes)
            # IPv4 заголовок 20 байт + TCP заголовок 20 байт + payload
            self.assertEqual(len(raw_pkt), 40 + len(b"FAKE_TLS"))

    def test_get_badsum_controller_singleton(self):
        """Проверка работы синглтона get_badsum_controller."""
        c1 = get_badsum_controller()
        c2 = get_badsum_controller()
        self.assertIs(c1, c2)

    def test_sni_spoofer_no_fake_in_socket(self):
        """Проверка, что SNISpoofer отправляет в сокет ТОЛЬКО настоящий ClientHello,
        а фейковый ClientHello уходит исключительно через badsum инъектор."""
        spoofer = SNISpoofer(whitelisted_sni="gosuslugi.ru", delay=0)
        mock_sock = MagicMock()
        real_ch = b"\x16\x03\x01\x00\x10REAL_CLIENT_HELLO"

        with patch("Floweryguard.sni_spoofer.get_badsum_controller") as mock_get_ctrl:
            mock_ctrl = MagicMock()
            mock_ctrl.is_available = True
            mock_get_ctrl.return_value = mock_ctrl

            res = spoofer.send_with_fake_sni_desync(mock_sock, real_ch)
            self.assertTrue(res)

            # Проверяем, что фейковый пакет инжектирован через WinDivert контроллер
            mock_ctrl.inject_fake_sni_packet.assert_called_once_with(mock_sock, spoofer._cached_fake_record)

            # КРИТИЧЕСКАЯ ПРОВЕРКА: в реальный TCP сокет отправлен ровно один раз ТОЛЬКО реальный ClientHello!
            self.assertEqual(mock_sock.sendall.call_count, 1)
            mock_sock.sendall.assert_called_once_with(real_ch)


class TestVoiceHelperBadsum(unittest.TestCase):
    """Тестирование формирования параметров winws с Badsum и AutoTTL."""

    def test_build_args_badsum(self):
        """Проверка аргументов winws с fooling=badsum."""
        helper = VoiceHelper(fooling="badsum", autottl=False, ttl=0, repeats=4)
        args = helper.build_winws_args()
        self.assertIn("--dpi-desync-fooling=badsum", args)
        self.assertIn("--dpi-desync-repeats=4", args)

    def test_build_args_badsum_and_autottl(self):
        """Проверка комбинации badsum + autottl."""
        helper = VoiceHelper(fooling="badsum", autottl=True, autottl_delta=3, repeats=6)
        args = helper.build_winws_args()
        self.assertIn("--dpi-desync-fooling=badsum", args)
        self.assertIn("--dpi-desync-autottl=3", args)

    def test_build_args_hybrid_fooling_string(self):
        """Проверка гибридной строки fooling='badsum,autottl'."""
        helper = VoiceHelper(fooling="badsum,autottl", autottl_delta=2)
        args = helper.build_winws_args()
        self.assertIn("--dpi-desync-fooling=badsum", args)
        self.assertIn("--dpi-desync-autottl=2", args)

    def test_build_args_ttl(self):
        """Проверка аргументов с жестким TTL."""
        helper = VoiceHelper(fooling="badsum", autottl=False, ttl=7)
        args = helper.build_winws_args()
        self.assertIn("--dpi-desync-fooling=badsum", args)
        self.assertIn("--dpi-desync-ttl=7", args)

    def test_config_desync_properties(self):
        """Проверка чтения настроек [desync] из Config."""
        cfg = Config("config.ini")
        self.assertTrue(hasattr(cfg, "packet_desync_fooling"))
        self.assertTrue(hasattr(cfg, "packet_desync_autottl"))
        self.assertTrue(hasattr(cfg, "packet_desync_ttl"))
        self.assertEqual(cfg.packet_desync_fooling, "badsum")
        self.assertTrue(cfg.packet_desync_autottl)


if __name__ == "__main__":
    unittest.main()
