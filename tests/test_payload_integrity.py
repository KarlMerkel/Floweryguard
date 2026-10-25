"""Тесты криптографической целостности полезной нагрузки и совместимости с TLS 1.3.

Предотвращают регрессии:
1. Поломку Transcript-Hash и ошибок DECRYPTION_FAILED_OR_BAD_RECORD_MAC / ERR_SSL_PROTOCOL_ERROR в TLS 1.3.
2. Несанкционированную модификацию байтов полезной нагрузки (bit-by-bit payload preservation).
3. Потерю или искажение данных при граничных условиях и мульти-записях TLS.
4. Включение опасных/мутирующих техник в дефолтной конфигурации.
"""

import unittest
import socket
import ssl
import struct
import threading
import time
from typing import List

from Floweryguard.tls_parser import (
    is_tls_client_hello,
    parse_sni,
    get_sni_offsets,
    create_tls_record_fragments,
    create_multi_tls_record_fragments,
)
from Floweryguard.strategy import (
    StrategyExecutor,
    ALL_STRATEGIES,
    STRATEGY_DISPATCH,
    get_strategy_engine,
)
from Floweryguard.config import Config, DEFAULT_CONFIG


class MockRecordingSocket:
    """Фиктивный сокет, записывающий все переданные чанки байт."""

    def __init__(self):
        self.sent_chunks: List[bytes] = []

    def sendall(self, data: bytes) -> None:
        if isinstance(data, (bytes, bytearray)):
            self.sent_chunks.append(bytes(data))

    def send(self, data: bytes, flags: int = 0) -> int:
        if isinstance(data, (bytes, bytearray)):
            self.sent_chunks.append(bytes(data))
            return len(data)
        return 0


def generate_valid_tls_client_hello(hostname: str = "www.google.com") -> bytes:
    """Генерирует валидный синтетический TLS 1.3 ClientHello с заданным SNI."""
    host_bytes = hostname.encode("idna")
    sni_entry = b"\x00" + struct.pack("!H", len(host_bytes)) + host_bytes
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack("!H", 0x0000) + struct.pack("!H", len(sni_list)) + sni_list

    # Добавляем supported_versions (TLS 1.3: 0x0304)
    sup_versions_payload = b"\x02\x03\x04"
    sup_versions_ext = struct.pack("!H", 0x002B) + struct.pack("!H", len(sup_versions_payload)) + sup_versions_payload

    exts = sni_ext + sup_versions_ext
    exts_block = struct.pack("!H", len(exts)) + exts

    session_id = b"\x00" * 32
    ciphers = struct.pack("!H", 4) + b"\x13\x01\x13\x02"  # TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
    comp = b"\x01\x00"

    body = b"\x03\x03" + (b"\x55" * 32) + bytes([len(session_id)]) + session_id + ciphers + comp + exts_block
    hs_len = len(body)
    hs_msg = bytes([0x01, (hs_len >> 16) & 0xFF, (hs_len >> 8) & 0xFF, hs_len & 0xFF]) + body
    record = b"\x16\x03\x01" + struct.pack("!H", len(hs_msg)) + hs_msg
    return record


class TestPayloadIntegrity(unittest.TestCase):
    """Проверка гарантий целостности байтов полезной нагрузки."""

    def setUp(self):
        self.test_hosts = [
            "www.google.com",
            "rr1---sn-aj5go5-5i.googlevideo.com",
            "ya.ru",
            "cloudflare.com",
            "discord.com",
            "rutracker.org",
            "github.com",
            "vk.com"
        ]

    def test_default_config_forbids_payload_mutations(self):
        """Проверка, что опасные мутирующие настройки по умолчанию СТРОГО ОТКЛЮЧЕНЫ."""
        cfg = Config()
        self.assertFalse(cfg.oob_data, "oob_data MUST be False by default to prevent TLS 1.3 desync")
        self.assertFalse(cfg.strip_ech, "strip_ech MUST be False by default to prevent Transcript-Hash failure")
        self.assertFalse(cfg.tls_padding, "tls_padding MUST be False by default to prevent handshake MAC corruption")

        bypass_defaults = DEFAULT_CONFIG["bypass"]
        self.assertFalse(bypass_defaults["oob_data"])
        self.assertFalse(bypass_defaults["strip_ech"])
        self.assertFalse(bypass_defaults["tls_padding"])

    def test_all_strategies_are_non_mutating(self):
        """Проверка, что ALL_STRATEGIES содержит исключительно чистые техники фрагментации."""
        forbidden_mutators = [
            "disoob_sni",
            "mixed_case_tcpsplit",
            "dummy_record_prepend",
            "tls_padding_split",
            "tcp_overlap_sni",
        ]
        for f in forbidden_mutators:
            self.assertNotIn(
                f,
                ALL_STRATEGIES,
                f"Стратегия {f} мутирует байты пакета и не должна входить в ALL_STRATEGIES!"
            )

    def test_tcp_fragmentation_strategies_preserve_exact_bytes(self):
        """Проверка bit-by-bit: конкатенация TCP-сегментов даёт точную копию оригинального ClientHello."""
        tcp_strategies = [
            "direct",
            "boringssl_split",
            "tcp_split_sni_start",
            "tcp_split_sni_mid",
            "multi_split",
        ]

        for host in self.test_hosts:
            client_hello = generate_valid_tls_client_hello(host)
            for strat_name in tcp_strategies:
                handler = STRATEGY_DISPATCH[strat_name]
                mock_sock = MockRecordingSocket()
                handler(mock_sock, client_hello, delay=0.0)

                reconstructed = b"".join(mock_sock.sent_chunks)
                self.assertEqual(
                    reconstructed,
                    client_hello,
                    f"Стратегия {strat_name} изменила байты пакета для {host}! "
                    f"Оригинал ({len(client_hello)}b) != Результат ({len(reconstructed)}b)"
                )

    def test_legacy_aliases_preserve_exact_bytes(self):
        """Проверка, что устаревшие алиасы обратной совместимости не мутируют полезную нагрузку."""
        legacy_aliases = [
            "disoob_sni",
            "mixed_case_tcpsplit",
            "dummy_record_prepend",
            "tls_padding_split",
            "tcp_overlap_sni",
        ]

        for host in self.test_hosts:
            client_hello = generate_valid_tls_client_hello(host)
            for alias in legacy_aliases:
                handler = STRATEGY_DISPATCH[alias]
                mock_sock = MockRecordingSocket()
                handler(mock_sock, client_hello, delay=0.0)

                reconstructed = b"".join(mock_sock.sent_chunks)
                self.assertEqual(
                    reconstructed,
                    client_hello,
                    f"Алиас {alias} изменил байты пакета для {host}!"
                )

    def test_tls_record_fragmentation_payload_integrity(self):
        """Проверка, что при разбиении TLS Record reassembled payload идентичен оригиналу."""
        for host in self.test_hosts:
            client_hello = generate_valid_tls_client_hello(host)
            original_payload = client_hello[5:]

            # 1. Тест create_tls_record_fragments (2 записи)
            frags = create_tls_record_fragments(client_hello)
            self.assertEqual(len(frags), 2)
            self.assertTrue(is_tls_client_hello(frags[0]))
            reassembled = b""
            for f in frags:
                self.assertEqual(f[0], 0x16)
                self.assertEqual(f[1], 0x03)
                f_len = struct.unpack("!H", f[3:5])[0]
                self.assertEqual(len(f[5:]), f_len)
                reassembled += f[5:]

            self.assertEqual(
                reassembled,
                original_payload,
                f"TLS Record фрагменты изменили payload ClientHello для {host}!"
            )

            # 2. Тест create_multi_tls_record_fragments (N записей)
            multi_frags = create_multi_tls_record_fragments(client_hello)
            self.assertGreaterEqual(len(multi_frags), 2)
            multi_reassembled = b""
            for f in multi_frags:
                self.assertEqual(f[0], 0x16)
                f_len = struct.unpack("!H", f[3:5])[0]
                self.assertEqual(len(f[5:]), f_len)
                multi_reassembled += f[5:]

            self.assertEqual(
                multi_reassembled,
                original_payload,
                f"Multi TLS Record фрагменты изменили payload ClientHello для {host}!"
            )

    def test_tls_record_frag_with_trailing_data_preserves_tail(self):
        """Проверка: если за первым ClientHello следуют дополнительные байты, они не теряются."""
        client_hello = generate_valid_tls_client_hello("www.google.com")
        extra_tail = b"EXTRA_STREAM_DATA_OR_NEXT_RECORD_12345"
        combined_data = client_hello + extra_tail

        frags = create_tls_record_fragments(combined_data)
        self.assertEqual(len(frags), 2)
        # Второй фрагмент должен завершаться хвостом extra_tail
        self.assertTrue(frags[1].endswith(extra_tail))

        # При сборе на стороне сервера данные хвоста сохранены без искажений
        rec1_len = struct.unpack("!H", frags[0][3:5])[0]
        rec2_len = struct.unpack("!H", frags[1][3:5])[0]
        rec1_payload = frags[0][5:5 + rec1_len]
        rec2_payload = frags[1][5:5 + rec2_len]
        tail_extracted = frags[1][5 + rec2_len:]

        self.assertEqual(rec1_payload + rec2_payload, client_hello[5:])
        self.assertEqual(tail_extracted, extra_tail)

    def test_non_tls_and_short_packets_unmodified(self):
        """Проверка: не-TLS данные и ультра-короткие пакеты передаются без изменений."""
        packets = [
            b"",
            b"A",
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            b"\x16\x03",
            b"\x16\x03\x01\x00\x02",
        ]
        for p in packets:
            frags = create_tls_record_fragments(p)
            self.assertEqual(frags, [p])
            multi_frags = create_multi_tls_record_fragments(p)
            self.assertEqual(multi_frags, [p])


if __name__ == "__main__":
    unittest.main()
