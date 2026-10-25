"""Unit tests for DoH Resolver, Wire Format parser, Cache, and DNSFailoverManager.
Strict standard library only (unittest, socket, struct, time, threading).
"""

import unittest
import os
import tempfile
import socket
import struct
import time
import threading
from unittest.mock import patch
from typing import List, Optional

from Floweryguard.doh_resolver import (
    DoHProvider,
    DNS_PRESETS,
    build_custom_provider,
    build_dns_query,
    parse_dns_name,
    parse_dns_response,
    DNSRecord,
    DNSResponse,
    ThreadSafeBoundedTTLCache,
    DoHResolver,
    DNSFailoverManager,
)


class TestDNSWireFormat(unittest.TestCase):
    """Тесты RFC 1035 wire format: формирование запросов и строгий разбор ответов."""

    def test_build_dns_query_type_a(self):
        query = build_dns_query("example.com", qtype=1, tx_id=0x1234)
        self.assertTrue(len(query) > 12)
        tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", query[:12])
        self.assertEqual(tx_id, 0x1234)
        self.assertEqual(flags, 0x0100)  # RD = 1
        self.assertEqual(qdcount, 1)
        self.assertEqual(ancount, 0)
        # Проверяем метки: 7example3com0
        expected_qname = b"\x07example\x03com\x00"
        self.assertIn(expected_qname, query)
        # Проверяем QTYPE (1) и QCLASS (1)
        self.assertTrue(query.endswith(struct.pack("!HH", 1, 1)))

    def test_build_dns_query_type_aaaa(self):
        query = build_dns_query("ipv6.google.com", qtype=28, tx_id=0xABCD)
        self.assertEqual(query[:2], b"\xAB\xCD")
        self.assertTrue(query.endswith(struct.pack("!HH", 28, 1)))

    def test_parse_valid_response_a(self):
        # 12 байт заголовок: id=0x1234, flags=0x8180 (NoError), qdcount=1, ancount=1
        header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
        # Question: \x07example\x03com\x00 QTYPE=1 QCLASS=1
        question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
        # Answer: compression pointer на offset 12 (\xC0\x0C), TYPE=1, CLASS=1, TTL=300, RDLENGTH=4, IP=93.184.216.34
        answer = (
            b"\xC0\x0C"
            + struct.pack("!HHIH", 1, 1, 300, 4)
            + socket.inet_aton("93.184.216.34")
        )
        packet = header + question + answer

        resp = parse_dns_response(packet)
        self.assertEqual(resp.id, 0x1234)
        self.assertEqual(resp.rcode, 0)
        self.assertEqual(len(resp.answers), 1)
        rec = resp.answers[0]
        self.assertEqual(rec.name, "example.com")
        self.assertEqual(rec.rtype, 1)
        self.assertEqual(rec.ttl, 300)
        self.assertEqual(rec.address, "93.184.216.34")

    def test_parse_valid_response_aaaa(self):
        header = struct.pack("!HHHHHH", 0x4321, 0x8180, 1, 1, 0, 0)
        question = b"\x04ipv6\x03com\x00" + struct.pack("!HH", 28, 1)
        raw_ip6 = socket.inet_pton(socket.AF_INET6, "2606:4700:4700::1111")
        answer = (
            b"\xC0\x0C"
            + struct.pack("!HHIH", 28, 1, 120, 16)
            + raw_ip6
        )
        packet = header + question + answer

        resp = parse_dns_response(packet)
        self.assertEqual(len(resp.answers), 1)
        rec = resp.answers[0]
        self.assertEqual(rec.rtype, 28)
        self.assertEqual(rec.ttl, 120)
        self.assertEqual(rec.address, "2606:4700:4700::1111")

    def test_parse_empty_answer_nxdomain(self):
        # NXDOMAIN: rcode = 3, ancount = 0
        header = struct.pack("!HHHHHH", 0x9999, 0x8183, 1, 0, 0, 0)
        question = b"\x08nonexist\x03com\x00" + struct.pack("!HH", 1, 1)
        packet = header + question

        resp = parse_dns_response(packet)
        self.assertEqual(resp.rcode, 3)
        self.assertEqual(len(resp.answers), 0)

    def test_parse_truncated_header(self):
        # Меньше 12 байт
        with self.assertRaises(ValueError):
            parse_dns_response(b"\x12\x34\x81\x80\x00\x01")

    def test_parse_truncated_question(self):
        header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 0, 0, 0)
        # Обрезанное имя домена
        with self.assertRaises(ValueError):
            parse_dns_response(header + b"\x07exam")

        # Имя есть, но отсутствуют QTYPE / QCLASS
        with self.assertRaises(ValueError):
            parse_dns_response(header + b"\x07example\x03com\x00\x00")

    def test_parse_truncated_answer_header(self):
        header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
        question = b"\x03foo\x00" + struct.pack("!HH", 1, 1)
        # Answer имеет только указатель \xC0\x0C и 4 байта (нужно 10 байт заголовка RR)
        bad_answer = b"\xC0\x0C\x00\x01\x00\x01"
        with self.assertRaises(ValueError):
            parse_dns_response(header + question + bad_answer)

    def test_parse_truncated_answer_rdata(self):
        header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
        question = b"\x03foo\x00" + struct.pack("!HH", 1, 1)
        # Заголовок указывает rdlength=4, но передано только 2 байта
        answer_short_rdata = b"\xC0\x0C" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x01\x02"
        with self.assertRaises(ValueError):
            parse_dns_response(header + question + answer_short_rdata)

    def test_compression_pointer_out_of_bounds(self):
        header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 0, 0, 0)
        # Указатель на 0x00FE, когда длина пакета всего 14 байт
        bad_packet = header + b"\xC0\xFE"
        with self.assertRaises(ValueError) as ctx:
            parse_dns_response(bad_packet)
        self.assertIn("выходит за границы", str(ctx.exception))

    def test_compression_pointer_loop(self):
        header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 0, 0, 0)
        # Указатель по смещению 12 указывает сам на себя (0x000C)
        loop_packet = header + b"\xC0\x0C"
        with self.assertRaises(ValueError) as ctx:
            parse_dns_response(loop_packet)
        self.assertIn("Превышена максимальная глубина", str(ctx.exception))

    def test_invalid_label_type(self):
        header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 0, 0, 0)
        # Байт метки 0x40 (зарезервирован/невалиден)
        bad_packet = header + b"\x40foo\x00"
        with self.assertRaises(ValueError) as ctx:
            parse_dns_response(bad_packet)
        self.assertIn("Недопустимый префикс", str(ctx.exception))


class TestDoHProviderAndValidation(unittest.TestCase):
    """Тесты структуры DoHProvider и функции валидации build_custom_provider."""

    def test_presets_exist_and_valid(self):
        for name in ("cloudflare", "google", "adguard", "quad9"):
            self.assertIn(name, DNS_PRESETS)
            p = DNS_PRESETS[name]
            self.assertTrue(len(p.server_ips) >= 1)
            for ip in p.server_ips:
                socket.inet_aton(ip)  # Не должно падать
            self.assertTrue(p.doh_path.startswith("/"))
            self.assertEqual(p.port, 443)

    def test_build_custom_provider_valid(self):
        provider = build_custom_provider(
            name="My DNS",
            doh_url="https://dns.quad9.net/dns-query",
            ipv4_list=["9.9.9.9", "149.112.112.112"]
        )
        self.assertEqual(provider.name, "My DNS")
        self.assertEqual(provider.doh_host, "dns.quad9.net")
        self.assertEqual(provider.doh_path, "/dns-query")
        self.assertEqual(provider.server_ips, ("9.9.9.9", "149.112.112.112"))
        self.assertEqual(provider.port, 443)

    def test_build_custom_provider_missing_https(self):
        with self.assertRaises(ValueError) as ctx:
            build_custom_provider("Bad", "http://dns.quad9.net/dns-query", ["9.9.9.9"])
        self.assertIn("https://", str(ctx.exception))

    def test_build_custom_provider_empty_ips(self):
        with self.assertRaises(ValueError) as ctx:
            build_custom_provider("Bad", "https://dns.quad9.net/dns-query", [])
        self.assertIn("не должен быть пустым", str(ctx.exception))

    def test_build_custom_provider_invalid_ip_format(self):
        with self.assertRaises(ValueError) as ctx:
            build_custom_provider("Bad", "https://dns.quad9.net/dns-query", ["999.9.9.9"])
        self.assertIn("Некорректный IPv4-адрес", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            build_custom_provider("Bad", "https://dns.quad9.net/dns-query", ["not-an-ip"])
        self.assertIn("Некорректный", str(ctx.exception))


class TestThreadSafeBoundedTTLCache(unittest.TestCase):
    """Тесты потокобезопасного TTL-кэша ответов."""

    def test_cache_set_get(self):
        cache = ThreadSafeBoundedTTLCache(maxsize=10)
        cache.set("google.com:1", ["142.250.70.206"], ttl=60.0)
        self.assertEqual(cache.get("google.com:1"), ["142.250.70.206"])
        self.assertIn("google.com:1", cache)
        self.assertEqual(len(cache), 1)

    def test_cache_ttl_expiration(self):
        cache = ThreadSafeBoundedTTLCache(maxsize=10)
        # Искусственно устанавливаем малый TTL через внутреннюю структуру для быстрого теста
        cache.set("short.ttl", ["1.1.1.1"], ttl=5.0)
        # Подменяем expire_time в прошлое
        cache._cache["short.ttl"] = (["1.1.1.1"], time.time() - 1.0)
        self.assertIsNone(cache.get("short.ttl"))
        self.assertNotIn("short.ttl", cache)

    def test_cache_fifo_eviction(self):
        cache = ThreadSafeBoundedTTLCache(maxsize=3)
        cache.set("k1", ["1.1.1.1"], ttl=60.0)
        cache.set("k2", ["2.2.2.2"], ttl=60.0)
        cache.set("k3", ["3.3.3.3"], ttl=60.0)
        self.assertEqual(len(cache), 3)

        # Добавляем 4-й элемент — первый k1 должен быть вытеснен
        cache.set("k4", ["4.4.4.4"], ttl=60.0)
        self.assertEqual(len(cache), 3)
        self.assertIsNone(cache.get("k1"))
        self.assertIsNotNone(cache.get("k2"))
        self.assertIsNotNone(cache.get("k3"))
        self.assertIsNotNone(cache.get("k4"))

    def test_cache_concurrency(self):
        cache = ThreadSafeBoundedTTLCache(maxsize=100)
        errors = []

        def worker(w_id: int):
            try:
                for i in range(50):
                    key = f"domain{i % 20}.com"
                    cache.set(key, [f"10.0.{w_id}.{i}"], ttl=10.0)
                    val = cache.get(key)
                    if val is not None and not isinstance(val, list):
                        errors.append("Invalid value type")
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])


class MockDoHResolver:
    """Мок резолвера для тестирования логики DNSFailoverManager без сетевых вызовов."""

    def __init__(self, provider: DoHProvider, succeed_after: Optional[int] = None, fail_always: bool = False):
        self.provider = provider
        self.call_count = 0
        self.succeed_after = succeed_after
        self.fail_always = fail_always

    def resolve(self, domain: str, qtype: int = 1) -> List[str]:
        self.call_count += 1
        if self.fail_always:
            raise OSError(f"Mock network failure for {self.provider.name}")
        if self.succeed_after is not None and self.call_count < self.succeed_after:
            raise OSError(f"Mock temporary failure #{self.call_count}")
        return ["93.184.216.34"]


class TestDNSFailoverManager(unittest.TestCase):
    """Тесты политики переключения на fallback и отсутствия тихого возврата."""

    def setUp(self):
        self.primary_prov = DoHProvider("CustomPrimary", "doh.custom.net", "/dns-query", ("192.0.2.1",))
        self.fallback_prov = DNS_PRESETS["cloudflare"]

    def test_failover_strictly_after_threshold(self):
        manager = DNSFailoverManager(
            primary_provider=self.primary_prov,
            fallback_provider=self.fallback_prov,
            fail_threshold=3
        )
        # Подменяем резолверы на моки
        mock_primary = MockDoHResolver(self.primary_prov, fail_always=True)
        mock_fallback = MockDoHResolver(self.fallback_prov, fail_always=False)
        manager.primary_resolver = mock_primary
        manager.fallback_resolver = mock_fallback

        self.assertFalse(manager.is_fallback_active)
        self.assertEqual(manager.consecutive_failures, 0)

        # Ошибка 1: порог не достигнут
        res1 = manager.resolve("example.com")
        self.assertEqual(res1, ["93.184.216.34"])
        self.assertEqual(mock_primary.call_count, 1)
        self.assertEqual(manager.consecutive_failures, 1)
        self.assertFalse(manager.is_fallback_active)

        # Ошибка 2: порог не достигнут
        res2 = manager.resolve("example.com")
        self.assertEqual(res2, ["93.184.216.34"])
        self.assertEqual(mock_primary.call_count, 2)
        self.assertEqual(manager.consecutive_failures, 2)
        self.assertFalse(manager.is_fallback_active)

        # Ошибка 3: порог (3) достигнут -> строго сейчас происходит переключение!
        res3 = manager.resolve("example.com")
        self.assertEqual(res3, ["93.184.216.34"])
        self.assertEqual(mock_primary.call_count, 3)
        self.assertEqual(manager.consecutive_failures, 3)
        self.assertTrue(manager.is_fallback_active)
        self.assertEqual(manager.active_provider.name, "Cloudflare")

    def test_session_stickiness_no_automatic_retry(self):
        """Проверяет критерий: после переключения на fallback в течение сессии primary больше не пробуется."""
        manager = DNSFailoverManager(
            primary_provider=self.primary_prov,
            fallback_provider=self.fallback_prov,
            fail_threshold=3
        )
        mock_primary = MockDoHResolver(self.primary_prov, fail_always=True)
        mock_fallback = MockDoHResolver(self.fallback_prov, fail_always=False)
        manager.primary_resolver = mock_primary
        manager.fallback_resolver = mock_fallback

        # Доводим до failover (3 ошибки)
        for _ in range(3):
            manager.resolve("domain.org")

        self.assertTrue(manager.is_fallback_active)
        self.assertEqual(mock_primary.call_count, 3)

        # Следующие 10 запросов не должны даже касаться primary!
        for _ in range(10):
            manager.resolve("domain.org")

        self.assertEqual(mock_primary.call_count, 3, "Primary НЕ должен повторно опрашиваться в этой сессии!")
        self.assertTrue(manager.is_fallback_active)

    def test_recovery_before_threshold_resets_counter(self):
        manager = DNSFailoverManager(
            primary_provider=self.primary_prov,
            fallback_provider=self.fallback_prov,
            fail_threshold=3
        )
        # primary фейлит 2 раза, на 3-й запрос отвечает успешно
        mock_primary = MockDoHResolver(self.primary_prov, succeed_after=3)
        mock_fallback = MockDoHResolver(self.fallback_prov, fail_always=False)
        manager.primary_resolver = mock_primary
        manager.fallback_resolver = mock_fallback

        # Запрос 1: фейл (счетчик = 1)
        manager.resolve("test.com")
        self.assertEqual(manager.consecutive_failures, 1)
        self.assertFalse(manager.is_fallback_active)

        # Запрос 2: фейл (счетчик = 2)
        manager.resolve("test.com")
        self.assertEqual(manager.consecutive_failures, 2)
        self.assertFalse(manager.is_fallback_active)

        # Запрос 3: успех на primary -> счетчик должен сброситься в 0!
        manager.resolve("test.com")
        self.assertEqual(manager.consecutive_failures, 0)
        self.assertFalse(manager.is_fallback_active)


class TestConfigDNSServer(unittest.TestCase):
    """Тесты поддержки простого параметра server в config.ini."""

    def test_preset_case_insensitive(self):
        from Floweryguard.config import Config
        from Floweryguard.proxy import get_dns_failover_manager
        cfg = Config("nonexistent_test.ini")
        cfg.set_override("enable_custom_dns", True)
        cfg.set_override("server", "quad9")
        mgr = get_dns_failover_manager(cfg)
        self.assertEqual(mgr.primary_provider.name, "Quad9")

    def test_preset_cloudflare(self):
        from Floweryguard.config import Config
        from Floweryguard.proxy import get_dns_failover_manager
        cfg = Config("nonexistent_test.ini")
        cfg.set_override("enable_custom_dns", True)
        cfg.set_override("server", "Cloudflare")
        mgr = get_dns_failover_manager(cfg)
        self.assertEqual(mgr.primary_provider.name, "Cloudflare")

    def test_config_ini_natural_resolution(self):
        """Проверяет, что get_dns_failover_manager читает server напрямую из config.ini без set_override."""
        import tempfile
        from Floweryguard.config import Config
        from Floweryguard.proxy import get_dns_failover_manager
        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False, encoding="utf-8") as tf:
            tf.write("[dns]\nenable_custom_dns = true\nserver = Quad9\n")
            temp_ini = tf.name
        try:
            cfg = Config(temp_ini)
            self.assertEqual(cfg.server, "Quad9")
            self.assertEqual(cfg.dns_server, "Quad9")
            mgr = get_dns_failover_manager(cfg, force_new=True)
            self.assertIsNotNone(mgr)
            self.assertEqual(mgr.primary_provider.name, "Quad9")
        finally:
            if os.path.exists(temp_ini):
                os.remove(temp_ini)

    def test_default_gateway_skips_virtual_adapter(self):
        """Проверяет, что get_default_gateway_ip пропускает виртуальные интерфейсы (Radmin VPN, Hamachi)."""
        from unittest.mock import patch
        from Floweryguard.profiles import get_default_gateway_ip
        fake_netsh_lines = [
            'Настройка для интерфейса "Radmin VPN"',
            '    DHCP включен:                          Нет',
            '    IP-адрес:                              26.241.15.10',
            '    Основной шлюз:                         26.0.0.1',
            'Настройка для интерфейса "Ethernet 2"',
            '    DHCP включен:                          Да',
            '    IP-адрес:                              192.168.1.100',
            '    Основной шлюз:                         192.168.1.1',
        ]
        fake_stdout = "\r\n".join(fake_netsh_lines).encode("utf-8")
        mock_proc = type("Proc", (), {"stdout": fake_stdout, "returncode": 0})()
        with patch("subprocess.run", return_value=mock_proc):
            gw = get_default_gateway_ip()
            self.assertEqual(gw, "192.168.1.1")

    def test_frozen_save_redirection(self):
        """Проверяет, что Config.save() в PyInstaller не сохраняет во временный каталог _MEIPASS."""
        import sys
        from Floweryguard.config import Config, get_app_base_dir
        cfg = Config("nonexistent_test.ini")
        fake_meipass = r"C:\Users\test\AppData\Local\Temp\_MEI123456"
        cfg.config_path = os.path.join(fake_meipass, "config.ini")
        old_frozen = getattr(sys, "frozen", False)
        try:
            sys.frozen = True
            sys._MEIPASS = fake_meipass
            with tempfile.TemporaryDirectory() as tmp_dir:
                with patch("Floweryguard.config.get_app_base_dir", return_value=tmp_dir):
                    cfg.save()
                    expected_saved = os.path.join(tmp_dir, "config.ini")
                    self.assertTrue(os.path.exists(expected_saved))
        finally:
            sys.frozen = old_frozen
            if hasattr(sys, "_MEIPASS"):
                del sys._MEIPASS


if __name__ == "__main__":
    unittest.main()

