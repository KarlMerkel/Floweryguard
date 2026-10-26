"""Тесты для исправлений Discord Media/GIF (Tenor, Giphy), Cloudflare Anycast и обхода блокировок сайтов."""

import unittest
from unittest.mock import MagicMock, patch
import socket
import time

from flowguard.proxy import (
    is_discord_media_host, is_bogon_or_sinkhole_ip, is_discord_host,
    is_plain_ip, is_captive_portal_host, DPIBypassProxy
)
from flowguard.strategy import StrategyExecutor, MAJOR_BLOCKED_PATTERNS, CDN_CLUSTERS, get_sni_offsets
from flowguard.sni_spoofer import build_fake_client_hello


class TestDiscordGifsAndBlockedSitesFixes(unittest.TestCase):
    def test_is_discord_media_host_includes_tenor_and_giphy(self):
        """Проверяет, что Tenor и Giphy распознаются как медиа-хосты Discord."""
        tenor_hosts = [
            "tenor.com",
            "c.tenor.com",
            "media.tenor.com",
            "api.tenor.com",
            "t.tenor.com",
        ]
        giphy_hosts = [
            "giphy.com",
            "media.giphy.com",
            "media0.giphy.com",
            "media1.giphy.com",
        ]
        for h in tenor_hosts + giphy_hosts:
            self.assertTrue(is_discord_media_host(h), f"Host {h} must be recognized as discord media")

    def test_is_bogon_or_sinkhole_ip_keeps_public_routes(self):
        """Частные диапазоны фильтруются, публичные адреса проверяются соединением."""
        sinkhole_ips = [
            "10.0.0.1",
            "10.200.1.5",
            "192.168.1.1",
            "192.168.0.254",
            "172.16.0.1",
            "172.31.255.254",
            "127.0.0.1",
            "0.0.0.0",
        ]
        for ip in sinkhole_ips:
            self.assertTrue(is_bogon_or_sinkhole_ip(ip), f"IP {ip} must be detected as bogon/sinkhole")

        clean_ips = [
            "192.144.59.14",
            "94.232.43.149",
            "8.47.69.1",
            "8.47.69.254",
            "8.6.112.1",
            "8.6.112.50",
            "104.21.5.1",
            "162.159.136.232",
            "142.250.74.110",
            "1.1.1.1",
            "8.8.8.8",
        ]
        for ip in clean_ips:
            self.assertFalse(is_bogon_or_sinkhole_ip(ip), f"IP {ip} must NOT be detected as bogon/sinkhole")

    def test_combo_tlsrec_tcpsplit_avoids_5byte_header_split(self):
        """Проверяет, что combo_tlsrec_tcpsplit не делит первую запись по 5-му байту (заголовку TLS)."""
        ch = build_fake_client_hello("cdn.discordapp.com")
        sent_chunks = []

        fake_sock = MagicMock()
        fake_sock.sendall.side_effect = lambda chunk: sent_chunks.append(chunk)

        StrategyExecutor.combo_tlsrec_tcpsplit(fake_sock, ch, delay=0.0)

        self.assertGreaterEqual(len(sent_chunks), 2)
        # Проверяем, что первый отправленный кусок строго больше 5 байт (содержит заголовок + тело)
        self.assertGreater(len(sent_chunks[0]), 5, "First chunk must not be only the 5-byte TLS header")

    def test_major_blocked_patterns_includes_gif_and_media(self):
        """Проверяет наличие Tenor, Giphy и других заблокированных ресурсов в MAJOR_BLOCKED_PATTERNS."""
        patterns = MAJOR_BLOCKED_PATTERNS
        for expected in ["tenor.com", "giphy.com", "rutracker", "x.com", "baskino", "flibusta"]:
            self.assertIn(expected, patterns)

    def test_pipe_sockets_does_not_record_success_on_stall_exception(self):
        """Проверяет, что при сбое передачи данных Discord media не фиксируется успех."""
        from flowguard.proxy import DPIBypassProxy
        from unittest.mock import MagicMock

        handler = object.__new__(DPIBypassProxy)
        handler.config = MagicMock()
        handler.config.enable_smart_sampling = True
        handler.strategy_engine = MagicMock()
        handler.buffer_size = 32768
        handler.bytes_tx = 0
        handler.bytes_rx = 0
        handler.timeout = 10.0
        handler.is_running = True

        client_sock = MagicMock()
        target_sock = MagicMock()
        target_sock.getpeername.return_value = ("162.159.130.232", 443)

        # target_sock вызывает TimeoutError при попытке чтения
        target_sock.recv.side_effect = socket.timeout("timed out")
        client_sock.recv.return_value = b""

        with patch("flowguard.proxy.select.select", return_value=([target_sock], [], [])):
            with patch("flowguard.proxy.time.time", side_effect=[100.0, 105.0, 105.1, 105.2]):
                handler._pipe_sockets(
                    client_sock,
                    target_sock,
                    host="media.discordapp.net",
                    strategy="combo_tlsrec_tcpsplit"
                )

        # Успех НЕ должен быть зафиксирован в strategy_engine
        handler.strategy_engine.record_success.assert_not_called()

    def test_is_discord_host_includes_tenor_and_giphy(self):
        """Проверяет, что Tenor и Giphy включены в is_discord_host для устранения DoH-задержки."""
        for h in ["tenor.com", "c.tenor.com", "media.tenor.com", "giphy.com", "media.giphy.com", "tenor.googleapis.com"]:
            self.assertTrue(is_discord_host(h), f"Host {h} must be recognized by is_discord_host")

    def test_is_discord_media_host_includes_tenor_googleapis(self):
        """Проверяет, что tenor.googleapis.com распознается как Discord media."""
        self.assertTrue(is_discord_media_host("tenor.googleapis.com"))

    def test_strategy_discord_cluster_and_patterns_include_tenor_api(self):
        """Проверяет, что tenor.googleapis.com включен в CDN_CLUSTERS['discord'] и MAJOR_BLOCKED_PATTERNS."""
        self.assertIn("tenor.googleapis.com", CDN_CLUSTERS["discord"])
        self.assertIn("tenor.googleapis.com", MAJOR_BLOCKED_PATTERNS)

    def test_universal_http_301_upgrade(self):
        """Проверяет Universal HTTP 301 Upgrade на порту 80 для обычных доменов и пропуск IP/NCSI."""
        handler = object.__new__(DPIBypassProxy)
        handler.config = MagicMock()
        handler.config.force_https = True
        handler.config.ncsi_spoof = True
        handler.whitelist_domains = set()
        handler._whitelist_lock = MagicMock()
        handler._check_reload_whitelist = MagicMock()

        # Тест 1: незаблокированный/любой домен filmix.biz -> 301 на https
        client_sock1 = MagicMock()
        raw_req1 = b"GET / HTTP/1.1\r\nHost: filmix.biz\r\n\r\n"
        handler._handle_http_request(client_sock1, raw_req1, "http://filmix.biz/")
        client_sock1.sendall.assert_called_once()
        sent_data1 = client_sock1.sendall.call_args[0][0]
        self.assertIn(b"301 Moved Permanently", sent_data1)
        self.assertIn(b"Location: https://filmix.biz/", sent_data1)

        # Тест 2: plain IP (например http://192.168.1.1/) НЕ должен редиректиться на https
        client_sock2 = MagicMock()
        raw_req2 = b"GET / HTTP/1.1\r\nHost: 192.168.1.1\r\n\r\n"
        with patch.object(handler, "_connect_target", return_value=None):
            handler._handle_http_request(client_sock2, raw_req2, "http://192.168.1.1/")
            sent_data2 = client_sock2.sendall.call_args[0][0]
            self.assertNotIn(b"301 Moved Permanently", sent_data2)

        # Тест 3: NCSI запрос перехватывается с 200 OK при ncsi_spoof=True
        client_sock3 = MagicMock()
        raw_req3 = b"GET /connecttest.txt HTTP/1.1\r\nHost: www.msftconnecttest.com\r\n\r\n"
        handler._handle_http_request(client_sock3, raw_req3, "http://www.msftconnecttest.com/connecttest.txt")
        sent_data3 = client_sock3.sendall.call_args[0][0]
        self.assertIn(b"200 OK", sent_data3)
        self.assertIn(b"Microsoft Connect Test", sent_data3)

        # Тест 4: OCSP и CRL запросы на порт 80 НЕ должны редиректиться на https
        client_sock4 = MagicMock()
        raw_req4 = b"GET /ocsp HTTP/1.1\r\nHost: ocsp.globalsign.com\r\n\r\n"
        with patch.object(handler, "_connect_target", return_value=None):
            handler._handle_http_request(client_sock4, raw_req4, "http://ocsp.globalsign.com/ocsp")
            sent_data4 = client_sock4.sendall.call_args[0][0]
            self.assertNotIn(b"301 Moved Permanently", sent_data4)

    def test_doh_harvester_skips_failover_when_resolved(self):
        """Проверяет, что при успешном ответе doh_harvester синхронный dns_failover не вызывается."""
        handler = object.__new__(DPIBypassProxy)
        handler.config = MagicMock()
        handler.config.enable_custom_dns = False
        handler.whitelist_domains = {"filmix.biz"}
        handler._whitelist_lock = MagicMock()
        handler._check_reload_whitelist = MagicMock()
        handler._try_direct_connect = MagicMock(return_value=None)

        handler.timeout = 5.0
        handler.doh_harvester = MagicMock()
        handler.doh_harvester.harvest.return_value = ["104.21.32.39"]
        handler.dns_failover = MagicMock()

        mock_sock = MagicMock()
        with patch("flowguard.proxy.socket.getaddrinfo", side_effect=Exception("no local dns")):
            with patch("flowguard.proxy.socket.socket", return_value=mock_sock):
                handler._connect_target("filmix.biz", 443)

        handler.doh_harvester.harvest.assert_called_once_with("filmix.biz")
    def test_discord_media_fast_path_not_evicted(self):
        """Проверяет, что cached_ip для медиа Discord не вытесняется из fast-path при наличии в _RECENT_DISCORD_IPS."""
        from flowguard.proxy import _WORKING_IP_CACHE, _RECENT_DISCORD_IPS
        handler = object.__new__(DPIBypassProxy)
        handler.timeout = 5.0
        mock_sock = MagicMock()
        handler._try_direct_connect = MagicMock(return_value=mock_sock)

        media_host = "cdn.discordapp.com"
        media_ip = "162.159.130.232"
        _WORKING_IP_CACHE.set(media_host, media_ip)
        _RECENT_DISCORD_IPS.set(media_ip, time.time())

        res = handler._connect_target(media_host, 443)
        self.assertIs(res, mock_sock)
        handler._try_direct_connect.assert_called_once()
        self.assertEqual(handler._try_direct_connect.call_args[0][0], media_ip)

    def test_fast_fallback_attempt3_deduplication(self):
        """Проверяет, что при сбое combo_tlsrec_tcpsplit в попытке 1/2 он не переназначается в попытке 3 даже для Discord/YouTube."""
        handler = object.__new__(DPIBypassProxy)
        handler.timeout = 5.0
        handler.strategy_engine = MagicMock()
        handler.strategy_engine.get_fallback_strategy.return_value = "tcp_split_sni_mid"
        handler.strategy_engine.allowed_strategy.side_effect = lambda name: name
        handler._connect_target = MagicMock(return_value=MagicMock())
        handler._safe_execute_strategy = MagicMock(return_value=True)
        handler._whitelist_lock = MagicMock()
        handler.whitelist_domains = set()
        handler._check_reload_whitelist = MagicMock()
        handler.shadow_prober = None

        first_packet = b"\x16\x03\x01\x00\x10test_client_hello"
        for test_host in ["rutracker.org", "cdn.discordapp.com", "www.youtube.com"]:
            handler.strategy_engine.reset_mock()
            handler._send_tls_client_hello_with_bypass = MagicMock(return_value=("combo_tlsrec_tcpsplit", test_host))
            with patch("flowguard.proxy.is_tls_client_hello", return_value=True), \
                 patch("flowguard.proxy._get_socket_meta", return_value={"target_ip": "162.159.130.232"}), \
                 patch.object(handler, "_probe_socket_response", side_effect=[
                     ("rst_server", None, 0.05),  # probe1 fails
                     ("rst_server", None, 0.05),  # probe2 fails
                     ("success", b"\x16\x03\x03\x00\x05server_hello", 0.05),  # probe3 succeeds
                 ]):
                client_sock = MagicMock()
                target_sock = MagicMock()
                sock, strat, host, resp = handler._handshake_with_fast_fallback(
                    client_sock, target_sock, test_host, 443, first_packet
                )
                handler.strategy_engine.get_fallback_strategy.assert_called()
                self.assertEqual(strat, "tcp_split_sni_mid", f"Host {test_host} must not repeat failed combo_tlsrec_tcpsplit")

    def test_universal_http_301_upgrade_exempts_plain_ips_and_portals(self):
        """Проверяет, что plain IP и captive portal не редиректятся на https, а обычные домены редиректятся."""
        handler = object.__new__(DPIBypassProxy)
        handler.config = MagicMock()
        handler.config.ncsi_spoof = False
        handler.whitelist_domains = {"filmix.biz"}
        handler._whitelist_lock = MagicMock()
        handler._check_reload_whitelist = MagicMock()

        for exempt_host in ["192.168.1.1", "routerlogin.net", "captive.apple.com"]:
            client_sock = MagicMock()
            raw_req = f"GET / HTTP/1.1\r\nHost: {exempt_host}\r\n\r\n".encode("latin1")
            with patch.object(handler, "_connect_target", return_value=None):
                handler._handle_http_request(client_sock, raw_req, f"http://{exempt_host}/")
                sent_data = client_sock.sendall.call_args[0][0]
                self.assertNotIn(b"301 Moved Permanently", sent_data, f"Host {exempt_host} must not be 301 redirected to https")

    def test_pipe_sockets_discord_media_identifies_tenor_and_giphy(self):
        """Проверяет, что _pipe_sockets корректно распознает Tenor и Giphy как медиа Discord."""
        handler = object.__new__(DPIBypassProxy)
        handler.config = MagicMock()
        handler.config.enable_smart_sampling = True
        handler.strategy_engine = MagicMock()
        handler.buffer_size = 32768
        handler.bytes_tx = 0
        handler.bytes_rx = 0
        handler.timeout = 5.0
        handler.is_running = True

        for gif_host in ["api.tenor.com", "tenor.googleapis.com", "media.giphy.com"]:
            handler.strategy_engine.reset_mock()
            client_sock = MagicMock()
            target_sock = MagicMock()
            target_sock.getpeername.return_value = ("142.250.74.110", 443)
            # Сервер отдал небольшой ответ (2KB JSON) и завершил поток
            target_sock.recv.side_effect = [b"HTTP/1.1 200 OK\r\nContent-Length: 2048\r\n\r\n" + b"X" * 2000, b""]
            client_sock.recv.return_value = b""

            with patch("flowguard.proxy.select.select", side_effect=[
                ([target_sock], [], []),
                ([target_sock], [], [])
            ]):
                handler._pipe_sockets(
                    client_sock,
                    target_sock,
                    host=gif_host,
                    strategy="combo_tlsrec_tcpsplit"
                )
            # Должен зафиксировать успех, несмотря на размер < 32KB
            handler.strategy_engine.record_success.assert_called()


if __name__ == "__main__":
    unittest.main()

