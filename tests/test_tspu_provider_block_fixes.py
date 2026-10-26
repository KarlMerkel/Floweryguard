"""Unit tests for TSPU Provider Block fixes:
1. Bogon/sinkhole IP filtering in _connect_target and fallback.
2. Separation of YouTube Web Anycast IPs from Google Video GGC IPs.
3. Discord Media (cdn.discordapp.com, media.discordapp.net) normal completion without 32KB threshold.
4. Calibration probe rejecting TLS Alert 0x15 and modern ClientHello format.
5. Tester not treating HTTP 404 on www.youtube.com as success.
"""

import socket
import time
import unittest
from unittest.mock import MagicMock, patch

from flowguard.config import Config
from flowguard.proxy import (
    DPIBypassProxy,
    is_bogon_or_sinkhole_ip,
    is_googlevideo_host,
    GOOGLE_VIDEO_ANYCAST_IPS,
    YOUTUBE_WEB_ANYCAST_IPS,
    _WORKING_IP_CACHE,
    _DEAD_IP_CACHE,
    _RESOLVED_IPS_CACHE,
    is_ip_dead,
    _set_socket_meta,
)
from flowguard.calibration import probe_tls_strategy
from flowguard.sni_spoofer import build_fake_client_hello
from flowguard.tls_parser import parse_sni, get_sni_offsets


class TestTSPUProviderBlockFixes(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.proxy = DPIBypassProxy(self.config)
        self.proxy.is_running = True
        self.proxy.strategy_engine = MagicMock()
        _WORKING_IP_CACHE.clear()
        _DEAD_IP_CACHE.clear()
        _RESOLVED_IPS_CACHE.clear()

    def tearDown(self):
        _WORKING_IP_CACHE.clear()
        _DEAD_IP_CACHE.clear()
        _RESOLVED_IPS_CACHE.clear()

    def test_bogon_filter_rejects_loopback_and_sinkholes(self):
        """is_bogon_or_sinkhole_ip correctly identifies bogon, loopback, and sinkhole IPs."""
        self.assertTrue(is_bogon_or_sinkhole_ip("127.0.0.1"))
        self.assertTrue(is_bogon_or_sinkhole_ip("127.0.1.1"))
        self.assertTrue(is_bogon_or_sinkhole_ip("0.0.0.0"))
        self.assertTrue(is_bogon_or_sinkhole_ip("::1"))
        self.assertTrue(is_bogon_or_sinkhole_ip("192.144.59.14"))
        self.assertTrue(is_bogon_or_sinkhole_ip("94.232.43.149"))
        self.assertTrue(is_bogon_or_sinkhole_ip(None))
        self.assertTrue(is_bogon_or_sinkhole_ip(""))

        # Valid public IPs
        self.assertFalse(is_bogon_or_sinkhole_ip("142.251.150.4"))
        self.assertFalse(is_bogon_or_sinkhole_ip("162.159.135.232"))
        self.assertFalse(is_bogon_or_sinkhole_ip("1.1.1.1"))

    def test_connect_target_ignores_bogon_from_getaddrinfo_and_triggers_fallback(self):
        """When getaddrinfo returns 127.0.0.1 (e.g. hosts file TSPU pollution),
        _connect_target drops it and triggers DoH/failover DNS.
        """
        host = "meduza.io"
        fake_addrinfo = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))
        ]

        with patch("socket.getaddrinfo", return_value=fake_addrinfo), \
             patch("socket.socket") as mock_sock_cls:
            mock_s = MagicMock()
            mock_sock_cls.return_value = mock_s

            # Set up doh_harvester to return real IP
            self.proxy.doh_harvester = MagicMock()
            self.proxy.doh_harvester.harvest.return_value = ["104.26.12.201"]

            sock = self.proxy._connect_target(host, 443)
            self.assertIsNotNone(sock)
            # Must connect to 104.26.12.201, NEVER 127.0.0.1
            mock_s.connect.assert_called_with(("104.26.12.201", 443))

    def test_connect_target_fallback_never_revives_bogon_ips(self):
        """When all candidates are exhausted, fallback_alive does not revive 127.0.0.1."""
        host = "127.0.0.1"
        self.assertTrue(is_bogon_or_sinkhole_ip(host))
        sock = self.proxy._connect_target(host, 443)
        self.assertIsNone(sock)

    def test_youtube_and_googlevideo_anycast_ip_separation(self):
        """YouTube Web uses YOUTUBE_WEB_ANYCAST_IPS and does not receive GGC IPs."""
        self.assertTrue(is_googlevideo_host("rr1---sn-4g5ednks.googlevideo.com"))
        self.assertFalse(is_googlevideo_host("www.youtube.com"))
        self.assertFalse(is_googlevideo_host("youtube.com"))

        # GGC IPs like 173.194.178.225 must only be in GOOGLE_VIDEO_ANYCAST_IPS
        self.assertIn("173.194.178.225", GOOGLE_VIDEO_ANYCAST_IPS)
        self.assertNotIn("173.194.178.225", YOUTUBE_WEB_ANYCAST_IPS)

        # www.youtube.com Anycast pool uses YOUTUBE_WEB_ANYCAST_IPS
        with patch("socket.getaddrinfo", side_effect=socket.gaierror), \
             patch("socket.socket") as mock_sock_cls, \
             patch("select.select", return_value=([MagicMock()], [MagicMock()], [])):
            mock_s = MagicMock()
            mock_sock_cls.return_value = mock_s
            mock_s.connect_ex.return_value = 0
            self.proxy.doh_harvester = None
            self.proxy.dns_failover = None
            with patch("flowguard.proxy.resolve_fallback_dns", return_value=None):
                sock = self.proxy._connect_target("www.youtube.com", 443)
                self.assertIsNotNone(sock)
                target_ip = None
                if mock_s.connect_ex.called:
                    target_ip = mock_s.connect_ex.call_args[0][0][0]
                elif mock_s.connect.called:
                    target_ip = mock_s.connect.call_args[0][0][0]
                self.assertIsNotNone(target_ip)
                self.assertIn(target_ip, YOUTUBE_WEB_ANYCAST_IPS)
                self.assertNotIn(target_ip, ("173.194.178.225", "173.194.180.92"))

    def test_discord_media_normal_completion_records_success_without_32kb_threshold(self):
        """Discord media requests (cdn.discordapp.com) record success on any response bytes
        and do not mark IP dead when client closes socket.
        """
        host = "cdn.discordapp.com"
        target_ip = "162.159.130.233"
        _WORKING_IP_CACHE.set(host, target_ip)

        client_sock = MagicMock()
        target_sock = MagicMock()
        _set_socket_meta(target_sock, target_ip=target_ip, connect_rtt=0.015)

        # Server sends 2048 bytes (avatar image thumbnail < 32KB)
        # Client receives and cleanly closes socket (b'')
        target_sock.recv.side_effect = [b"A" * 2048]
        client_sock.recv.side_effect = [b""]

        call_idx = [0]
        def fake_select(r, w, x, timeout):
            call_idx[0] += 1
            if call_idx[0] == 1:
                return ([target_sock], [], [])
            elif call_idx[0] == 2:
                return ([client_sock], [], [])
            return ([], [], [])

        with patch("select.select", side_effect=fake_select):
            self.proxy._pipe_sockets(
                client_sock,
                target_sock,
                host=host,
                strategy="combo_tlsrec_tcpsplit"
            )

        # Success must be recorded despite < 32KB
        self.proxy.strategy_engine.record_success.assert_called_with(
            host, "combo_tlsrec_tcpsplit", ip=target_ip
        )
        self.proxy.strategy_engine.record_failure.assert_not_called()
        self.assertFalse(is_ip_dead(target_ip))

    def test_calibration_probe_rejects_tls_alert_0x15(self):
        """probe_tls_strategy correctly fails when server responds with TLS Alert (0x15)."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"\x15\x03\x03\x00\x02\x02\x28"  # TLS Alert (handshake failure)

        with patch("socket.socket", return_value=mock_sock):
            ok, latency, detail = probe_tls_strategy("discord.com", "combo_tlsrec_tcpsplit", ip="162.159.135.232")
            self.assertFalse(ok)
            self.assertIn("TLS Alert", detail)

    def test_calibration_probe_accepts_tls_server_hello_0x16(self):
        """probe_tls_strategy succeeds when server responds with TLS ServerHello (0x16)."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"\x16\x03\x03\x00\x50\x02\x00\x00"  # TLS ServerHello

        with patch("socket.socket", return_value=mock_sock):
            ok, latency, detail = probe_tls_strategy("discord.com", "combo_tlsrec_tcpsplit", ip="162.159.135.232")
            self.assertTrue(ok)
            self.assertIn("TLS ServerHello OK", detail)

    def test_modern_client_hello_structure(self):
        """build_fake_client_hello produces a valid ClientHello with SNI and modern TLS 1.3/1.2 ciphers."""
        ch = build_fake_client_hello("www.youtube.com")
        self.assertIsNotNone(ch)
        self.assertEqual(ch[0], 0x16)  # Handshake

        sni_info = parse_sni(ch)
        self.assertIsNotNone(sni_info)
        host, start, length = sni_info
        self.assertEqual(host, "www.youtube.com")

        offsets = get_sni_offsets(ch)
        self.assertIsNotNone(offsets)
        start, mid, end = offsets
        self.assertEqual(ch[start:end], b"www.youtube.com")

    def test_tester_does_not_treat_404_on_youtube_as_success(self):
        """In tester.py, HTTP 404 on www.youtube.com is treated as failure."""
        import urllib.error
        from flowguard.tester import test_proxy_connection

        fake_err = urllib.error.HTTPError("https://www.youtube.com", 404, "Not Found", {}, None)

        with patch("urllib.request.build_opener") as mock_build_opener:
            mock_opener = MagicMock()
            mock_opener.open.side_effect = fake_err
            mock_build_opener.return_value = mock_opener

            with patch("socket.socket") as mock_sock:
                mock_s = MagicMock()
                mock_s.recvfrom.return_value = (b"X" * 70, ("35.217.11.71", 50007))
                mock_sock.return_value = mock_s

                # Limit TEST_TARGETS to www.youtube.com for this test
                with patch("flowguard.tester.TEST_TARGETS", [{"name": "YouTube", "host": "www.youtube.com", "port": 443}]):
                    results = test_proxy_connection()
                    yt_res = [r for r in results if r["host"] == "www.youtube.com"][0]
                    self.assertFalse(yt_res["status"])
                    self.assertEqual(yt_res["code"], 404)


    def test_discord_idle_keepalive_timeout_with_prior_data_does_not_mark_ip_dead(self):
        """When a connection to cdn.discordapp.com receives response data (< 32KB image thumbnail) and
        subsequently times out on idle keepalive (select returns not readable),
        it must NOT mark the IP dead and must NOT record strategy failure.
        """
        host = "cdn.discordapp.com"
        target_ip = "162.159.135.232"
        _WORKING_IP_CACHE.set(host, target_ip)

        client_sock = MagicMock()
        target_sock = MagicMock()
        _set_socket_meta(target_sock, target_ip=target_ip, connect_rtt=0.015)

        # Server sends 1500 bytes JSON (e.g. /api/v9/users/@me)
        target_sock.recv.side_effect = [b"HTTP/1.1 200 OK\r\nContent-Length: 1500\r\n\r\n" + b"X" * 1450]
        # Then connection sits idle and times out in select
        call_idx = [0]
        def fake_select(r, w, x, timeout):
            call_idx[0] += 1
            if call_idx[0] == 1:
                return ([target_sock], [], [])
            # Timeout (idle keepalive)
            return ([], [], [])

        with patch("select.select", side_effect=fake_select):
            self.proxy._pipe_sockets(
                client_sock,
                target_sock,
                host=host,
                strategy="combo_tlsrec_tcpsplit"
            )

        self.assertFalse(is_ip_dead(target_ip))
        self.proxy.strategy_engine.record_failure.assert_not_called()
        self.proxy.strategy_engine.record_success.assert_called_with(
            host, "combo_tlsrec_tcpsplit", ip=target_ip
        )

    def test_discord_api_under_32kb_records_success(self):
        """Requests to discord.com under 32KB (e.g. 4KB API response) record success
        and mark IP working on keepalive idle.
        """
        host = "discord.com"
        target_ip = "162.159.135.232"
        _WORKING_IP_CACHE.set(host, target_ip)

        client_sock = MagicMock()
        target_sock = MagicMock()
        _set_socket_meta(target_sock, target_ip=target_ip, connect_rtt=0.015)

        client_sock.recv.side_effect = [b"GET /api/v9/users/@me HTTP/1.1\r\n\r\n"]
        target_sock.recv.side_effect = [b"HTTP/1.1 200 OK\r\n\r\n" + b"A" * 4000]

        call_idx = [0]
        def fake_select(r, w, x, timeout):
            call_idx[0] += 1
            if call_idx[0] == 1:
                return ([client_sock], [], [])
            elif call_idx[0] == 2:
                return ([target_sock], [], [])
            return ([], [], [])

        with patch("select.select", side_effect=fake_select):
            self.proxy._pipe_sockets(
                client_sock,
                target_sock,
                host=host,
                strategy="combo_tlsrec_tcpsplit"
            )

        self.proxy.strategy_engine.record_success.assert_called_with(
            host, "combo_tlsrec_tcpsplit", ip=target_ip
        )
        self.proxy.strategy_engine.record_failure.assert_not_called()
        self.assertFalse(is_ip_dead(target_ip))

    def test_probe_socket_response_rejects_tls_alert_and_http_blockpage(self):
        """_probe_socket_response returns 'rst_server' (failure) for TLS Alert or cleartext HTTP blockpage."""
        sock_alert = MagicMock()
        sock_alert.recv.return_value = b"\x15\x03\x03\x00\x02\x02\x28"  # TLS Alert

        with patch("select.select", return_value=([sock_alert], [], [])):
            status, resp, delta = self.proxy._probe_socket_response(sock_alert, time.time(), 0.05, "combo_tlsrec_tcpsplit")
            self.assertEqual(status, "rst_server")

        sock_http = MagicMock()
        sock_http.recv.return_value = b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n\r\nBlock"

        with patch("select.select", return_value=([sock_http], [], [])):
            status, resp, delta = self.proxy._probe_socket_response(sock_http, time.time(), 0.05, "combo_tlsrec_tcpsplit")
            self.assertEqual(status, "rst_server")

    def test_youtube_web_anycast_ip_cached_and_not_evicted(self):
        """YouTube Web Anycast IPs (e.g. 142.251.150.4) are valid for www.youtube.com
        and can be cached and used in fast-path without being evicted.
        """
        from flowguard.proxy import mark_ip_working, _WORKING_IP_CACHE
        yt_ip = "142.251.150.4"
        mark_ip_working(yt_ip, "www.youtube.com")
        self.proxy.route_health.record(self.proxy.strategy_engine._current_network, 'www.youtube.com', 443, yt_ip, 'progress')
        self.assertEqual(_WORKING_IP_CACHE.get("www.youtube.com"), yt_ip)

        # Fast-path does not pop it
        mock_direct = MagicMock(return_value=MagicMock())
        with patch.object(self.proxy, "_try_direct_connect", mock_direct):
            sock = self.proxy._connect_target("www.youtube.com", 443)
            self.assertIsNotNone(sock)
            mock_direct.assert_called_once_with(yt_ip, 443, timeout=unittest.mock.ANY)

    def test_calibration_probe_rejects_http_blockpage(self):
        """probe_tls_strategy rejects cleartext HTTP blockpage injection from ISP on port 443."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\nBlocked"

        with patch("socket.socket", return_value=mock_sock):
            ok, latency, detail = probe_tls_strategy("meduza.io", "combo_tlsrec_tcpsplit", ip="8.6.112.0")
            self.assertFalse(ok)
            self.assertIn("HTTP block page", detail)


if __name__ == "__main__":
    unittest.main()
