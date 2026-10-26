"""Unit tests for Discord media, GIF picker, keep-alive closures and IP pool revival fixes."""

import unittest
from unittest.mock import patch, MagicMock
import socket
import time

from flowguard.proxy import (
    DPIBypassProxy, _DEAD_IP_CACHE, mark_ip_dead, mark_ip_working, is_ip_dead,
    DISCORD_CDN_ANYCAST_IPS, DISCORD_MEDIA_ANYCAST_IPS, _set_socket_meta,
    _WORKING_IP_CACHE, _RESOLVED_IPS_CACHE
)
from flowguard.strategy import (
    classify_cdn_cluster, ThompsonStrategySelector
)


class TestDiscordMediaDeepFixes(unittest.TestCase):
    def setUp(self):
        for cache in (_DEAD_IP_CACHE, _WORKING_IP_CACHE, _RESOLVED_IPS_CACHE):
            cache.clear()
            self.addCleanup(cache.clear)

    def test_classify_cdn_cluster_tenor_googleapis(self):
        """tenor.googleapis.com must be classified as 'discord' cluster, not 'google'."""
        cluster = classify_cdn_cluster("tenor.googleapis.com")
        self.assertEqual(cluster, "discord")

        # Generic googleapis.com should still be 'google'
        self.assertEqual(classify_cdn_cluster("youtubei.googleapis.com"), "google")
        self.assertEqual(classify_cdn_cluster("googleapis.com"), "google")

        # Tenor and giphy domains
        self.assertEqual(classify_cdn_cluster("c.tenor.com"), "discord")
        self.assertEqual(classify_cdn_cluster("media.giphy.com"), "discord")

    def test_get_fallback_strategy_for_media_hosts(self):
        """Медиа Discord, Tenor и Giphy: combo, пока он не упал; после сбоя combo — другая совместимая техника."""
        selector = ThompsonStrategySelector(enabled=False)
        media_hosts = [
            "tenor.googleapis.com",
            "media.tenor.com",
            "c.tenor.com",
            "media.giphy.com",
            "giphy.com",
            "cdn.discordapp.com",
            "media.discordapp.net",
            "attachments.discord.net",
            "images-ext-1.discordapp.net"
        ]
        for host in media_hosts:
            strat = selector.get_fallback_strategy(host, failed_strategy="tls_record_frag")
            self.assertEqual(strat, "combo_tlsrec_tcpsplit", f"Failed for {host}")
            strat = selector.get_fallback_strategy(host, failed_strategy="combo_tlsrec_tcpsplit")
            self.assertIn(strat, ("tls_record_frag", "multi_split", "tcp_split_sni_start"), f"Failed for {host}")

    def test_pipe_sockets_got_initial_response_acknowledged(self):
        """_pipe_sockets sets server_replied_app_data=True and total_server_bytes=1 on got_initial_response."""
        proxy = object.__new__(DPIBypassProxy)
        proxy.config = MagicMock()
        proxy.strategy_engine = MagicMock()
        proxy.buffer_size = 32768
        proxy.bytes_tx = 0
        proxy.bytes_rx = 0
        proxy.timeout = 5.0
        proxy.is_running = True

        client_sock = MagicMock()
        target_sock = MagicMock()
        target_sock.getpeername.return_value = ("162.159.130.233", 443)

        # Client immediately closes keep-alive socket (b"")
        client_sock.recv.return_value = b""

        with patch("select.select", return_value=([client_sock], [], [])), \
             patch.object(DPIBypassProxy, "_record_route_failure") as mock_mark_dead, \
             patch("flowguard.proxy.mark_ip_working") as mock_mark_working:

            proxy._pipe_sockets(
                client_sock,
                target_sock,
                host="cdn.discordapp.com",
                strategy="combo_tlsrec_tcpsplit",
                got_initial_response=True
            )

            # IP must NOT be marked dead
            mock_mark_dead.assert_not_called()
            mock_mark_working.assert_called_with("162.159.130.233", "cdn.discordapp.com")
            proxy.strategy_engine.record_failure.assert_not_called()
            proxy.strategy_engine.record_success.assert_called_with(
                "cdn.discordapp.com", "combo_tlsrec_tcpsplit", ip="162.159.130.233"
            )

    def test_pipe_sockets_discord_media_normal_client_close(self):
        """Client closing idle HTTP/2 stream after receiving media does NOT ban IP."""
        proxy = object.__new__(DPIBypassProxy)
        proxy.config = MagicMock()
        proxy.strategy_engine = MagicMock()
        proxy.buffer_size = 32768
        proxy.bytes_tx = 0
        proxy.bytes_rx = 0
        proxy.timeout = 5.0
        proxy.is_running = True

        client_sock = MagicMock()
        target_sock = MagicMock()
        target_sock.getpeername.return_value = ("162.159.133.233", 443)

        # 1. Client sends request
        # 2. Server sends image data
        # 3. Client cleanly closes socket (EOF)
        call_seq = [0]
        def fake_select(r, w, x, t):
            call_seq[0] += 1
            if call_seq[0] == 1:
                return ([client_sock], [], [])
            elif call_seq[0] == 2:
                return ([target_sock], [], [])
            elif call_seq[0] == 3:
                return ([client_sock], [], [])
            return ([], [], [])

        client_sock.recv.side_effect = [b"GET /avatars/avatar.png HTTP/2\r\n", b""]
        target_sock.recv.side_effect = [b"HTTP/2 200 OK\r\n\r\n<img_bytes_12345>"]

        with patch("select.select", side_effect=fake_select), \
             patch.object(DPIBypassProxy, "_record_route_failure") as mock_mark_dead, \
             patch("flowguard.proxy.mark_ip_working") as mock_mark_working:

            proxy._pipe_sockets(
                client_sock,
                target_sock,
                host="cdn.discordapp.com",
                strategy="combo_tlsrec_tcpsplit",
                got_initial_response=False
            )

            mock_mark_dead.assert_not_called()
            mock_mark_working.assert_called_with("162.159.133.233", "cdn.discordapp.com")
            proxy.strategy_engine.record_failure.assert_not_called()
            proxy.strategy_engine.record_success.assert_called_with(
                "cdn.discordapp.com", "combo_tlsrec_tcpsplit", ip="162.159.133.233"
            )

    def test_discord_com_rest_api_small_payload_no_false_ban(self):
        """Discord GIF picker API (< 32KB) closed after > 4.0s keepalive does NOT ban discord.com."""
        proxy = object.__new__(DPIBypassProxy)
        proxy.config = MagicMock()
        proxy.strategy_engine = MagicMock()
        proxy.buffer_size = 32768
        proxy.bytes_tx = 0
        proxy.bytes_rx = 0
        proxy.timeout = 5.0
        proxy.is_running = True

        client_sock = MagicMock()
        target_sock = MagicMock()
        target_sock.getpeername.return_value = ("162.159.137.232", 443)

        call_seq = [0]
        def fake_select(r, w, x, t):
            call_seq[0] += 1
            if call_seq[0] == 1:
                return ([client_sock], [], [])
            elif call_seq[0] == 2:
                return ([target_sock], [], [])
            elif call_seq[0] == 3:
                return ([client_sock], [], [])
            return ([], [], [])

        # Small 9.9KB response for gifs/trending
        client_sock.recv.side_effect = [b"GET /api/v9/gifs/trending HTTP/1.1\r\n\r\n", b""]
        target_sock.recv.side_effect = [b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n" + b"X" * 1000]

        # Simulate 10 seconds elapsed between server reply and client socket closure
        base_time = 1000.0
        time_seq = [
            base_time,        # init
            base_time + 0.1,  # client send
            base_time + 0.2,  # server recv
            base_time + 10.0, # client clean close (now - last_server_byte_time = 9.8s > 4.0s)
            base_time + 10.1,
            base_time + 10.2,
        ]

        with patch("select.select", side_effect=fake_select), \
             patch("time.time", side_effect=time_seq), \
             patch.object(DPIBypassProxy, "_record_route_failure") as mock_mark_dead, \
             patch("flowguard.proxy.mark_ip_working") as mock_mark_working:

            proxy._pipe_sockets(
                client_sock,
                target_sock,
                host="discord.com",
                strategy="combo_tlsrec_tcpsplit",
                got_initial_response=False
            )

            # Must NOT be marked dead!
            mock_mark_dead.assert_not_called()
            mock_mark_working.assert_called_with("162.159.137.232", "discord.com")
            proxy.strategy_engine.record_failure.assert_not_called()

    def test_connect_target_revives_dead_ip_on_pool_exhaustion(self):
        """When all Anycast IPs are marked dead, _connect_target revives the oldest dead IP instead of returning None."""
        from flowguard.config import Config
        config = Config("_test_defaults_missing.ini")
        proxy = DPIBypassProxy(config)
        proxy.doh_harvester = None
        proxy.dns_failover = MagicMock()
        proxy.dns_failover.resolve.return_value = []

        # Mark all Discord CDN Anycast IPs as dead with staggered timestamps
        t_now = time.time()
        for idx, ip in enumerate(DISCORD_CDN_ANYCAST_IPS):
            # ip 0 has dead_until closest to now (oldest dead IP)
            _DEAD_IP_CACHE.set(ip, t_now + 10.0 + idx * 5.0)

        # Verify all are marked dead initially
        for ip in DISCORD_CDN_ANYCAST_IPS:
            self.assertTrue(is_ip_dead(ip))

        # Attempt connection to cdn.discordapp.com
        # Fake socket creation to avoid real network call
        with patch("socket.socket") as mock_socket_cls, \
             patch("socket.getaddrinfo", return_value=[]), \
             patch("flowguard.proxy.get_dns_failover_manager", return_value=None), \
             patch("flowguard.proxy.resolve_fallback_dns", return_value=None):
            fake_sock = MagicMock()
            fake_sock.connect.return_value = None
            fake_sock.connect_ex.return_value = 0
            mock_socket_cls.return_value = fake_sock

            sock = proxy._connect_target("cdn.discordapp.com", 443)
            self.assertIsNotNone(sock, "Must not return None on pool exhaustion")

            # Check that fake_sock was connected to the revived IP (oldest dead IP = DISCORD_CDN_ANYCAST_IPS[0])
            self.assertTrue(fake_sock.connect.called or fake_sock.connect_ex.called)
            connected_target = (fake_sock.connect.call_args or fake_sock.connect_ex.call_args)[0][0]
            self.assertIn(connected_target[0], DISCORD_CDN_ANYCAST_IPS[:2])
            self.assertFalse(is_ip_dead(connected_target[0]))
            self.assertEqual(connected_target[1], 443)


    def test_pipe_sockets_discord_media_exception_after_data_transferred_does_not_ban_ip(self):
        """Socket error (e.g. client ECONNRESET on stream abort) after data was transferred does not ban IP."""
        proxy = object.__new__(DPIBypassProxy)
        proxy.config = MagicMock()
        proxy.strategy_engine = MagicMock()
        proxy.buffer_size = 32768
        proxy.bytes_tx = 0
        proxy.bytes_rx = 0
        proxy.timeout = 5.0
        proxy.is_running = True

        client_sock = MagicMock()
        target_sock = MagicMock()
        target_sock.getpeername.return_value = ("162.159.130.233", 443)

        call_seq = [0]
        def fake_select(r, w, x, t):
            call_seq[0] += 1
            if call_seq[0] == 1:
                return ([client_sock], [], [])
            elif call_seq[0] == 2:
                return ([target_sock], [], [])
            elif call_seq[0] == 3:
                return ([client_sock], [], [])
            return ([], [], [])

        client_sock.recv.side_effect = [b"GET /attachments/photo.jpg HTTP/2\r\n", socket.error("connection reset")]
        target_sock.recv.side_effect = [b"HTTP/2 200 OK\r\n\r\n<first_image_chunk>"]

        with patch("select.select", side_effect=fake_select), \
             patch.object(DPIBypassProxy, "_record_route_failure") as mock_mark_dead, \
             patch("flowguard.proxy.mark_ip_working") as mock_mark_working:

            proxy._pipe_sockets(
                client_sock,
                target_sock,
                host="cdn.discordapp.com",
                strategy="combo_tlsrec_tcpsplit",
                got_initial_response=False
            )

            # Since data was received from server, client ECONNRESET is not a DPI block
            mock_mark_dead.assert_not_called()
            mock_mark_working.assert_called_with("162.159.130.233", "cdn.discordapp.com")
            proxy.strategy_engine.record_failure.assert_not_called()

    def test_pipe_sockets_discord_media_exception_on_stall_bans_ip(self):
        """Socket error or timeout when server sent 0 bytes and request was pending bans IP."""
        proxy = object.__new__(DPIBypassProxy)
        proxy.config = MagicMock()
        proxy.strategy_engine = MagicMock()
        proxy.buffer_size = 32768
        proxy.bytes_tx = 0
        proxy.bytes_rx = 0
        proxy.timeout = 5.0
        proxy.is_running = True

        client_sock = MagicMock()
        target_sock = MagicMock()
        target_sock.getpeername.return_value = ("162.159.130.233", 443)

        call_seq = [0]
        def fake_select(r, w, x, t):
            call_seq[0] += 1
            if call_seq[0] == 1:
                return ([client_sock], [], [])
            elif call_seq[0] == 2:
                return ([target_sock], [], [])
            return ([], [], [])

        client_sock.recv.side_effect = [b"GET /attachments/photo.jpg HTTP/2\r\n"]
        target_sock.recv.side_effect = socket.timeout("timed out")

        with patch("select.select", side_effect=fake_select), \
             patch.object(DPIBypassProxy, "_record_route_failure") as mock_mark_dead:

            proxy._pipe_sockets(
                client_sock,
                target_sock,
                host="cdn.discordapp.com",
                strategy="combo_tlsrec_tcpsplit",
                got_initial_response=False
            )

            # Server never replied, so this stall properly marks IP dead
            self.assertEqual(mock_mark_dead.call_args.args[2], "162.159.130.233")
            proxy.strategy_engine.record_failure.assert_called_with(
                "cdn.discordapp.com", "combo_tlsrec_tcpsplit", ip="162.159.130.233", is_tspu=False
            )

    def test_pipe_sockets_idle_keepalive_timeout_after_window_update_does_not_ban_ip(self):
        """HTTP/2 WINDOW_UPDATE frame followed by idle keep-alive timeout does NOT ban IP."""
        proxy = object.__new__(DPIBypassProxy)
        proxy.config = MagicMock()
        proxy.strategy_engine = MagicMock()
        proxy.buffer_size = 32768
        proxy.bytes_tx = 0
        proxy.bytes_rx = 0
        proxy.timeout = 5.0
        proxy.is_running = True

        client_sock = MagicMock()
        target_sock = MagicMock()
        target_sock.getpeername.return_value = ("162.159.130.233", 443)

        call_seq = [0]
        def fake_select(r, w, x, t):
            call_seq[0] += 1
            if call_seq[0] == 1:
                return ([client_sock], [], [])  # client sends request
            elif call_seq[0] == 2:
                return ([target_sock], [], [])  # server sends image
            elif call_seq[0] == 3:
                return ([client_sock], [], [])  # client sends WINDOW_UPDATE
            elif call_seq[0] == 4:
                return ([], [], [])             # timeout on idle keepalive
            return ([], [], [])

        client_sock.recv.side_effect = [b"GET /avatar.png HTTP/2\r\n", b"WINDOW_UPDATE_FRAME"]
        target_sock.recv.side_effect = [b"HTTP/2 200 OK\r\n\r\n<img_data>"]

        with patch("select.select", side_effect=fake_select), \
             patch.object(DPIBypassProxy, "_record_route_failure") as mock_mark_dead, \
             patch("flowguard.proxy.mark_ip_working") as mock_mark_working:

            proxy._pipe_sockets(
                client_sock,
                target_sock,
                host="cdn.discordapp.com",
                strategy="combo_tlsrec_tcpsplit",
                got_initial_response=False
            )

            mock_mark_dead.assert_not_called()
            mock_mark_working.assert_called_with("162.159.130.233", "cdn.discordapp.com")
            proxy.strategy_engine.record_failure.assert_not_called()
            proxy.strategy_engine.record_success.assert_called_with(
                "cdn.discordapp.com", "combo_tlsrec_tcpsplit", ip="162.159.130.233"
            )

    def test_pipe_sockets_discord_com_assets_request_clean_close_does_not_ban_ip(self):
        """Requests for discord.com/assets/ (icons, emojis, sounds) clean close after idle does NOT ban IP."""
        proxy = object.__new__(DPIBypassProxy)
        proxy.config = MagicMock()
        proxy.strategy_engine = MagicMock()
        proxy.buffer_size = 32768
        proxy.bytes_tx = 0
        proxy.bytes_rx = 0
        proxy.timeout = 5.0
        proxy.is_running = True

        client_sock = MagicMock()
        target_sock = MagicMock()
        target_sock.getpeername.return_value = ("162.159.137.232", 443)

        cur_time = [1000.0]
        def fake_time():
            return cur_time[0]

        call_seq = [0]
        def fake_select(r, w, x, t):
            call_seq[0] += 1
            if call_seq[0] == 1:
                cur_time[0] = 1000.0
                return ([client_sock], [], [])  # client sends request
            elif call_seq[0] == 2:
                cur_time[0] = 1000.1
                return ([target_sock], [], [])  # server sends 2KB icon
            elif call_seq[0] == 3:
                cur_time[0] = 1005.0            # 4.9s later, client closes idle keepalive
                return ([client_sock], [], [])
            return ([], [], [])

        client_sock.recv.side_effect = [b"GET /assets/icon.svg HTTP/1.1\r\nHost: discord.com\r\n\r\n", b""]
        target_sock.recv.side_effect = [b"HTTP/1.1 200 OK\r\nContent-Length: 2000\r\n\r\n" + b"S" * 2000]

        with patch("select.select", side_effect=fake_select), \
             patch("time.time", side_effect=fake_time), \
             patch.object(DPIBypassProxy, "_record_route_failure") as mock_mark_dead, \
             patch("flowguard.proxy.mark_ip_working") as mock_mark_working:

            proxy._pipe_sockets(
                client_sock,
                target_sock,
                host="discord.com",
                strategy="combo_tlsrec_tcpsplit",
                got_initial_response=False
            )

            mock_mark_dead.assert_not_called()
            mock_mark_working.assert_called_with("162.159.137.232", "discord.com")
            proxy.strategy_engine.record_failure.assert_not_called()
            proxy.strategy_engine.record_success.assert_called_with(
                "discord.com", "combo_tlsrec_tcpsplit", ip="162.159.137.232"
            )

    def test_pipe_sockets_discord_com_rest_api_exception_after_data_marks_working(self):
        """When socket error occurs on discord.com REST API after data was received, IP is marked working."""
        proxy = object.__new__(DPIBypassProxy)
        proxy.config = MagicMock()
        proxy.strategy_engine = MagicMock()
        proxy.buffer_size = 32768
        proxy.bytes_tx = 0
        proxy.bytes_rx = 0
        proxy.timeout = 5.0
        proxy.is_running = True

        client_sock = MagicMock()
        target_sock = MagicMock()
        target_sock.getpeername.return_value = ("162.159.137.232", 443)

        call_seq = [0]
        def fake_select(r, w, x, t):
            call_seq[0] += 1
            if call_seq[0] == 1:
                return ([client_sock], [], [])
            elif call_seq[0] == 2:
                return ([target_sock], [], [])
            elif call_seq[0] == 3:
                return ([client_sock], [], [])
            return ([], [], [])

        client_sock.recv.side_effect = [b"GET /api/v9/gifs/trending HTTP/1.1\r\nHost: discord.com\r\n\r\n", socket.error("conn reset")]
        target_sock.recv.side_effect = [b"HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n" + b"G" * 5000]

        with patch("select.select", side_effect=fake_select), \
             patch.object(DPIBypassProxy, "_record_route_failure") as mock_mark_dead, \
             patch("flowguard.proxy.mark_ip_working") as mock_mark_working:

            proxy._pipe_sockets(
                client_sock,
                target_sock,
                host="discord.com",
                strategy="combo_tlsrec_tcpsplit",
                got_initial_response=False
            )

            mock_mark_dead.assert_not_called()
            mock_mark_working.assert_called_with("162.159.137.232", "discord.com")
            proxy.strategy_engine.record_failure.assert_not_called()
            proxy.strategy_engine.record_success.assert_called_with(
                "discord.com", "combo_tlsrec_tcpsplit", ip="162.159.137.232"
            )

    def test_gateway_handshake_success_does_not_prematurely_cache_working_ip(self):
        """Рукопожатие gateway.discord.gg при успехе не должно преждевременно кэшировать IP (отложено до _pipe_sockets)."""
        proxy = object.__new__(DPIBypassProxy)
        proxy.shadow_prober = None
        client_sock = MagicMock()
        mock_sock = MagicMock()
        target_ip = "162.159.136.234"
        _set_socket_meta(mock_sock, target_ip=target_ip, connect_rtt=0.02)
        proxy._probe_socket_response = MagicMock(return_value=("success", b"\x16\x03\x03\x00\x50", 15.0))
        proxy._send_tls_client_hello_with_bypass = MagicMock(return_value=("combo_tlsrec_tcpsplit", "gateway.discord.gg"))

        with patch("flowguard.proxy.is_tls_client_hello", return_value=True), \
             patch("flowguard.proxy.mark_ip_working") as mock_mark_working:
            res_sock, strat, eff_host, resp = proxy._handshake_with_fast_fallback(
                client_sock, mock_sock, "gateway.discord.gg", 443, b"\x16\x03\x01\x00\x10"
            )
            self.assertIsNotNone(res_sock)
            mock_mark_working.assert_not_called()

    def test_pipe_sockets_discord_gateway_stall_under_32kb_bans_ip(self):
        """Закрытие WebSocket клиентом на gateway.discord.gg при отсутствии ответа сервера распознаётся как stall ТСПУ и банит IP."""
        proxy = object.__new__(DPIBypassProxy)
        proxy.config = MagicMock()
        proxy.strategy_engine = MagicMock()
        proxy.buffer_size = 32768
        proxy.bytes_tx = 0
        proxy.bytes_rx = 0
        proxy.timeout = 5.0
        proxy.is_running = True

        client_sock = MagicMock()
        target_sock = MagicMock()
        target_ip = "162.159.136.234"
        target_sock.getpeername.return_value = (target_ip, 443)

        call_seq = [0]
        def fake_select(r, w, x, t):
            call_seq[0] += 1
            if call_seq[0] == 1:
                return ([client_sock], [], [])
            elif call_seq[0] == 2:
                # Клиент закрывает сокет, сервер так и не ответил
                return ([client_sock], [], [])
            return ([], [], [])

        client_sock.recv.side_effect = [b"GET /?v=9&encoding=json HTTP/1.1\r\nHost: gateway.discord.gg\r\n\r\n", b""]
        target_sock.recv.side_effect = []

        with patch("select.select", side_effect=fake_select), \
             patch.object(DPIBypassProxy, "_record_route_failure") as mock_mark_dead, \
             patch("flowguard.proxy.mark_ip_working") as mock_mark_working:
            proxy._pipe_sockets(
                client_sock,
                target_sock,
                host="gateway.discord.gg",
                strategy="combo_tlsrec_tcpsplit",
                got_initial_response=False
            )
            self.assertEqual(mock_mark_dead.call_args.args[2], target_ip)
            mock_mark_working.assert_not_called()
            proxy.strategy_engine.record_failure.assert_called_with(
                "gateway.discord.gg", "combo_tlsrec_tcpsplit", ip=target_ip, is_tspu=False
            )

    def test_pipe_sockets_discord_gateway_clean_close_with_data_under_32kb_does_not_ban_ip(self):
        """Штатное закрытие WebSocket клиентом на gateway.discord.gg после ответа сервера не банит IP и фиксирует успех."""
        proxy = object.__new__(DPIBypassProxy)
        proxy.config = MagicMock()
        proxy.strategy_engine = MagicMock()
        proxy.buffer_size = 32768
        proxy.bytes_tx = 0
        proxy.bytes_rx = 0
        proxy.timeout = 5.0
        proxy.is_running = True

        client_sock = MagicMock()
        target_sock = MagicMock()
        target_ip = "162.159.136.234"
        target_sock.getpeername.return_value = (target_ip, 443)

        call_seq = [0]
        def fake_select(r, w, x, t):
            call_seq[0] += 1
            if call_seq[0] == 1:
                return ([client_sock], [], [])
            elif call_seq[0] == 2:
                return ([target_sock], [], [])
            elif call_seq[0] == 3:
                return ([client_sock], [], [])
            return ([], [], [])

        client_sock.recv.side_effect = [b"GET /?v=9&encoding=json HTTP/1.1\r\nHost: gateway.discord.gg\r\n\r\n", b""]
        target_sock.recv.side_effect = [b"HTTP/1.1 101 Switching Protocols\r\n\r\n" + b"X" * 12000]

        with patch("select.select", side_effect=fake_select), \
             patch.object(DPIBypassProxy, "_record_route_failure") as mock_mark_dead, \
             patch("flowguard.proxy.mark_ip_working") as mock_mark_working:
            proxy._pipe_sockets(
                client_sock,
                target_sock,
                host="gateway.discord.gg",
                strategy="combo_tlsrec_tcpsplit",
                got_initial_response=False
            )
            mock_mark_dead.assert_not_called()
            mock_mark_working.assert_called_with(target_ip, "gateway.discord.gg")
            proxy.strategy_engine.record_success.assert_called_with(
                "gateway.discord.gg", "combo_tlsrec_tcpsplit", ip=target_ip
            )

    def test_discord_rest_api_under_32kb_records_success(self):
        """Ответы Discord REST API (<32KB, например 1500 байт на /boost или /guilds) фиксируют успех."""
        proxy = object.__new__(DPIBypassProxy)
        proxy.config = MagicMock()
        proxy.strategy_engine = MagicMock()
        proxy.buffer_size = 32768
        proxy.bytes_tx = 0
        proxy.bytes_rx = 0
        proxy.timeout = 5.0
        proxy.is_running = True

        client_sock = MagicMock()
        target_sock = MagicMock()
        target_ip = "162.159.136.232"
        target_sock.getpeername.return_value = (target_ip, 443)

        call_seq = [0]
        def fake_select(r, w, x, t):
            call_seq[0] += 1
            if call_seq[0] == 1:
                return ([client_sock], [], [])
            elif call_seq[0] == 2:
                return ([target_sock], [], [])
            elif call_seq[0] == 3:
                return ([target_sock], [], [])
            return ([], [], [])

        client_sock.recv.side_effect = [b"GET /api/v9/users/@me/guilds HTTP/1.1\r\nHost: discord.com\r\n\r\n"]
        target_sock.recv.side_effect = [b"HTTP/1.1 200 OK\r\nContent-Length: 1500\r\n\r\n" + b"J" * 1500, b""]

        with patch("select.select", side_effect=fake_select), \
             patch("flowguard.proxy.mark_ip_working") as mock_mark_working:
            proxy._pipe_sockets(
                client_sock,
                target_sock,
                host="discord.com",
                strategy="combo_tlsrec_tcpsplit",
                got_initial_response=False
            )
            mock_mark_working.assert_called_with(target_ip, "discord.com")
            proxy.strategy_engine.record_success.assert_called_with(
                "discord.com", "combo_tlsrec_tcpsplit", ip=target_ip
            )

    def test_winws_strict_isolation_does_not_disable_proxy_desync(self):
        """strict=True изолирован от fallback кэша и не возвращает True при внешнем winws без подтвержденных аргументов."""
        from flowguard.voice_helper import is_winws_tcp_filtering_active, VoiceHelper
        ext_vh = VoiceHelper(mode="proxy")
        ext_vh.managed_by_us = False

        with patch("flowguard.voice_helper.is_system_winws_running", return_value=True), \
             patch("flowguard.voice_helper.get_winws_command_lines", return_value=[]), \
             patch("flowguard.voice_helper.is_windivert_driver_running", return_value=True):
            # Без strict fallback на WinDivert возвращает True
            self.assertTrue(is_winws_tcp_filtering_active(voice_helper=ext_vh, force_refresh=True, strict=False))
            # В strict режиме для proxy.py кэш strict=False НЕ должен возвращать True!
            self.assertFalse(is_winws_tcp_filtering_active(voice_helper=ext_vh, force_refresh=False, strict=True))

    def test_discord_core_anycast_contains_gateway_and_web_nodes(self):
        """DISCORD_CORE_ANYCAST_IPS содержит .234 для Gateway и .232/.233 для Web."""
        from flowguard.proxy import DISCORD_CORE_ANYCAST_IPS
        gateway_nodes = [ip for ip in DISCORD_CORE_ANYCAST_IPS if ip.endswith(".234")]
        web_nodes = [ip for ip in DISCORD_CORE_ANYCAST_IPS if ip.endswith(".232") or ip.endswith(".233")]
        self.assertGreaterEqual(len(gateway_nodes), 5)
        self.assertGreaterEqual(len(web_nodes), 6)
        self.assertEqual(gateway_nodes[0], "162.159.134.234")
        self.assertIn("162.159.136.234", gateway_nodes)
        self.assertIn("162.159.136.232", web_nodes)

    def test_discord_com_web_pool_and_gateway_pool_separation(self):
        """discord.com использует пул Web/API (.232/.233) с 162.159.136.232 во главе, а gateway - .234."""
        from flowguard.proxy import DISCORD_CORE_ANYCAST_IPS
        web_nodes = [ip for ip in DISCORD_CORE_ANYCAST_IPS if ip.endswith(".232") or ip.endswith(".233")]
        gateway_nodes = [ip for ip in DISCORD_CORE_ANYCAST_IPS if ip.endswith(".234")]
        self.assertEqual(web_nodes[0], "162.159.136.232")
        self.assertEqual(gateway_nodes[0], "162.159.134.234")
        # Убедимся, что gateway (.234) не попадают в web_nodes
        for ip in web_nodes:
            self.assertFalse(ip.endswith(".234"), f"Gateway IP {ip} found in web nodes!")

    def test_pipe_sockets_discord_com_boost_under_32kb_marks_ip_working(self):
        """Ответ Discord REST API на /boost (<32KB) при последующем таймауте неактивности keep-alive фиксирует успех и помечает IP."""
        proxy = object.__new__(DPIBypassProxy)
        proxy.config = MagicMock()
        proxy.strategy_engine = MagicMock()
        proxy.buffer_size = 32768
        proxy.bytes_tx = 0
        proxy.bytes_rx = 0
        proxy.timeout = 5.0
        proxy.is_running = True

        client_sock = MagicMock()
        target_sock = MagicMock()
        target_ip = "162.159.136.232"
        target_sock.getpeername.return_value = (target_ip, 443)

        call_seq = [0]
        def fake_select(r, w, x, t):
            call_seq[0] += 1
            if call_seq[0] == 1:
                return ([client_sock], [], [])
            elif call_seq[0] == 2:
                return ([target_sock], [], [])
            elif call_seq[0] == 3:
                # таймаут select (нет активных сокетов)
                return ([], [], [])
            return ([], [], [])

        client_sock.recv.side_effect = [b"GET /api/v9/guilds/123/boost HTTP/1.1\r\nHost: discord.com\r\n\r\n"]
        target_sock.recv.side_effect = [b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n" + b"B" * 1000]

        with patch("select.select", side_effect=fake_select), \
             patch("flowguard.proxy.mark_ip_working") as mock_mark_working:
            proxy._pipe_sockets(
                client_sock,
                target_sock,
                host="discord.com",
                strategy="combo_tlsrec_tcpsplit",
                got_initial_response=False
            )
            # Ответ /boost (<32KB) валиден и доказывает обход DPI: IP помечается рабочим
            mock_mark_working.assert_called_with(target_ip, "discord.com")
            proxy.strategy_engine.record_success.assert_called_with(
                "discord.com", "combo_tlsrec_tcpsplit", ip=target_ip
            )

    def test_pipe_sockets_discord_com_inactivity_timeout_without_response_marks_ip_dead(self):
        """Таймаут неактивности на discord.com без ответа сервера банит IP и не помечает как рабочий."""
        proxy = object.__new__(DPIBypassProxy)
        proxy.config = MagicMock()
        proxy.strategy_engine = MagicMock()
        proxy.buffer_size = 32768
        proxy.bytes_tx = 0
        proxy.bytes_rx = 0
        proxy.timeout = 5.0
        proxy.is_running = True

        client_sock = MagicMock()
        target_sock = MagicMock()
        target_ip = "162.159.136.232"
        target_sock.getpeername.return_value = (target_ip, 443)

        call_seq = [0]
        def fake_select(r, w, x, t):
            call_seq[0] += 1
            if call_seq[0] == 1:
                return ([client_sock], [], [])
            elif call_seq[0] == 2:
                # таймаут select (сервер не ответил)
                return ([], [], [])
            return ([], [], [])

        client_sock.recv.side_effect = [b"GET /api/v9/guilds/123/boost HTTP/1.1\r\nHost: discord.com\r\n\r\n"]
        target_sock.recv.side_effect = []

        with patch("select.select", side_effect=fake_select), \
             patch.object(DPIBypassProxy, "_record_route_failure") as mock_mark_dead, \
             patch("flowguard.proxy.mark_ip_working") as mock_mark_working:
            proxy._pipe_sockets(
                client_sock,
                target_sock,
                host="discord.com",
                strategy="combo_tlsrec_tcpsplit",
                got_initial_response=False
            )
            mock_mark_working.assert_not_called()
            self.assertEqual(mock_mark_dead.call_args.args[2], target_ip)
            proxy.strategy_engine.record_failure.assert_called_with(
                "discord.com", "combo_tlsrec_tcpsplit", ip=target_ip, is_tspu=False
            )

    def test_handshake_discord_subdomain_does_not_prematurely_cache(self):
        """Рукопожатие canary.discord.com / ptb.discord.com не кэширует IP преждевременно."""
        proxy = object.__new__(DPIBypassProxy)
        proxy.shadow_prober = None
        client_sock = MagicMock()
        mock_sock = MagicMock()
        target_ip = "162.159.136.232"
        _set_socket_meta(mock_sock, target_ip=target_ip, connect_rtt=0.02)
        proxy._probe_socket_response = MagicMock(return_value=("success", b"\x16\x03\x03\x00\x50", 15.0))
        proxy._send_tls_client_hello_with_bypass = MagicMock(return_value=("combo_tlsrec_tcpsplit", "canary.discord.com"))

        with patch("flowguard.proxy.is_tls_client_hello", return_value=True), \
             patch("flowguard.proxy.mark_ip_working") as mock_mark_working:
            res_sock, strat, eff_host, resp = proxy._handshake_with_fast_fallback(
                client_sock, mock_sock, "canary.discord.com", 443, b"\x16\x03\x01\x00\x10"
            )
            self.assertIsNotNone(res_sock)
            mock_mark_working.assert_not_called()

    def test_connect_target_pins_primary_gateway_ip(self):
        """Для gateway.discord.gg первичным кандидатом всегда является 162.159.134.234."""
        from flowguard.config import Config
        config = Config("_test_defaults_missing.ini")
        proxy = DPIBypassProxy(config)
        proxy.doh_harvester = None
        proxy.dns_failover = MagicMock()
        proxy.dns_failover.resolve.return_value = []

        with patch("socket.socket") as mock_socket_cls, \
             patch("socket.getaddrinfo", return_value=[]), \
             patch("flowguard.proxy.get_dns_failover_manager", return_value=None), \
             patch("flowguard.proxy.resolve_fallback_dns", return_value=None):
            fake_sock = MagicMock()
            fake_sock.connect.return_value = None
            fake_sock.connect_ex.return_value = 0
            mock_socket_cls.return_value = fake_sock

            sock = proxy._connect_target("gateway.discord.gg", 443)
            self.assertIsNotNone(sock)
            connected_ip = (fake_sock.connect.call_args or fake_sock.connect_ex.call_args)[0][0][0]
            self.assertEqual(connected_ip, "162.159.134.234")

    def test_connect_target_pins_primary_discord_com_ip(self):
        """Для discord.com первичным кандидатом всегда является 162.159.136.232."""
        from flowguard.config import Config
        config = Config("_test_defaults_missing.ini")
        proxy = DPIBypassProxy(config)
        proxy.doh_harvester = None
        proxy.dns_failover = MagicMock()
        proxy.dns_failover.resolve.return_value = []

        with patch("socket.socket") as mock_socket_cls, \
             patch("socket.getaddrinfo", return_value=[]), \
             patch("flowguard.proxy.get_dns_failover_manager", return_value=None), \
             patch("flowguard.proxy.resolve_fallback_dns", return_value=None):
            fake_sock = MagicMock()
            fake_sock.connect.return_value = None
            fake_sock.connect_ex.return_value = 0
            mock_socket_cls.return_value = fake_sock

            sock = proxy._connect_target("discord.com", 443)
            self.assertIsNotNone(sock)
            connected_ip = (fake_sock.connect.call_args or fake_sock.connect_ex.call_args)[0][0][0]
            self.assertEqual(connected_ip, "162.159.136.232")

    def test_pipe_sockets_discord_gateway_stall_after_14kb_data_bans_ip(self):
        """Зависание ТСПУ на gateway.discord.gg после 14КБ данных (>3.0с молчания) распознается как stall и банит IP."""
        proxy = object.__new__(DPIBypassProxy)
        proxy.config = MagicMock()
        proxy.strategy_engine = MagicMock()
        proxy.buffer_size = 32768
        proxy.bytes_tx = 0
        proxy.bytes_rx = 0
        proxy.timeout = 5.0
        proxy.is_running = True

        client_sock = MagicMock()
        target_sock = MagicMock()
        target_ip = "162.159.136.234"
        target_sock.getpeername.return_value = (target_ip, 443)

        cur_time = [1000.0]
        def fake_time():
            return cur_time[0]

        call_seq = [0]
        def fake_select(r, w, x, t):
            call_seq[0] += 1
            if call_seq[0] == 1:
                cur_time[0] = 1000.0
                return ([client_sock], [], [])
            elif call_seq[0] == 2:
                cur_time[0] = 1000.1
                return ([target_sock], [], [])  # сервер прислал 14КБ
            elif call_seq[0] == 3:
                cur_time[0] = 1004.0            # 3.9с молчания от сервера, клиент закрыл сокет по таймауту
                return ([client_sock], [], [])
            return ([], [], [])

        client_sock.recv.side_effect = [b"GET /?v=9&encoding=json HTTP/1.1\r\nHost: gateway.discord.gg\r\n\r\n", b""]
        target_sock.recv.side_effect = [b"HTTP/1.1 101 Switching Protocols\r\n\r\n" + b"W" * 14000]

        with patch("select.select", side_effect=fake_select), \
             patch("time.time", side_effect=fake_time), \
             patch.object(DPIBypassProxy, "_record_route_failure") as mock_mark_dead, \
             patch("flowguard.proxy.mark_ip_working") as mock_mark_working:
            proxy._pipe_sockets(
                client_sock,
                target_sock,
                host="gateway.discord.gg",
                strategy="combo_tlsrec_tcpsplit",
                got_initial_response=False
            )
            self.assertEqual(mock_mark_dead.call_args.args[2], target_ip)
            mock_mark_working.assert_not_called()
            proxy.strategy_engine.record_failure.assert_called_with(
                "gateway.discord.gg", "combo_tlsrec_tcpsplit", ip=target_ip, is_tspu=False
            )

    def test_pipe_sockets_discord_app_bundle_stall_after_16kb_data_bans_ip(self):
        """Зависание ТСПУ на discord.com/app после 16КБ (>3.0с молчания) распознается как stall и банит IP."""
        proxy = object.__new__(DPIBypassProxy)
        proxy.config = MagicMock()
        proxy.strategy_engine = MagicMock()
        proxy.buffer_size = 32768
        proxy.bytes_tx = 0
        proxy.bytes_rx = 0
        proxy.timeout = 5.0
        proxy.is_running = True

        client_sock = MagicMock()
        target_sock = MagicMock()
        target_ip = "162.159.137.232"
        target_sock.getpeername.return_value = (target_ip, 443)

        cur_time = [1000.0]
        def fake_time():
            return cur_time[0]

        call_seq = [0]
        def fake_select(r, w, x, t):
            call_seq[0] += 1
            if call_seq[0] == 1:
                cur_time[0] = 1000.0
                return ([client_sock], [], [])
            elif call_seq[0] == 2:
                cur_time[0] = 1000.1
                return ([target_sock], [], [])  # сервер прислал 16КБ бандла
            elif call_seq[0] == 3:
                cur_time[0] = 1004.5            # 4.4с молчания ТСПУ, клиент закрыл сокет
                return ([client_sock], [], [])
            return ([], [], [])

        client_sock.recv.side_effect = [b"GET /app HTTP/1.1\r\nHost: discord.com\r\n\r\n", b""]
        target_sock.recv.side_effect = [b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + b"H" * 16000]

        with patch("select.select", side_effect=fake_select), \
             patch("time.time", side_effect=fake_time), \
             patch.object(DPIBypassProxy, "_record_route_failure") as mock_mark_dead, \
             patch("flowguard.proxy.mark_ip_working") as mock_mark_working:
            proxy._pipe_sockets(
                client_sock,
                target_sock,
                host="discord.com",
                strategy="combo_tlsrec_tcpsplit",
                got_initial_response=False
            )
            self.assertEqual(mock_mark_dead.call_args.args[2], target_ip)
            mock_mark_working.assert_not_called()
            proxy.strategy_engine.record_failure.assert_called_with(
                "discord.com", "combo_tlsrec_tcpsplit", ip=target_ip, is_tspu=False
            )


if __name__ == "__main__":
    unittest.main()
