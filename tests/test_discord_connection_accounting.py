"""Проверки независимости оценки соединения Discord от постороннего трафика."""

import socket
import unittest
from unittest.mock import MagicMock, patch

from flowguard.proxy import DPIBypassProxy, _set_socket_meta, _clean_socket_meta


class TestDiscordConnectionAccounting(unittest.TestCase):
    def test_incomplete_bundle_is_not_upload_after_unrelated_traffic(self):
        for previous_bytes in (0, 1024 * 1024):
            for disconnected_by_reset in (False, True):
                with self.subTest(previous_bytes=previous_bytes, reset=disconnected_by_reset):
                    proxy = object.__new__(DPIBypassProxy)
                    proxy.strategy_engine = MagicMock()
                    proxy.buffer_size = 32768
                    proxy.bytes_tx = previous_bytes
                    proxy.bytes_rx = 0
                    proxy.timeout = 5.0
                    proxy.is_running = True

                    client = MagicMock(spec=socket.socket)
                    upstream = MagicMock(spec=socket.socket)
                    ip = "162.159.136.232"
                    _set_socket_meta(upstream, target_ip=ip, connect_rtt=0.02)
                    self.addCleanup(_clean_socket_meta, upstream)
                    client.recv.side_effect = [
                        b"GET /assets/app.js HTTP/1.1\r\nHost: discord.com\r\n\r\n",
                        ConnectionResetError() if disconnected_by_reset else b"",
                    ]
                    partial_response = b"HTTP/1.1 200 OK\r\nContent-Length: 65536\r\n\r\n" + b"x" * 12000
                    upstream.recv.return_value = partial_response
                    now = [1000.0]
                    events = iter(((1000.0, client), (1000.1, upstream), (1004.0, client)))

                    def select_ready(*args):
                        timestamp, readable = next(events)
                        now[0] = timestamp
                        return [readable], [], []

                    with patch("flowguard.proxy.select.select", side_effect=select_ready), \
                         patch("flowguard.proxy.time.time", side_effect=lambda: now[0]), \
                         patch.object(DPIBypassProxy, "_record_route_failure") as route_failure, \
                         patch("flowguard.proxy.mark_ip_working") as mark_working:
                        proxy._pipe_sockets(client, upstream, host="discord.com",
                                            strategy="combo_tlsrec_tcpsplit")
                    proxy.strategy_engine.record_success.assert_not_called()
                    mark_working.assert_not_called()
                    route_failure.assert_called_with("discord.com", 443, ip)
                    proxy.strategy_engine.record_failure.assert_called_with(
                        "discord.com", "combo_tlsrec_tcpsplit", ip=ip, is_tspu=False
                    )
                    client.sendall.assert_called_once_with(partial_response)
