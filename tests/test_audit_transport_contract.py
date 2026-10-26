"""Целостность HTTP-тела и первого сообщения TLS через CONNECT."""

import socket
import threading
import unittest
from unittest.mock import Mock, MagicMock, patch

from flowguard.config import Config
from flowguard.proxy import DPIBypassProxy
from flowguard.sni_spoofer import build_fake_client_hello
from flowguard.tls_parser import create_tls_record_fragments, collect_client_hello


class TestAuditTransport(unittest.TestCase):
    def test_collect_fragmented_hello_over_local_sockets(self):
        writer, reader = socket.socketpair()
        self.addCleanup(writer.close)
        self.addCleanup(reader.close)
        reader.settimeout(2)
        hello = build_fake_client_hello('example.com')
        pieces = create_tls_record_fragments(hello, 7)
        wire = b''.join(pieces)
        writer.sendall(wire)
        initial = reader.recv(1)
        self.assertEqual(collect_client_hello(reader, initial, 2), wire)
        self.assertEqual(reader.gettimeout(), 2)

    def test_incomplete_hello_is_rejected_without_waiting_forever(self):
        sock = Mock()
        sock.recv.return_value = b''
        with self.assertRaises(EOFError):
            collect_client_hello(sock, b'\x16', 1)

    def test_non_tls_binary_payload_is_not_parsed_as_clienthello(self):
        sock = Mock()
        payload = b'\x16\x00PING'
        self.assertEqual(collect_client_hello(sock, payload, 1), payload)
        sock.recv.assert_not_called()

    def make_proxy(self):
        proxy = object.__new__(DPIBypassProxy)
        proxy.config = Config()
        proxy.timeout = 1
        proxy.buffer_size = 65536
        proxy._lock = threading.Lock()
        proxy._whitelist_lock = threading.Lock()
        proxy._logged_whitelisted_lock = threading.Lock()
        proxy._logged_whitelisted = set()
        proxy.whitelist_domains = set()
        proxy._check_reload_whitelist = Mock()
        proxy._concurrency_sem = Mock()
        proxy.active_connections = 1
        return proxy

    def test_http_body_is_byte_exact(self):
        proxy = self.make_proxy()
        body = b'file\r\nHost: original\r\nend'
        request = b'POST / HTTP/1.1\r\nHost: example.com\r\n\r\n' + body
        result = proxy._obfuscate_http_request(request, 'example.com')
        self.assertEqual(result.partition(b'\r\n\r\n')[2], body)
        self.assertIn(b'hoSt: example.com', result.partition(b'\r\n\r\n')[0])

    def test_fragmented_clienthello_is_collected_before_waiting_for_server(self):
        proxy = self.make_proxy()
        fragments = create_tls_record_fragments(build_fake_client_hello('example.com'))
        client = MagicMock(spec=socket.socket)
        client.recv.side_effect = [b'CONNECT example.com:443 HTTP/1.1\r\n\r\n', *fragments]
        upstream = MagicMock(spec=socket.socket)
        proxy._connect_target = Mock(return_value=upstream)
        proxy._handshake_with_fast_fallback = Mock(return_value=(None, '', '', b''))
        proxy._handle_client(client, ('127.0.0.1', 1234))
        self.assertEqual(proxy._handshake_with_fast_fallback.call_args.args[-1], b''.join(fragments))

    def test_short_non_tls_request_does_not_wait_for_nine_bytes(self):
        proxy = self.make_proxy()
        client = MagicMock(spec=socket.socket)
        client.recv.side_effect = [b'CONNECT example.com:123 HTTP/1.1\r\n\r\n', b'PING\n', AssertionError('Лишнее ожидание')]
        proxy._connect_target = Mock(return_value=MagicMock(spec=socket.socket))
        proxy._handshake_with_fast_fallback = Mock(return_value=(None, '', '', b''))
        proxy._handle_client(client, ('127.0.0.1', 1234))
        self.assertEqual(client.recv.call_count, 2)
        self.assertEqual(proxy._handshake_with_fast_fallback.call_args.args[-1], b'PING\n')

    def test_failed_fake_sni_still_sends_real_hello(self):
        proxy = self.make_proxy()
        proxy.config.set_override('fake_sni_record', True)
        proxy.sni_spoofer = Mock()
        proxy.sni_spoofer.send_with_fake_sni_desync.return_value = False
        proxy.strategy_engine = Mock()
        hello = build_fake_client_hello('example.com')
        upstream = Mock()
        with patch('flowguard.proxy.is_winws_tcp_filtering_active', return_value=False):
            strategy, host = proxy._send_tls_client_hello_with_bypass(upstream, hello, 'example.com')
        upstream.sendall.assert_called_once_with(hello)
        self.assertEqual(strategy, 'direct')
