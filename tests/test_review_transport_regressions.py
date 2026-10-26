"""Регрессии проверки TLS и передачи начала CONNECT-туннеля."""

import socket
import ssl
import threading
import unittest
from unittest.mock import MagicMock, patch

from flowguard.doh_resolver import DoHResolver, DNS_PRESETS
from flowguard.proxy import DPIBypassProxy


class TestDnsTlsVerification(unittest.TestCase):
    def test_certificate_verification_without_optional_packages(self):
        resolver = DoHResolver(next(iter(DNS_PRESETS.values())))
        with patch.dict('sys.modules', {'certifi': None}):
            context = resolver._get_ssl_context()
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)


class TestConnectPayload(unittest.TestCase):
    def test_clienthello_in_same_read_as_connect_is_forwarded(self):
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        tls = ssl.create_default_context().wrap_bio(incoming, outgoing, server_hostname='example.com')
        with self.assertRaises(ssl.SSLWantReadError):
            tls.do_handshake()
        hello = outgoing.read()
        client = MagicMock(spec=socket.socket)
        client.recv.side_effect = [b'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n' + hello, b'']
        upstream = MagicMock(spec=socket.socket)
        proxy = object.__new__(DPIBypassProxy)
        proxy.timeout = 1
        proxy.buffer_size = 65536
        proxy._lock = threading.Lock()
        proxy._concurrency_sem = threading.BoundedSemaphore(1)
        proxy._concurrency_sem.acquire()
        proxy.active_connections = 1
        proxy._connect_target = MagicMock(return_value=upstream)
        proxy._handshake_with_fast_fallback = MagicMock(return_value=(None, '', '', b''))
        proxy._handle_client(client, ('127.0.0.1', 12345))
        proxy._handshake_with_fast_fallback.assert_called_once_with(client, upstream, 'example.com', 443, hello)
        self.assertEqual(proxy.active_connections, 0)
