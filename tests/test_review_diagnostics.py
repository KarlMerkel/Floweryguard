"""Диагностика должна проверять содержимое и использовать проверенный TLS."""

import socket
import ssl
import unittest
import urllib.request
from unittest.mock import MagicMock, patch

from flowguard.config import Config
from flowguard.log_sender import LogSender
from flowguard import tester


class TestDiagnostics(unittest.TestCase):
    def test_report_transport_checks_certificate_and_configured_port(self):
        config = Config('_test_defaults_missing.ini')
        config.set_value('proxy', 'port', 8123)
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b'{}'
        opener = MagicMock()
        opener.open.return_value = response
        with patch('flowguard.log_sender.urllib.request.build_opener', return_value=opener) as build:
            self.assertEqual(LogSender(config)._open_url(urllib.request.Request('https://example.com/report')), b'{}')
        handlers = build.call_args_list[0].args
        proxy = next(h for h in handlers if isinstance(h, urllib.request.ProxyHandler))
        tls = next(h for h in handlers if isinstance(h, urllib.request.HTTPSHandler))
        self.assertEqual(proxy.proxies['https'], 'http://127.0.0.1:8123')
        self.assertEqual(tls._context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(tls._context.check_hostname)

    def test_report_direct_fallback_ignores_system_proxy(self):
        proxy_opener, direct_opener = MagicMock(), MagicMock()
        proxy_opener.open.side_effect = OSError('Прокси недоступен')
        direct_opener.open.return_value.__enter__.return_value.read.return_value = b'{}'
        with patch('flowguard.log_sender.urllib.request.build_opener',
                   side_effect=[proxy_opener, direct_opener]) as build:
            self.assertEqual(LogSender()._open_url(urllib.request.Request('https://example.com/report')), b'{}')
        handlers = build.call_args_list[1].args
        proxy = next(h for h in handlers if isinstance(h, urllib.request.ProxyHandler))
        self.assertEqual(proxy.proxies, {})

    def test_http_200_with_stalled_body_is_failure(self):
        response = MagicMock()
        response.getcode.return_value = 200
        response.read.side_effect = socket.timeout('Загрузка остановилась после заголовков')
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value = response
        udp = MagicMock(spec=socket.socket)
        udp.recvfrom.return_value = (b'', ('127.0.0.1', 1))
        with patch.object(tester, 'TEST_TARGETS', [{'name': 'Example', 'host': 'example.com'}]), \
             patch('flowguard.tester.urllib.request.build_opener', return_value=opener), \
             patch('flowguard.tester.socket.socket', return_value=udp):
            results = tester.test_proxy_connection()
        self.assertFalse(results[0]['status'])
        self.assertIn('error', results[0])
