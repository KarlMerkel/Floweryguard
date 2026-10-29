"""Диагностика проверяет сертификаты и не запрашивает содержимое страницы."""
import ssl
import unittest
from unittest.mock import Mock, patch

from flowguard.certificate_diagnostics import check_certificate


class CertificateDiagnosticTests(unittest.TestCase):
    def test_verification_failure_is_reported_without_insecure_retry(self):
        context = Mock()
        error = ssl.SSLCertVerificationError(1, 'verification failed')
        error.verify_code = 62
        error.verify_message = 'Hostname mismatch'
        context.wrap_socket.side_effect = error
        with patch('ssl.create_default_context', return_value=context), \
                patch('socket.create_connection') as connect:
            result = check_certificate('animego.me')
        self.assertEqual(result['status'], 'certificate_error')
        self.assertEqual(result['verify_code'], 62)
        context.wrap_socket.assert_called_once()
        self.assertEqual(context.wrap_socket.call_args.kwargs['server_hostname'], 'animego.me')
        connect.return_value.close.assert_called_once()

    def test_tunnel_checks_requested_hostname_and_reads_no_page(self):
        context = Mock()
        tls = context.wrap_socket.return_value
        tls.getpeercert.return_value = {'subject': ((('commonName', 'example.com'),),),
                                      'notAfter': 'Jan 1 00:00:00 2027 GMT'}
        tls.version.return_value = 'TLSv1.3'
        tls.getpeername.return_value = ('127.0.0.1', 8118)
        with patch('ssl.create_default_context', return_value=context), \
                patch('http.client.HTTPConnection') as connection:
            result = check_certificate('example.com', proxy=('127.0.0.1', 8118))
        self.assertEqual(result['status'], 'verified')
        connection.return_value.set_tunnel.assert_called_once_with('example.com', 443)
        connection.return_value.request.assert_not_called()
        tls.recv.assert_not_called()
        tls.close.assert_called_once()

    def test_host_cannot_contain_url_credentials_or_headers(self):
        for host in ('https://host/path?token=x', 'a\r\nX: y', 'user:secret@host'):
            with self.subTest(host=host), self.assertRaises(ValueError):
                check_certificate(host)
