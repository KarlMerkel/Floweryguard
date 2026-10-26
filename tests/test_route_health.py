"""Оценка передачи без расшифровки TLS и без глобальной блокировки IP."""
import unittest

from flowguard.route_health import RouteHealth, TransferProgress


class TestTransferProgress(unittest.TestCase):
    def test_initial_tls_response_is_not_transfer_success(self):
        progress = TransferProgress()
        self.assertFalse(progress.proven)
        self.assertEqual(progress.finish('client_eof', 20), 'unknown')

    def test_no_reply_after_request_can_change_next_route(self):
        progress = TransferProgress()
        progress.sent(700, now=1)
        self.assertEqual(progress.finish('client_eof', 1.1), 'unknown')
        self.assertEqual(progress.finish('client_eof', 9), 'suspect')

    def test_small_response_and_immediate_cancel_are_unknown(self):
        progress = TransferProgress()
        progress.sent(500)
        progress.received(14000, 1)
        self.assertEqual(progress.finish('client_eof', 1.1), 'unknown')
        self.assertEqual(progress.finish('server_eof', 20), 'unknown')

    def test_plateau_then_client_timeout_is_suspect_not_success(self):
        progress = TransferProgress()
        progress.sent(700)
        progress.received(14000, 1)
        self.assertEqual(progress.finish('client_eof', 16), 'suspect')
        self.assertEqual(progress.finish('client_reset', 16), 'suspect')
        self.assertFalse(progress.proven)

    def test_upload_and_local_delivery_error_are_not_path_failure(self):
        progress = TransferProgress()
        progress.received(14000, 1)
        self.assertEqual(progress.finish('client_write_error', 16), 'unknown')
        progress.sent(64000)
        self.assertEqual(progress.finish('client_eof', 16), 'unknown')

    def test_bulk_transfer_is_proven(self):
        progress = TransferProgress()
        progress.received(32768, 1)
        self.assertFalse(progress.proven)
        progress.received(32768, 2)
        self.assertTrue(progress.proven)
        self.assertEqual(progress.finish('client_eof', 30), 'progress')


class TestRouteHealth(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.health = RouteHealth(clock=lambda: self.now, max_entries=2)

    def test_evidence_is_separate_for_host_port_and_network(self):
        self.health.record('wifi', 'X.COM.', 443, '192.0.2.1', 'suspect')
        self.assertEqual(self.health.status('wifi', 'x.com', 443, '192.0.2.1'), 'suspect')
        for network, host, port in [('phone', 'x.com', 443), ('wifi', 'example.com', 443), ('wifi', 'x.com', 8443)]:
            self.assertEqual(self.health.status(network, host, port, '192.0.2.1'), 'unknown')

    def test_suspicion_expires_and_progress_rehabilitates(self):
        args = ('wifi', 'x.com', 443, '192.0.2.1')
        self.health.record(*args, 'suspect')
        self.now += 46
        self.assertEqual(self.health.status(*args), 'unknown')
        self.health.record(*args, 'suspect')
        self.health.record(*args, 'progress')
        self.health.record(*args, 'unknown')
        self.assertEqual(self.health.status(*args), 'progress')

    def test_store_is_bounded(self):
        for ip in ('192.0.2.1', '192.0.2.2', '192.0.2.3'):
            self.health.record('wifi', 'x.com', 443, ip, 'suspect')
        self.assertEqual(self.health.status('wifi', 'x.com', 443, '192.0.2.1'), 'unknown')
