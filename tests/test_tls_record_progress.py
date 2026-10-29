"""Границы TLS-записей не зависят от размера HTTP-ответа."""
import unittest
from flowguard.route_health import TransferProgress


def record(size):
    return b'\x17\x03\x03' + size.to_bytes(2, 'big') + b'x' * size


class TlsRecordProgressTests(unittest.TestCase):
    def test_complete_small_records_are_not_stalls(self):
        for size in (100, 8000, 14000):
            progress = TransferProgress()
            progress.sent(300, 0)
            data = record(size)
            progress.received(len(data), 1, data=data)
            self.assertFalse(progress.stall_window)
            self.assertEqual(progress.finish('idle_timeout', 16), 'unknown')

    def test_large_transfer_followed_by_incomplete_record_is_not_success(self):
        progress = TransferProgress()
        progress.sent(300, 0)
        data = record(16000) * 5
        progress.received(len(data), 1, data=data)
        self.assertTrue(progress.proven)
        partial = record(16000)[:12000]
        progress.received(len(partial), 2, data=partial)
        self.assertTrue(progress.stall_window)
        self.assertEqual(progress.finish('idle_timeout', 18), 'suspect')

    def test_split_headers_and_payload_reassemble_without_storing_body(self):
        progress = TransferProgress()
        data = record(200)
        for value in data[:-1]:
            progress.received(1, 1, data=bytes([value]))
        self.assertTrue(progress.incomplete_record)
        progress.received(1, 2, data=data[-1:])
        self.assertFalse(progress.incomplete_record)

    def test_non_tls_bytes_cannot_be_misclassified_from_size(self):
        progress = TransferProgress()
        progress.sent(300, 0)
        progress.received(14000, 1, data=b'x' * 14000)
        self.assertEqual(progress.finish('idle_timeout', 16), 'unknown')

    def test_finished_records_do_not_imply_complete_http_response(self):
        progress = TransferProgress()
        data = record(16000)
        progress.received(len(data), 1, data=data)
        self.assertEqual(progress.finish('server_eof', 2), 'unknown')
