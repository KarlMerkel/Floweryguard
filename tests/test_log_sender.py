import unittest
from Floweryguard.log_sender import (
    sanitize_text,
    collect_system_snapshot,
    build_multipart_payload,
    LogSender
)


class TestLogSender(unittest.TestCase):

    def test_sanitize_windows_username(self):
        sample = "Error at C:\\Users\\VasyaPupkin\\Documents\\Flowery\\logs\\test.log in user dir"
        sanitized = sanitize_text(sample)
        self.assertNotIn("VasyaPupkin", sanitized)
        self.assertIn("C:\\Users\\[USER]\\Documents", sanitized)

    def test_sanitize_linux_username(self):
        sample = "Loading file from /home/alex/project/config.ini"
        sanitized = sanitize_text(sample)
        self.assertNotIn("alex", sanitized)
        self.assertIn("/home/[USER]/project", sanitized)

    def test_sanitize_ip_address(self):
        sample = "Client connected from 192.168.1.105 with public IP 178.62.204.15 and DNS 1.1.1.1 or 8.8.8.8"
        sanitized = sanitize_text(sample)
        self.assertNotIn("192.168.1.105", sanitized)
        self.assertNotIn("178.62.204.15", sanitized)
        self.assertIn("[IP_REDACTED]", sanitized)
        # Публичные DNS-резолверы должны сохраняться для диагностики
        self.assertIn("1.1.1.1", sanitized)
        self.assertIn("8.8.8.8", sanitized)

    def test_system_snapshot_structure(self):
        snap = collect_system_snapshot()
        self.assertIn("flowery_version", snap)
        self.assertIn("platform", snap)
        self.assertIn("is_admin", snap)
        self.assertIn("ipv4_ttl", snap)
        self.assertIn("quic_blocked", snap)
        self.assertIn("proxy_enabled", snap)

    def test_multipart_payload_formatting(self):
        fields = {"chat_id": "12345678", "caption": "Test report"}
        files = {"document": ("test.txt", b"Hello world log content")}
        body, content_type = build_multipart_payload(fields, files)

        self.assertTrue(content_type.startswith("multipart/form-data; boundary="))
        self.assertIn(b'name="chat_id"', body)
        self.assertIn(b"12345678", body)
        self.assertIn(b'filename="test.txt"', body)
        self.assertIn(b"Hello world log content", body)

    def test_prepare_sanitized_report(self):
        sender = LogSender()
        filename, file_bytes = sender.prepare_sanitized_report(user_comment="Test issue description")
        self.assertTrue(filename.startswith("Flowery_Report_"))
        self.assertTrue(filename.endswith(".txt"))
        text = file_bytes.decode("utf-8")
        self.assertIn("ДИАГНОСТИЧЕСКИЙ ОТЧЁТ", text)
        self.assertIn("Test issue description", text)

    def test_send_to_telegram_validation(self):
        sender = LogSender()
        ok, msg = sender.send_to_telegram("", "", "test.txt", b"data")
        self.assertFalse(ok)
        self.assertIn("Не указан bot_token или chat_id", msg)

    def test_send_to_gateway_validation(self):
        sender = LogSender()
        ok, msg = sender.send_to_gateway("https://flowery.YOUR-NAME.workers.dev/report", "test.txt", b"data")
        self.assertFalse(ok)
        self.assertIn("Адрес сервера-шлюза ещё не настроен", msg)


if __name__ == "__main__":
    unittest.main()
