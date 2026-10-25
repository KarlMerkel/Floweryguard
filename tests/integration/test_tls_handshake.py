"""Проверка TLS через прокси с доступом к внешним серверам."""

import socket
import ssl
import unittest

from flowguard.config import Config


class TestTLS13HandshakeEndToEnd(unittest.TestCase):
    """Сквозной тест TLS 1.3 с внешними серверами через локальный прокси."""

    def test_real_tls13_proxy_handshake(self):
        """Сквозная проверка TLS 1.3 рукопожатия с реальными серверами через локальный прокси."""
        import urllib.request
        from Floweryguard.proxy import DPIBypassProxy

        cfg = Config("_test_defaults_missing.ini")
        cfg.set_override("port", 0)
        cfg.set_override("auto_system_proxy", False)
        cfg.set_override("auto_strategy", False)
        proxy = DPIBypassProxy(cfg)
        proxy.start()

        try:
            address = "http://127.0.0.1:" + str(proxy.server_sock.getsockname()[1])
            proxy_handler = urllib.request.ProxyHandler({"https": address, "http": address})
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            opener = urllib.request.build_opener(proxy_handler, urllib.request.HTTPSHandler(context=context))

            test_urls = ["https://www.google.com", "https://ya.ru"]
            for url in test_urls:
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
                    with opener.open(req, timeout=8.0) as resp:
                        self.assertEqual(resp.status, 200)
                except urllib.error.HTTPError as e:
                    # Сервер ответил по TLS 1.3 через прокси, рукопожатие успешно (код 200, 301, 302, 403, 429)
                    self.assertIn(e.code, (200, 301, 302, 307, 403, 429))
                except (urllib.error.URLError, socket.error) as e:
                    # Если машина оффлайн или DNS не разрешает узел
                    if "getaddrinfo failed" in str(e) or "Temporary failure in name resolution" in str(e) or "timed out" in str(e):
                        raise unittest.SkipTest(f"Сетевое окружение недоступно для {url}: {e}")
                    raise
        finally:
            proxy.stop()


if __name__ == "__main__":
    unittest.main()
