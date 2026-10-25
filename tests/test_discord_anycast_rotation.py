"""Тесты для исправления зависания Discord на домашнем интернете:
1. Ликвидация ловушки 32KB (75KB HTML + stall на /assets/*.js).
2. Ротация Anycast IP Cloudflare (Happy Eyeballs Discord IP Rotation).
3. Исключение вечного кэширования Anycast IP Cloudflare (short TTL = 15s).
4. Устранение зомби-потоков при закрытии сокета клиентом.
"""

import time
import socket
import unittest
from unittest.mock import MagicMock, patch

from flowguard.proxy import (
    DPIBypassProxy,
    _WORKING_IP_CACHE,
    _DEAD_IP_CACHE,
    _RECENT_DISCORD_IPS,
    is_ip_dead,
    mark_ip_dead,
    mark_ip_working,
    is_cloudflare_anycast_ip,
    CLOUDFLARE_ANYCAST_PREFIXES,
    DISCORD_CLOUDFLARE_ANYCAST_IPS,
    _set_socket_meta,
    ThreadSafeBoundedCache,
)
from flowguard.config import Config


class TestDiscordAnycastRotationAndTrapFixes(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.proxy = DPIBypassProxy(self.config)
        self.proxy.is_running = True
        self.proxy.strategy_engine = MagicMock()
        self.proxy.shadow_prober = None
        self.proxy.doh_harvester = None
        self.proxy.dns_failover = None
        _WORKING_IP_CACHE.clear()
        _DEAD_IP_CACHE.clear()
        _RECENT_DISCORD_IPS.clear()

    def tearDown(self):
        _WORKING_IP_CACHE.clear()
        _DEAD_IP_CACHE.clear()
        _RECENT_DISCORD_IPS.clear()

    def test_cloudflare_anycast_prefix_detection(self):
        """Проверка детекции Cloudflare Anycast IP по префиксам."""
        self.assertTrue(is_cloudflare_anycast_ip("162.159.135.232"))
        self.assertTrue(is_cloudflare_anycast_ip("162.159.128.233"))
        self.assertTrue(is_cloudflare_anycast_ip("104.16.123.45"))
        self.assertTrue(is_cloudflare_anycast_ip("104.27.1.1"))
        self.assertTrue(is_cloudflare_anycast_ip("172.64.0.1"))
        self.assertTrue(is_cloudflare_anycast_ip("172.67.100.200"))

        # Не-Cloudflare IP
        self.assertFalse(is_cloudflare_anycast_ip("142.250.185.174"))  # Google
        self.assertFalse(is_cloudflare_anycast_ip("1.1.1.1"))
        self.assertFalse(is_cloudflare_anycast_ip(None))
        self.assertFalse(is_cloudflare_anycast_ip(""))

    def test_discord_stall_without_response_evicts_cache_and_marks_ip_dead(self):
        """Когда клиент Discord отправил запрос, но сервер вернул 0 байт (TSPU drop),
        и наступает закрытие сокета клиентом (таймаут Electron), прокси обязан вытеснить
        зависший Anycast IP из кэша и пометить его мертвым на 45с.
        """
        host = "discord.com"
        target_ip = "162.159.135.232"
        _WORKING_IP_CACHE.set(host, target_ip)

        client_sock = MagicMock()
        target_sock = MagicMock()
        _set_socket_meta(target_sock, target_ip=target_ip, connect_rtt=0.01)

        # Клиент отправил запрос, сервер вернул 0 байт, затем клиент закрыл соединение
        client_sock.recv.side_effect = [b"GET / HTTP/1.1\r\n\r\n", b""]
        target_sock.recv.side_effect = []

        call_idx = [0]
        def fake_select(r, w, x, timeout):
            call_idx[0] += 1
            if call_idx[0] == 1:
                return ([client_sock], [], [])
            elif call_idx[0] == 2:
                return ([client_sock], [], [])
            return ([], [], [])

        with patch("select.select", side_effect=fake_select):
            self.proxy._pipe_sockets(
                client_sock,
                target_sock,
                host=host,
                strategy="combo_tlsrec_tcpsplit"
            )

        # 1. IP вытеснен из _WORKING_IP_CACHE
        self.assertIsNone(_WORKING_IP_CACHE.get(host))
        # 2. IP помечен как мертвый на 45с
        self.assertTrue(is_ip_dead(target_ip))
        # 3. IP записан в _RECENT_DISCORD_IPS
        self.assertIsNotNone(_RECENT_DISCORD_IPS.get(target_ip))
        # 4. Зафиксирован сбой (failure)
        self.proxy.strategy_engine.record_failure.assert_called_with(
            host, "combo_tlsrec_tcpsplit", ip=target_ip, is_tspu=False
        )

    def test_discord_normal_data_completion_does_not_mark_ip_dead(self):
        """Когда клиент Discord закрывает сокет после успешного получения данных (>0 байт, аватары/HTML),
        это является нормальным завершением: IP НЕ помечается мертвым и сбой НЕ фиксируется.
        """
        host = "cdn.discordapp.com"
        target_ip = "162.159.135.232"
        _WORKING_IP_CACHE.set(host, target_ip)

        client_sock = MagicMock()
        target_sock = MagicMock()
        _set_socket_meta(target_sock, target_ip=target_ip, connect_rtt=0.01)

        target_sock.recv.side_effect = [b"AVATAR_IMAGE_DATA_12345"]
        client_sock.recv.side_effect = [b""]

        call_idx = [0]
        def fake_select(r, w, x, timeout):
            call_idx[0] += 1
            if call_idx[0] == 1:
                return ([target_sock], [], [])
            elif call_idx[0] == 2:
                return ([client_sock], [], [])
            return ([], [], [])

        with patch("select.select", side_effect=fake_select):
            self.proxy._pipe_sockets(
                client_sock,
                target_sock,
                host=host,
                strategy="combo_tlsrec_tcpsplit"
            )

        # IP НЕ должен быть помечен как мертвый
        self.assertFalse(is_ip_dead(target_ip))
        # Успех зафиксирован
        self.proxy.strategy_engine.record_success.assert_called_with(
            host, "combo_tlsrec_tcpsplit", ip=target_ip
        )
        self.proxy.strategy_engine.record_failure.assert_not_called()

    def test_mark_ip_working_cloudflare_anycast_short_ttl(self):
        """Anycast IP Cloudflare для Discord кэшируются с TTL 300с,
        предотвращая устаревание во время чтения чата.
        """
        host = "discord.com"
        cf_ip = "162.159.135.232"

        mark_ip_working(cf_ip, host)
        # Сразу после вызова IP присутствует в кэше
        self.assertEqual(_WORKING_IP_CACHE.get(host), cf_ip)

        # Спустя 20 секунд IP все еще в кэше (300с TTL)
        with patch("time.time", return_value=time.time() + 20.0):
            self.assertEqual(_WORKING_IP_CACHE.get(host), cf_ip)

        # Спустя 305 секунд IP истекает
        with patch("time.time", return_value=time.time() + 305.0):
            self.assertIsNone(_WORKING_IP_CACHE.get(host))

    def test_connect_target_fast_path_does_not_lock_onto_dead_discord_ip(self):
        """Fast-path обязан сбрасывать мертвый Discord IP из кэша и запускать Happy Eyeballs."""
        host = "discord.com"
        dead_ip = "162.159.135.232"
        _WORKING_IP_CACHE.set(host, dead_ip)
        mark_ip_dead(dead_ip, duration=45.0)

        mock_direct = MagicMock()
        fake_socket = MagicMock()
        fake_socket.connect_ex.return_value = 0
        with patch.object(self.proxy, "_try_direct_connect", mock_direct), \
             patch("socket.socket", return_value=fake_socket), \
             patch("flowguard.proxy.resolve_fallback_dns", return_value=None):
            with patch("socket.getaddrinfo", return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("162.159.136.232", 443)),
            ]):
                sock = self.proxy._connect_target(host, 443)
                # fast-path не должен был подключаться к dead_ip
                for call in mock_direct.call_args_list:
                    self.assertNotEqual(call[0][0], dead_ip)

    def test_happy_eyeballs_discord_ip_rotation(self):
        """Happy Eyeballs при повторных запросах циклически ротирует Anycast IP Cloudflare
        и приоритизирует свежие адреса над недавно использованными.
        """
        host = "discord.com"
        ips = ["162.159.135.232", "162.159.136.232", "162.159.137.232"]

        # Помечаем первый IP как недавно использованный
        _RECENT_DISCORD_IPS.set("162.159.135.232", time.time())

        # Проверяем, что в candidate_ips свежие адреса 136 и 137 идут первыми
        with patch("socket.getaddrinfo", return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443)) for ip in ips
        ]):
            connected_ips = []
            def fake_try_direct(ip, port, timeout):
                connected_ips.append(ip)
                mock_s = MagicMock()
                return mock_s

            # Запускаем _connect_target, эмулируя прямое подключение к первому выбранному кандидату
            with patch.object(self.proxy, "_try_direct_connect", side_effect=fake_try_direct):
                # Подключаемся через прямой коннект
                with patch("socket.socket") as mock_sock_cls:
                    mock_sock = MagicMock()
                    mock_sock.connect_ex.return_value = 0
                    mock_sock_cls.return_value = mock_sock

                    s = self.proxy._connect_target(host, 443)
                    self.assertIsNotNone(s)

                    # Свежий IP из пула web nodes должен быть выбран, а не устаревший 135
                    from flowguard.proxy import _get_socket_meta
                    meta = _get_socket_meta(s)
                    core_web_nodes = (
                        "162.159.136.232", "162.159.137.232", "162.159.138.232",
                        "162.159.128.233", "162.159.129.233", "162.159.130.233"
                    )
                    self.assertIn(meta.get("target_ip"), core_web_nodes)
                    self.assertNotEqual(meta.get("target_ip"), "162.159.135.232")

    def test_discord_dead_ip_strictly_excluded_from_happy_eyeballs(self):
        """Мертвый IP Cloudflare, сброшенный после тайм-аута, полностью исключается из перебора."""
        host = "discord.com"
        dead_ip = "162.159.135.232"
        good_ip = "162.159.137.232"
        mark_ip_dead(dead_ip, duration=45.0)

        with patch("socket.getaddrinfo", return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (dead_ip, 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (good_ip, 443)),
        ]):
            with patch("socket.socket") as mock_sock_cls:
                mock_sock = MagicMock()
                mock_sock.connect_ex.return_value = 0
                mock_sock_cls.return_value = mock_sock

                s = self.proxy._connect_target(host, 443)
                self.assertIsNotNone(s)
                from flowguard.proxy import _get_socket_meta
                meta = _get_socket_meta(s)
                self.assertNotEqual(meta.get("target_ip"), dead_ip)
                self.assertIn(meta.get("target_ip"), DISCORD_CLOUDFLARE_ANYCAST_IPS)

    def test_discord_econnreset_without_response_evicts_cache_and_marks_ip_dead(self):
        """Проверка обрыва соединения через ConnectionResetError (WSAECONNRESET) при отсутствии
        ответа от сервера (0 байт). IP Cloudflare должен быть вытеснен из кэша и помечен мертвым.
        """
        host = "discord.com"
        target_ip = "162.159.135.232"
        _WORKING_IP_CACHE.set(host, target_ip)

        client_sock = MagicMock()
        target_sock = MagicMock()
        _set_socket_meta(target_sock, target_ip=target_ip, connect_rtt=0.01)

        # Клиент отправил запрос, сервер ничего не вернул (0 байт), затем сброс соединения
        client_sock.recv.side_effect = [b"GET / HTTP/1.1\r\n\r\n", ConnectionResetError(10054, "Connection reset by peer")]
        target_sock.recv.side_effect = []

        call_idx = [0]
        def fake_select(r, w, x, timeout):
            call_idx[0] += 1
            if call_idx[0] == 1:
                return ([client_sock], [], [])
            elif call_idx[0] == 2:
                return ([client_sock], [], [])
            return ([], [], [])

        with patch("select.select", side_effect=fake_select):
            self.proxy._pipe_sockets(
                client_sock,
                target_sock,
                host=host,
                strategy="combo_tlsrec_tcpsplit"
            )

        # 1. IP вытеснен из _WORKING_IP_CACHE
        self.assertIsNone(_WORKING_IP_CACHE.get(host))
        # 2. IP помечен как мертвый на 45с
        self.assertTrue(is_ip_dead(target_ip))
        # 3. IP записан в _RECENT_DISCORD_IPS
        self.assertIsNotNone(_RECENT_DISCORD_IPS.get(target_ip))
        # 4. Зафиксирован сбой (failure)
        self.proxy.strategy_engine.record_failure.assert_called_with(
            host, "combo_tlsrec_tcpsplit", ip=target_ip, is_tspu=False
        )

    def test_zombie_thread_eliminated_on_discord_client_abort(self):
        """При обрыве клиентом Discord активного туннеля (EOF) сессия разрывается немедленно,
        не продолжая цикл select с одним лишь target_sock.
        """
        client_sock = MagicMock()
        target_sock = MagicMock()
        _set_socket_meta(target_sock, target_ip="162.159.135.232", connect_rtt=0.01)

        client_sock.recv.return_value = b""
        target_sock.recv.return_value = b"H" * 75698

        select_calls = []
        def fake_select(r, w, x, timeout):
            select_calls.append(list(r))
            if len(select_calls) == 1:
                return ([target_sock], [], [])
            elif len(select_calls) == 2:
                return ([client_sock], [], [])
            return ([], [], [])

        with patch("select.select", side_effect=fake_select):
            self.proxy._pipe_sockets(
                client_sock,
                target_sock,
                host="discord.com",
                strategy="combo_tlsrec_tcpsplit"
            )

        # После того, как клиент прислал EOF на шаге 2, select больше НЕ вызывается (break)
        self.assertEqual(len(select_calls), 2)

    def test_connect_target_fast_path_uses_and_keeps_working_discord_ip(self):
        """Если в _WORKING_IP_CACHE сохранен рабочий Discord IP, fast-path продолжает
        использовать его для последовательных запросов в пределах TTL, не уничтожая кэш.
        """
        host = "discord.com"
        working_ip = "162.159.136.232"
        _WORKING_IP_CACHE.set(host, working_ip, ttl=15.0)

        mock_direct = MagicMock(return_value=MagicMock())
        with patch.object(self.proxy, "_try_direct_connect", mock_direct):
            with patch("socket.getaddrinfo", return_value=[]):
                sock = self.proxy._connect_target(host, 443)
                self.assertIsNotNone(sock)
                mock_direct.assert_called_once_with(working_ip, 443, timeout=unittest.mock.ANY)
                self.assertIsNotNone(_RECENT_DISCORD_IPS.get(working_ip))

        # При повторном запросе working_ip сохраняется в кэше и снова используется fast-path
        mock_direct.reset_mock()
        mock_direct.return_value = MagicMock()
        with patch.object(self.proxy, "_try_direct_connect", mock_direct):
            s2 = self.proxy._connect_target(host, 443)
            self.assertIsNotNone(s2)
            mock_direct.assert_called_once_with(working_ip, 443, timeout=unittest.mock.ANY)

    def test_thread_safe_bounded_cache_clear_clears_timestamps_and_ttls(self):
        """Метод clear() обязан очищать как значения кэша, так и временные метки и TTL."""
        cache = ThreadSafeBoundedCache(maxsize=10, default_ttl=60.0)
        cache.set("a", 1, ttl=15.0)
        cache.set("b", 2)
        self.assertEqual(len(cache), 2)
        self.assertIn("a", cache._ttls)
        self.assertIn("a", cache._timestamps)

        cache.clear()
        self.assertEqual(len(cache), 0)
        self.assertEqual(len(cache._timestamps), 0)
        self.assertEqual(len(cache._ttls), 0)
        self.assertIsNone(cache.get("a"))
        self.assertIsNone(cache.get("b"))

    def test_verified_discord_ip_not_marked_dead_on_small_api_client_close(self):
        """Проверенные Anycast IP (162.159.136.232 / 162.159.134.234) не должны помечаться мертвыми
        при штатном закрытии сокета клиентом после получения небольшого API-ответа (<32KB).
        """
        host = "discord.com"
        target_ip = "162.159.136.232"
        _WORKING_IP_CACHE.set(host, target_ip)

        client_sock = MagicMock()
        target_sock = MagicMock()
        _set_socket_meta(target_sock, target_ip=target_ip, connect_rtt=0.01)

        client_sock.recv.side_effect = [b"GET /api/v9/experiments HTTP/1.1\r\n\r\n", b""]
        target_sock.recv.side_effect = [b"HTTP/1.1 200 OK\r\nContent-Length: 800\r\n\r\n" + b"x" * 750]

        call_idx = [0]
        def fake_select(r, w, x, to):
            call_idx[0] += 1
            if call_idx[0] == 1:
                return ([client_sock], [], [])
            elif call_idx[0] == 2:
                return ([target_sock], [], [])
            elif call_idx[0] == 3:
                return ([client_sock], [], [])
            return ([], [], [])

        with patch("select.select", side_effect=fake_select):
            self.proxy._pipe_sockets(client_sock, target_sock, host=host, strategy="combo_tlsrec_tcpsplit")

        self.assertFalse(is_ip_dead(target_ip))
        self.proxy.strategy_engine.record_failure.assert_not_called()

    def test_verified_discord_ip_marked_dead_on_actual_stall(self):
        """Если проверенный Anycast IP реально завис (>4с ожидания после 18KB),
        при обрыве клиентом IP должен быть помечен мертвым.
        """
        host = "discord.com"
        target_ip = "162.159.136.232"
        _WORKING_IP_CACHE.set(host, target_ip)

        client_sock = MagicMock()
        target_sock = MagicMock()
        _set_socket_meta(target_sock, target_ip=target_ip, connect_rtt=0.01)

        client_sock.recv.side_effect = [b"GET /assets/bundle.js HTTP/1.1\r\n\r\n", b""]
        target_sock.recv.side_effect = [b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 18000]

        base_time = 1000.0
        call_idx = [0]
        def fake_time():
            return base_time + call_idx[0] * 5.0

        def fake_select(r, w, x, to):
            call_idx[0] += 1
            if call_idx[0] == 1:
                return ([client_sock], [], [])
            elif call_idx[0] == 2:
                return ([target_sock], [], [])
            elif call_idx[0] == 3:
                return ([client_sock], [], [])
            return ([], [], [])

        with patch("time.time", side_effect=fake_time), patch("select.select", side_effect=fake_select):
            self.proxy._pipe_sockets(client_sock, target_sock, host=host, strategy="combo_tlsrec_tcpsplit")
            self.assertTrue(is_ip_dead(target_ip))
            self.proxy.strategy_engine.record_failure.assert_called_with(
                host, "combo_tlsrec_tcpsplit", ip=target_ip, is_tspu=False
            )


if __name__ == "__main__":
    unittest.main()
