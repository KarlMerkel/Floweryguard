"""Тесты для исправлений YouTube Video Streams (googlevideo.com Anycast Edge)
и Discord Desktop Startup (chk-webapp, early_connect, EOF symmetrical close).
"""

import unittest
from unittest.mock import patch, MagicMock
import socket
import time

from flowguard.config import Config
from flowguard.proxy import (
    DPIBypassProxy,
    is_plain_ip,
    is_ip_dead,
    mark_ip_dead,
    mark_ip_working,
    record_ip_strategy_failure,
    is_discord_host,
    GOOGLE_EDGE_ANYCAST_IPS,
    _DEAD_IP_CACHE,
)


class TestYouTubeDiscordFixes(unittest.TestCase):
    def setUp(self):
        from flowguard.proxy import _WORKING_IP_CACHE, _DEAD_IP_CACHE, _RESOLVED_IPS_CACHE
        _WORKING_IP_CACHE._cache.clear()
        _DEAD_IP_CACHE._cache.clear()
        _RESOLVED_IPS_CACHE._cache.clear()
        self.config = Config("_test_defaults_missing.ini")
        self.proxy = DPIBypassProxy(self.config)
        self.proxy.shadow_prober = MagicMock()

    def tearDown(self):
        from flowguard.proxy import _WORKING_IP_CACHE, _DEAD_IP_CACHE, _RESOLVED_IPS_CACHE
        _WORKING_IP_CACHE._cache.clear()
        _DEAD_IP_CACHE._cache.clear()
        _RESOLVED_IPS_CACHE._cache.clear()

    def test_ipv6_mode_default_disabled(self):
        """Проверка, что ipv6_mode по умолчанию 'disabled' во избежание WinError 10051."""
        self.assertEqual(self.config.ipv6_mode, "disabled")

    def test_is_plain_ip(self):
        """Проверка распознавания IPv4/IPv6 против доменных имен."""
        self.assertTrue(is_plain_ip("173.194.178.225"))
        self.assertTrue(is_plain_ip("127.0.0.1"))
        self.assertTrue(is_plain_ip("2001:4860:4860::8888"))
        self.assertTrue(is_plain_ip("::1"))

        self.assertFalse(is_plain_ip("googlevideo.com"))
        self.assertFalse(is_plain_ip("rr1---sn-4g5ednks.googlevideo.com"))
        self.assertFalse(is_plain_ip("discord.com"))
        self.assertFalse(is_plain_ip("gateway.discord.gg"))
        self.assertFalse(is_plain_ip(""))
        self.assertFalse(is_plain_ip(None))

    def test_domain_names_never_marked_dead(self):
        """Доменные имена никогда не должны помечаться как мертвые IP."""
        domain = "rr1---sn-4g5ednks.googlevideo.com"
        mark_ip_dead(domain, duration=300.0)
        self.assertNotIn(domain, _DEAD_IP_CACHE)
        self.assertFalse(is_ip_dead(domain))

        # Тест record_ip_strategy_failure
        res = record_ip_strategy_failure(domain, "combo_tlsrec_tcpsplit")
        self.assertFalse(res)
        self.assertNotIn(domain, _DEAD_IP_CACHE)

    def test_googlevideo_real_ggc_ip_priority(self):
        """Для хостов *.googlevideo.com приоритет отдаётся реальным GGC IP-адресам из DNS, а не Anycast Edge IP."""
        host = "rr1---sn-4g5ednks.googlevideo.com"
        mock_sock = MagicMock()

        connected_ips = []

        def fake_connect(addr):
            connected_ips.append(addr[0])

        def fake_connect_ex(addr):
            connected_ips.append(addr[0])
            return 0

        mock_sock.connect.side_effect = fake_connect
        mock_sock.connect_ex.side_effect = fake_connect_ex

        with patch("socket.socket") as mock_sock_cls, \
             patch("socket.getaddrinfo") as mock_gai:
            mock_sock_cls.return_value = mock_sock
            # Имитируем, что локальный DNS вернул реальный GGC IP ноды кэширования видео
            real_ggc_ip = "172.217.132.170"
            mock_gai.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", (real_ggc_ip, 443))
            ]

            # Вызываем _connect_target
            res = self.proxy._connect_target(host, 443)
            self.assertIsNotNone(res)

            # Первый IP, к которому подключились, ДОЛЖЕН быть реальным GGC IP (предотвращает HTTP 400 / Bandaid 404)
            self.assertTrue(len(connected_ips) > 0)
            self.assertEqual(connected_ips[0], real_ggc_ip)

    def test_googlevideo_anycast_fallback_when_dns_empty(self):
        """Когда DNS/DoH не вернул ни одного IP для googlevideo.com,
        _connect_target обязан задействовать резервные GOOGLE_EDGE_ANYCAST_IPS,
        предотвращая сбой воспроизведения первого видео в Shorts.
        """
        host = "rr1---sn-no-dns.googlevideo.com"
        mock_sock = MagicMock()
        connected_ips = []

        def fake_connect(addr):
            connected_ips.append(addr[0])

        def fake_connect_ex(addr):
            connected_ips.append(addr[0])
            return 0

        mock_sock.connect.side_effect = fake_connect
        mock_sock.connect_ex.side_effect = fake_connect_ex

        with patch("socket.socket", return_value=mock_sock), \
             patch("socket.getaddrinfo", return_value=[]), \
             patch.object(self.proxy.doh_harvester, "harvest", return_value=[]), \
             patch.object(self.proxy.dns_failover, "resolve", return_value=[]), \
             patch("flowguard.proxy.resolve_fallback_dns", return_value=None):
            res = self.proxy._connect_target(host, 443)
            self.assertIsNotNone(res)
            self.assertTrue(len(connected_ips) > 0)
            self.assertIn(connected_ips[0], GOOGLE_EDGE_ANYCAST_IPS)

    def test_discord_host_detection(self):
        """Проверка идентификации хостов Discord и устойчивости к None/типам."""
        self.assertTrue(is_discord_host("discord.com"))
        self.assertTrue(is_discord_host("gateway.discord.gg"))
        self.assertTrue(is_discord_host("cdn.discordapp.com"))
        self.assertTrue(is_discord_host("latency.discord.media"))
        self.assertTrue(is_discord_host("dc-telemetry.net"))
        self.assertTrue(is_discord_host("sub.dc-telemetry.net"))
        self.assertTrue(is_discord_host("chk-webapp.res-err.err-conn-closed.dur-0.v1.dc-telemetry.net"))
        self.assertTrue(is_discord_host("discordapp.net"))
        self.assertTrue(is_discord_host("images.discordapp.net"))
        self.assertFalse(is_discord_host("discord-attachments-uploads-prd.storage.googleapis.com"))
        self.assertFalse(is_discord_host("www.youtube.com"))
        self.assertFalse(is_discord_host("googlevideo.com"))
        self.assertFalse(is_discord_host(None))
        self.assertFalse(is_discord_host(""))
        self.assertFalse(is_discord_host(12345))

    def test_google_youtube_host_detection(self):
        """Проверка идентификации хостов Google/YouTube и устойчивости к None/типам."""
        from flowguard.proxy import is_google_or_youtube_host
        self.assertTrue(is_google_or_youtube_host("www.youtube.com"))
        self.assertTrue(is_google_or_youtube_host("rr1---sn-4g5ednks.googlevideo.com"))
        self.assertTrue(is_google_or_youtube_host("ytimg.com"))
        self.assertFalse(is_google_or_youtube_host("discord.com"))
        self.assertFalse(is_google_or_youtube_host(None))
        self.assertFalse(is_google_or_youtube_host(""))
        self.assertFalse(is_google_or_youtube_host(999))

    def test_googlevideo_per_host_cache_isolation(self):
        """Проверка изолированного кэширования для каждого отдельного поддомена *.googlevideo.com без отравления generic googlevideo.com."""
        from flowguard.proxy import _WORKING_IP_CACHE
        node_ip = "173.194.181.36"
        host1 = "rr1---sn-4g5ednks.googlevideo.com"
        mark_ip_working(node_ip, host1)
        self.proxy.route_health.record(self.proxy.strategy_engine._current_network, host1, 443, node_ip, 'progress')

        # Должен быть закэширован конкретный FQDN host, но НЕ generic 'googlevideo.com'
        self.assertEqual(_WORKING_IP_CACHE.get(host1), node_ip)
        self.assertIsNone(_WORKING_IP_CACHE.get("googlevideo.com"))

        # Подключение к rr1 использует fast-path
        mock_sock = MagicMock()
        with patch.object(self.proxy, "_try_direct_connect", return_value=mock_sock) as mock_direct, \
             patch("socket.getaddrinfo") as mock_gai:
            res = self.proxy._connect_target(host1, 443)
            self.assertEqual(res, mock_sock)
            mock_direct.assert_called_once_with(node_ip, 443, timeout=unittest.mock.ANY)
            mock_gai.assert_not_called()

        # Подключение к rr2 НЕ должно использовать IP от rr1
        mock_sock2 = MagicMock()
        mock_sock2.connect_ex.return_value = 0
        node2_ip = "173.194.177.10"
        with patch("socket.socket", return_value=mock_sock2), \
             patch("socket.getaddrinfo") as mock_gai2:
            mock_gai2.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", (node2_ip, 443))
            ]
            res2 = self.proxy._connect_target("rr2---sn-other.googlevideo.com", 443)
            self.assertIsNotNone(res2)
            mock_gai2.assert_called_once()

    def test_googlevideo_fallback_when_edge_ips_excluded(self):
        """Если все Google Edge Anycast IP исключены (в fallback), _connect_target должен обратиться к DNS."""
        host = "rr1---sn-fallback.googlevideo.com"
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0

        fallback_dns_ip = "192.0.2.1"
        with patch("socket.socket", return_value=mock_sock), \
             patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", (fallback_dns_ip, 443))
            ]
            # Исключаем все Anycast IP
            res = self.proxy._connect_target(host, 443, exclude_ip=GOOGLE_EDGE_ANYCAST_IPS)
            self.assertIsNotNone(res)
            mock_gai.assert_called_once()

    def test_mss_clamping_only_for_target_sock(self):
        """TCP MSS clamping должен выполняться ТОЛЬКО при отправке наружу (target_sock),
        и никогда при отправке клиенту (client_sock на loopback).
        """
        self.proxy.is_running = True
        client_sock = MagicMock()
        target_sock = MagicMock()

        large_chunk = b"X" * 4096

        # 1. Отправка от сервера клиенту (other is client_sock)
        # s is target_sock -> other is client_sock
        target_sock.recv.side_effect = [large_chunk, b""]
        client_sock.recv.side_effect = [b""]

        with patch("select.select") as mock_select:
            mock_select.side_effect = [
                ([target_sock], [], []),
                ([target_sock], [], []),
                ([client_sock], [], []),
            ]
            self.proxy._pipe_sockets(client_sock, target_sock, host="test.org")

        # client_sock.sendall должен быть вызван 1 раз со всеми 4096 байтами (без нарезки по 1380!)
        self.assertEqual(client_sock.sendall.call_count, 1)
        self.assertEqual(client_sock.sendall.call_args[0][0], large_chunk)

        # 2. Отправка от клиента серверу (other is target_sock)
        client_sock.reset_mock()
        target_sock.reset_mock()
        client_sock.recv.side_effect = [large_chunk, b""]
        target_sock.recv.side_effect = [b""]

        with patch("select.select") as mock_select:
            mock_select.side_effect = [
                ([client_sock], [], []),
                ([client_sock], [], []),
                ([target_sock], [], []),
            ]
            self.proxy._pipe_sockets(client_sock, target_sock, host="test.org")

        # target_sock.sendall должен быть вызван напрямую 1 раз (Windows MTUManager управляет сегментацией пакетов)
        self.assertEqual(target_sock.sendall.call_count, 1)
        self.assertEqual(target_sock.sendall.call_args[0][0], large_chunk)

    def test_pipe_sockets_eof_half_close(self):
        """При получении EOF от клиента (not data) должен выполняться Half-Close:
        target_sock.shutdown(SHUT_WR), клиент удаляется из опроса select, а сервер продолжает передачу ответа.
        """
        self.proxy.is_running = True
        client_sock = MagicMock()
        target_sock = MagicMock()

        # Шаг 1: клиент отправляет EOF (b"")
        # Шаг 2: сервер отправляет ответ b"HTTP/1.1 200 OK\r\n\r\n"
        # Шаг 3: сервер отправляет EOF (b"")
        client_sock.recv.side_effect = [b""]
        target_sock.recv.side_effect = [b"HTTP/1.1 200 OK\r\n\r\n", b""]

        with patch("select.select") as mock_select:
            mock_select.side_effect = [
                ([client_sock], [], []),
                ([target_sock], [], []),
                ([target_sock], [], []),
            ]
            self.proxy._pipe_sockets(client_sock, target_sock, host="discord.com")

        # target_sock.shutdown(SHUT_WR) обязан быть вызван при закрытии клиентской стороны на запись
        target_sock.shutdown.assert_any_call(socket.SHUT_WR)
        # client_sock.shutdown(SHUT_WR) обязан быть вызван при завершении сервера
        client_sock.shutdown.assert_any_call(socket.SHUT_WR)

    def test_discord_early_connect_strictly_disabled(self):
        """Для всех хостов Discord (включая dc-telemetry.net) early_connect обязан отключаться,
        а при сбое физического подключения должен возвращаться HTTP 502 Bad Gateway.
        """
        client_sock = MagicMock()
        client_sock.recv.return_value = b"CONNECT test.chk-webapp.v1.dc-telemetry.net:443 HTTP/1.1\r\n\r\n"

        with patch.object(self.proxy, "_connect_target", return_value=None):
            self.proxy._handle_client(client_sock, ("127.0.0.1", 54321))

            # 200 Connection Established НЕ должен быть отправлен
            for call_args in client_sock.sendall.call_args_list:
                self.assertNotIn(b"200 Connection Established", call_args[0][0])

            # Должен быть отправлен чистый 502 Bad Gateway
            client_sock.sendall.assert_called_with(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")

    def test_winws_tcp_filtering_detection(self):
        """Проверка детекции активности WinDivert TCP фильтрации."""
        from flowguard.voice_helper import (
            is_winws_tcp_filtering_active,
            VoiceHelper,
            set_active_voice_helper,
        )

        # 1. winws не запущен в системе -> False
        with patch("flowguard.voice_helper.is_system_winws_running", return_value=False):
            self.assertFalse(is_winws_tcp_filtering_active(force_refresh=True))

        # 2. winws запущен Flowery в режиме proxy (по умолчанию только UDP Discord Voice) -> False
        our_vh = VoiceHelper(mode="proxy", tcp_desync=False)
        our_vh.managed_by_us = True
        set_active_voice_helper(our_vh)
        with patch("flowguard.voice_helper.is_system_winws_running", return_value=True):
            self.assertFalse(is_winws_tcp_filtering_active(voice_helper=our_vh, force_refresh=True))

        # 3. winws запущен Flowery в режиме packet c tcp_desync=True -> True
        our_vh_tcp = VoiceHelper(mode="packet", tcp_desync=True)
        our_vh_tcp.managed_by_us = True
        with patch("flowguard.voice_helper.is_system_winws_running", return_value=True):
            self.assertTrue(is_winws_tcp_filtering_active(voice_helper=our_vh_tcp, force_refresh=True))

        # 4. Внешний zapret (не managed_by_us) -> True
        ext_vh = VoiceHelper(mode="proxy")
        ext_vh.managed_by_us = False
        with patch("flowguard.voice_helper.is_system_winws_running", return_value=True), \
             patch("flowguard.voice_helper.get_winws_command_lines", return_value=["winws.exe --wf-tcp=80,443 --filter-tcp=80,443"]):
            self.assertTrue(is_winws_tcp_filtering_active(voice_helper=ext_vh, force_refresh=True))

        # 5. Внешний zapret, но аргументы не удалось прочитать из-за UAC -> проверка WinDivert драйвера
        with patch("flowguard.voice_helper.is_system_winws_running", return_value=True), \
             patch("flowguard.voice_helper.get_winws_command_lines", return_value=[]), \
             patch("flowguard.voice_helper.is_windivert_driver_running", return_value=True):
            self.assertTrue(is_winws_tcp_filtering_active(voice_helper=ext_vh, force_refresh=True))

        with patch("flowguard.voice_helper.is_system_winws_running", return_value=True), \
             patch("flowguard.voice_helper.get_winws_command_lines", return_value=[]), \
             patch("flowguard.voice_helper.is_windivert_driver_running", return_value=False):
            self.assertFalse(is_winws_tcp_filtering_active(voice_helper=ext_vh, force_refresh=True))

    def test_proxy_uses_direct_when_external_zapret_active(self):
        """Когда в системе активен внешний zapret TCP (winws), Flowery proxy использует стратегию 'direct'
        во избежание двойной фрагментации / коллизии desync поверх desync.
        """
        # Валидный ClientHello пакет
        client_hello = (
            b"\x16\x03\x01\x00\x30"  # TLS Record Header
            + b"\x01\x00\x00\x2c\x03\x03" + b"\x00" * 32  # ClientHello random
            + b"\x00\x00\x02\x00\x2f\x01\x00"  # Ciphers
        )
        target_sock = MagicMock()

        # При активном winws TCP: стратегия direct
        with patch("flowguard.proxy.is_winws_tcp_filtering_active", return_value=True):
            strat, effective_host = self.proxy._send_tls_client_hello_with_bypass(
                target_sock, client_hello, "www.youtube.com"
            )
            self.assertEqual(strat, "direct")
            target_sock.sendall.assert_called_once_with(client_hello)

    def test_anycast_edge_ip_never_cached_in_working_ip_cache_for_googlevideo(self):
        """Google Edge Anycast IPs никогда не должны кэшироваться в _WORKING_IP_CACHE для хостов *.googlevideo.com."""
        from flowguard.proxy import _WORKING_IP_CACHE, mark_ip_working
        anycast_ip = "173.194.178.225"
        host = "rr1---sn-4g5ednks.googlevideo.com"

        # 1. Попытка пометить Anycast IP как рабочий для googlevideo
        mark_ip_working(anycast_ip, host)
        self.assertIsNone(_WORKING_IP_CACHE.get(host))

        # 2. Реальный GGC IP должен успешно кэшироваться
        real_ggc_ip = "172.217.132.170"
        mark_ip_working(real_ggc_ip, host)
        self.assertEqual(_WORKING_IP_CACHE.get(host), real_ggc_ip)

        # 3. Если Anycast IP искусственно попал в кэш, _connect_target обязан его удалить и пойти в DNS
        _WORKING_IP_CACHE.set(host, anycast_ip)
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        with patch("socket.socket", return_value=mock_sock), \
             patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", (real_ggc_ip, 443))
            ]
            res = self.proxy._connect_target(host, 443)
            self.assertIsNotNone(res)
            # Anycast IP должен быть вычищен из кэша
            self.assertNotEqual(_WORKING_IP_CACHE.get(host), anycast_ip)
            mock_gai.assert_called_once()

    def test_fast_fallback_attempt2_uses_combo_when_direct_fails_under_winws(self):
        """Когда в тандеме с winws первая попытка со стратегией 'direct' падает от ТСПУ (RST),
        Fast-Fallback ОБЯЗАН не пропускать Попытку 2, не признавать IP мёртвым и применить combo_tlsrec_tcpsplit.
        """
        client_sock = MagicMock()
        target_sock1 = MagicMock()
        target_sock2 = MagicMock()

        # Имитируем сокетную мету
        from flowguard.proxy import _set_socket_meta
        _set_socket_meta(target_sock1, "172.217.132.170", 0.030)
        _set_socket_meta(target_sock2, "172.217.132.170", 0.030)

        client_hello = (
            b"\x16\x03\x01\x00\x30"
            + b"\x01\x00\x00\x2c\x03\x03" + b"\x00" * 32
            + b"\x00\x00\x02\x00\x2f\x01\x00"
        )

        executed_strategies = []

        def fake_execute(strat, sock, data, host=None):
            executed_strategies.append(strat)
            return True

        with patch("flowguard.proxy.is_winws_tcp_filtering_active", return_value=True), \
             patch.object(self.proxy, "_safe_execute_strategy", side_effect=fake_execute), \
             patch.object(self.proxy, "_connect_target", return_value=target_sock2), \
             patch.object(self.proxy, "_probe_socket_response") as mock_probe:

            # Попытка 1: direct получает RST от ТСПУ
            # Попытка 2: combo_tlsrec_tcpsplit получает ServerHello (success)
            mock_probe.side_effect = [
                ("rst_fast", None, 15.0),
                ("success", b"\x16\x03\x03\x00\x50serverhello", 40.0),
            ]

            res_sock, used_strat, eff_host, resp = self.proxy._handshake_with_fast_fallback(
                client_sock, target_sock1, "rr1---sn-4g5ednks.googlevideo.com", 443, client_hello
            )

            # Соединение обязано завершиться успехом на Попытке 2 с комбо-стратегией
            self.assertEqual(res_sock, target_sock2)
            self.assertEqual(used_strat, "combo_tlsrec_tcpsplit")
            self.assertIn("combo_tlsrec_tcpsplit", executed_strategies)
            # IP не должен быть заблокирован как мёртвый
            self.assertFalse(is_ip_dead("172.217.132.170"))

    def test_discord_host_detection_trailing_dot(self):
        """Хосты Discord с точкой на конце (FQDN) должны корректно распознаваться."""
        self.assertTrue(is_discord_host("gateway.discord.gg."))
        self.assertTrue(is_discord_host("cdn.discordapp.com."))
        self.assertTrue(is_discord_host("dc-telemetry.net."))
        self.assertTrue(is_discord_host("discord.com."))

    def test_happy_eyeballs_does_not_mark_slower_candidates_dead(self):
        """Happy Eyeballs не должен помечать более медленные/отмененные IP мертвыми."""
        sock_fast = MagicMock()
        sock_fast.connect_ex.return_value = 0
        sock_slow = MagicMock()
        sock_slow.connect_ex.return_value = 115  # EINPROGRESS / in progress

        socks = [sock_slow, sock_fast]
        with patch("socket.socket", side_effect=lambda *a, **kw: socks.pop() if socks else MagicMock()), \
             patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("192.0.2.1", 443)),
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("192.0.2.2", 443)),
            ]
            res = self.proxy._connect_target("multi.example.com", 443)
            self.assertIsNotNone(res)
            # Ни один IP не должен быть признан мертвым
            self.assertFalse(is_ip_dead("192.0.2.1"))
            self.assertFalse(is_ip_dead("192.0.2.2"))

    def test_pipe_sockets_does_not_record_success_on_http_error_or_tls_alert(self):
        """_pipe_sockets не фиксирует успех в Thompson Sampling при получении HTTP 4xx/5xx или TLS Alert (0x15)."""
        self.proxy.is_running = True
        client_sock = MagicMock()
        target_sock = MagicMock()

        # Случай 1: сервер ответил HTTP 400 Bad Request
        client_sock.recv.side_effect = [b"GET / HTTP/1.1\r\nHost: test.org\r\n\r\n", b""]
        target_sock.recv.side_effect = [b"HTTP/1.1 400 Bad Request\r\n\r\n", b""]

        with patch("select.select") as mock_select, \
             patch.object(self.proxy.strategy_engine, "record_success") as mock_rec_succ:
            mock_select.side_effect = [
                ([client_sock], [], []),
                ([target_sock], [], []),
                ([client_sock], [], []),
                ([target_sock], [], []),
            ]
            self.proxy._pipe_sockets(client_sock, target_sock, host="test.org", strategy="multi_split")
            mock_rec_succ.assert_not_called()

        # Случай 2: сервер ответил TLS Alert (0x15)
        client_sock.reset_mock()
        target_sock.reset_mock()
        client_sock.recv.side_effect = [b"\x16\x03\x01\x00\x10clienthello", b""]
        target_sock.recv.side_effect = [b"\x15\x03\x03\x00\x02\x02\x50", b""]  # TLS Alert

        with patch("select.select") as mock_select, \
             patch.object(self.proxy.strategy_engine, "record_success") as mock_rec_succ:
            mock_select.side_effect = [
                ([client_sock], [], []),
                ([target_sock], [], []),
                ([client_sock], [], []),
                ([target_sock], [], []),
            ]
            self.proxy._pipe_sockets(client_sock, target_sock, host="test.org", strategy="multi_split")
            mock_rec_succ.assert_not_called()

    def test_early_connect_graceful_shutdown_on_remote_failure(self):
        """При сбое удаленного подключения в режиме early_connect клиент закрывается gracefully с кодом ошибки, а не сбрасывается."""
        client_sock = MagicMock()
        tls_hello = b"\x16\x03\x01\x00\x10\x01\x00\x00\x0crecord..."
        client_sock.recv.return_value = b"CONNECT target.com:443 HTTP/1.1\r\n\r\n"

        def fake_recv(buf_size):
            return tls_hello

        with patch.object(self.proxy, "_connect_target", return_value=None):
            # Внутри _handle_client при early_connect клиент читает first_packet
            client_sock.recv.side_effect = [
                b"CONNECT target.com:443 HTTP/1.1\r\n\r\n",
                tls_hello,
            ]
            self.proxy._handle_client(client_sock, ("127.0.0.1", 12345))

            # Должен быть отправлен TLS Alert или HTTP 502, затем shutdown(SHUT_WR)
            client_sock.shutdown.assert_any_call(socket.SHUT_WR)
            client_sock.close.assert_called()

    def test_host_classification_and_normalization(self):
        """Проверка расширенной классификации YouTube и FQDN нормализации."""
        from flowguard.proxy import is_google_or_youtube_host
        self.assertTrue(is_google_or_youtube_host("youtube-nocookie.com"))
        self.assertTrue(is_google_or_youtube_host("youtubei.googleapis.com"))
        self.assertTrue(is_google_or_youtube_host("gvt1.com"))
        self.assertTrue(is_google_or_youtube_host("yt.be"))

        # Проверка _parse_http_target нормализации
        h, p, _ = self.proxy._parse_http_target(b"GET / HTTP/1.1\r\nHost: example.com.:8080\r\n\r\n", "http://example.com.:8080/")
        self.assertEqual(h, "example.com")
        self.assertEqual(p, 8080)

    def test_ttl_cache_expiration(self):
        """Проверка работы TTL в ThreadSafeBoundedCache."""
        from flowguard.proxy import ThreadSafeBoundedCache
        cache = ThreadSafeBoundedCache(maxsize=10, default_ttl=0.1)
        cache.set("k1", "v1")
        self.assertEqual(cache.get("k1"), "v1")
        self.assertIn("k1", cache)

        time.sleep(0.15)
        self.assertIsNone(cache.get("k1"))
        self.assertNotIn("k1", cache)

    def test_subnet_inherits_domain_weights_when_cold(self):
        """Холодный составной ключ domain:IP/24 наследует веса базового домена."""
        from flowguard.strategy import ThompsonStrategySelector
        engine = ThompsonStrategySelector(enabled=True)
        engine.set_network_context("test_net")

        # Обучаем базовый домен
        domain = "example-cdn.com"
        for _ in range(5):
            engine.record_success(domain, "boringssl_split", rtt_ms=30.0)

        domain_scores = engine.get_scores_for_key(domain)
        self.assertIsNotNone(domain_scores)
        self.assertGreater(domain_scores["boringssl_split"][0], 5.0)

        # Обращаемся к новому IP в подсети
        subnet_scores = engine.get_scores_for_key(domain, ip="192.0.2.42")
        self.assertIsNotNone(subnet_scores)
        # Подсеть должна унаследовать веса базового домена
        self.assertEqual(subnet_scores["boringssl_split"][0], domain_scores["boringssl_split"][0])

    def test_pipe_sockets_handles_target_rst_without_loop_and_records_failure(self):
        """_pipe_sockets при сбросе соединения удаленным сервером (RST / ConnectionResetError)
        немедленно завершает цикл, не зависает, не регистрирует ложный успех и фиксирует сбой."""
        self.proxy.is_running = True
        client_sock = MagicMock()
        target_sock = MagicMock()
        client_sock.recv.return_value = b"GET /watch?v=123 HTTP/1.1\r\nHost: test.org\r\n\r\n"
        target_sock.sendall.side_effect = ConnectionResetError("Connection reset by peer (TSPU RST)")

        with patch("select.select") as mock_select, \
             patch.object(self.proxy.strategy_engine, "record_success") as mock_rec_succ, \
             patch.object(self.proxy.strategy_engine, "record_failure") as mock_rec_fail:
            mock_select.return_value = ([client_sock], [], [])

            # Вызываем _pipe_sockets
            self.proxy._pipe_sockets(client_sock, target_sock, host="test.org", strategy="combo_tlsrec_tcpsplit")

            # Должен выйти сразу, без зависания
            mock_rec_succ.assert_not_called()
            mock_rec_fail.assert_called_once()
            self.assertEqual(mock_rec_fail.call_args[0][0], "test.org")
            self.assertEqual(mock_rec_fail.call_args[0][1], "combo_tlsrec_tcpsplit")

    def test_happy_eyeballs_immediate_refused_and_exceptional_fds(self):
        """Happy Eyeballs немедленно бракует IP с ошибками connect_ex и Winsock exceptional fds,
        не добавляя их в пул и не ожидая таймаута."""
        # IP 1: немедленный отказ 10061 (WSAECONNREFUSED)
        sock_refused = MagicMock()
        sock_refused.connect_ex.return_value = 10061

        # IP 2: успешное подключение
        sock_ok = MagicMock()
        sock_ok.connect_ex.return_value = 0

        socks = [sock_ok, sock_refused]
        with patch("socket.socket", side_effect=lambda *a, **kw: socks.pop() if socks else MagicMock()), \
             patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("192.0.2.1", 443)),
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("192.0.2.2", 443)),
            ]
            res = self.proxy._connect_target("fast.example.com", 443)
            self.assertIsNotNone(res)
            # Отказавший IP понижен для этого хоста, успешный — нет
            self.assertEqual(self.proxy.route_health.status(self.proxy.strategy_engine._current_network, "fast.example.com", 443, "192.0.2.1"), 'suspect')
            self.assertEqual(self.proxy.route_health.status(self.proxy.strategy_engine._current_network, "fast.example.com", 443, "192.0.2.2"), 'unknown')

    def test_pipe_sockets_discord_and_established_idle_timeout(self):
        """_pipe_sockets устанавливает 60.0с сокет таймауты, 15.0с stall timeout и 45.0с idle_timeout для Discord."""
        self.proxy.is_running = True
        client_sock = MagicMock()
        target_sock = MagicMock()

        # Тест 1: Discord хост без прикладных данных -> select_timeout должен быть 15.0с (защита от зависаний)
        captured_timeouts = []
        def fake_select(r, w, x, timeout):
            captured_timeouts.append(timeout)
            return ([], [], [])

        with patch("select.select", side_effect=fake_select):
            self.proxy._pipe_sockets(client_sock, target_sock, host="discord.com", got_initial_response=True)

        # Проверяем, что таймаут на сокетах 60.0с
        client_sock.settimeout.assert_called_with(60.0)
        target_sock.settimeout.assert_called_with(60.0)
        self.assertIn(15.0, captured_timeouts)

        # Тест 2: обычный хост без ответа -> select_timeout равен float(self.timeout)
        captured_timeouts.clear()
        with patch("select.select", side_effect=fake_select):
            self.proxy._pipe_sockets(client_sock, target_sock, host="example.com", got_initial_response=False)
        self.assertIn(float(self.proxy.timeout), captured_timeouts)

        # Тест 3: Discord хост с портом "discord.com:443" без ответа -> select_timeout 15.0с
        captured_timeouts.clear()
        with patch("select.select", side_effect=fake_select):
            self.proxy._pipe_sockets(client_sock, target_sock, host="discord.com:443", got_initial_response=True)
        self.assertIn(15.0, captured_timeouts)

        # Тест 4: Established туннель общего домена после ответа сервера -> select_timeout должен быть 300.0с
        captured_timeouts.clear()
        call_count_ex = [0]
        def fake_select_ex(r, w, x, timeout):
            captured_timeouts.append(timeout)
            call_count_ex[0] += 1
            if call_count_ex[0] == 1:
                return ([target_sock], [], [])
            return ([], [], [])

        target_sock.recv.return_value = b"HTTP/1.1 200 OK\r\n\r\n"
        with patch("select.select", side_effect=fake_select_ex):
            self.proxy._pipe_sockets(client_sock, target_sock, host="example.com", got_initial_response=True)
        self.assertEqual(captured_timeouts[0], float(self.proxy.timeout))
        self.assertEqual(captured_timeouts[1], 300.0)

        # Тест 5: Discord хост, где ответ сервера приходит во время цикла _pipe_sockets -> переключается на idle 300.0с (Chromium keep-alive pool)
        captured_timeouts.clear()
        call_count = [0]
        def fake_select_seq(r, w, x, timeout):
            captured_timeouts.append(timeout)
            call_count[0] += 1
            if call_count[0] == 1:
                return ([target_sock], [], [])
            return ([], [], [])

        target_sock.recv.return_value = b"\x17\x03\x03\x00\x05hello"
        with patch("select.select", side_effect=fake_select_seq):
            self.proxy._pipe_sockets(client_sock, target_sock, host="discord.com", got_initial_response=False)
        self.assertEqual(captured_timeouts[0], min(15.0, float(self.proxy.timeout)))
        self.assertEqual(captured_timeouts[1], 300.0)

    def test_googlevideo_fallback_to_anycast_when_single_ip_excluded(self):
        """Когда DNS вернул единственный GGC IP и он исключен при fast fallback,
        _connect_target должен задействовать GOOGLE_EDGE_ANYCAST_IPS (исправление первого видео Shorts).
        """
        host = "rr1---sn-silent-drop.googlevideo.com"
        mock_sock = MagicMock()
        connected_ips = []

        def fake_connect_ex(addr):
            connected_ips.append(addr[0])
            return 0

        mock_sock.connect_ex.side_effect = fake_connect_ex

        failed_ggc_ip = "173.194.176.153"
        with patch("socket.socket", return_value=mock_sock), \
             patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 0, "", (failed_ggc_ip, 443))]), \
             patch.object(self.proxy.doh_harvester, "harvest", return_value=[failed_ggc_ip]), \
             patch.object(self.proxy.dns_failover, "resolve", return_value=[failed_ggc_ip]), \
             patch("flowguard.proxy.resolve_fallback_dns", return_value=failed_ggc_ip):
            res = self.proxy._connect_target(host, 443, exclude_ip={failed_ggc_ip})
            self.assertIsNotNone(res)
            self.assertTrue(len(connected_ips) > 0)
            self.assertIn(connected_ips[0], GOOGLE_EDGE_ANYCAST_IPS)
            self.assertNotIn(failed_ggc_ip, connected_ips)

    def test_resolve_fallback_dns_ipv6_filtering(self):
        """resolve_fallback_dns не должен возвращать IPv6 адрес, если ipv6_mode == 'disabled'."""
        from flowguard.proxy import resolve_fallback_dns
        mock_mgr = MagicMock()
        mock_mgr.resolve_one.return_value = "2a00:1450:4011:40::19"
        with patch("flowguard.proxy.get_dns_failover_manager", return_value=mock_mgr):
            res = resolve_fallback_dns("test-ipv6-only.googlevideo.com")
            self.assertIsNone(res)

    def test_dc_telemetry_immediate_rejection(self):
        """Запросы к *.dc-telemetry.net должны немедленно завершаться 502 Bad Gateway без DNS ожидания."""
        from flowguard.proxy import resolve_fallback_dns
        self.assertIsNone(resolve_fallback_dns("streamer-relay.dc-telemetry.net"))
        self.assertIsNone(resolve_fallback_dns("dc-telemetry.net"))

        self.assertIsNone(self.proxy._connect_target("streamer-relay.dc-telemetry.net", 443))

        mock_client = MagicMock()
        mock_client.recv.return_value = b"CONNECT streamer-relay.dc-telemetry.net:443 HTTP/1.1\r\nHost: streamer-relay.dc-telemetry.net\r\n\r\n"
        self.proxy._handle_client(mock_client, ("127.0.0.1", 54321))
        mock_client.sendall.assert_called_with(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")

    def test_quic_block_discord_detection(self):
        """quic_block должен содержать 'discord' в KNOWN_BROWSER_KEYS и находить Discord.exe."""
        from flowguard.quic_block import KNOWN_BROWSER_KEYS, get_installed_browsers
        import glob
        import os
        self.assertIn("discord", KNOWN_BROWSER_KEYS)
        browsers = get_installed_browsers()
        has_discord = bool(glob.glob(os.path.expandvars(r"%LocalAppData%\Discord\app-*\Discord.exe")))
        if has_discord:
            self.assertIn("discord", browsers)
            self.assertTrue(browsers["discord"].lower().endswith("discord.exe"))

    def test_quic_block_discord_electron_preferred_over_launcher_stub(self):
        """get_installed_browsers обязан предпочесть исполняемый файл app-*/Discord.exe
        перед заглушкой-лаунчером Discord.exe.
        """
        from flowguard.quic_block import get_installed_browsers
        stub_path = r"C:\Users\test\AppData\Local\Discord\Discord.exe"
        electron_path = r"C:\Users\test\AppData\Local\Discord\app-1.0.9261\Discord.exe"

        with patch("sys.platform", "win32"), \
             patch("glob.glob", return_value=[stub_path, electron_path]), \
             patch("os.path.isfile", return_value=True):
            browsers = get_installed_browsers()
            self.assertIn("discord", browsers)
            self.assertEqual(browsers["discord"], electron_path)

    def fresh_engine(self):
        """Движок без накопленных другими тестами наблюдений."""
        import os
        import tempfile
        from flowguard.strategy import ThompsonStrategySelector
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return ThompsonStrategySelector(enabled=True, scores_file=os.path.join(directory.name, "scores.json"))

    def test_youtube_and_google_start_with_combo(self):
        """Без наблюдений YouTube, Google и Discord начинают с combo_tlsrec_tcpsplit, без случайной разведки."""
        engine = self.fresh_engine()
        for _ in range(20):
            self.assertEqual(engine.select_strategy("www.youtube.com", is_youtube=True), "combo_tlsrec_tcpsplit")
            self.assertEqual(engine.select_strategy("rr1---sn-4g5ednks.googlevideo.com"), "combo_tlsrec_tcpsplit")
            self.assertEqual(engine.select_strategy("gateway.discord.gg", is_discord=True), "combo_tlsrec_tcpsplit")

    def test_pipe_sockets_websocket_sets_3600_timeout(self):
        """Для WebSocket хостов (is_ws=True) _pipe_sockets устанавливает таймаут сокетов 3600.0с."""
        self.proxy.is_running = True
        client_sock = MagicMock()
        target_sock = MagicMock()
        with patch("select.select", return_value=([], [], [])):
            self.proxy._pipe_sockets(client_sock, target_sock, host="gateway.discord.gg")
        client_sock.settimeout.assert_called_with(3600.0)
        target_sock.settimeout.assert_called_with(3600.0)

    def test_handshake_fast_fallback_youtube_skip_attempt2_and_use_observations(self):
        """При сбое Attempt 1 для YouTube Попытка 2 пропускается (skip_attempt2_fast_path),
        а Попытка 3 использует технику, подтвердившую передачу данных."""
        for _ in range(40):
            self.proxy.strategy_engine.record_success(
                'googlevideo.com', 'tls_record_frag', ip='198.51.100.2', rtt_ms=25)
        from flowguard.sni_spoofer import build_fake_client_hello
        ch = build_fake_client_hello("googlevideo.com")
        current_sock = MagicMock()
        new_sock = MagicMock()
        from flowguard.proxy import _set_socket_meta
        _set_socket_meta(current_sock, target_ip="198.51.100.1", connect_rtt=0.02)
        _set_socket_meta(new_sock, target_ip="198.51.100.2", connect_rtt=0.02)
        self.proxy._connect_target = MagicMock(return_value=new_sock)
        self.proxy._send_tls_client_hello_with_bypass = MagicMock(return_value=("combo_tlsrec_tcpsplit", "googlevideo.com"))
        self.proxy._probe_socket_response = MagicMock(side_effect=[
            ("silent_drop", None, 600.0),  # Attempt 1
            ("success", b"HTTP/1.1 200 OK\r\n\r\n", 50.0),  # Attempt 3
        ])
        executed_strategies = []
        def fake_exec(strat, sock, pkt, host=""):
            executed_strategies.append(strat)
            return True
        self.proxy._safe_execute_strategy = MagicMock(side_effect=fake_exec)

        res_sock, res_strat, _, _ = self.proxy._handshake_with_fast_fallback(
            client_sock=MagicMock(),
            target_sock=current_sock,
            target_host="googlevideo.com",
            target_port=443,
            first_packet=ch
        )
        self.assertEqual(res_strat, "tls_record_frag")
        self.assertEqual(executed_strategies, ["tls_record_frag"])

    def test_pipe_sockets_discord_direct_ip_sets_3600_timeout(self):
        """Прямые IP подключения Discord (Gateway / Voice) должны получать таймаут 3600.0с."""
        self.proxy.is_running = True
        client_sock = MagicMock()
        target_sock = MagicMock()
        with patch("select.select", return_value=([], [], [])):
            self.proxy._pipe_sockets(client_sock, target_sock, host="162.159.130.233")
        client_sock.settimeout.assert_called_with(3600.0)
        target_sock.settimeout.assert_called_with(3600.0)

    def test_youtube_subdomains_start_with_combo_without_flags(self):
        """Все варианты доменов YouTube (youtube-nocookie.com, yt.be, gvt1.com) без наблюдений начинают с combo."""
        engine = self.fresh_engine()
        for d in ["youtube-nocookie.com", "yt.be", "gvt1.com", "www.youtube-nocookie.com", "rr3---sn-test.googlevideo.com"]:
            strat = engine.select_strategy(d)
            self.assertEqual(strat, "combo_tlsrec_tcpsplit", f"Failed for {d}")

    def test_discord_voice_helper_prioritizes_active_discord_udp(self):
        """VoiceHelper обязан предпочитать ACTIVE_DISCORD_UDP.bin перед discord-ip-discovery.bin во избежание NO_ROUTE."""
        from flowguard.voice_helper import VoiceHelper
        import tempfile
        import os
        with tempfile.TemporaryDirectory() as td:
            p_active = os.path.join(td, 'ACTIVE_DISCORD_UDP.bin')
            p_disc = os.path.join(td, 'discord-ip-discovery.bin')
            with open(p_active, 'wb') as f: f.write(b'active')
            with open(p_disc, 'wb') as f: f.write(b'disc')
            vh = VoiceHelper(bin_dir=td)
            self.assertEqual(os.path.basename(vh.fake_discord), 'ACTIVE_DISCORD_UDP.bin')

    def test_discord_media_small_avatar_download_records_success(self):
        """Загрузка аватара/картинки Discord <32KB должна штатно завершаться и записывать успех без бана IP."""
        from flowguard.proxy import is_ip_dead
        client_sock = MagicMock()
        target_sock = MagicMock()
        cdn_ip = '162.159.136.232'
        from flowguard.proxy import _set_socket_meta
        _set_socket_meta(target_sock, target_ip=cdn_ip, connect_rtt=0.05)

        read_cycle = [
            [client_sock],  # readable: клиент шлет GET
            [target_sock],  # readable: сервер шлет аватар
            [client_sock],  # readable: клиент закрывает сокет (EOF)
        ]
        def fake_select(r, w, x, t):
            if read_cycle:
                return read_cycle.pop(0), [], []
            return [], [], []

        client_sock.recv.side_effect = [b'GET /avatar.png HTTP/1.1\r\n\r\n', b'']
        target_sock.recv.side_effect = [b'HTTP/1.1 200 OK\r\nContent-Length: 4000\r\n\r\n' + b'A'*4000]

        with patch('select.select', side_effect=fake_select):
            self.proxy._pipe_sockets(client_sock, target_sock, host='cdn.discordapp.com', strategy='combo_tlsrec_tcpsplit')

        self.assertFalse(is_ip_dead(cdn_ip))

    def test_discord_media_select_strategy_pinned_to_combo(self):
        """Медиа хосты Discord (cdn, media) обязаны безусловно выбирать combo_tlsrec_tcpsplit."""
        for h in ['cdn.discordapp.com', 'media.discordapp.net', 'images-ext-1.discordapp.net']:
            s = self.proxy.strategy_engine.select_strategy(h)
            self.assertEqual(s, 'combo_tlsrec_tcpsplit', f'Expected combo_tlsrec_tcpsplit for {h}, got {s}')


if __name__ == "__main__":
    unittest.main()


