"""Тесты для проверки исправлений пула соединений Chromium, ловушки 32KB,
расширенной фиксации стратегии combo_tlsrec_tcpsplit и быстрого DoH Failover.
"""

import socket
import time
import unittest
from unittest.mock import MagicMock, patch

from flowguard.config import Config
from flowguard.proxy import (
    DPIBypassProxy,
    is_ip_dead,
    mark_ip_dead,
    mark_ip_working,
    _DEAD_IP_CACHE,
    _WORKING_IP_CACHE,
    _RESOLVED_IPS_CACHE,
)
from flowguard.strategy import ThompsonStrategySelector, MAJOR_BLOCKED_PATTERNS


class TestLivePreconnectDohFixes(unittest.TestCase):
    def setUp(self):
        _WORKING_IP_CACHE._cache.clear()
        _DEAD_IP_CACHE._cache.clear()
        _RESOLVED_IPS_CACHE._cache.clear()
        self.config = Config("_test_defaults_missing.ini")
        self.proxy = DPIBypassProxy(self.config)
        self.proxy.is_running = True
        self.selector = ThompsonStrategySelector(enabled=True)

    def tearDown(self):
        _WORKING_IP_CACHE._cache.clear()
        _DEAD_IP_CACHE._cache.clear()
        _RESOLVED_IPS_CACHE._cache.clear()

    def test_chromium_preconnect_timeout_no_false_ip_penalty(self):
        """Проверяет, что неиспользованное pre-connect соединение Chromium (select timeout без данных от клиента)
        НЕ штрафует IP как мёртвый и НЕ записывает сбой стратегии.
        """
        target_ip = "162.159.130.234"
        client_sock = MagicMock()
        target_sock = MagicMock()
        target_sock.getpeername.return_value = (target_ip, 443)

        # Симулируем таймаут select: readable пустой
        with patch("select.select", return_value=([], [], [])):
            with patch.object(self.proxy.strategy_engine, "record_failure") as mock_rec_fail:
                # got_initial_response = True, но клиент так и не отправил app_data
                self.proxy._pipe_sockets(
                    client_sock,
                    target_sock,
                    host="cdn.discordapp.com",
                    strategy="combo_tlsrec_tcpsplit",
                    got_initial_response=True,
                )
                # IP не должен быть помечен как мертвый!
                self.assertFalse(is_ip_dead(target_ip))
                # record_failure не должен быть вызван!
                mock_rec_fail.assert_not_called()

    def test_chromium_preconnect_client_eof_no_false_ip_penalty(self):
        """Проверяет, что закрытие клиентом неиспользованного pre-connect соединения (client_sock recv -> b'')
        НЕ штрафует IP как мёртвый и НЕ штрафует combo_tlsrec_tcpsplit.
        """
        target_ip = "162.159.130.235"
        client_sock = MagicMock()
        target_sock = MagicMock()
        target_sock.getpeername.return_value = (target_ip, 443)

        # Клиент закрывает сокет (b"") без отправки данных
        client_sock.recv.return_value = b""

        select_returns = [([client_sock], [], []), ([], [], [])]
        with patch("select.select", side_effect=lambda r, w, e, t: select_returns.pop(0) if select_returns else ([], [], [])):
            with patch.object(self.proxy.strategy_engine, "record_failure") as mock_rec_fail:
                self.proxy._pipe_sockets(
                    client_sock,
                    target_sock,
                    host="cdn.discordapp.com",
                    strategy="combo_tlsrec_tcpsplit",
                    got_initial_response=True,
                )
                self.assertFalse(is_ip_dead(target_ip))
                mock_rec_fail.assert_not_called()

    def test_discordapp_com_recognized_as_discord_media(self):
        """Проверяет, что discordapp.com распознается как media-домен Discord."""
        target_ip = "162.159.135.234"
        client_sock = MagicMock()
        target_sock = MagicMock()
        target_sock.getpeername.return_value = (target_ip, 443)

        # Сервер передает 4KB данных (маленький аватар / картинка), затем клиент штатно закрывает
        recv_calls = [b"HTTP/1.1 200 OK\r\n\r\n" + b"X" * 4096, b""]
        def target_recv_side_effect(buf):
            if recv_calls:
                return recv_calls.pop(0)
            return b""
        target_sock.recv.side_effect = target_recv_side_effect
        client_sock.recv.return_value = b""

        select_iterations = [
            ([target_sock], [], []),  # Сервер шлет 4KB
            ([client_sock], [], []),  # Клиент закрывает keep-alive
        ]
        with patch("select.select", side_effect=lambda r, w, e, t: select_iterations.pop(0) if select_iterations else ([], [], [])):
            with patch.object(self.proxy.strategy_engine, "record_failure") as mock_rec_fail:
                self.proxy._pipe_sockets(
                    client_sock,
                    target_sock,
                    host="discordapp.com",
                    strategy="combo_tlsrec_tcpsplit",
                    got_initial_response=False,
                )
                self.assertFalse(is_ip_dead(target_ip))
                mock_rec_fail.assert_not_called()

    def test_32kb_stall_trap_idle_keepalive_not_penalized(self):
        """Проверяет, что когда клиент закрывает keep-alive соединение после получения ответа (<32KB),
        оно НЕ штрафуется как зависание, даже если с момента ответа прошло >= 4 секунд.
        """
        target_ip = "162.159.130.236"
        client_sock = MagicMock()
        target_sock = MagicMock()
        target_sock.getpeername.return_value = (target_ip, 443)

        # 1. Клиент шлет запрос
        # 2. Сервер шлет 2KB JSON API ответ (<32KB)
        # 3. Соединение в простое 5 секунд
        # 4. Клиент закрывает keep-alive пул
        events = [
            ([client_sock], [], []),  # client sends request
            ([target_sock], [], []),  # server sends 2KB response
            ([client_sock], [], []),  # client cleanly closes after 5 seconds idle
        ]

        client_recvs = [b"GET /api/v9/users/@me HTTP/1.1\r\nHost: discord.com\r\n\r\n", b""]
        client_sock.recv.side_effect = lambda buf: client_recvs.pop(0) if client_recvs else b""
        target_sock.recv.side_effect = [b"HTTP/1.1 200 OK\r\nContent-Length: 2048\r\n\r\n" + b"A" * 2000, b""]

        real_time = time.time
        time_state = {"t": 1000.0}

        def fake_time():
            return time_state["t"]

        def fake_select(r, w, e, timeout):
            if events:
                ev = events.pop(0)
                if len(events) == 0:
                    # На третьем шаге прошло 5 секунд
                    time_state["t"] += 5.0
                return ev
            return [], [], []

        with patch("time.time", side_effect=fake_time):
            with patch("select.select", side_effect=fake_select):
                with patch.object(self.proxy.strategy_engine, "record_failure") as mock_rec_fail:
                    with patch.object(self.proxy.strategy_engine, "record_success") as mock_rec_succ:
                        # Для доменов Discord Media (<32KB) штатное закрытие keep-alive пула не должно штрафоваться
                        self.proxy._pipe_sockets(
                            client_sock,
                            target_sock,
                            host="cdn.discordapp.com",
                            strategy="combo_tlsrec_tcpsplit",
                        )
                        self.assertFalse(is_ip_dead(target_ip))
                        mock_rec_fail.assert_not_called()
                        mock_rec_succ.assert_called()

    def test_chromium_preconnect_timeout_no_false_success(self):
        """Проверяет, что неиспользованное pre-connect соединение Chromium (select timeout без данных от клиента)
        НЕ записывает ложный успех стратегии (no false success).
        """
        target_ip = "162.159.130.234"
        client_sock = MagicMock()
        target_sock = MagicMock()
        target_sock.getpeername.return_value = (target_ip, 443)

        with patch("select.select", return_value=([], [], [])):
            with patch.object(self.proxy.strategy_engine, "record_failure") as mock_rec_fail:
                with patch.object(self.proxy.strategy_engine, "record_success") as mock_rec_succ:
                    self.proxy._pipe_sockets(
                        client_sock,
                        target_sock,
                        host="cdn.discordapp.com",
                        strategy="combo_tlsrec_tcpsplit",
                        got_initial_response=True,
                    )
                    self.assertFalse(is_ip_dead(target_ip))
                    mock_rec_fail.assert_not_called()
                    mock_rec_succ.assert_not_called()

    def test_chromium_preconnect_reset_no_ip_penalty(self):
        """Проверяет, что ошибка сокета/RST при закрытии неиспользованного pre-connect соединения
        НЕ штрафует IP как мертвый (client_sent_app_data is False).
        """
        target_ip = "162.159.130.237"
        client_sock = MagicMock()
        target_sock = MagicMock()
        target_sock.getpeername.return_value = (target_ip, 443)
        client_sock.recv.side_effect = ConnectionResetError("Connection reset by peer")

        with patch("select.select", return_value=([client_sock], [], [])):
            with patch.object(self.proxy.strategy_engine, "record_failure") as mock_rec_fail:
                self.proxy._pipe_sockets(
                    client_sock,
                    target_sock,
                    host="discord.com",
                    strategy="combo_tlsrec_tcpsplit",
                    got_initial_response=True,
                )
                self.assertFalse(is_ip_dead(target_ip))
                mock_rec_fail.assert_not_called()

    def test_major_blocked_fallback_excludes_direct(self):
        """Проверяет, что при сбое combo_tlsrec_tcpsplit для крупных заблокированных доменов
        стратегия 'direct' исключается из кандидатов fallback.
        """
        for dom in ["x.com", "rutracker.org", "pornhub.com", "patreon.com"]:
            fb = self.selector.get_fallback_strategy(
                host=dom,
                failed_strategy="combo_tlsrec_tcpsplit",
                failed_strategies=["combo_tlsrec_tcpsplit"]
            )
            self.assertNotEqual(fb, "direct", f"Fallback for '{dom}' must never be 'direct'")

    def test_major_blocked_sites_pinned_to_combo_tlsrec_tcpsplit(self):
        """Проверяет, что для всех крупных заблокированных сайтов (X, СМИ, трекеры, NTC, Patreon)
        select_strategy всегда возвращает combo_tlsrec_tcpsplit.
        """
        test_domains = [
            "x.com", "twitter.com", "api.twitter.com", "abs.twimg.com",
            "bbc.com", "www.bbc.com", "svoboda.org", "dw.com", "currenttime.tv",
            "tvrain.tv", "novayagazeta.eu", "themoscowtimes.com", "zona.media",
            "istories.media", "holod.media", "meduza.io",
            "pornhub.com", "linkedin.com", "torproject.org", "ntc.party", "hdrezka.me",
            "patreon.com",
            "rutracker.org", "nnmclub.to", "rutor.info", "kinozal.tv", "t-ru.org"
        ]
        for dom in test_domains:
            strat = self.selector.select_strategy(dom)
            self.assertEqual(
                strat,
                "combo_tlsrec_tcpsplit",
                f"Domain '{dom}' should be pinned to combo_tlsrec_tcpsplit, got '{strat}'"
            )

    def test_discord_media_fallback_avoids_failed_combo_and_sni_mid(self):
        """После сбоя combo на том же IP медиа Discord не повторяет его и не выбирает
        tcp_split_sni_mid, direct или boringssl_split.
        """
        media_hosts = [
            "cdn.discordapp.com",
            "media.discordapp.net",
            "attachments.discord.net",
            "discordapp.com",
            "discordapp.net",
        ]
        for host in media_hosts:
            fallback = self.selector.get_fallback_strategy(
                host=host,
                failed_strategy="combo_tlsrec_tcpsplit",
                failed_strategies=["combo_tlsrec_tcpsplit"],
                is_discord=True,
            )
            self.assertIn(
                fallback,
                ("tls_record_frag", "multi_split", "tcp_split_sni_start"),
                f"Fallback for Discord media '{host}' got '{fallback}'"
            )

    @patch("socket.socket")
    def test_fast_doh_failover_on_poisoned_local_ip(self, mock_socket_cls):
        """Проверяет, что при таймауте/сбое подключения к локальному/отравленному IP (hosts/DNS poisoning)
        происходит быстрый переход на здоровые Anycast/CDN IP через DoH.
        """
        poisoned_ip = "185.246.223.127"
        healthy_doh_ip = "104.21.5.10"

        # Мокаем DoH резолверы
        self.proxy.dns_failover = MagicMock()
        self.proxy.dns_failover.resolve.return_value = [healthy_doh_ip]
        self.proxy.doh_harvester = MagicMock()
        self.proxy.doh_harvester.harvest.return_value = [healthy_doh_ip]

        # Создаем сокеты: первый (к poisoned_ip) падает с таймаутом, второй (к healthy_doh_ip) успешен
        mock_sock_poisoned = MagicMock()
        mock_sock_poisoned.connect.side_effect = socket.timeout("timed out")

        mock_sock_healthy = MagicMock()
        mock_sock_healthy.connect.return_value = None

        mock_socket_cls.side_effect = [mock_sock_poisoned, mock_sock_healthy]

        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", (poisoned_ip, 443))]):
            s = self.proxy._connect_target("blocked-site.org", 443, timeout=5.0)

            # Проверяем, что соединение успешно установлено со вторым (здоровым DoH) сокетом
            self.assertIsNotNone(s)
            self.assertEqual(s, mock_sock_healthy)
            # Отравленный IP понижен для этого хоста
            self.assertEqual(self.proxy.route_health.status(self.proxy.strategy_engine._current_network, "blocked-site.org", 443, poisoned_ip), 'suspect')
            # Таймаут первого подключения должен быть ограничен min(1.5, timeout) = 1.5s
            mock_sock_poisoned.settimeout.assert_called_with(1.5)

    def test_whitelisted_domains_include_doh_ips(self):
        """Проверяет, что для доменов из whitelist DoH резолвинг вызывается и добавляется в candidate_ips."""
        self.proxy.whitelist_domains = {"whitelisted-media.net"}
        self.proxy.dns_failover = MagicMock()
        self.proxy.dns_failover.resolve.return_value = ["104.22.1.2"]
        self.proxy.doh_harvester = MagicMock()
        self.proxy.doh_harvester.harvest.return_value = ["104.22.1.3"]

        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 443))]):
            with patch("socket.socket") as mock_sock_cls:
                mock_s = MagicMock()
                mock_sock_cls.return_value = mock_s
                mock_s.connect_ex.return_value = 0

                s = self.proxy._connect_target("whitelisted-media.net", 443)
                self.assertIsNotNone(s)
                # dns_failover или doh_harvester должны быть вызваны
                self.assertTrue(self.proxy.dns_failover.resolve.called or self.proxy.doh_harvester.harvest.called)


if __name__ == "__main__":
    unittest.main()
