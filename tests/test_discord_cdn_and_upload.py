"""Тесты для исправления скорости загрузки и скачивания файлов Discord:
1. Исключение внешних облачных хранилищ (.storage.googleapis.com, .amazonaws.com, .blob.core.windows.net) из is_discord_host
2. Ограничение DISCORD_CLOUDFLARE_ANYCAST_IPS только для core-доменов (discord.com, gateway.discord.gg)
   с сохранением оригинальных DNS IP для CDN (cdn.discordapp.com, media.discordapp.net)
3. Исправление 32KB ловушки в _pipe_sockets для upload-потоков (bytes_tx > 0)
4. Прямая отправка данных без микро-чанкования по 1380 байт
"""

import unittest
from unittest.mock import patch, MagicMock
import socket
import time

from flowguard.config import Config
from flowguard.proxy import (
    DPIBypassProxy,
    is_discord_host,
    is_ip_dead,
    mark_ip_dead,
    mark_ip_working,
    DISCORD_CLOUDFLARE_ANYCAST_IPS,
    DISCORD_CDN_ANYCAST_IPS,
    DISCORD_MEDIA_ANYCAST_IPS,
    _DEAD_IP_CACHE,
    _WORKING_IP_CACHE,
    _RESOLVED_IPS_CACHE,
)


class TestDiscordCdnAndUpload(unittest.TestCase):
    def setUp(self):
        _WORKING_IP_CACHE._cache.clear()
        _DEAD_IP_CACHE._cache.clear()
        _RESOLVED_IPS_CACHE._cache.clear()
        self.config = Config("_test_defaults_missing.ini")
        self.proxy = DPIBypassProxy(self.config)

    def tearDown(self):
        _WORKING_IP_CACHE._cache.clear()
        _DEAD_IP_CACHE._cache.clear()
        _RESOLVED_IPS_CACHE._cache.clear()

    def test_is_discord_host_excludes_external_cloud_storage(self):
        """Проверка исключения облачных хранилищ из is_discord_host."""
        # Google Cloud Storage (используется Discord для загрузки больших файлов)
        self.assertFalse(is_discord_host("discord-attachments-uploads-prd.storage.googleapis.com"))
        self.assertFalse(is_discord_host("storage.googleapis.com"))
        # AWS S3
        self.assertFalse(is_discord_host("discord-uploads.s3.amazonaws.com"))
        self.assertFalse(is_discord_host("s3.amazonaws.com"))
        # Azure Blob Storage
        self.assertFalse(is_discord_host("discord.blob.core.windows.net"))

        # Настоящие Discord хосты должны оставаться True
        self.assertTrue(is_discord_host("discord.com"))
        self.assertTrue(is_discord_host("gateway.discord.gg"))
        self.assertTrue(is_discord_host("cdn.discordapp.com"))
        self.assertTrue(is_discord_host("media.discordapp.net"))
        self.assertTrue(is_discord_host("images-ext-1.discordapp.net"))
        self.assertTrue(is_discord_host("attachments.discord.net"))
        self.assertTrue(is_discord_host("dl.discordapp.net"))
        self.assertTrue(is_discord_host("canary.discord.com"))
        self.assertTrue(is_discord_host("ptb.discord.com"))
        self.assertTrue(is_discord_host("dis.gd"))

    @patch("socket.getaddrinfo")
    @patch("socket.socket")
    def test_core_discord_uses_anycast_candidates(self, mock_socket_cls, mock_getaddrinfo):
        """Core Discord хосты (discord.com, gateway.discord.gg) используют Anycast Cloudflare."""
        # Мокаем сокет
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_cls.return_value = mock_sock

        # getaddrinfo возвращает произвольный IP
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("104.16.248.249", 443))
        ]

        # Для discord.com сокет должен подключаться к Anycast IP из DISCORD_CLOUDFLARE_ANYCAST_IPS
        s = self.proxy._connect_target("discord.com", 443)
        self.assertIsNotNone(s)
        called_args = mock_sock.connect_ex.call_args or mock_sock.connect.call_args
        connected_ip = called_args[0][0][0]
        self.assertEqual(connected_ip, "104.16.248.249")

    @patch("socket.getaddrinfo")
    @patch("socket.socket")
    def test_cdn_discord_uses_real_dns_candidates(self, mock_socket_cls, mock_getaddrinfo):
        """CDN хосты (cdn.discordapp.com, attachments) используют проверенные Anycast IP Cloudflare."""
        dns_cdn_ip = "162.159.135.233"  # Реальный DNS IP CDN ноды Discord
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (dns_cdn_ip, 443))
        ]
        mock_sock = MagicMock()
        mock_sock.connect.return_value = None
        mock_sock.connect_ex.return_value = 0
        mock_socket_cls.return_value = mock_sock

        s = self.proxy._connect_target("cdn.discordapp.com", 443)
        self.assertIsNotNone(s)
        called_args = mock_sock.connect.call_args or mock_sock.connect_ex.call_args
        connected_ip = called_args[0][0][0]
        self.assertEqual(connected_ip, dns_cdn_ip)

    @patch("socket.getaddrinfo")
    @patch("socket.socket")
    def test_media_discord_uses_real_dns_candidates(self, mock_socket_cls, mock_getaddrinfo):
        """media.discordapp.net использует проверенные Media Anycast IP Cloudflare."""
        dns_media_ip = "162.159.134.232"
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (dns_media_ip, 443))
        ]
        mock_sock = MagicMock()
        mock_sock.connect.return_value = None
        mock_sock.connect_ex.return_value = 0
        mock_socket_cls.return_value = mock_sock

        s = self.proxy._connect_target("media.discordapp.net", 443)
        self.assertIsNotNone(s)
        called_args = mock_sock.connect.call_args or mock_sock.connect_ex.call_args
        connected_ip = called_args[0][0][0]
        self.assertEqual(connected_ip, dns_media_ip)

    def test_upload_flow_records_success_and_avoids_32kb_stall_ban(self):
        """Upload flow: клиент отправляет большой объем данных (>0 байт, HTTP PUT/POST),
        сервер возвращает короткий ответ (<32KB, например HTTP 200 OK 500 байт),
        после чего клиент закрывает сокет.
        Проверяем, что соединение считается успешным и НЕ банит IP как зависший (stall).
        """
        self.proxy.is_running = True
        client_sock = MagicMock()
        target_sock = MagicMock()

        test_target_ip = "162.159.135.233"
        target_sock.getpeername.return_value = (test_target_ip, 443)

        upload_payload = b"X" * 65536  # 64 KB загрузки
        short_response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"

        # 1. Клиент отправляет тело запроса (upload_payload)
        # 2. Сервер возвращает короткий HTTP 200 OK (длина < 32768)
        # 3. Клиент завершает отправку (b"")
        client_sock.recv.side_effect = [upload_payload, b""]
        target_sock.recv.side_effect = [short_response, b""]

        with patch("select.select") as mock_select, \
             patch.object(self.proxy.strategy_engine, "record_success") as mock_record_success, \
             patch.object(self.proxy.strategy_engine, "record_failure") as mock_record_failure:
            mock_select.side_effect = [
                ([client_sock], [], []),  # клиент отправил данные
                ([target_sock], [], []),  # сервер ответил 200 OK
                ([client_sock], [], []),  # клиент закрыл соединение
                ([target_sock], [], []),  # сервер закрыл соединение
            ]

            self.proxy._pipe_sockets(
                client_sock,
                target_sock,
                host="cdn.discordapp.com",
                strategy="combo_tlsrec_tcpsplit"
            )

            # Проверяем, что зафиксирован успех стратегии и IP НЕ забанен
            mock_record_success.assert_called_with("cdn.discordapp.com", "combo_tlsrec_tcpsplit", ip=test_target_ip)
            mock_record_failure.assert_not_called()
            self.assertFalse(is_ip_dead(test_target_ip))

    def test_upload_flow_direct_sendall_without_microchunking(self):
        """Проверяем, что данные при upload передаются единым sendall без микро-чанкования по 1380 байт."""
        self.proxy.is_running = True
        client_sock = MagicMock()
        target_sock = MagicMock()

        target_sock.getpeername.return_value = ("142.250.180.10", 443)
        large_chunk = b"A" * 8192

        client_sock.recv.side_effect = [large_chunk, b""]
        target_sock.recv.side_effect = [b""]

        with patch("select.select") as mock_select:
            mock_select.side_effect = [
                ([client_sock], [], []),
                ([client_sock], [], []),
                ([target_sock], [], []),
            ]
            self.proxy._pipe_sockets(client_sock, target_sock, host="discord-attachments-uploads-prd.storage.googleapis.com")

        # target_sock.sendall должен быть вызван ровно 1 раз для всего 8192-байтового чанка
        self.assertEqual(target_sock.sendall.call_count, 1)
        self.assertEqual(target_sock.sendall.call_args[0][0], large_chunk)

    def test_is_discord_host_with_ports_and_cloud_storage(self):
        """Проверка корректной обработки портов и облачных хранилищ в is_discord_host."""
        self.assertFalse(is_discord_host("discord-attachments-uploads-prd.storage.googleapis.com:443"))
        self.assertFalse(is_discord_host("storage.googleapis.com:443"))
        self.assertFalse(is_discord_host("storage.googleapis.com"))
        self.assertFalse(is_discord_host("discord-uploads.s3.amazonaws.com:443"))
        self.assertFalse(is_discord_host("discord.blob.core.windows.net:443"))
        # С портами для реальных доменов Discord
        self.assertTrue(is_discord_host("discord.com:443"))
        self.assertTrue(is_discord_host("cdn.discordapp.com:443"))
        self.assertTrue(is_discord_host("dl.discordapp.net:443"))

    def test_small_upload_flow_avoids_stall_ban(self):
        """Микро-загрузка: клиент отправляет небольшой запрос (<1024 байт, 250 байт),
        сервер возвращает короткий ответ (200 байт < 32KB), после чего сокет закрывается.
        Проверяем, что соединение считается успешным и НЕ банит IP как зависший (stall).
        """
        self.proxy.is_running = True
        client_sock = MagicMock()
        target_sock = MagicMock()

        test_target_ip = "162.159.136.232"
        target_sock.getpeername.return_value = (test_target_ip, 443)

        small_payload = b'{"content": "hello world"}'  # 26 байт
        short_response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"

        client_sock.recv.side_effect = [small_payload, b""]
        target_sock.recv.side_effect = [short_response, b""]

        with patch("select.select") as mock_select, \
             patch.object(self.proxy.strategy_engine, "record_success") as mock_record_success, \
             patch.object(self.proxy.strategy_engine, "record_failure") as mock_record_failure:
            mock_select.side_effect = [
                ([client_sock], [], []),
                ([target_sock], [], []),
                ([client_sock], [], []),
                ([target_sock], [], []),
            ]

            self.proxy._pipe_sockets(
                client_sock,
                target_sock,
                host="discord.com",
                strategy="combo_tlsrec_tcpsplit"
            )

            mock_record_success.assert_called_with("discord.com", "combo_tlsrec_tcpsplit", ip=test_target_ip)
            mock_record_failure.assert_not_called()
            self.assertFalse(is_ip_dead(test_target_ip))

    def test_cdn_small_download_avoids_stall_ban(self):
        """Скачивание небольшого файла (<32KB, 5KB) с CDN хоста (dl.discordapp.net) с реальным DNS IP
        (не входящим в Anycast) НЕ должно вызывать ложный stall и бан IP.
        """
        self.proxy.is_running = True
        client_sock = MagicMock()
        target_sock = MagicMock()

        real_cdn_dns_ip = "162.159.135.233"
        target_sock.getpeername.return_value = (real_cdn_dns_ip, 443)

        download_payload = b"IMG_DATA" * 600  # 4800 байт (< 32KB)

        client_sock.recv.side_effect = [b"GET /file HTTP/1.1\r\n\r\n", b""]
        target_sock.recv.side_effect = [download_payload, b""]

        with patch("select.select") as mock_select, \
             patch.object(self.proxy.strategy_engine, "record_success") as mock_record_success, \
             patch.object(self.proxy.strategy_engine, "record_failure") as mock_record_failure:
            mock_select.side_effect = [
                ([client_sock], [], []),
                ([target_sock], [], []),
                ([client_sock], [], []),
                ([target_sock], [], []),
            ]

            self.proxy._pipe_sockets(
                client_sock,
                target_sock,
                host="dl.discordapp.net",
                strategy="combo_tlsrec_tcpsplit"
            )

            mock_record_success.assert_called_with("dl.discordapp.net", "combo_tlsrec_tcpsplit", ip=real_cdn_dns_ip)
            mock_record_failure.assert_not_called()
            self.assertFalse(is_ip_dead(real_cdn_dns_ip))

    def test_socket_buffer_sizes_are_at_least_1mb(self):
        """Проверка, что сокеты в _connect_target настраиваются с буферами не менее 1 МБ (1048576 байт)."""
        mock_sock = MagicMock()
        mock_sock.connect.return_value = None
        with patch("socket.socket", return_value=mock_sock):
            self.proxy._connect_target("1.1.1.1", 443)
            calls = mock_sock.setsockopt.call_args_list
            rcv_calls = [c for c in calls if c[0][1] == socket.SO_RCVBUF]
            snd_calls = [c for c in calls if c[0][1] == socket.SO_SNDBUF]
            self.assertTrue(len(rcv_calls) > 0)
            self.assertTrue(len(snd_calls) > 0)
            self.assertGreaterEqual(rcv_calls[0][0][2], 1048576)
            self.assertGreaterEqual(snd_calls[0][0][2], 1048576)

    def test_direct_connect_buffer_size_is_at_least_1mb(self):
        """Проверка размера сокетных буферов в _try_direct_connect."""
        mock_sock = MagicMock()
        mock_sock.connect.return_value = None
        with patch("socket.socket", return_value=mock_sock):
            self.proxy._try_direct_connect("162.159.136.232", 443)
            calls = mock_sock.setsockopt.call_args_list
            rcv_calls = [c for c in calls if c[0][1] == socket.SO_RCVBUF]
            snd_calls = [c for c in calls if c[0][1] == socket.SO_SNDBUF]
            self.assertTrue(len(rcv_calls) > 0)
            self.assertTrue(len(snd_calls) > 0)
            self.assertGreaterEqual(rcv_calls[0][0][2], 1048576)
            self.assertGreaterEqual(snd_calls[0][0][2], 1048576)


if __name__ == "__main__":
    unittest.main()
