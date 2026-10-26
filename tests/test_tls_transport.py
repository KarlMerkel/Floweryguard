"""Передача байтов и half-close на настоящих локальных сокетах."""
import socket
import threading
import unittest
from unittest.mock import Mock, patch

from flowguard.tls_transport import relay_tls


class TestTlsTransport(unittest.TestCase):
    def test_idle_long_lived_connection_observes_proxy_stop(self):
        app, client = socket.socketpair()
        upstream, server = socket.socketpair()
        for sock in (app, client, upstream, server):
            self.addCleanup(sock.close)
        running = threading.Event()
        running.set()
        entered_select = threading.Event()
        result = []
        import select
        real_select = select.select

        def select_ready(*args):
            entered_select.set()
            return real_select(*args)

        def relay():
            result.append(relay_tls(client, upstream, running.is_set, 1, 4096, Mock(), Mock(), long_lived=True))

        with patch('flowguard.tls_transport.select.select', side_effect=select_ready):
            worker = threading.Thread(target=relay, daemon=True)
            worker.start()
            self.assertTrue(entered_select.wait(2))
            running.clear()
            worker.join(2)
            # Разбудить старую реализацию после фиксации результата, чтобы тест не оставлял поток.
            stopped = not worker.is_alive()
            server.shutdown(socket.SHUT_WR)
            worker.join(2)
        self.assertTrue(stopped)
        self.assertEqual(result[0][1], 'stopped')

    def test_stalled_half_close_updates_route_before_drain_finishes(self):
        client, upstream = Mock(), Mock()
        client.recv.side_effect = [b'request', b'']
        upstream.recv.return_value = b'x' * 14000
        now = [0]
        events = iter([(0, client), (1, upstream), (9, client), (24, None)])
        suspect = Mock()
        client.send.side_effect = lambda data: len(data)
        upstream.send.side_effect = lambda data: len(data)

        def ready(*args):
            if args[1]:
                return [], args[1], []
            now[0], source = next(events)
            if source is None:
                suspect.assert_called_once()
            return ([source] if source is not None else []), [], []

        with patch('flowguard.tls_transport.select.select', side_effect=ready), \
             patch('flowguard.tls_transport.time.monotonic', side_effect=lambda: now[0]):
            progress, reason = relay_tls(client, upstream, lambda: True, 15, 65536,
                                         Mock(), Mock(), on_suspect=suspect)
        self.assertEqual(reason, 'client_eof')
        self.assertEqual(progress.server_bytes, 14000)

    def test_half_close_drains_response_without_replay_or_loss(self):
        app, client = socket.socketpair()
        upstream, server = socket.socketpair()
        for sock in (app, client, upstream, server):
            self.addCleanup(sock.close)
            sock.settimeout(3)
        result, errors, counters = [], [], []
        reward = Mock()
        request = b'\x17' + bytes(range(256)) * 400
        response = b'\x17' + bytes(range(255, -1, -1)) * 800

        def relay():
            try:
                result.append(relay_tls(client, upstream, lambda: True, 1, 4096,
                                        lambda *args: counters.append(args), reward))
            except Exception as error:
                errors.append(error)
            finally:
                client.shutdown(socket.SHUT_WR)

        worker = threading.Thread(target=relay, daemon=True)
        worker.start()
        app.sendall(request)
        app.shutdown(socket.SHUT_WR)
        received = bytearray()
        while True:
            data = server.recv(4096)
            if not data:
                break
            received.extend(data)
        self.assertEqual(received, request)
        server.sendall(response)
        server.shutdown(socket.SHUT_WR)
        received = bytearray()
        while True:
            data = app.recv(4096)
            if not data:
                break
            received.extend(data)
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(received, response)
        self.assertEqual(result[0][1], 'server_eof')
        self.assertEqual(result[0][0].server_bytes, len(response))
        self.assertEqual(sum(n for direction, n in counters if direction == 'tx'), len(request))
        self.assertEqual(sum(n for direction, n in counters if direction == 'rx'), len(response))
        reward.assert_called_once_with()

    def idle_close_time(self, response_size):
        """Момент закрытия простаивающего туннеля после запроса и ответа заданного размера."""
        client, upstream = Mock(), Mock()
        client.recv.return_value = b'request'
        upstream.recv.return_value = b'x' * response_size
        client.send.side_effect = lambda data: len(data)
        upstream.send.side_effect = lambda data: len(data)
        now = [0.0]
        events = iter([client, upstream])

        def ready(readers, writers, *_):
            if writers:
                return [], writers, []
            source = next(events, None)
            if source is None:
                now[0] += 1.0
                return [], [], []
            return [source], [], []

        with patch('flowguard.tls_transport.select.select', side_effect=ready), \
             patch('flowguard.tls_transport.time.monotonic', side_effect=lambda: now[0]):
            progress, reason = relay_tls(client, upstream, lambda: True, 15, 65536, Mock(), Mock())
        self.assertEqual(reason, 'idle_timeout')
        self.assertEqual(progress.server_bytes, response_size)
        return now[0]

    def test_stalled_response_closes_quickly_but_finished_keepalive_stays(self):
        # Обрыв на 14 КБ: клиент быстро получает закрытие и повторяет запрос по другому адресу.
        self.assertLessEqual(self.idle_close_time(14000), 16.0)
        # Завершённый короткий ответ: keep-alive соединение переиспользуется браузером.
        self.assertGreaterEqual(self.idle_close_time(3000), 300.0)

    def test_delivery_error_does_not_reward_unforwarded_bytes(self):
        client, upstream = Mock(), Mock()
        upstream.recv.return_value = b'x' * 100000
        client.send.side_effect = ConnectionResetError()
        reward = Mock()
        with patch('flowguard.tls_transport.select.select', side_effect=lambda readers, writers, *_: ([], writers, []) if writers else ([upstream], [], [])):
            progress, reason = relay_tls(client, upstream, lambda: True, 1, 131072, Mock(), reward)
        self.assertEqual(reason, 'client_write_error')
        self.assertEqual(progress.server_bytes, 0)
        reward.assert_not_called()
