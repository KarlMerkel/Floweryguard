"""Заблокированный получатель не должен блокировать обратное направление."""

import socket
import threading
import time
import unittest
from unittest.mock import Mock

from flowguard.tls_transport import relay_tls


class TestBackpressure(unittest.TestCase):
    def test_reverse_traffic_and_stop_while_client_does_not_read(self):
        app, client = socket.socketpair()
        upstream, server = socket.socketpair()
        for sock in (app, client, upstream, server):
            self.addCleanup(sock.close)
            sock.settimeout(2)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        running = threading.Event()
        running.set()
        results = []
        relay = threading.Thread(target=lambda: results.append(relay_tls(
            client, upstream, running.is_set, 15, 16384, Mock(), Mock())), daemon=True)
        relay.start()

        def flood():
            try:
                server.sendall(b'x' * (4 * 1024 * 1024))
            except OSError:
                return

        producer = threading.Thread(target=flood, daemon=True)
        producer.start()
        time.sleep(0.1)
        app.sendall(b'reverse')
        try:
            received = server.recv(7)
        except socket.timeout:
            received = b''
        running.clear()
        relay.join(2)
        stopped = not relay.is_alive()
        app.close()
        server.close()
        producer.join(3)
        relay.join(3)
        self.assertEqual(received, b'reverse')
        self.assertTrue(stopped)
