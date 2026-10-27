"""Метаданные закрытого соединения не должны переходить новому сокету."""

import socket
import unittest
from unittest.mock import patch

from flowguard.proxy import _set_socket_meta, _get_socket_meta, _SOCKET_META


class TestSocketMetadataIdentity(unittest.TestCase):
    def test_reused_identity_does_not_return_other_socket_ip(self):
        key = -12345
        self.addCleanup(_SOCKET_META.pop, key, None)
        with socket.socket() as old, socket.socket() as new:
            with patch('flowguard.proxy.id', return_value=key, create=True):
                _set_socket_meta(old, '192.0.2.1', 0.02)
                self.assertEqual(_get_socket_meta(old)['target_ip'], '192.0.2.1')
                self.assertEqual(_get_socket_meta(new), {})
                _set_socket_meta(new, '192.0.2.2', 0.04)
                self.assertEqual(_get_socket_meta(new)['target_ip'], '192.0.2.2')
