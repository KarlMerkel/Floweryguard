"""Выбор маршрута Discord CDN с сохранением резервных адресов."""

import socket
import time
import unittest
from unittest.mock import MagicMock, patch

from flowguard.config import Config
from flowguard.proxy import (
    DPIBypassProxy, DISCORD_CDN_ANYCAST_IPS, DISCORD_MEDIA_ANYCAST_IPS,
    _WORKING_IP_CACHE, _RESOLVED_IPS_CACHE, _DEAD_IP_CACHE, _RECENT_DISCORD_IPS,
    mark_ip_dead,
)


class TestDiscordMediaPrimary(unittest.TestCase):
    PRIMARY = '162.159.136.232'
    HOSTS = ('cdn.discordapp.com', 'media.discordapp.net', 'images-ext-1.discordapp.net')

    def setUp(self):
        self.clear_caches()
        self.addCleanup(self.clear_caches)
        self.proxy = DPIBypassProxy(Config('_test_defaults_missing.ini'))
        self.proxy.doh_harvester = None
        self.proxy.dns_failover = MagicMock()
        self.proxy.dns_failover.resolve.return_value = []

    @staticmethod
    def clear_caches():
        for cache in (_WORKING_IP_CACHE, _RESOLVED_IPS_CACHE, _DEAD_IP_CACHE, _RECENT_DISCORD_IPS):
            cache.clear()

    def connect(self, host, excluded=None):
        fake_socket = MagicMock(spec=socket.socket)
        fake_socket.connect_ex.return_value = 0
        fake_socket.getsockopt.return_value = 0
        with patch('flowguard.proxy.socket.getaddrinfo', return_value=[]), \
             patch('flowguard.proxy.resolve_fallback_dns', return_value=None), \
             patch('flowguard.proxy.socket.socket', return_value=fake_socket):
            connected = self.proxy._connect_target(host, 443, exclude_ip=excluded)
        self.assertIsNotNone(connected)
        call = fake_socket.connect.call_args or fake_socket.connect_ex.call_args
        return call.args[0][0]

    def test_media_uses_primary_even_when_recently_used(self):
        """Параллельные картинки не должны уходить на зависающие узлы ради ротации."""
        for host in self.HOSTS:
            with self.subTest(host=host):
                self.clear_caches()
                _RECENT_DISCORD_IPS.set(self.PRIMARY, time.time())
                self.assertEqual(self.connect(host), self.PRIMARY)

    def test_dead_primary_uses_alternative(self):
        for host in self.HOSTS:
            with self.subTest(host=host):
                self.clear_caches()
                mark_ip_dead(self.PRIMARY, duration=45)
                selected = self.connect(host)
                self.assertNotEqual(selected, self.PRIMARY)
                self.assertIn(selected, DISCORD_CDN_ANYCAST_IPS + DISCORD_MEDIA_ANYCAST_IPS)

    def test_excluded_primary_uses_alternative(self):
        for host in self.HOSTS:
            with self.subTest(host=host):
                self.clear_caches()
                selected = self.connect(host, excluded={self.PRIMARY})
                self.assertNotEqual(selected, self.PRIMARY)
                self.assertIn(selected, DISCORD_CDN_ANYCAST_IPS + DISCORD_MEDIA_ANYCAST_IPS)

    def test_cached_working_alternative_keeps_priority(self):
        """Рабочий адрес конкретной сети важнее начального предпочтения."""
        for host in self.HOSTS:
            with self.subTest(host=host):
                self.clear_caches()
                alternative = '162.159.130.233'
                _WORKING_IP_CACHE.set(host, alternative)
                self.assertEqual(self.connect(host), alternative)
