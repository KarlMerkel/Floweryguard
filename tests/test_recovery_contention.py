"""Занятые пробы не должны лишать соседние подключения резерва."""
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from flowguard.route_recovery import RecoveryRoutes


class TestRecoveryContention(unittest.TestCase):
    def test_other_host_waits_for_inflight_probe_and_gets_own_result(self):
        entered, release = threading.Event(), threading.Event()
        calls = []

        def probe(host, port, ip, strategy, timeout):
            calls.append(host)
            if host == 'updates.discord.com':
                entered.set()
                release.wait(1)
            return True

        manager = RecoveryRoutes(probe=probe)
        self.addCleanup(manager.close)
        pairs = [('1.1.1.1', 'direct')]
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(manager.find, 'wifi', 'updates.discord.com', 443, pairs, 1)
            self.assertTrue(entered.wait(1))
            second = pool.submit(manager.find, 'wifi', 'cdn.discordapp.com', 443, pairs, 1)
            try:
                time.sleep(.08)
                self.assertFalse(second.done(), 'Занятость ошибочно возвращена как отсутствие маршрута')
            finally:
                release.set()
            self.assertEqual(first.result(1), pairs[0])
            self.assertEqual(second.result(1), pairs[0])
        self.assertEqual(calls, ['updates.discord.com', 'cdn.discordapp.com'])

    def test_waiting_for_slot_respects_deadline(self):
        manager = RecoveryRoutes(probe=lambda *args: True)
        self.addCleanup(manager.close)
        manager._gate.acquire()
        try:
            started = time.monotonic()
            self.assertIsNone(manager.find('wifi', 'discord.com', 443, [('1.1.1.1', 'direct')], .1))
            elapsed = time.monotonic() - started
            self.assertGreaterEqual(elapsed, .08)
            self.assertLess(elapsed, .5)
        finally:
            manager._gate.release()

    def test_cancelled_wait_does_not_probe(self):
        manager = RecoveryRoutes(probe=lambda *args: self.fail('Проба после отмены'))
        self.addCleanup(manager.close)
        self.assertIsNone(manager.find('wifi', 'discord.com', 443,
                                       [('1.1.1.1', 'direct')], 1, cancelled=lambda: True))

    def test_same_host_reuses_result_while_second_probe_is_still_running(self):
        slow_started, release = threading.Event(), threading.Event()

        def probe(host, port, ip, strategy, timeout):
            if ip == '1.0.0.1':
                slow_started.set()
                release.wait(1)
                return False
            slow_started.wait(1)
            return True

        manager = RecoveryRoutes(probe=probe)
        self.addCleanup(manager.close)
        pairs = [('1.1.1.1', 'direct'), ('1.0.0.1', 'direct')]
        try:
            self.assertEqual(manager.find('wifi', 'discord.com', 443, pairs, 1), pairs[0])
            started = time.monotonic()
            self.assertEqual(manager.find('wifi', 'discord.com', 443, pairs, 1), pairs[0])
            self.assertLess(time.monotonic() - started, .2)
        finally:
            release.set()

    def test_stop_interrupts_wait_for_slot(self):
        manager = RecoveryRoutes(probe=lambda *args: self.fail('Проба после остановки'))
        self.addCleanup(manager.close)
        manager._gate.acquire()
        timer = threading.Timer(.08, manager.close)
        timer.start()
        try:
            started = time.monotonic()
            self.assertIsNone(manager.find('wifi', 'discord.com', 443, [('1.1.1.1', 'direct')], 2))
            self.assertLess(time.monotonic() - started, .5)
        finally:
            manager._gate.release()
            timer.join()
