"""Ограниченные TLS-пробы резервных маршрутов без повторения запросов клиента."""
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
import ipaddress
import socket
import ssl
import threading
import time

from .strategy import StrategyExecutor


# Резервные кандидаты CDN, не принудительные маршруты. Каждый требует проверки
# сертификата целевого имени; пользовательский трафик остаётся сквозным TLS.
CDN_RECOVERY_CANDIDATES = ('8.6.112.0', '8.47.69.0')


def verify_tls_route(host, port, ip, strategy, timeout):
    """Проверяет доверенную цепочку и имя. Не делает HTTP-запросов и не обучает селектор."""
    try:
        address = ipaddress.ip_address(ip)
        if not address.is_global or port != 443 or timeout <= 0:
            return False
        execute = getattr(StrategyExecutor, strategy, None)
        if execute is None:
            return False
        deadline = time.monotonic() + timeout
        context = ssl.create_default_context()
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        tls = context.wrap_bio(incoming, outgoing, server_hostname=host)
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            first = True
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                sock.settimeout(remaining)
                complete = False
                try:
                    tls.do_handshake()
                    complete = True
                except ssl.SSLWantReadError:
                    pass
                data = outgoing.read()
                if data:
                    if first:
                        execute(sock, data, delay=0.001)
                        first = False
                    else:
                        sock.sendall(data)
                if complete:
                    return True
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                sock.settimeout(remaining)
                data = sock.recv(65536)
                if not data:
                    return False
                incoming.write(data)
    except (OSError, ValueError):
        return False


class RecoveryRoutes:
    """Не более двух проб одновременно, без очереди сетевых задач и бессрочных результатов."""

    def __init__(self, probe=verify_tls_route, clock=time.monotonic):
        self._probe = probe
        self._clock = clock
        self._lock = threading.Lock()
        self._gate = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix='RouteRecovery')
        self._active = []
        self._states = OrderedDict()
        self._closed = False

    @staticmethod
    def _key(network, host, port):
        return network, host.lower().rstrip('.'), port

    def get(self, network, host, port):
        with self._lock:
            state = self._states.get(self._key(network, host, port))
            if not self._closed and state and state['expires'] > self._clock():
                return state['route']
        return None

    def reject(self, network, host, port, ip):
        with self._lock:
            state = self._states.get(self._key(network, host, port))
            if state and state['route'] and state['route'][0] == ip:
                state['route'] = None
                state['expires'] = 0

    def find(self, network, host, port, pairs, timeout):
        cached = self.get(network, host, port)
        if cached:
            return cached if cached in pairs else None
        if timeout <= 0 or not pairs or not self._gate.acquire(False):
            return None
        try:
            key = self._key(network, host, port)
            with self._lock:
                if self._closed or any(not future.done() for future in self._active):
                    return None
                now = self._clock()
                state = self._states.setdefault(key, dict(route=None, expires=0, retry=0, cursor=0))
                self._states.move_to_end(key)
                while len(self._states) > 128:
                    self._states.popitem(last=False)
                if now < state['retry']:
                    return None
                state['retry'] = now + 5
                pairs = list(dict.fromkeys(pairs))
                chosen = [pairs[(state['cursor'] + i) % len(pairs)] for i in range(min(2, len(pairs)))]
                state['cursor'] += len(chosen)
                jobs = {self._pool.submit(self._probe, host, port, ip, strategy, timeout): (ip, strategy)
                        for ip, strategy in chosen}
                self._active = list(jobs)
            try:
                for future in as_completed(jobs, timeout=timeout):
                    try:
                        valid = future.result()
                    except Exception:
                        valid = False
                    if valid:
                        with self._lock:
                            if self._closed:
                                return None
                            state['route'] = jobs[future]
                            state['expires'] = self._clock() + 60
                        return jobs[future]
            except TimeoutError:
                return None
            return None
        finally:
            self._gate.release()

    def close(self):
        with self._lock:
            self._closed = True
            self._states.clear()
            for future in self._active:
                future.cancel()
        # Уже начатые пробы имеют общий короткий deadline; новых задач не будет.
        self._pool.shutdown(wait=False)
