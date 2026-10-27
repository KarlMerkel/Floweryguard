"""Наблюдения о передаче данных отдельно от успешного TLS-рукопожатия."""

from collections import OrderedDict
import threading
import time


class TransferProgress:
    """Зашифрованный поток: объём доказывает прогресс, но не полноту HTTP-ответа."""

    def __init__(self):
        self.client_bytes = 0
        self.server_bytes = 0
        self.last_received = 0.0
        self.client_closed_at = None
        self.first_sent = None

    def sent(self, count, now=0.0):
        if self.first_sent is None and count:
            self.first_sent = now
        self.client_bytes += count

    def received(self, count, now):
        self.server_bytes += count
        self.last_received = now

    @property
    def proven(self):
        return self.server_bytes >= 65536

    @property
    def stall_window(self):
        """Запрос отправлен, а ответ отсутствует или замер на типичном для обрыва объёме."""
        return (not self.proven and 0 < self.client_bytes < 32768
                and (self.server_bytes == 0 or 6144 <= self.server_bytes < 32768))

    def finish(self, reason, now):
        if self.proven:
            return 'progress'
        if reason == 'client_eof' and self.client_closed_at is not None:
            now = self.client_closed_at
        waiting_since = self.last_received if self.server_bytes else self.first_sent
        # Это повод сменить приоритет следующего соединения, а не доказательство DPI.
        # Короткие ответы и отмены не штрафуют стратегию или IP других доменов.
        if (reason in ('client_eof', 'client_reset', 'idle_timeout') and self.stall_window
                and waiting_since is not None and now - waiting_since >= 3.0):
            return 'suspect'
        return 'unknown'


class RouteHealth:
    """Ограниченный потокобезопасный кэш наблюдений по сети, хосту, порту и IP."""

    def __init__(self, clock=time.monotonic, max_entries=1024):
        self._clock = clock
        self._max_entries = max_entries
        self._entries = OrderedDict()
        self._strategies = OrderedDict()
        self._attempts = OrderedDict()
        self._exploration = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def _key(network, host, port, ip):
        return network, host.lower().rstrip('.'), port, ip

    def record(self, network, host, port, ip, outcome):
        if not ip or outcome not in ('progress', 'suspect'):
            return
        key = self._key(network, host, port, ip)
        expires = self._clock() + (300.0 if outcome == 'progress' else 45.0)
        with self._lock:
            self._entries[key] = (outcome, expires)
            self._entries.move_to_end(key)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)
            scope = key[:3]
            if outcome == 'suspect':
                self._exploration[scope] = self._clock() + 300.0
                self._exploration.move_to_end(scope)
                while len(self._exploration) > self._max_entries:
                    self._exploration.popitem(last=False)
            else:
                self._exploration.pop(scope, None)

    def note_attempt(self, network, host, port, ip):
        """Помнит порядок проб, не объявляя доступный TCP успешной передачей."""
        key = self._key(network, host, port, ip)
        with self._lock:
            self._attempts[key] = self._clock()
            self._attempts.move_to_end(key)
            while len(self._attempts) > self._max_entries:
                self._attempts.popitem(last=False)

    def status(self, network, host, port, ip):
        key = self._key(network, host, port, ip)
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return 'unknown'
            if self._clock() >= entry[1]:
                del self._entries[key]
                return 'unknown'
            return entry[0]

    def proven_ips(self, network, port):
        """Адреса, через которые в этой сети недавно прошёл заметный объём данных; сначала свежие."""
        now = self._clock()
        with self._lock:
            found = [key[3] for key, (outcome, expires) in reversed(self._entries.items())
                     if key[0] == network and key[2] == port and outcome == 'progress' and expires > now]
        return list(dict.fromkeys(found))

    def clear(self):
        with self._lock:
            self._entries.clear()
            self._strategies.clear()
            self._attempts.clear()
            self._exploration.clear()

    def record_strategy(self, network, host, port, ip, strategy, outcome):
        """Короткая подсказка для нового подключения, без штрафа общей статистики."""
        if not host or not ip or not strategy or outcome not in ('progress', 'suspect'):
            return
        key = (network, host.lower().rstrip('.'), port, ip, strategy)
        expires = self._clock() + (300.0 if outcome == 'progress' else 45.0)
        with self._lock:
            self._strategies[key] = (outcome, expires)
            self._strategies.move_to_end(key)
            while len(self._strategies) > self._max_entries:
                self._strategies.popitem(last=False)

    def _strategy_observations(self, network, host, port, ip, outcome):
        scope = (network, host.lower().rstrip('.'), port, ip)
        now = self._clock()
        with self._lock:
            return [key[4] for key, (state, expires) in reversed(self._strategies.items())
                    if key[:4] == scope and state == outcome and expires > now]

    def stalled_strategies(self, network, host, port, ip):
        return set(self._strategy_observations(network, host, port, ip, 'suspect'))

    def progressing_strategies(self, network, host, port, ip):
        return self._strategy_observations(network, host, port, ip, 'progress')

    def rank(self, network, host, port, candidates):
        """После сбоя неизвестные узлы пробуются до повторов уже испробованных."""
        priority = {'progress': 0, 'unknown': 1, 'suspect': 2}
        now = self._clock()
        scope = (network, host.lower().rstrip('.'), port)
        with self._lock:
            exploring = self._exploration.get(scope, 0) > now
            if not exploring:
                self._exploration.pop(scope, None)

            def order(ip):
                key = scope + (ip,)
                state, expires = self._entries.get(key, ('unknown', 0))
                if expires <= now:
                    state = 'unknown'
                attempted = self._attempts.get(key) if exploring else None
                if attempted is not None and now - attempted >= 300.0:
                    attempted = None
                return priority[state], attempted is not None, attempted or 0

            return sorted(candidates, key=order)
