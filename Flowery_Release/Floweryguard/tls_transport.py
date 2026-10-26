"""Передача непрозрачного TLS-потока с наблюдением за прогрессом."""

import select
import socket
import time

from .route_health import TransferProgress


def relay_tls(client, upstream, running, timeout, buffer_size, on_bytes, on_progress,
              long_lived=False, on_suspect=None):
    """Не расшифровывает и не повторяет запросы; возвращает наблюдение и причину остановки."""
    progress = TransferProgress()
    readers = [client, upstream]
    announced = False
    half_closed = False
    reason = 'stopped'
    last_activity = time.monotonic()
    client.settimeout(3600.0 if long_lived else 60.0)
    upstream.settimeout(3600.0 if long_lived else 60.0)
    while running():
        wait = 3600.0 if long_lived else (300.0 if progress.server_bytes else max(15.0, timeout))
        if half_closed:
            wait = max(15.0, timeout)
        remaining = wait - (time.monotonic() - last_activity)
        if remaining <= 0:
            reason = 'client_eof' if half_closed else 'idle_timeout'
            break
        try:
            # Проверять остановку прокси, не сокращая срок жизни WebSocket/RTC.
            readable, _, _ = select.select(readers, [], [], min(1.0, remaining))
        except (OSError, ValueError):
            reason = 'select_error'
            break
        if not readable:
            continue
        for source in readable:
            destination = upstream if source is client else client
            try:
                data = source.recv(buffer_size)
            except OSError:
                reason = 'client_reset' if source is client else 'server_error'
                return progress, reason
            if not data:
                if source is upstream:
                    return progress, 'server_eof'
                half_closed = True
                progress.client_closed_at = time.monotonic()
                last_activity = progress.client_closed_at
                if (not long_lived and on_suspect is not None
                        and progress.finish('client_eof', progress.client_closed_at) == 'suspect'):
                    on_suspect(progress, 'client_eof')
                readers.remove(client)
                try:
                    upstream.shutdown(socket.SHUT_WR)
                except OSError:
                    return progress, 'server_error'
                continue
            try:
                destination.sendall(data)
            except OSError:
                reason = 'client_write_error' if destination is client else 'server_error'
                return progress, reason
            last_activity = time.monotonic()
            if source is client:
                progress.sent(len(data), time.monotonic())
                on_bytes('tx', len(data))
            else:
                progress.received(len(data), time.monotonic())
                on_bytes('rx', len(data))
                if progress.proven and not announced:
                    announced = True
                    on_progress()
    return progress, reason
