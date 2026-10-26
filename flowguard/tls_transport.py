"""Двунаправленная передача TLS с ограниченными буферами и временем простоя."""

import select
import socket
import time

from .route_health import TransferProgress


def relay_tls(client, upstream, running, timeout, buffer_size, on_bytes, on_progress,
              long_lived=False, on_suspect=None):
    """Не расшифровывает и не повторяет запросы; учитывает доставленные байты."""
    progress = TransferProgress()
    sockets = (client, upstream)
    buffers = {client: bytearray(), upstream: bytearray()}
    readers = set(sockets)
    shutdown_pending = set()
    announced = False
    last_activity = time.monotonic()
    short_idle = max(15.0, min(60.0, float(timeout)))
    capacity = max(4096, min(buffer_size, 262144))
    for sock in sockets:
        sock.setblocking(False)
    while running():
        # Зависший ответ закрывается быстро, чтобы клиент повторил запрос по другому адресу;
        # простаивающее keep-alive соединение с завершённым ответом браузер может переиспользовать.
        if client not in readers or (not long_lived and (progress.server_bytes == 0 or progress.stall_window)):
            wait = short_idle
        else:
            wait = 3600.0 if long_lived else 300.0
        remaining = wait - (time.monotonic() - last_activity)
        if remaining <= 0:
            if buffers[client]:
                return progress, 'client_write_error'
            if buffers[upstream]:
                return progress, 'server_error'
            return progress, 'client_eof' if client not in readers else 'idle_timeout'
        readable_sockets = [s for s in sockets if s in readers and
                            len(buffers[upstream if s is client else client]) < capacity]
        writable_sockets = [s for s in sockets if buffers[s]]
        if not readable_sockets and not writable_sockets:
            return progress, 'server_eof'
        try:
            # Ошибки сокета проявляются в recv/send; exceptfds в Windows означает OOB-данные.
            readable, writable, _ = select.select(
                readable_sockets, writable_sockets, [], min(0.25, remaining))
        except (OSError, ValueError):
            return progress, 'select_error'
        for destination in writable:
            try:
                count = destination.send(buffers[destination])
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:
                return progress, 'client_write_error' if destination is client else 'server_error'
            if count <= 0:
                return progress, 'client_write_error' if destination is client else 'server_error'
            del buffers[destination][:count]
            last_activity = time.monotonic()
            if destination is client:
                progress.received(count, last_activity)
                on_bytes('rx', count)
                if progress.proven and not announced:
                    announced = True
                    on_progress()
            else:
                progress.sent(count, last_activity)
                on_bytes('tx', count)
        for source in readable:
            destination = upstream if source is client else client
            try:
                data = source.recv(capacity - len(buffers[destination]))
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:
                return progress, 'client_reset' if source is client else 'server_error'
            if data:
                buffers[destination].extend(data)
                continue
            readers.discard(source)
            shutdown_pending.add(destination)
            if source is client:
                progress.client_closed_at = time.monotonic()
                last_activity = progress.client_closed_at
                if (not long_lived and on_suspect is not None and
                        progress.finish('client_eof', last_activity) == 'suspect'):
                    on_suspect(progress, 'client_eof')
        for destination in list(shutdown_pending):
            if not buffers[destination]:
                try:
                    destination.shutdown(socket.SHUT_WR)
                except OSError:
                    return progress, 'server_error' if destination is upstream else 'client_write_error'
                shutdown_pending.remove(destination)
        if upstream not in readers and not buffers[client]:
            return progress, 'server_eof'
    return progress, 'stopped'
