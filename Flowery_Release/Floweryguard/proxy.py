"""Ядро Flowery (Glue) — Локальный HTTP/HTTPS CONNECT Прокси
с полной поддержкой Discord (включая войсы, WebSockets и CDN)
и техниками обхода DPI (Proxy-Level):
1. TCP Split (фрагментация ClientHello на мелкие TCP-сегменты)
2. TLS Record Layer Fragmentation (сплит одного ClientHello на несколько валидных TLS Record)
3. OOB Data (TCP Urgent Pointer на позиции SNI)
4. HTTP Host Header Obfuscation (модификация регистра Host для обычного HTTP)
"""

import socket
import select
import threading
import time
import sys
import os
import struct
from typing import Optional, Tuple, List, Dict, Any, Set
from Floweryguard.config import Config, load_whitelist_domains, is_host_in_whitelist
from Floweryguard.tls_parser import is_tls_client_hello, parse_sni, create_tls_record_fragments
from Floweryguard.sni_spoofer import SNISpoofer
from Floweryguard.strategy import get_strategy_engine, execute_strategy, StrategyExecutor


def is_discord_ip(ip_str: str) -> bool:
    """Проверяет, входит ли IP в автономную систему Discord или Cloudflare Discord диапазоны."""
    try:
        parts = [int(p) for p in ip_str.split(".")]
        if len(parts) != 4:
            return False
        # 66.22.192.0/18 (Discord Inc ASN)
        if parts[0] == 66 and parts[1] == 22 and 192 <= parts[2] <= 255:
            return True
        # 162.159.128.0/17 (Cloudflare Discord Edge)
        if parts[0] == 162 and parts[1] == 159 and 128 <= parts[2] <= 255:
            return True
    except Exception:
        pass
    return False


def is_discord_host(host: str) -> bool:
    """Проверяет, относится ли хост к инфраструктуре Discord (включая войсы *.discord.media и шлюзы)."""
    h = host.lower()
    return (
        "discord" in h
        or h.endswith(".discord.media")
        or h.endswith(".discord.gg")
        or h.endswith(".discordapp.com")
        or h.endswith(".discordapp.net")
        or h.endswith(".discord.co")
        or h.endswith(".discordcdn.com")
        or h.endswith(".discord.dev")
        or h.endswith(".dis.gd")
        or h == "dis.gd"
        or "discordactivities" in h
        or "discordstatus.com" in h
        or is_discord_ip(h)
    )


def is_google_or_youtube_host(host: str) -> bool:
    """Проверяет, относится ли хост к YouTube/Google Video, обрабатываемым zapret на уровне WinDivert."""
    h = host.lower()
    return any(p in h for p in [
        "youtube.com", "googlevideo.com", "ytimg.com", "youtu.be",
        "ggpht.com", "googleusercontent.com"
    ])



class ThreadSafeBoundedCache:
    """Потокобезопасный кэш с ограничением максимального размера (FIFO вытеснение)."""

    def __init__(self, maxsize: int = 1024):
        self._maxsize = maxsize
        self._lock = threading.Lock()
        self._cache: Dict[str, Any] = {}

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._cache.get(key, default)

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            if len(self._cache) >= self._maxsize and key not in self._cache:
                try:
                    first_key = next(iter(self._cache))
                    del self._cache[first_key]
                except (StopIteration, KeyError):
                    pass
            self._cache[key] = value

    def pop(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._cache.pop(key, default)

    def __contains__(self, key: str) -> bool:
        with self._lock:
            return key in self._cache

    def __getitem__(self, key: str) -> Any:
        with self._lock:
            return self._cache[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.set(key, value)

    def __len__(self) -> int:
        with self._lock:
            return len(self._cache)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


_FALLBACK_DNS_SERVERS = ["77.88.8.8", "77.88.8.1", "1.1.1.1", "8.8.8.8"]
_DNS_CACHE = ThreadSafeBoundedCache(maxsize=1024)
_WORKING_IP_CACHE = ThreadSafeBoundedCache(maxsize=1024)


def resolve_fallback_dns(domain: str) -> Optional[str]:
    """Резервный резолвинг доменов через независимые DNS-серверы, если оператор блокирует DNS."""
    domain_clean = domain.lower().strip(".")
    cached = _DNS_CACHE.get(domain_clean)
    if cached:
        return cached

    # Пробуем разобрать IP, если уже передан IP
    try:
        socket.inet_aton(domain_clean)
        return domain_clean
    except Exception:
        pass

    # Поддержка IDN / национальных доменов (RFC 3490)
    try:
        domain_ascii = domain_clean.encode("idna").decode("ascii")
    except Exception:
        domain_ascii = domain_clean

    tx_id = os.urandom(2)
    flags = b"\x01\x00"
    counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
    qname = b""
    for part in domain_ascii.split("."):
        if not part:
            continue
        qname += bytes([len(part)]) + part.encode("ascii", errors="ignore")
    qname += b"\x00"
    query = tx_id + flags + counts + qname + b"\x00\x01\x00\x01"

    for dns_ip in _FALLBACK_DNS_SERVERS:
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.5)
            s.sendto(query, (dns_ip, 53))
            data, _ = s.recvfrom(1024)

            if len(data) < 12 or data[:2] != tx_id:
                continue
            ancount = (data[6] << 8) | data[7]
            if ancount == 0:
                continue

            idx = 12
            while idx < len(data) and data[idx] != 0:
                if (data[idx] & 0xC0) == 0xC0:
                    idx += 2
                    break
                idx += 1 + data[idx]
            if idx < len(data) and data[idx] == 0:
                idx += 5

            for _ in range(ancount):
                if idx >= len(data):
                    break
                if (data[idx] & 0xC0) == 0xC0:
                    idx += 2
                else:
                    while idx < len(data) and data[idx] != 0:
                        idx += 1 + data[idx]
                    idx += 1
                if idx + 10 > len(data):
                    break
                atype = (data[idx] << 8) | data[idx + 1]
                rdlen = (data[idx + 8] << 8) | data[idx + 9]
                idx += 10
                if atype == 1 and rdlen == 4:
                    ip = socket.inet_ntoa(data[idx:idx + 4])
                    _DNS_CACHE.set(domain_clean, ip)
                    return ip
                idx += rdlen
        except Exception:
            continue
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass
    return None


def _safe_close_socket(sock: Optional[socket.socket]) -> None:
    """Безопасное и корректное закрытие TCP сокета (shutdown -> close)."""
    if sock:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass


class DPIBypassProxy:
    """Локальный прокси сервер с поддержкой техник обхода блокировок."""

    def __init__(self, config: Config):
        self.config = config
        self.host = config.proxy_host
        self.port = config.proxy_port
        self.buffer_size = config.buffer_size
        self.timeout = config.timeout
        self.is_running = False
        self.server_sock: Optional[socket.socket] = None
        self._lock = threading.Lock()
        self._whitelist_lock = threading.Lock()
        self._concurrency_sem = threading.BoundedSemaphore(256)
        self.active_connections = 0
        self.sni_spoofer = SNISpoofer(
            whitelisted_sni=config.whitelist_whitelisted_sni,
            delay=config.fragment_delay
        )
        self.whitelist_domains, self.whitelist_path = load_whitelist_domains(config.whitelist_file)
        self._whitelist_mtime = os.path.getmtime(self.whitelist_path) if (self.whitelist_path and os.path.exists(self.whitelist_path)) else 0
        self._whitelist_last_check = time.time()
        self.strategy_engine = get_strategy_engine()
        self.strategy_engine.enabled = config.auto_strategy
        self._logged_whitelisted: Set[str] = set()
        self._logged_whitelisted_lock = threading.Lock()

    def _check_reload_whitelist(self) -> None:
        """Проверяет изменение whitelist.txt и перезагружает на лету (hot-reload)."""
        now = time.time()
        if now - self._whitelist_last_check < 2.0:
            return
        self._whitelist_last_check = now
        if self.whitelist_path and os.path.exists(self.whitelist_path):
            try:
                mtime = os.path.getmtime(self.whitelist_path)
                if mtime != self._whitelist_mtime:
                    new_domains, _ = load_whitelist_domains(self.whitelist_path)
                    with self._whitelist_lock:
                        self.whitelist_domains = new_domains
                        self._whitelist_mtime = mtime
                    print(f"\033[96m[*] Whitelist обновлён на лету ({len(new_domains)} доменов из {os.path.basename(self.whitelist_path)})\033[0m")
            except Exception:
                pass

    def start(self) -> None:
        """Запускает слушающий сокет прокси сервера."""
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((self.host, self.port))
        self.server_sock.listen(128)
        self.is_running = True

        tcp_split_status = "\033[92mВКЛ\033[0m" if self.config.tcp_split else "\033[90mВЫКЛ\033[0m"
        tls_frag_status = "\033[92mВКЛ\033[0m" if self.config.tls_record_frag else "\033[90mВЫКЛ\033[0m"
        oob_status = "\033[92mВКЛ\033[0m" if self.config.oob_data else "\033[90mВЫКЛ\033[0m"
        host_obf_status = "\033[92mВКЛ\033[0m" if self.config.http_host_obfuscation else "\033[90mВЫКЛ\033[0m"
        whitelist_status = f"\033[92mВКЛ\033[0m ({self.config.whitelist_whitelisted_sni})" if self.config.whitelist_fake_sni_record else "\033[90mВЫКЛ\033[0m"
        wl_mode = "Строго whitelist" if self.config.only_target_domains else "Глобальный + Whitelist"

        auto_strat_status = "\033[92mВКЛ (Thompson Sampling Nova-style)\033[0m" if self.config.auto_strategy else f"\033[90mВЫКЛ ({self.config.default_strategy})\033[0m"
        print(f"\033[92m[*] Прокси-сервер Flowery запущен на {self.host}:{self.port}\033[0m")
        print("\033[94m[*] Активные техники обхода DPI и белых списков:\033[0m")
        print(f"    - Auto-Strategy Engine: {auto_strat_status}")
        print(f"    - TCP Split: {tcp_split_status}")
        print(f"    - TLS Record Fragmentation: {tls_frag_status} (полная поддержка Discord & Voice)")
        print(f"    - OOB Urgent Data: {oob_status}")
        print(f"    - HTTP Host Obfuscation: {host_obf_status}")
        print(f"    - Whitelist Fake SNI Desync: {whitelist_status}")
        with self._whitelist_lock:
            wl_count = len(self.whitelist_domains)
        print(f"    - Whitelist доменов: \033[92m{wl_count}\033[0m хостов ({self.config.whitelist_file}, режим: {wl_mode})")

        threading.Thread(target=self._accept_loop, daemon=True, name="ProxyAcceptLoop").start()

    def _accept_loop(self) -> None:
        """Цикл приёма входящих соединений с троттлингом (ограничение шторма потоков)."""
        while self.is_running and self.server_sock:
            try:
                client_sock, client_addr = self.server_sock.accept()
                if not self._concurrency_sem.acquire(blocking=False):
                    # Защита от перегрузки дескрипторов
                    try:
                        client_sock.sendall(b"HTTP/1.1 503 Service Unavailable\r\n\r\n")
                        client_sock.close()
                    except Exception:
                        pass
                    continue

                with self._lock:
                    self.active_connections += 1

                try:
                    t = threading.Thread(
                        target=self._handle_client,
                        args=(client_sock, client_addr),
                        daemon=True
                    )
                    t.start()
                except Exception:
                    with self._lock:
                        self.active_connections = max(0, self.active_connections - 1)
                    try:
                        self._concurrency_sem.release()
                    except Exception:
                        pass
                    _safe_close_socket(client_sock)
            except (socket.error, OSError):
                break

    def stop(self) -> None:
        """Останавливает сервер и сохраняет обученные веса стратегий."""
        self.is_running = False
        if self.strategy_engine:
            try:
                self.strategy_engine.save_scores(force=True)
            except Exception:
                pass
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
            self.server_sock = None
        print("\033[93m[*] Прокси-сервер остановлен.\033[0m")

    def _handle_client(self, client_sock: socket.socket, client_addr: Tuple[str, int]) -> None:
        """Обрабатывает одно клиентское подключение."""
        target_sock: Optional[socket.socket] = None
        try:
            client_sock.settimeout(self.timeout)
            try:
                client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
                client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
            except Exception:
                pass

            # Читаем HTTP/CONNECT заголовки целиком
            raw_req = b""
            while b"\r\n\r\n" not in raw_req and b"\n\n" not in raw_req and len(raw_req) < 65536:
                chunk = client_sock.recv(4096)
                if not chunk:
                    break
                raw_req += chunk

            if not raw_req:
                return

            req_text = raw_req.decode("latin1", errors="ignore")
            lines = req_text.split("\r\n")
            if not lines or not lines[0]:
                return

            first_line = lines[0]
            parts = first_line.split()
            if len(parts) < 2:
                return

            method, target = parts[0], parts[1]

            if method.upper() == "CONNECT":
                # HTTPS туннелирование
                if ":" in target:
                    target_host, target_port_str = target.rsplit(":", 1)
                    if target_host.startswith("[") and target_host.endswith("]"):
                        target_host = target_host[1:-1]
                    try:
                        target_port = int(target_port_str)
                    except ValueError:
                        target_port = 443
                else:
                    target_host = target
                    target_port = 443

                target_sock = self._connect_target(target_host, target_port)
                if not target_sock:
                    client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    return

                # Сообщаем клиенту об успешном установлении туннеля
                client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

                # Читаем первый пакет рукопожатия от клиента (TLS ClientHello)
                first_packet = client_sock.recv(self.buffer_size)
                if not first_packet:
                    return

                # Гарантируем считывание минимум 9 байт для надежного распознавания TLS ClientHello
                while len(first_packet) < 9:
                    try:
                        more = client_sock.recv(self.buffer_size)
                        if not more:
                            break
                        first_packet += more
                    except Exception:
                        break

                # Если это TLS ClientHello, гарантируем считывание всей записи целиком
                if is_tls_client_hello(first_packet) and len(first_packet) >= 5:
                    record_len = struct.unpack("!H", first_packet[3:5])[0]
                    if 4 <= record_len <= 18432:
                        total_expected = 5 + record_len
                        while len(first_packet) < total_expected:
                            try:
                                more = client_sock.recv(min(self.buffer_size, total_expected - len(first_packet)))
                                if not more:
                                    break
                                first_packet += more
                            except Exception:
                                break

                # Применяем DPI bypass техники к ClientHello
                strat_used, effective_host = self._send_tls_client_hello_with_bypass(target_sock, first_packet, target_host)

            else:
                # Обычный HTTP запрос (не CONNECT)
                strat_used = "http"
                target_host, target_port, path = self._parse_http_target(raw_req, target)
                effective_host = target_host
                target_sock = self._connect_target(target_host, target_port)
                if not target_sock:
                    client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    return

                # Применяем HTTP Host Obfuscation, если включено
                mod_req = self._obfuscate_http_request(raw_req)
                target_sock.sendall(mod_req)

            # Переходим к двунаправленной пересылке трафика
            self._pipe_sockets(client_sock, target_sock, host=effective_host, strategy=strat_used)

        except Exception:
            pass
        finally:
            with self._lock:
                self.active_connections = max(0, self.active_connections - 1)
            try:
                self._concurrency_sem.release()
            except Exception:
                pass
            _safe_close_socket(client_sock)
            if target_sock:
                _safe_close_socket(target_sock)

    def _connect_target(self, host: str, port: int) -> Optional[socket.socket]:
        """Устанавливает соединение с целевым сервером с авто-перебором IP, кэшированием живых IP и fallback DNS."""
        candidate_ips = []

        # 1. Если для хоста уже известен рабочий IP, пробуем его первым
        cached_ip = _WORKING_IP_CACHE.get(host)
        if cached_ip:
            candidate_ips.append(cached_ip)

        # 2. Получаем все IP-адреса хоста через getaddrinfo (защита от заблокированных RKN Cloudflare IP)
        try:
            addr_infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
            for ai in addr_infos:
                ip_addr = ai[4][0]
                if ip_addr not in candidate_ips:
                    candidate_ips.append(ip_addr)
        except Exception:
            pass

        # 3. Резервный DNS, если системный DNS не смог отрезолвить
        if not candidate_ips:
            fallback_ip = resolve_fallback_dns(host)
            if fallback_ip and fallback_ip not in candidate_ips:
                candidate_ips.append(fallback_ip)

        if not candidate_ips:
            candidate_ips.append(host)

        # 4. Если кандидат всего один - прямое подключение
        if len(candidate_ips) == 1:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(min(4.0, float(self.timeout)))
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
                except Exception:
                    pass
                s.connect((candidate_ips[0], port))
                _WORKING_IP_CACHE.set(host, candidate_ips[0])
                return s
            except Exception:
                _WORKING_IP_CACHE.pop(host, None)
                # Резервная попытка через fallback DNS перед отказом
                fallback_ip = resolve_fallback_dns(host)
                if fallback_ip and fallback_ip != candidate_ips[0]:
                    try:
                        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s2.settimeout(min(4.0, float(self.timeout)))
                        s2.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        s2.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                        s2.connect((fallback_ip, port))
                        _WORKING_IP_CACHE.set(host, fallback_ip)
                        return s2
                    except Exception:
                        pass
                return None

        # 5. Happy Eyeballs (RFC 8305): каскадный опрос нескольких IP с задержкой 250 мс
        # Это мгновенно обходит единичные заблокированные RKN IP-адреса Cloudflare (как у Discord)
        connecting = {}
        stagger_delay = 0.25
        end_time = time.time() + self.timeout

        for i, target_ip in enumerate(candidate_ips):
            s = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setblocking(False)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
                except Exception:
                    pass
                err = s.connect_ex((target_ip, port))
                if err == 0:
                    s.setblocking(True)
                    s.settimeout(self.timeout)
                    for other in connecting:
                        try:
                            other.close()
                        except Exception:
                            pass
                    _WORKING_IP_CACHE.set(host, target_ip)
                    return s
                connecting[s] = target_ip
            except Exception:
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass
                continue

            wait_time = stagger_delay if i < len(candidate_ips) - 1 else max(0.1, end_time - time.time())
            try:
                _, writable, _ = select.select([], list(connecting.keys()), [], max(0.01, wait_time))
            except Exception:
                writable = []

            for ws in writable:
                try:
                    sock_err = ws.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                except Exception:
                    sock_err = 1
                if sock_err == 0:
                    ws.setblocking(True)
                    ws.settimeout(self.timeout)
                    try:
                        ws.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        ws.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
                        ws.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
                    except Exception:
                        pass
                    win_ip = connecting.get(ws, target_ip)
                    for other in list(connecting.keys()):
                        if other is not ws:
                            try:
                                other.close()
                            except Exception:
                                pass
                    if win_ip and win_ip != host:
                        _WORKING_IP_CACHE.set(host, win_ip)
                    return ws
                else:
                    failed_ip = connecting.pop(ws, None)
                    if failed_ip and _WORKING_IP_CACHE.get(host) == failed_ip:
                        _WORKING_IP_CACHE.pop(host, None)
                    try:
                        ws.close()
                    except Exception:
                        pass

        # Ожидание оставшихся соединений
        while connecting and time.time() < end_time:
            rem = max(0.01, end_time - time.time())
            try:
                _, writable, _ = select.select([], list(connecting.keys()), [], rem)
            except Exception:
                break
            for ws in writable:
                try:
                    sock_err = ws.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                except Exception:
                    sock_err = 1
                if sock_err == 0:
                    ws.setblocking(True)
                    ws.settimeout(self.timeout)
                    try:
                        ws.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        ws.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
                        ws.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
                    except Exception:
                        pass
                    win_ip = connecting.get(ws, host)
                    for other in list(connecting.keys()):
                        if other is not ws:
                            try:
                                other.close()
                            except Exception:
                                pass
                    if win_ip and win_ip != host:
                        _WORKING_IP_CACHE.set(host, win_ip)
                    return ws
                else:
                    failed_ip = connecting.pop(ws, None)
                    if failed_ip and _WORKING_IP_CACHE.get(host) == failed_ip:
                        _WORKING_IP_CACHE.pop(host, None)
                    try:
                        ws.close()
                    except Exception:
                        pass

        for s in connecting:
            try:
                s.close()
            except Exception:
                pass

        _WORKING_IP_CACHE.pop(host, None)
        return None

    def _send_tls_client_hello_with_bypass(self, target_sock: socket.socket, data: bytes, target_host: str) -> Tuple[str, str]:
        """Отправляет TLS ClientHello с использованием комбинации техник DPI bypass.
        
        Возвращает (использованная_стратегия, эффективный_хост).
        """
        if not is_tls_client_hello(data):
            target_sock.sendall(data)
            return "direct", target_host

        sni_info = parse_sni(data)
        sni_name = sni_info[0] if sni_info else target_host

        lower_host = target_host.lower()
        lower_sni = sni_name.lower()

        self._check_reload_whitelist()
        with self._whitelist_lock:
            wl = self.whitelist_domains
            is_whitelisted = is_host_in_whitelist(sni_name, wl) or is_host_in_whitelist(target_host, wl)

        with self._logged_whitelisted_lock:
            if is_whitelisted and sni_name not in self._logged_whitelisted:
                if len(self._logged_whitelisted) > 256:
                    self._logged_whitelisted.clear()
                self._logged_whitelisted.add(sni_name)
                print(f"\033[92m[+] DPI Bypass активирован: {sni_name} (найден в {self.config.whitelist_file})\033[0m")

        is_discord = is_discord_host(sni_name) or is_discord_host(target_host)
        is_youtube = is_google_or_youtube_host(lower_host) or is_google_or_youtube_host(lower_sni)

        # Если включен режим strictly whitelist, и хост не в вайтлисте, не Discord и не YouTube:
        if self.config.only_target_domains and not (is_whitelisted or is_discord or is_youtube):
            target_sock.sendall(data)
            return "direct", sni_name

        # Тандем с zapret: для Discord при активном winws.exe используем чистый direct
        # во избежание двойной десинхронизации на Cloudflare edge (100-150 мс вместо таймаутов)
        if is_discord:
            try:
                from Floweryguard.voice_helper import is_system_winws_running
                if is_system_winws_running():
                    target_sock.sendall(data)
                    return "direct", sni_name
            except Exception:
                pass

        # Техника 5: Fake Whitelisted SNI Desync (только если явно включено и не для Discord)
        if self.config.whitelist_fake_sni_record and not is_discord:
            self.sni_spoofer.send_with_fake_sni_desync(target_sock, data)
            return "fake_sni_record", sni_name

        # Движок адаптивных стратегий (Thompson Sampling в стиле Nova)
        if self.config.auto_strategy:
            strategy = self.strategy_engine.select_strategy(
                sni_name,
                is_youtube=is_youtube,
                is_discord=is_discord
            )
            execute_strategy(strategy, target_sock, data, delay=self.config.fragment_delay)
            return strategy, sni_name

        # Ручные/статические режимы без автоподбора:
        strategy = self.config.default_strategy
        if is_youtube and strategy == "boringssl_split":
            # Защита от неработающего boringssl_split для YouTube на современных ТСПУ
            strategy = "disoob_sni"

        execute_strategy(strategy, target_sock, data, delay=self.config.fragment_delay)
        return strategy, sni_name

    def _send_fragmented_stream(self, target_sock: socket.socket, data: bytes,
                                sni_info: Optional[Tuple[str, int, int]] = None) -> None:
        """Реализация техники TCP Split (разбиение пакета на фрагменты с задержкой)."""
        if not self.config.tcp_split or len(data) <= self.config.fragment_size:
            target_sock.sendall(data)
            return

        frag_size = max(1, self.config.fragment_size)
        delay = self.config.fragment_delay

        if sni_info and self.config.oob_data:
            sni_start = sni_info[1]
            if sni_start > 0:
                target_sock.sendall(data[:sni_start])
                time.sleep(delay)
            try:
                target_sock.send(b"a", socket.MSG_OOB)
            except Exception:
                pass
            target_sock.sendall(data[sni_start:])
            return

        target_sock.sendall(data[:frag_size])
        if delay > 0:
            time.sleep(delay)
        target_sock.sendall(data[frag_size:])

    def _obfuscate_http_request(self, raw_req: bytes) -> bytes:
        """Техника 4: HTTP Host Obfuscation & Whitelist Spoofing."""
        if self.config.whitelist_spoof_sni:
            return self.sni_spoofer.obfuscate_http_request(raw_req)

        if not self.config.http_host_obfuscation:
            return raw_req

        try:
            if b"\r\nHost: " in raw_req:
                return raw_req.replace(b"\r\nHost: ", b"\r\nhoSt: ")
            elif b"\nHost: " in raw_req:
                return raw_req.replace(b"\nHost: ", b"\nhoSt: ")
        except Exception:
            pass
        return raw_req

    def _parse_http_target(self, raw_req: bytes, target_url: str) -> Tuple[str, int, str]:
        """Извлекает хост, порт и путь из HTTP-запроса."""
        port = 80
        host = ""
        path = "/"

        if target_url.startswith("http://"):
            url_no_scheme = target_url[7:]
            slash_idx = url_no_scheme.find("/")
            if slash_idx != -1:
                host_port = url_no_scheme[:slash_idx]
                path = url_no_scheme[slash_idx:]
            else:
                host_port = url_no_scheme
                path = "/"
            if ":" in host_port:
                h, p = host_port.rsplit(":", 1)
                if h.startswith("[") and h.endswith("]"):
                    h = h[1:-1]
                host = h
                try:
                    port = int(p)
                except ValueError:
                    port = 80
            else:
                host = host_port
        else:
            for line in raw_req.split(b"\r\n"):
                if line.lower().startswith(b"host:"):
                    h_val = line[5:].strip().decode("latin1", errors="ignore")
                    if ":" in h_val:
                        h, p = h_val.rsplit(":", 1)
                        if h.startswith("[") and h.endswith("]"):
                            h = h[1:-1]
                        host = h
                        try:
                            port = int(p)
                        except ValueError:
                            port = 80
                    else:
                        host = h_val
                    break

        return host, port, path

    def _pipe_sockets(
        self,
        client_sock: socket.socket,
        target_sock: socket.socket,
        host: str = "",
        strategy: str = ""
    ) -> None:
        """Двунаправленная надёжная пересылка трафика между клиентом и целевым сервером."""
        try:
            # Снимаем искусственные таймауты: готовность сокетов полностью контролируется select.select
            client_sock.settimeout(None)
            target_sock.settimeout(None)
        except Exception:
            pass

        sockets = [client_sock, target_sock]
        got_response = False

        try:
            while self.is_running:
                # До получения первого ответа сервера используем таймаут рукопожатия,
                # чтобы упавшие соединения не копились в пуле дескрипторов и не вызывали 503
                select_timeout = min(6.0, float(self.timeout)) if not got_response else 30.0
                try:
                    readable, _, _ = select.select(sockets, [], [], select_timeout)
                except (socket.error, ValueError):
                    break

                if not readable:
                    if not got_response:
                        break
                    continue

                for s in readable:
                    other = target_sock if s is client_sock else client_sock
                    try:
                        data = s.recv(self.buffer_size)
                        if not data:
                            try:
                                other.shutdown(socket.SHUT_WR)
                            except Exception:
                                pass
                            return
                        if s is target_sock and not got_response:
                            got_response = True
                            if host and strategy and strategy not in ("direct", "http"):
                                self.strategy_engine.record_success(host, strategy)
                        other.sendall(data)
                    except (socket.error, OSError, TimeoutError):
                        return
        finally:
            if not got_response and host and strategy and strategy not in ("direct", "http"):
                self.strategy_engine.record_failure(host, strategy)

