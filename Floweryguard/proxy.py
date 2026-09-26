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
import queue
from typing import Optional, Tuple, List, Dict, Any, Set
from Floweryguard.config import Config, load_whitelist_domains, is_host_in_whitelist
from Floweryguard.tls_parser import is_tls_client_hello, parse_sni, create_tls_record_fragments
from Floweryguard.sni_spoofer import SNISpoofer
from Floweryguard.strategy import get_strategy_engine, execute_strategy, StrategyExecutor
from Floweryguard.logger import get_logger

logger = get_logger("Proxy")


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


_FALLBACK_DNS_SERVERS = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "9.9.9.9", "77.88.8.8"]
_DNS_CACHE = ThreadSafeBoundedCache(maxsize=1024)
_WORKING_IP_CACHE = ThreadSafeBoundedCache(maxsize=1024)
_DEAD_IP_CACHE = ThreadSafeBoundedCache(maxsize=2048)
# Предустановленные blackhole IP (Cymru/Tor blackholes, блокирующие TLS в РФ)
for _dead_ip in ("204.8.99.144", "204.8.99.146"):
    _DEAD_IP_CACHE.set(_dead_ip, time.time() + 86400.0)


def is_ip_dead(ip: str) -> bool:
    """Проверяет, помечен ли IP как нерабочий / сбрасывающий соединения (с TTL 10 минут)."""
    dead_until = _DEAD_IP_CACHE.get(ip)
    if dead_until is not None:
        if time.time() < dead_until:
            return True
        else:
            _DEAD_IP_CACHE.pop(ip, None)
    return False


def mark_ip_dead(ip: Optional[str], duration: float = 600.0) -> None:
    """Помечает IP как нерабочий на заданное время (по умолчанию 10 минут)."""
    if ip:
        _DEAD_IP_CACHE.set(ip, time.time() + duration)


def mark_ip_working(ip: Optional[str], host: Optional[str] = None) -> None:
    """Помечает IP как проверенный и рабочий, снимая флаг нерабочего."""
    if ip:
        _DEAD_IP_CACHE.pop(ip, None)
        if host:
            _WORKING_IP_CACHE.set(host, ip)


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
            s.settimeout(0.8)
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


_SOCKET_META = ThreadSafeBoundedCache(maxsize=2048)

def _set_socket_meta(sock: socket.socket, target_ip: str, connect_rtt: float) -> None:
    """Сохраняет метаданные подключения (IP, RTT) для сокета в потокобезопасный ограниченный кэш."""
    try:
        _SOCKET_META.set(id(sock), {"target_ip": target_ip, "connect_rtt": connect_rtt})
    except Exception:
        pass

def _get_socket_meta(sock: Optional[socket.socket]) -> Dict[str, Any]:
    """Возвращает метаданные подключения для сокета."""
    if not sock:
        return {}
    return _SOCKET_META.get(id(sock), {})

def _clean_socket_meta(sock: Optional[socket.socket]) -> None:
    """Удаляет метаданные закрытого сокета."""
    if sock:
        _SOCKET_META.pop(id(sock), None)

def _safe_close_socket(sock: Optional[socket.socket]) -> None:
    """Безопасное и корректное закрытие TCP сокета (shutdown -> close)."""
    if sock:
        _clean_socket_meta(sock)
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass


class ShadowProber:
    """Бесшумный фоновый зонд (Shadow Prober) с жестким rate limit и защитой от шторма сокетов.
    
    - Строго 1 фоновый демон-поток.
    - Очередь maxsize=16 (при переполнении новые задачи отбрасываются).
    - Rate limit: не более 1 зонда в 1.5 секунды.
    - Cooldown: не чаще 1 раза в 15 минут на домен.
    - Игнорирует хосты, у которых уже накоплена стабильная статистика (alpha >= 3).
    """

    def __init__(self, strategy_engine):
        self.strategy_engine = strategy_engine
        self.task_queue: queue.Queue = queue.Queue(maxsize=16)
        self._recently_probed: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._worker_loop, daemon=True, name="ShadowProber")
        self._thread.start()

    def maybe_enqueue(self, host: str, ip: Optional[str] = None) -> None:
        """Попытка поставить домен в очередь фонового зондирования с отсевом лишней нагрузки."""
        if not host:
            return
        
        # Не зондируем чистые IP или локальные адреса
        clean_h = host.strip("[]")
        if clean_h.replace(".", "").isdigit() or "localhost" in clean_h or ":" in clean_h:
            return

        # Игнорируем фоновые метрики и статику
        h_lower = host.lower()
        if any(bad in h_lower for bad in ("analytics", "telemetry", "metric", "stat", "tracker", "beacon")):
            return

        now = time.time()
        with self._lock:
            last = self._recently_probed.get(host, 0.0)
            if now - last < 900.0:  # 15 минут кулдаун
                return

            # Проверяем, есть ли уже стабильная статистика
            composite_key = self.strategy_engine._get_composite_key(host, ip)
            scores = self.strategy_engine._scores.get(composite_key)
            if scores:
                # Если уже есть стратегия с alpha >= 3, зонд не нужен
                if any(ab[0] >= 3.0 for ab in scores.values()):
                    return

            self._recently_probed[host] = now

        try:
            self.task_queue.put_nowait((host, ip))
        except queue.Full:
            pass  # Очередь полна — отбрасываем без блокировки

    def _worker_loop(self) -> None:
        while True:
            try:
                host, ip = self.task_queue.get()
                time.sleep(1.5)  # Rate limit: 1.5 секунды между зондами
                self._probe_host(host, ip)
                self.task_queue.task_done()
            except Exception:
                pass

    def _probe_host(self, host: str, ip: Optional[str]) -> None:
        """Тихо проверяет альтернативные стратегии на отдельном сокете."""
        is_yt = is_google_or_youtube_host(host.lower())
        is_dc = is_discord_host(host)

        # Выбираем альтернативную стратегию для проверки
        test_strat = "disoob_sni" if is_yt else ("combo_tlsrec_tcpsplit" if not is_dc else "direct")
        target_ip = ip or host
        s = None
        try:
            family = socket.AF_INET6 if ":" in str(target_ip) else socket.AF_INET
            s = socket.socket(family, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((target_ip, 443))
            
            # Минимальный ClientHello с SNI для тестового рукопожатия
            test_hello = self._build_dummy_client_hello(host)
            execute_strategy(test_strat, s, test_hello, delay=0.003)
            
            # Ждем первый байт ответа
            s.settimeout(1.0)
            resp = s.recv(16)
            if resp and resp[0] == 0x16:  # TLS Record (ServerHello / Handshake)
                self.strategy_engine.record_success(host, test_strat, ip=target_ip)
            # При отсутствии ответа на синтетический ClientHello НЕ налагаем штраф,
            # так как современные CDN могут отсекать тестовые запросы без полных расширений TLS 1.3
        except Exception:
            pass
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass

    @staticmethod
    def _build_dummy_client_hello(hostname: str) -> bytes:
        """Генерирует минимальный валидный TLS 1.2 ClientHello с расширением SNI."""
        host_bytes = hostname.encode("utf-8")
        sni_ext = (
            b"\x00\x00"  # Extension: server_name
            + struct.pack("!H", len(host_bytes) + 5)
            + struct.pack("!H", len(host_bytes) + 3)
            + b"\x00"  # HostName type: 0
            + struct.pack("!H", len(host_bytes))
            + host_bytes
        )
        extensions = sni_ext
        extensions_len = len(extensions)

        cipher_suites = (
            b"\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x0a\xc0\x09\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35"
        )
        ch_body = (
            b"\x03\x03"  # Client version: TLS 1.2
            + os.urandom(32)  # Random
            + b"\x00"  # Session ID length: 0
            + struct.pack("!H", len(cipher_suites))
            + cipher_suites
            + b"\x01\x00"  # Compression: null
            + struct.pack("!H", extensions_len)
            + extensions
        )
        handshake = b"\x01" + struct.pack("!I", len(ch_body))[1:] + ch_body
        record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
        return record


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
        self.strategy_engine.configure_allowed(
            tcp_split=config.tcp_split,
            tls_record_frag=config.tls_record_frag,
            oob_data=config.oob_data
        )
        self.shadow_prober = ShadowProber(self.strategy_engine) if config.auto_strategy else None
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

    def _reclaim_port(self) -> bool:
        """Освобождает порт прокси (WinError 10048), если он занят зависшим процессом."""
        try:
            import subprocess
            res = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True,
                text=True,
                timeout=3
            )
            target = f":{self.port} "
            pids = set()
            for line in res.stdout.splitlines():
                if target in line and "LISTENING" in line:
                    parts = line.strip().split()
                    if parts:
                        pids.add(parts[-1])
            curr_pid = str(os.getpid())
            reclaimed = False
            for pid in pids:
                if pid != curr_pid and pid != "0":
                    print(f"\033[93m[!] Порт {self.port} занят процессом PID {pid}. Принудительное освобождение...\033[0m")
                    subprocess.run(["taskkill", "/F", "/PID", pid], capture_output=True, timeout=3)
                    reclaimed = True
            time.sleep(0.3)
            return reclaimed
        except Exception:
            return False

    def start(self) -> None:
        """Запускает слушающий сокет прокси сервера."""
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_sock.bind((self.host, self.port))
        except OSError as e:
            if getattr(e, "winerror", None) == 10048 or getattr(e, "errno", None) == 98:
                self._reclaim_port()
                time.sleep(0.3)
                self.server_sock.bind((self.host, self.port))
            else:
                raise
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
                client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
                client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
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

                # Выполняем отправку ClientHello с защитой от ТСПУ и бесшовным ретраем
                target_sock, strat_used, effective_host, init_resp = self._handshake_with_fast_fallback(
                    client_sock, target_sock, target_host, target_port, first_packet
                )
                if not target_sock:
                    return

                if init_resp:
                    client_sock.sendall(init_resp)

            else:
                # Обычный HTTP запрос (не CONNECT)
                strat_used = "http"
                target_host, target_port, path = self._parse_http_target(raw_req, target)
                effective_host = target_host
                target_sock = self._connect_target(target_host, target_port)
                if not target_sock:
                    client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    return

                # Преобразуем absolute-form URI в relative path согласно RFC 7230 раздел 5.3.1
                clean_req = raw_req
                if target.startswith("http://"):
                    first_crlf = raw_req.find(b"\r\n")
                    if first_crlf != -1:
                        first_line_b = raw_req[:first_crlf]
                        rest_b = raw_req[first_crlf:]
                        fl_parts = first_line_b.split(b" ", 2)
                        if len(fl_parts) >= 3:
                            new_fl = fl_parts[0] + b" " + path.encode("latin1", errors="ignore") + b" " + fl_parts[2]
                            clean_req = new_fl + rest_b

                # Применяем HTTP Host Obfuscation, если включено
                mod_req = self._obfuscate_http_request(clean_req)
                target_sock.sendall(mod_req)
                init_resp = None

            # Переходим к двунаправленной пересылке трафика
            self._pipe_sockets(
                client_sock,
                target_sock,
                host=effective_host,
                strategy=strat_used,
                got_initial_response=bool(init_resp)
            )

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

    def _connect_target(self, host: str, port: int, exclude_ip: Optional[Any] = None) -> Optional[socket.socket]:
        """Устанавливает соединение с целевым сервером с авто-перебором IP, фильтрацией мертвых IP и Happy Eyeballs.
        
        Параметр exclude_ip позволяет ротировать IP при блокировках со стороны ТСПУ.
        """
        t_connect_start = time.time()
        candidate_ips = []
        excluded_set = set()
        if exclude_ip:
            if isinstance(exclude_ip, (set, list, tuple)):
                excluded_set.update(str(x) for x in exclude_ip)
            else:
                excluded_set.add(str(exclude_ip))

        # 1. Если для хоста уже известен рабочий проверенный IP и он жив
        cached_ip = _WORKING_IP_CACHE.get(host)
        if cached_ip and cached_ip not in excluded_set and not is_ip_dead(cached_ip):
            candidate_ips.append(cached_ip)

        # 2. Получаем все IP-адреса хоста через getaddrinfo (Dual-Stack IPv4 + IPv6)
        try:
            addr_infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            v4_ips = []
            v6_ips = []
            for ai in addr_infos:
                ip_addr = ai[4][0]
                if ip_addr not in candidate_ips and ip_addr not in excluded_set:
                    if ai[0] == socket.AF_INET:
                        if ip_addr not in v4_ips:
                            v4_ips.append(ip_addr)
                    elif ai[0] == socket.AF_INET6:
                        if ip_addr not in v6_ips:
                            v6_ips.append(ip_addr)
            # В РФ на мобильном интернете IPv4 основной, IPv6 дополнительный
            for ip in v4_ips:
                if ip not in candidate_ips:
                    candidate_ips.append(ip)
            for ip in v6_ips:
                if ip not in candidate_ips:
                    candidate_ips.append(ip)
        except Exception:
            pass

        # 3. Резервный независимый DNS (активируется, если системный DNS заблокирован или включен кастомный DNS)
        if not candidate_ips or self.config.enable_custom_dns or host in _DNS_CACHE:
            fallback_ip = resolve_fallback_dns(host)
            if fallback_ip and fallback_ip not in candidate_ips and fallback_ip not in excluded_set:
                candidate_ips.append(fallback_ip)

        # 4. Фильтруем заведомо мёртвые / сбрасывающие IP (черный список мертвых IP с TTL 10 мин)
        alive_candidates = [ip for ip in candidate_ips if not is_ip_dead(ip) and ip not in excluded_set]
        if alive_candidates:
            candidate_ips = alive_candidates

        if not candidate_ips:
            if host not in excluded_set and not is_ip_dead(host):
                candidate_ips.append(host)
            else:
                return None

        # 5. Если кандидат всего один - прямое подключение
        if len(candidate_ips) == 1:
            s = None
            try:
                family = socket.AF_INET6 if ":" in candidate_ips[0] else socket.AF_INET
                s = socket.socket(family, socket.SOCK_STREAM)
                s.settimeout(min(4.0, float(self.timeout)))
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
                t_conn = time.time()
                s.connect((candidate_ips[0], port))
                _set_socket_meta(s, candidate_ips[0], max(0.001, time.time() - t_conn))
                return s
            except Exception:
                if s:
                    _safe_close_socket(s)
                mark_ip_dead(candidate_ips[0], duration=300.0)
                _WORKING_IP_CACHE.pop(host, None)
                # Резервная попытка через fallback DNS перед отказом
                fallback_ip = resolve_fallback_dns(host)
                if fallback_ip and fallback_ip != candidate_ips[0] and fallback_ip not in excluded_set and not is_ip_dead(fallback_ip):
                    s2 = None
                    try:
                        family2 = socket.AF_INET6 if ":" in fallback_ip else socket.AF_INET
                        s2 = socket.socket(family2, socket.SOCK_STREAM)
                        s2.settimeout(min(4.0, float(self.timeout)))
                        s2.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        s2.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                        s2.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
                        s2.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
                        t_conn = time.time()
                        s2.connect((fallback_ip, port))
                        _set_socket_meta(s2, fallback_ip, max(0.001, time.time() - t_conn))
                        return s2
                    except Exception:
                        if s2:
                            _safe_close_socket(s2)
                        mark_ip_dead(fallback_ip, duration=300.0)
                return None

        # 6. Happy Eyeballs (RFC 8305): каскадный опрос нескольких IP с задержкой 250 мс
        connecting = {}
        stagger_delay = 0.25
        end_time = time.time() + self.timeout

        for i, target_ip in enumerate(candidate_ips):
            s = None
            try:
                family = socket.AF_INET6 if ":" in target_ip else socket.AF_INET
                s = socket.socket(family, socket.SOCK_STREAM)
                s.setblocking(False)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                t_conn = time.time()
                err = s.connect_ex((target_ip, port))
                if err == 0:
                    s.setblocking(True)
                    s.settimeout(self.timeout)
                    try:
                        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
                        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
                    except Exception:
                        pass
                    _set_socket_meta(s, target_ip, max(0.001, time.time() - t_conn))
                    for other in connecting:
                        try:
                            other.close()
                        except Exception:
                            pass
                    return s
                connecting[s] = (target_ip, t_conn)
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
                        ws.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
                        ws.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
                    except Exception:
                        pass
                    info = connecting.get(ws)
                    if info and isinstance(info, tuple):
                        win_ip = info[0]
                        t_c = info[1]
                    else:
                        try:
                            win_ip = ws.getpeername()[0]
                        except Exception:
                            win_ip = target_ip
                        t_c = t_connect_start
                    _set_socket_meta(ws, win_ip, max(0.001, time.time() - t_c))
                    for other in list(connecting.keys()):
                        if other is not ws:
                            try:
                                other.close()
                            except Exception:
                                pass
                    return ws
                else:
                    failed_info = connecting.pop(ws, None)
                    failed_ip = failed_info[0] if isinstance(failed_info, tuple) else failed_info
                    if failed_ip:
                        mark_ip_dead(failed_ip, duration=300.0)
                        if _WORKING_IP_CACHE.get(host) == failed_ip:
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
                        ws.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
                        ws.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
                    except Exception:
                        pass
                    info = connecting.get(ws)
                    if info and isinstance(info, tuple):
                        win_ip = info[0]
                        t_c = info[1]
                    else:
                        try:
                            win_ip = ws.getpeername()[0]
                        except Exception:
                            win_ip = host
                        t_c = t_connect_start
                    _set_socket_meta(ws, win_ip, max(0.001, time.time() - t_c))
                    for other in list(connecting.keys()):
                        if other is not ws:
                            try:
                                other.close()
                            except Exception:
                                pass
                    return ws
                else:
                    failed_info = connecting.pop(ws, None)
                    failed_ip = failed_info[0] if isinstance(failed_info, tuple) else failed_info
                    if failed_ip:
                        mark_ip_dead(failed_ip, duration=300.0)
                        if _WORKING_IP_CACHE.get(host) == failed_ip:
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

        return None

    def _send_tls_client_hello_with_bypass(
        self,
        target_sock: socket.socket,
        data: bytes,
        target_host: str,
        ip: Optional[str] = None
    ) -> Tuple[str, str]:
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
                logger.info(f"[+] DPI Bypass активирован: {sni_name} (найден в {self.config.whitelist_file})")

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
                is_discord=is_discord,
                ip=ip
            )
            execute_strategy(strategy, target_sock, data, delay=self.config.fragment_delay)
            return strategy, sni_name

        # Ручные/статические режимы без автоподбора:
        strategy = self.config.default_strategy
        if is_youtube:
            strategy = "disoob_sni"
        elif not is_discord and strategy in ("disoob_sni", "boringssl_split", "dummy_record_prepend"):
            strategy = "tcp_split_sni_mid"

        execute_strategy(strategy, target_sock, data, delay=self.config.fragment_delay)
        return strategy, sni_name

    def _handshake_with_fast_fallback(
        self,
        client_sock: socket.socket,
        target_sock: socket.socket,
        target_host: str,
        target_port: int,
        first_packet: bytes
    ) -> Tuple[Optional[socket.socket], str, str, Optional[bytes]]:
        """Отправляет TLS ClientHello, проверяет ответ на инъекции ТСПУ (RST / Silent Drop)
        и при необходимости выполняет бесшовный Fast-Fallback на альтернативный IP/порт и стратегию обхода.
        
        Возвращает (живой_target_sock, использованная_стратегия, effective_host, первый_ответ_сервера).
        """
        if not is_tls_client_hello(first_packet):
            # Не TLS трафик - отправляем как есть
            try:
                target_sock.sendall(first_packet)
                return target_sock, "direct", target_host, None
            except Exception:
                return None, "direct", target_host, None

        current_sock = target_sock
        meta = _get_socket_meta(current_sock)
        current_ip = meta.get("target_ip")
        base_rtt = meta.get("connect_rtt", 0.050)

        # 1. Первая попытка отправки ClientHello
        strat_used, effective_host = self._send_tls_client_hello_with_bypass(
            current_sock, first_packet, target_host, ip=current_ip
        )
        t_send = time.time()

        # Окно ожидания первого ответа сервера (ServerHello):
        # Адаптивный таймаут: не менее 600 мс для мобильных сетей и зарубежных хостов
        probe_timeout = min(1.8, max(0.60, base_rtt * 3.5))

        try:
            readable, _, exceptional = select.select([current_sock], [], [current_sock], probe_timeout)
        except Exception:
            readable, exceptional = [], [current_sock]

        is_tspu = False
        first_resp = None

        if exceptional:
            delta = time.time() - t_send
            if delta < base_rtt * 0.4 or delta < 0.015:
                is_tspu = True
        elif readable:
            try:
                first_resp = current_sock.recv(self.buffer_size)
            except (ConnectionResetError, socket.error):
                first_resp = b""

            if first_resp:
                # Успешный ответ сервера получен без задержек (Zero Latency Fast Path)
                mark_ip_working(current_ip, effective_host)
                if self.shadow_prober:
                    self.shadow_prober.maybe_enqueue(effective_host, ip=current_ip)
                return current_sock, strat_used, effective_host, first_resp
            else:
                delta = time.time() - t_send
                # Правило классификации RTT:
                # ТСПУ инжектит RST мгновенно (1-15 мс), реальный сервер отвечает не быстрее base_rtt * 0.7
                if delta < base_rtt * 0.5 or delta < 0.020:
                    is_tspu = True
                    logger.warning(
                        f"[!] ТСПУ RST детекция: {effective_host} ({current_ip or 'IP'}) "
                        f"сброс за {delta*1000:.1f}мс (базовый RTT {base_rtt*1000:.1f}мс, strat={strat_used}) -> Мгновенный обход..."
                    )
                else:
                    # Сервер реально отклонил соединение или порт закрыт
                    mark_ip_dead(current_ip, duration=300.0)
                    _WORKING_IP_CACHE.pop(effective_host, None)
                    self.strategy_engine.record_failure(effective_host, strat_used, ip=current_ip, is_tspu=False)
                    _safe_close_socket(current_sock)
                    return None, strat_used, effective_host, None
        else:
            # Таймаут (тишина): возможный Silent Drop от ТСПУ или блокировка фрагментации со стороны CDN
            delta = time.time() - t_send
            is_yt = is_google_or_youtube_host(effective_host.lower())
            if strat_used in ("direct", "boringssl_split", "tcp_split_sni_start") or is_yt:
                is_tspu = True
                logger.warning(
                    f"[!] ТСПУ Silent Drop: {effective_host} ({current_ip or 'IP'}) "
                    f"тишина > {delta*1000:.0f}мс (strat={strat_used}) -> Мгновенный обход..."
                )
            elif strat_used != "direct":
                # Сервер или CDN (например, Cloudflare на fandom.com) не отвечает на фрагментированный ClientHello
                is_tspu = True
                logger.info(
                    f"[!] Drop на фрагментацию ({strat_used}): {effective_host} "
                    f"тишина > {delta*1000:.0f}мс -> Fallback на direct/альтернативу..."
                )

        if not is_tspu:
            return current_sock, strat_used, effective_host, None

        # 2. Подтвержденный ТСПУ сброс / дроп: Запускаем Transparent Fast-Fallback
        _safe_close_socket(current_sock)
        _WORKING_IP_CACHE.pop(effective_host, None)
        self.strategy_engine.record_failure(effective_host, strat_used, ip=current_ip, is_tspu=True)

        is_yt = is_google_or_youtube_host(effective_host.lower())
        is_dc = is_discord_host(effective_host)
        fallback_strat = self.strategy_engine.get_fallback_strategy(
            effective_host,
            failed_strategy=strat_used,
            is_youtube=is_yt,
            is_discord=is_dc,
            ip=current_ip
        )

        # Защита от 5-tuple / IP:IP бана: ротируем IP из DNS-пула, а если пул пуст — пробуем повторно тот же IP
        new_sock = self._connect_target(target_host, target_port, exclude_ip={current_ip})
        if not new_sock:
            new_sock = self._connect_target(target_host, target_port)

        if not new_sock:
            mark_ip_dead(current_ip, duration=300.0)
            return None, fallback_strat, effective_host, None

        meta_new = _get_socket_meta(new_sock)
        new_ip = meta_new.get("target_ip", current_ip)
        logger.info(
            f"[+] Fast-Fallback: {effective_host} -> стратегия '{fallback_strat}' "
            f"(IP: {current_ip} -> {new_ip})"
        )

        execute_strategy(fallback_strat, new_sock, first_packet, delay=self.config.fragment_delay)
        return new_sock, fallback_strat, effective_host, None
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
        strategy: str = "",
        got_initial_response: bool = False
    ) -> None:
        """Двунаправленная надёжная пересылка трафика между клиентом и целевым сервером."""
        try:
            # Снимаем искусственные таймауты: готовность сокетов полностью контролируется select.select
            client_sock.settimeout(None)
            target_sock.settimeout(None)
        except Exception:
            pass

        sockets = [client_sock, target_sock]
        client_sent_app_data = False
        server_replied_app_data = got_initial_response
        client_closed_normally = False
        has_socket_error = False
        total_server_bytes = 0
        success_recorded = False
        meta_target = _get_socket_meta(target_sock)
        target_ip = meta_target.get("target_ip")

        try:
            while self.is_running:
                # До получения ответа сервера на запрос клиента используем таймаут
                select_timeout = float(self.timeout) if not server_replied_app_data else 60.0
                try:
                    readable, _, _ = select.select(sockets, [], [], select_timeout)
                except (socket.error, ValueError):
                    break

                if not readable:
                    if client_sent_app_data and not server_replied_app_data:
                        # Клиент отправил запрос, но сервер не ответил в пределах таймаута
                        has_socket_error = True
                        break
                    elif not client_sent_app_data:
                        # Клиент держал пустое соединение в пуле (pre-connect) и не отправлял запрос
                        # Это нормальный keep-alive таймаут, закрываем сокет без ошибки
                        break
                    continue

                for s in readable:
                    other = target_sock if s is client_sock else client_sock
                    try:
                        data = s.recv(self.buffer_size)
                        if not data:
                            if s is client_sock:
                                client_closed_normally = True
                            try:
                                other.shutdown(socket.SHUT_WR)
                            except Exception:
                                pass
                            if s in sockets:
                                sockets.remove(s)
                            if not sockets:
                                return
                            continue

                        if s is client_sock:
                            if data and (data[0] == 0x17 or data.startswith(b"GET ") or data.startswith(b"POST ") or data.startswith(b"HEAD ") or data.startswith(b"HTTP/")):
                                client_sent_app_data = True
                        elif s is target_sock:
                            total_server_bytes += len(data)
                            if data and (data[0] == 0x17 or data.startswith(b"HTTP/") or len(data) > 0):
                                if not server_replied_app_data:
                                    server_replied_app_data = True
                                    mark_ip_working(target_ip, host)

                            # Фиксируем успех: получение ответа от сервера доказывает успешный обход DPI
                            if not success_recorded and total_server_bytes > 0:
                                success_recorded = True
                                if host and strategy and strategy not in ("direct", "http"):
                                    self.strategy_engine.record_success(host, strategy, ip=target_ip)

                        other.sendall(data)
                    except (socket.error, OSError, TimeoutError):
                        has_socket_error = True
                        return
        finally:
            # Завершение сессии: анализ результата работы стратегии
            if has_socket_error and not client_closed_normally:
                # Ошибка (таймаут/RST сервера) фиксируется только если клиент реально отправил запрос, а сервер так и не ответил
                if client_sent_app_data and not server_replied_app_data and total_server_bytes == 0:
                    if host and strategy and strategy not in ("direct", "http"):
                        self.strategy_engine.record_failure(host, strategy, ip=target_ip, is_tspu=False)
            elif (client_closed_normally or total_server_bytes > 0 or server_replied_app_data):
                # Сессия завершилась штатно или данные получены: подтверждаем успех, если не был подтвержден ранее
                if not success_recorded and host and strategy and strategy not in ("direct", "http"):
                    self.strategy_engine.record_success(host, strategy, ip=target_ip)

