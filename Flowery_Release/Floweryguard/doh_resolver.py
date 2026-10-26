"""DNS-over-HTTPS (DoH) резолвер с кэшированием, защитой от DPI и автоматическим failover.

Реализовано строго на стандартной библиотеке Python 3.8+ (RFC 1035 wire format, TLS SNI verification,
HTTPConnection с готовым TLS-сокетом, ThreadSafeBoundedTTLCache).
"""

import os
import sys
import time
import socket
import ssl
import http.client
import struct
import threading
import urllib.parse
from dataclasses import dataclass
from typing import Tuple, List, Optional, Dict, Union, Any

import logging

try:
    try:
        from Floweryguard.logger import _get_app_version
    except ImportError:
        from flowguard.logger import _get_app_version
except ImportError:
    def _get_app_version(): return "1.3.0"

try:
    from Floweryguard.logger import get_logger
except ImportError:
    from flowguard.logger import get_logger

logger = get_logger("DoH")


# ---------------------------------------------------------------------------
# 1. Структура данных DoHProvider и встроенные пресеты
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DoHProvider:
    """Описатель DoH-провайдера.
    
    server_ips — обязательный кортеж литеральных IP-адресов, так как резолвить
    сам DoH-хост через DNS до настройки DNS невозможно.
    """
    name: str
    doh_host: str
    doh_path: str
    server_ips: Tuple[str, ...]
    port: int = 443

    @property
    def doh_url(self) -> str:
        """Возвращает полный DoH URL-адрес провайдера."""
        if self.port and self.port != 443:
            return f"https://{self.doh_host}:{self.port}{self.doh_path}"
        return f"https://{self.doh_host}{self.doh_path}"


DNS_PRESETS: Dict[str, DoHProvider] = {
    "cloudflare": DoHProvider(
        name="Cloudflare",
        doh_host="cloudflare-dns.com",
        doh_path="/dns-query",
        server_ips=("1.1.1.1", "1.0.0.1"),
        port=443,
    ),
    "google": DoHProvider(
        name="Google",
        doh_host="dns.google",
        doh_path="/dns-query",
        server_ips=("8.8.8.8", "8.8.4.4"),
        port=443,
    ),
    "adguard": DoHProvider(
        name="AdGuard",
        doh_host="dns.adguard-dns.com",
        doh_path="/dns-query",
        server_ips=("94.140.14.14", "94.140.15.15"),
        port=443,
    ),
    "quad9": DoHProvider(
        name="Quad9",
        doh_host="dns.quad9.net",
        doh_path="/dns-query",
        server_ips=("9.9.9.9", "149.112.112.112"),
        port=443,
    ),
}


def build_custom_provider(
    name: str,
    doh_url: str,
    ipv4_list: Union[List[str], Tuple[str, ...]]
) -> DoHProvider:
    """Валидирует пользовательский ввод и собирает объект DoHProvider.

    Требования:
    - doh_url должен начинаться с https:// и содержать hostname;
    - ipv4_list не должен быть пустым;
    - каждый IP проверяется через socket.inet_aton;
    - при ошибке формируется понятное сообщение на русском языке без голого traceback.
    """
    if not doh_url or not isinstance(doh_url, str):
        raise ValueError("URL DoH-сервера не может быть пустым.")

    clean_url = doh_url.strip()
    if clean_url.lower().startswith("dot://"):
        clean_url = "https://" + clean_url[6:]
    elif not clean_url.lower().startswith("https://"):
        raise ValueError("URL DoH-сервера должен начинаться с 'https://' (например: https://dns.quad9.net/dns-query).")

    try:
        parsed = urllib.parse.urlsplit(clean_url)
    except Exception as e:
        raise ValueError(f"Не удалось разобрать URL DoH-сервера: {e}")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL DoH-сервера должен содержать корректное доменное имя хоста.")

    path = parsed.path
    if not path or path == "/":
        path = "/dns-query"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    port = parsed.port or 443

    if not ipv4_list:
        raise ValueError("Список IP-адресов DoH-сервера не должен быть пустым.")

    valid_ips: List[str] = []
    for raw_ip in ipv4_list:
        if not raw_ip:
            continue
        ip_str = str(raw_ip).strip()
        if not ip_str:
            continue
        parts = ip_str.split(".")
        if len(parts) != 4:
            raise ValueError(f"Некорректный IPv4-адрес '{ip_str}': ожидается ровно 4 октета (например, 9.9.9.9).")
        for octet in parts:
            if not octet.isdigit() or not (0 <= int(octet) <= 255):
                raise ValueError(f"Некорректный IPv4-адрес '{ip_str}': октет '{octet}' должен быть числом от 0 до 255.")
        try:
            socket.inet_aton(ip_str)
        except (socket.error, OSError):
            raise ValueError(f"Некорректный формат IPv4-адреса: '{ip_str}'.")
        if ip_str not in valid_ips:
            valid_ips.append(ip_str)

    if not valid_ips:
        raise ValueError("Не указано ни одного валидного IPv4-адреса для DoH-сервера.")

    provider_name = name.strip() if name and name.strip() else f"Custom ({hostname})"
    return DoHProvider(
        name=provider_name,
        doh_host=hostname,
        doh_path=path,
        server_ips=tuple(valid_ips),
        port=port
    )


def extract_san_domain(der_bytes: bytes) -> Optional[str]:
    """Извлекает первое валидное доменное имя (dNSName) из расширения SAN сертификата."""
    san_oid = b"\x55\x1d\x11"
    idx = der_bytes.find(san_oid)
    if idx != -1:
        sub = der_bytes[idx:idx + 400]
        i = 0
        while i < len(sub) - 2:
            if sub[i] == 0x82:
                length = sub[i + 1]
                name = sub[i + 2:i + 2 + length].decode("ascii", errors="ignore").strip()
                if "." in name and len(name) >= 4 and not name.startswith("."):
                    clean = name.lstrip("*.")
                    if "." in clean:
                        return clean
                i += 2 + length
            else:
                i += 1

    import re
    candidates = re.findall(b"([a-zA-Z0-9][-a-zA-Z0-9]*\\.[a-zA-Z]{2,})", der_bytes)
    ignore = ["lencr", "identrust", "digicert", "sectigo", "crl", "ocsp", "isrg"]
    for c in candidates:
        d = c.decode("ascii", errors="ignore").strip()
        if "." in d and not any(ign in d.lower() for ign in ignore):
            return d
    return None


def auto_detect_dns_provider(user_input: str) -> DoHProvider:
    """Умное автоопределение параметров DNS из одного ввода пользователя (IP, домен или URL).
    
    Пользователю не нужно разбираться в DoH-шаблонах и портах — он вводит один адрес,
    а функция сама определяет протокол, порт (443/853), имя сертификата и путь.
    """
    text = user_input.strip()
    if not text:
        raise ValueError("Адрес DNS-сервера не может быть пустым.")

    # 1. Проверка по известным пресетам
    for p in DNS_PRESETS.values():
        if text in p.server_ips or text.lower() == p.doh_host.lower():
            return p

    # 2. Если введён полный URL (https://..., dot://...)
    if text.lower().startswith(("http://", "https://", "dot://")):
        clean = "https://" + text[6:] if text.lower().startswith("dot://") else text
        parsed = urllib.parse.urlsplit(clean)
        host = parsed.hostname or text
        path = parsed.path if parsed.path and parsed.path != "/" else "/dns-query"
        port = parsed.port or 443
        ips: List[str] = []
        try:
            socket.inet_aton(host)
            ips.append(host)
        except Exception:
            try:
                for ai in socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM):
                    ip_cand = ai[4][0]
                    if ip_cand not in ips:
                        ips.append(ip_cand)
            except Exception as e:
                logger.debug("Failed getting addrinfo for %s: %s", host, e)
        if not ips:
            raise ValueError(f"Не удалось определить IP-адрес для хоста '{host}'.")
        return DoHProvider(name=host, doh_host=host, doh_path=path, server_ips=tuple(ips), port=port)

    # 3. Если введён литеральный IPv4
    try:
        socket.inet_aton(text)
        is_ip = True
    except Exception:
        is_ip = False

    if is_ip:
        ip = text
        detected_host = ip
        detected_port = 443
        # Проверяем порты TLS (443, 853) и читаем имя домена из сертификата
        for test_port in (443, 853):
            try:
                s = socket.create_connection((ip, test_port), timeout=2.0)
                ctx = ssl._create_unverified_context()
                ss = ctx.wrap_socket(s)
                cert = ss.getpeercert(binary_form=True)
                ss.close()
                dom = extract_san_domain(cert)
                if dom:
                    detected_host = dom
                    detected_port = test_port
                    break
            except Exception as e:
                logger.debug("Port %s TLS check failed for %s: %s", test_port, ip, e)
        return DoHProvider(
            name=detected_host,
            doh_host=detected_host,
            doh_path="/dns-query",
            server_ips=(ip,),
            port=detected_port
        )

    # 4. Если введён домен (например, dns-ai.ru)
    host = text.split("/")[0].strip()
    ips = []
    try:
        for ai in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM):
            ip_cand = ai[4][0]
            if ip_cand not in ips:
                ips.append(ip_cand)
    except Exception as e:
        raise ValueError(f"Не удалось разрешить домен '{host}' в IP-адрес: {e}")

    return DoHProvider(
        name=host,
        doh_host=host,
        doh_path="/dns-query",
        server_ips=tuple(ips),
        port=443
    )


# ---------------------------------------------------------------------------
# 2. DNS Wire-Format: кодирование запроса и декодирование ответа (RFC 1035)
# ---------------------------------------------------------------------------

def build_dns_query(domain: str, qtype: int = 1, tx_id: Optional[int] = None) -> bytes:
    """Формирует DNS wire-format запрос (RFC 1035) для домена и типа записи.

    По умолчанию qtype=1 (A), также поддерживается qtype=28 (AAAA).
    """
    if tx_id is None:
        raw_tx = os.urandom(2)
    else:
        raw_tx = struct.pack("!H", tx_id & 0xFFFF)

    flags = b"\x01\x00"  # Standard query с RD (Recursion Desired) = 1
    counts = struct.pack("!HHHH", 1, 0, 0, 0)  # QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0

    domain_clean = domain.lower().strip(".")
    try:
        domain_ascii = domain_clean.encode("idna").decode("ascii")
    except Exception:
        domain_ascii = domain_clean

    qname_parts = domain_ascii.split(".")
    qname = b""
    for part in qname_parts:
        if not part:
            continue
        p_bytes = part.encode("ascii", errors="replace")
        if len(p_bytes) > 63:
            raise ValueError(f"Метка доменного имени слишком длинная (> 63 байт): {part}")
        qname += bytes([len(p_bytes)]) + p_bytes
    qname += b"\x00"

    qtype_bytes = struct.pack("!H", qtype)
    qclass_bytes = struct.pack("!H", 1)  # IN (Internet) = 1

    return raw_tx + flags + counts + qname + qtype_bytes + qclass_bytes


def parse_dns_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Парсит DNS wire-format имя с поддержкой сжатия (RFC 1035 4.1.4).

    Возвращает (распарсенное_имя, новый_offset_после_поля_в_исходном_потоке).
    Стиль tls_parser: проверка границ на каждом шаге, контролируемый ValueError при повреждении данных.
    """
    if offset >= len(data):
        raise ValueError(f"Обрезанный пакет: смещение {offset} выходит за границы данных ({len(data)})")

    labels: List[str] = []
    curr = offset
    jumped = False
    next_offset = offset
    depth = 0
    max_depth = 20

    while True:
        if depth > max_depth:
            raise ValueError("Превышена максимальная глубина указателей сжатия DNS (обнаружен цикл)")
        if curr >= len(data):
            raise ValueError(f"Обрезанный пакет: смещение {curr} выходит за границы при разборе имени")

        length = data[curr]
        if length == 0:
            curr += 1
            if not jumped:
                next_offset = curr
            break

        if (length & 0xC0) == 0xC0:
            # Указатель сжатия DNS (2 байта: 11xxxxxx xxxxxxxx)
            if curr + 2 > len(data):
                raise ValueError("Обрезанный пакет: неполный указатель сжатия DNS")
            ptr = ((length & 0x3F) << 8) | data[curr + 1]
            if ptr >= len(data):
                raise ValueError(f"Указатель сжатия DNS {ptr} выходит за границы пакета ({len(data)})")
            if not jumped:
                next_offset = curr + 2
                jumped = True
            curr = ptr
            depth += 1
            continue

        if (length & 0xC0) != 0:
            raise ValueError(f"Недопустимый префикс длины метки DNS: {length:#04x}")

        curr += 1
        if curr + length > len(data):
            raise ValueError(f"Обрезанный пакет: метка длины {length} выходит за пределы данных ({len(data)})")

        try:
            label = data[curr:curr + length].decode("ascii", errors="replace")
        except Exception:
            label = ""
        labels.append(label)
        curr += length
        if not jumped:
            next_offset = curr

    return ".".join(labels), next_offset


@dataclass
class DNSRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes
    address: Optional[str] = None


@dataclass
class DNSResponse:
    id: int
    flags: int
    rcode: int
    answers: List[DNSRecord]


def parse_dns_response(data: bytes) -> DNSResponse:
    """Разбирает ответ DNS wire format (RFC 1035) с проверками границ на каждом шаге.

    При любых дефектах структуры выбрасывает контролируемый ValueError.
    """
    if len(data) < 12:
        raise ValueError(f"Пакет DNS слишком короткий ({len(data)} байт, ожидается минимум 12)")

    tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[0:12])
    rcode = flags & 0x000F
    offset = 12

    # 1. Пропускаем секцию вопросов (Question)
    for q_idx in range(qdcount):
        if offset >= len(data):
            raise ValueError(f"Обрезанный пакет в секции Question #{q_idx}")
        _, offset = parse_dns_name(data, offset)
        if offset + 4 > len(data):
            raise ValueError(f"Обрезанный заголовок Question #{q_idx} (ожидается QTYPE и QCLASS)")
        offset += 4  # QTYPE (2) + QCLASS (2)

    # 2. Разбираем секцию ответов (Answer)
    answers: List[DNSRecord] = []
    for a_idx in range(ancount):
        if offset >= len(data):
            raise ValueError(f"Обрезанный пакет перед Answer #{a_idx}")
        rname, offset = parse_dns_name(data, offset)
        if offset + 10 > len(data):
            raise ValueError(f"Обрезанный заголовок Resource Record #{a_idx}")
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        if offset + rdlength > len(data):
            raise ValueError(f"Обрезанные данные RDATA в Resource Record #{a_idx} (длина {rdlength})")
        rdata = data[offset:offset + rdlength]
        offset += rdlength

        address: Optional[str] = None
        if rtype == 1:  # Type A (IPv4)
            if rdlength == 4:
                address = socket.inet_ntoa(rdata)
            else:
                raise ValueError(f"Некорректная длина RDATA для типа A: {rdlength} (ожидается 4)")
        elif rtype == 28:  # Type AAAA (IPv6)
            if rdlength == 16:
                address = socket.inet_ntop(socket.AF_INET6, rdata)
            else:
                raise ValueError(f"Некорректная длина RDATA для типа AAAA: {rdlength} (ожидается 16)")

        answers.append(DNSRecord(
            name=rname,
            rtype=rtype,
            rclass=rclass,
            ttl=ttl,
            rdata=rdata,
            address=address
        ))

    return DNSResponse(
        id=tx_id,
        flags=flags,
        rcode=rcode,
        answers=answers
    )


# ---------------------------------------------------------------------------
# 3. ThreadSafeBoundedTTLCache (паттерн ThreadSafeBoundedCache из proxy.py)
# ---------------------------------------------------------------------------

class ThreadSafeBoundedTTLCache:
    """Потокобезопасный кэш DNS-ответов с ограничением максимального размера (FIFO) и TTL."""

    def __init__(self, maxsize: int = 1024):
        self._maxsize = maxsize
        self._lock = threading.Lock()
        self._cache: Dict[str, Tuple[List[str], float]] = {}  # key -> (ips, expire_time)

    def get(self, key: str) -> Optional[List[str]]:
        now = time.time()
        with self._lock:
            item = self._cache.get(key)
            if item is None:
                return None
            ips, expire_time = item
            if now >= expire_time:
                del self._cache[key]
                return None
            return list(ips)

    def set(self, key: str, ips: List[str], ttl: float) -> None:
        effective_ttl = max(5.0, min(float(ttl), 86400.0))
        expire_time = time.time() + effective_ttl
        with self._lock:
            if len(self._cache) >= self._maxsize and key not in self._cache:
                try:
                    first_key = next(iter(self._cache))
                    del self._cache[first_key]
                except (StopIteration, KeyError) as e:
                    logger.debug(f"Исключение при вытеснении из DoH кэша: {e}")
            self._cache[key] = (list(ips), expire_time)

    def pop(self, key: str) -> Optional[List[str]]:
        with self._lock:
            item = self._cache.pop(key, None)
            return list(item[0]) if item else None

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._cache)

    def __contains__(self, key: str) -> bool:
        return self.get(key) is not None


# ---------------------------------------------------------------------------
# 4. DoHResolver — сам DoH резолвер
# ---------------------------------------------------------------------------

class DoHResolver:
    """DNS-over-HTTPS резолвер с прямым подключением по IP и проверкой TLS-сертификата.
    
    Подключение осуществляется напрямую по IP из server_ips (без системного DNS),
    затем оборачивается в TLS сокетом с server_hostname=doh_host для валидации сертификата.
    Запрос отправляется через http.client.HTTPConnection с готовым сокетом (conn.sock = tls_sock).
    """

    def __init__(
        self,
        provider: DoHProvider,
        timeout: float = 4.0,
        max_cache_size: int = 1024,
        ssl_context: Optional[ssl.SSLContext] = None
    ):
        self.provider = provider
        self.timeout = timeout
        self.cache = ThreadSafeBoundedTTLCache(maxsize=max_cache_size)
        self._ssl_context = ssl_context

    def _get_ssl_context(self) -> ssl.SSLContext:
        if self._ssl_context is not None:
            return self._ssl_context
        # Проверяем цепочку доверия и имя DoH/DoT-сервера системным хранилищем.
        # Фиксированный IP не защищает от подмены сервера на сетевом маршруте.
        ctx = ssl.create_default_context()
        self._ssl_context = ctx
        return self._ssl_context

    @staticmethod
    def _recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
        data = b""
        while len(data) < num_bytes:
            chunk = sock.recv(num_bytes - len(data))
            if not chunk:
                raise ConnectionResetError(f"Соединение закрыто до получения {num_bytes} байт (получено {len(data)})")
            data += chunk
        return data

    def _query_dot(self, ip: str, query_bytes: bytes, port: int = 853) -> bytes:
        """Выполняет DNS-over-TLS (DoT, RFC 7858) запрос напрямую через TLS-сокет."""
        raw_sock: Optional[socket.socket] = None
        tls_sock: Optional[ssl.SSLSocket] = None
        try:
            family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            raw_sock = socket.socket(family, socket.SOCK_STREAM)
            raw_sock.settimeout(self.timeout)
            raw_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            raw_sock.connect((ip, port))

            ctx = self._get_ssl_context()
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname=self.provider.doh_host)
            raw_sock = None

            # Префикс 2 байта длины (RFC 7858)
            tls_sock.sendall(struct.pack("!H", len(query_bytes)) + query_bytes)
            len_buf = self._recv_exact(tls_sock, 2)
            resp_len = struct.unpack("!H", len_buf)[0]
            return self._recv_exact(tls_sock, resp_len)
        finally:
            if tls_sock:
                try:
                    tls_sock.close()
                except Exception as e:
                    logger.debug("Error closing tls_sock in _query_dot: %s", e)
            elif raw_sock:
                try:
                    raw_sock.close()
                except Exception as e:
                    logger.debug("Error closing raw_sock in _query_dot: %s", e)

    def _query_ip(self, ip: str, query_bytes: bytes) -> bytes:
        """Выполняет DoH POST запрос к конкретному IP адресу провайдера.
        
        При порте 853 или если сервер требует HTTP/2 (HTTP 505), автоматически использует DoT (RFC 7858).
        """
        if self.provider.port == 853:
            return self._query_dot(ip, query_bytes, 853)

        raw_sock: Optional[socket.socket] = None
        tls_sock: Optional[ssl.SSLSocket] = None
        conn: Optional[http.client.HTTPConnection] = None
        try:
            family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            raw_sock = socket.socket(family, socket.SOCK_STREAM)
            raw_sock.settimeout(self.timeout)
            raw_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            raw_sock.connect((ip, self.provider.port))

            ctx = self._get_ssl_context()
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname=self.provider.doh_host)
            raw_sock = None  # Владение сокетом перешло к tls_sock

            conn = http.client.HTTPConnection(self.provider.doh_host, port=self.provider.port, timeout=self.timeout)
            conn.sock = tls_sock

            headers = {
                "Content-Type": "application/dns-message",
                "Accept": "application/dns-message",
                "User-Agent": f"Flowery-DoH/{_get_app_version()}",
            }
            conn.request("POST", self.provider.doh_path, body=query_bytes, headers=headers)
            resp = conn.getresponse()
            if resp.status == 505:
                # Сервер требует HTTP/2 (RFC 8484 5.2). Автоматически переключаемся на DoT (RFC 7858, порт 853)
                try:
                    conn.close()
                except Exception as e:
                    logger.debug("Error closing HTTP conn on 505: %s", e)
                conn = None
                return self._query_dot(ip, query_bytes, 853)

            if resp.status != 200:
                raise ValueError(f"HTTP статус DoH ответа {resp.status} {resp.reason}")
            data = resp.read()
            return data
        finally:
            if conn:
                try:
                    conn.close()
                except Exception as e:
                    logger.debug("Error closing conn in _query_ip: %s", e)
            elif tls_sock:
                try:
                    tls_sock.close()
                except Exception as e:
                    logger.debug("Error closing tls_sock in _query_ip: %s", e)
            elif raw_sock:
                try:
                    raw_sock.close()
                except Exception as e:
                    logger.debug("Error closing raw_sock in _query_ip: %s", e)

    def resolve(self, domain: str, qtype: int = 1) -> List[str]:
        """Резолвит доменное имя в список IP-адресов.
        
        Использует кэш TTL. При промахе перебирает доступные IP из provider.server_ips.
        """
        domain_clean = domain.lower().strip(".")
        cache_key = f"{domain_clean}:{qtype}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached

        # Если передан литеральный IPv4
        is_ipv4 = False
        try:
            socket.inet_aton(domain_clean)
            is_ipv4 = True
        except (OSError, ValueError):
            is_ipv4 = False

        if is_ipv4:
            return [domain_clean] if qtype == 1 else []

        # Если передан литеральный IPv6
        is_ipv6 = False
        try:
            socket.inet_pton(socket.AF_INET6, domain_clean)
            is_ipv6 = True
        except (OSError, ValueError):
            is_ipv6 = False

        if is_ipv6:
            return [domain_clean] if qtype == 28 else []

        query_bytes = build_dns_query(domain_clean, qtype=qtype)
        last_error: Optional[Exception] = None

        for ip in self.provider.server_ips:
            try:
                raw_resp = self._query_ip(ip, query_bytes)
                dns_resp = parse_dns_response(raw_resp)
                if dns_resp.rcode != 0:
                    # NXDOMAIN или другой код завершения — сервер ответил, домен не найден
                    return []

                ips: List[str] = []
                min_ttl = 300
                for record in dns_resp.answers:
                    if record.rtype == qtype and record.address:
                        if record.address not in ips:
                            ips.append(record.address)
                        if record.ttl > 0:
                            min_ttl = min(min_ttl, record.ttl)

                if ips:
                    self.cache.set(cache_key, ips, min_ttl)
                return ips
            except Exception as e:
                last_error = e
                continue

        err_msg = f"DoH резолвер '{self.provider.name}' не смог разрешить '{domain}': {last_error}"
        raise OSError(err_msg)

    def resolve_one(self, domain: str, qtype: int = 1) -> Optional[str]:
        """Возвращает первый найденный IP адрес или None."""
        try:
            ips = self.resolve(domain, qtype=qtype)
            return ips[0] if ips else None
        except Exception:
            return None


# ---------------------------------------------------------------------------
# 5. DNSFailoverManager — слой политики поверх резолвера
# ---------------------------------------------------------------------------

class DNSFailoverManager:
    """Слой политики переключения DNS.

    Модель: один активный DNS-провайдер на всю сессию.
    - primary: пользовательский DoH (если задан) или дефолтный пресет;
    - fallback: жестко зашитый Cloudflare пресет (не второй кастомный);
    - переключение на fallback происходит строго после fail_threshold (2-3) неудач подряд;
    - при переключении: цветной статус в консоль и запись через logger.warning;
    - остаётся на fallback до перезапуска приложения (автоматического возврата нет);
    - при следующем запуске снова пробует primary первым с выводом понятного сообщения.
    """

    def __init__(
        self,
        primary_provider: DoHProvider,
        fallback_provider: Optional[DoHProvider] = None,
        fail_threshold: int = 3,
        timeout: float = 4.0
    ):
        self.primary_provider = primary_provider

        # Гарантируем, что fallback провайдер отличен от primary (B5)
        # Исключаем аномалию «Cloudflare -> Cloudflare»
        if fallback_provider is not None:
            self.fallback_provider = fallback_provider
        else:
            p_name = (primary_provider.name or "").lower()
            if "cloudflare" in p_name or "1.1.1.1" in p_name:
                self.fallback_provider = DNS_PRESETS["google"]
            else:
                self.fallback_provider = DNS_PRESETS["cloudflare"]

        if (
            self.fallback_provider.name.lower() == self.primary_provider.name.lower()
            or (set(self.fallback_provider.server_ips) & set(self.primary_provider.server_ips))
        ):
            for cand_key in ("google", "quad9", "cloudflare"):
                cand = DNS_PRESETS[cand_key]
                if (
                    cand.name.lower() != self.primary_provider.name.lower()
                    and not (set(cand.server_ips) & set(self.primary_provider.server_ips))
                ):
                    self.fallback_provider = cand
                    break

        self.fail_threshold = max(2, fail_threshold)
        self.timeout = timeout

        self.primary_resolver = DoHResolver(self.primary_provider, timeout=self.timeout)
        self.fallback_resolver = DoHResolver(self.fallback_provider, timeout=self.timeout)

        self._lock = threading.Lock()
        self._consecutive_failures: int = 0
        self._is_fallback_active: bool = False
        self._first_attempt_done: bool = False

    @property
    def is_fallback_active(self) -> bool:
        with self._lock:
            return self._is_fallback_active

    @property
    def active_provider(self) -> DoHProvider:
        with self._lock:
            return self.fallback_provider if self._is_fallback_active else self.primary_provider

    @property
    def consecutive_failures(self) -> int:
        with self._lock:
            return self._consecutive_failures

    def check_primary_startup(self, test_domain: str = "cloudflare.com") -> bool:
        """Проверяет primary DNS при старте сессии с записью статуса в лог."""
        if self.primary_provider.name == self.fallback_provider.name:
            return True

        try:
            ips = self.primary_resolver.resolve(test_domain, qtype=1)
            if ips:
                with self._lock:
                    self._first_attempt_done = True
                    self._consecutive_failures = 0
                logger.debug("[DNS] Primary DNS (%s) работает", self.primary_provider.name)
                return True
        except Exception as e:
            logger.debug("Primary DNS check exception: %s", e)

        with self._lock:
            self._first_attempt_done = True
            self._consecutive_failures = self.fail_threshold
            self._is_fallback_active = True

        msg = f"[DNS] Пробую ваш DNS ({self.primary_provider.name})... не ответил, использую {self.fallback_provider.name}"
        logger.debug(msg)
        return False

    def resolve(self, domain: str, qtype: int = 1) -> List[str]:
        """Выполняет резолвинг домена с применением политики failover."""
        with self._lock:
            is_fallback = self._is_fallback_active

        if is_fallback:
            return self.fallback_resolver.resolve(domain, qtype=qtype)

        try:
            ips = self.primary_resolver.resolve(domain, qtype=qtype)
            if ips:
                with self._lock:
                    self._consecutive_failures = 0
                    if not self._first_attempt_done:
                        self._first_attempt_done = True
                        if self.primary_provider.name != self.fallback_provider.name:
                            logger.debug("[DNS] Primary DNS (%s) работает", self.primary_provider.name)
                return ips
            # Пустой список (например, NXDOMAIN) — это валидный ответ, а не ошибка сети
            with self._lock:
                self._consecutive_failures = 0
            return []
        except Exception as e:
            should_switch = False
            with self._lock:
                self._consecutive_failures += 1
                if not self._first_attempt_done:
                    self._first_attempt_done = True
                    if self.primary_provider.name != self.fallback_provider.name:
                        logger.debug(
                            "[DNS] Primary DNS (%s) не ответил для %s, fallback на %s (ошибка: %s)",
                            self.primary_provider.name,
                            domain,
                            self.fallback_provider.name,
                            e,
                        )
                if self._consecutive_failures >= self.fail_threshold and not self._is_fallback_active:
                    self._is_fallback_active = True
                    should_switch = True

            if should_switch:
                logger.warning(f"[DNS] {self.primary_provider.name} не отвечает ({self.fail_threshold} сбоев подряд) — переключаюсь на {self.fallback_provider.name}")

            # Выполняем аварийный запрос через fallback, чтобы соединение не оборвалось
            try:
                return self.fallback_resolver.resolve(domain, qtype=qtype)
            except Exception as fb_err:
                raise OSError(f"Оба DNS провайдера недоступны ({self.primary_provider.name}: {e}, {self.fallback_provider.name}: {fb_err})")

    def resolve_one(self, domain: str, qtype: int = 1) -> Optional[str]:
        """Возвращает первый IP-адрес или None при невозможности резолвинга."""
        try:
            ips = self.resolve(domain, qtype=qtype)
            return ips[0] if ips else None
        except Exception as e:
            logger.debug("resolve_one failed for %s: %s", domain, e)
            return None


class MultiDoHHarvester:
    """Многопоточный харвестер альтернативных Anycast IP одного домена через разные DoH-резолверы.
    
    Физический принцип:
    - Блок-листы ТСПУ иногда завязаны на конкретный Anycast IP CDN (Cloudflare, Google, Fastly).
    - Разные независимые публичные DoH-резолверы (Cloudflare, Google, Quad9, AdGuard)
      отвечают из разных географических точек и дата-центров, возвращая разные edge-IP.
    - Харвестер опрашивает 2-3 DoH-резолвера параллельно, собирает все уникальные IP.
    - Если один IP заблокирован ТСПУ, другие остаются доступными для обхода!
    """

    def __init__(self, providers: Optional[Any] = None, timeout: float = 3.0):
        if providers is not None and not isinstance(providers, (list, tuple, set)):
            timeout = getattr(providers, "timeout", timeout)
            providers = None
        if not providers:
            providers = [
                DNS_PRESETS["cloudflare"],
                DNS_PRESETS["google"],
                DNS_PRESETS["quad9"],
            ]
        self.providers = providers
        self.timeout = timeout
        self.resolvers = [DoHResolver(p, timeout=timeout) for p in self.providers]
        self._cache = ThreadSafeBoundedTTLCache(maxsize=1024)

    def harvest(self, domain: str, qtype: int = 1) -> List[str]:
        """Параллельно опрашивает все DoH-провайдеры и возвращает дедуплицированный список всех IP."""
        domain_clean = domain.lower().strip(".")
        cached = self._cache.get(f"{domain_clean}:{qtype}")
        if cached:
            return cached

        results: List[str] = []
        threads = []
        lock = threading.Lock()

        def _worker(resolver: DoHResolver):
            try:
                ips = resolver.resolve(domain_clean, qtype=qtype)
                with lock:
                    for ip in ips:
                        if ip not in results:
                            results.append(ip)
            except Exception as e:
                logger.debug("MultiDoHHarvester worker exception for %s: %s", domain_clean, e)

        for r in self.resolvers:
            t = threading.Thread(target=_worker, args=(r,), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=self.timeout + 0.5)

        if results:
            self._cache.set(f"{domain_clean}:{qtype}", results, 600)
        return results

