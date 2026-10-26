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
import ipaddress
try:
    threading.stack_size(262144)  # 256 KB stack size to prevent RAM/virtual memory exhaustion on Windows
except Exception:
    pass
import time
import sys
import os
import struct
import queue
import weakref
from .route_health import RouteHealth
from .tls_transport import relay_tls
from .tls_parser import collect_client_hello
from typing import Optional, Tuple, List, Dict, Any, Set
try:
    from flowguard.config import Config, load_whitelist_domains, is_host_in_whitelist
    from flowguard.tls_parser import is_tls_client_hello, parse_sni, create_tls_record_fragments
    from flowguard.sni_spoofer import SNISpoofer
    from flowguard.strategy import get_strategy_engine, execute_strategy, StrategyExecutor, MAJOR_BLOCKED_PATTERNS
    from flowguard.logger import get_logger
    from flowguard.calibration import WarmUpHarvester
except ImportError:
    from Floweryguard.config import Config, load_whitelist_domains, is_host_in_whitelist
    from Floweryguard.tls_parser import is_tls_client_hello, parse_sni, create_tls_record_fragments
    from Floweryguard.sni_spoofer import SNISpoofer
    from Floweryguard.strategy import get_strategy_engine, execute_strategy, StrategyExecutor, MAJOR_BLOCKED_PATTERNS
    from Floweryguard.logger import get_logger
    try:
        from Floweryguard.calibration import WarmUpHarvester
    except ImportError:
        WarmUpHarvester = None

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


CLOUDFLARE_ANYCAST_PREFIXES: Tuple[str, ...] = (
    "162.159.",
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.",
    "104.21.", "104.22.", "104.23.", "104.24.", "104.25.",
    "104.26.", "104.27.",
    "172.64.", "172.65.", "172.66.", "172.67."
)


def is_cloudflare_anycast_ip(ip: Optional[str]) -> bool:
    """Проверяет, принадлежит ли IP к Anycast-диапазонам Cloudflare."""
    if not ip or not isinstance(ip, str):
        return False
    ip_clean = ip.strip()
    return any(ip_clean.startswith(prefix) for prefix in CLOUDFLARE_ANYCAST_PREFIXES)


try:
    from flowguard.voice_helper import is_winws_tcp_filtering_active
except ImportError:
    try:
        from Floweryguard.voice_helper import is_winws_tcp_filtering_active
    except ImportError:
        def is_winws_tcp_filtering_active() -> bool:
            return False


def is_discord_host(host: Optional[str]) -> bool:
    """Проверяет, относится ли хост к инфраструктуре Discord (включая войсы *.discord.media и шлюзы)."""
    if not host:
        return False
    h = str(host).lower().strip()
    if h.startswith("[") and "]" in h:
        h = h[1:h.find("]")]
    elif ":" in h:
        h = h.split(":")[0]
    h = h.rstrip(".")
    if any(h == ext.lstrip(".") or h.endswith(ext) for ext in (".storage.googleapis.com", ".amazonaws.com", ".blob.core.windows.net")):
        return False
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
        or "dc-telemetry.net" in h
        or "attachments.discord.net" in h
        or "tenor.com" in h
        or "giphy.com" in h
        or "tenor.googleapis.com" in h
        or is_discord_ip(h)
    )


def is_discord_network_host(host: Optional[str]) -> bool:
    """Проверяет, относится ли хост к веб/CDN/медиа инфраструктуре Discord на Cloudflare Anycast."""
    if not host:
        return False
    h = str(host).lower().strip()
    if h.startswith("[") and "]" in h:
        h = h[1:h.find("]")]
    elif ":" in h:
        h = h.split(":")[0]
    h = h.rstrip(".")
    if h.endswith(".discord.media"):
        return False
    return (
        h in ("discord.com", "gateway.discord.gg", "cdn.discordapp.com", "media.discordapp.net", "attachments.discord.net")
        or h.endswith(".discord.com")
        or h.endswith(".discord.gg")
        or h.endswith(".discordapp.com")
        or h.endswith(".discordapp.net")
        or h.endswith(".discord.net")
        or "images-ext" in h
        or "attachments.discord.net" in h
        or "cdn.discordapp.com" in h
        or "media.discordapp.net" in h
    )


def is_discord_media_host(host: Optional[str]) -> bool:
    """Проверяет, относится ли хост к CDN или медиа Discord (аватарки, картинки, вложения, GIF Tenor/Giphy)."""
    if not host:
        return False
    h = str(host).lower().strip()
    if h.startswith("[") and "]" in h:
        h = h[1:h.find("]")]
    elif ":" in h:
        h = h.split(":")[0]
    h = h.rstrip(".")
    if h.endswith(".discord.media"):
        return False
    return (
        any(m in h for m in (
            "cdn.discordapp.com", "media.discordapp.net", "attachments.discord.net",
            "images-ext", "dl.discordapp.net", "dl2.discordapp.net",
            "tenor.com", "giphy.com", "tenor.googleapis.com"
        ))
        or h.endswith(".discordapp.com")
        or h.endswith(".discordapp.net")
        or h.endswith(".discord.net")
        or h.endswith(".tenor.com")
        or h.endswith(".giphy.com")
    )


def is_google_or_youtube_host(host: Optional[str]) -> bool:
    """Проверяет, относится ли хост к YouTube/Google Video, обрабатываемым zapret на уровне WinDivert."""
    if not host:
        return False
    h = str(host).lower().rstrip(".")
    return any(p in h for p in [
        "youtube.com", "googlevideo.com", "ytimg.com", "youtu.be",
        "ggpht.com", "googleusercontent.com", "youtube-nocookie.com", "yt.be", "gvt1.com",
        "youtubei.googleapis.com", "youtubei."
    ])


def is_googlevideo_host(host: Optional[str]) -> bool:
    """Проверяет, относится ли хост к медиа-серверам Google Video (GGC)."""
    if not host:
        return False
    h = str(host).lower().rstrip(".")
    return "googlevideo.com" in h


def is_gaming_host(host: Optional[str]) -> bool:
    """Проверяет, относится ли хост к игровым сервисам (Steam, сетевые игры, PlayStation, PlayFab, GameGuard)."""
    if not host:
        return False
    h = str(host).lower().rstrip(".")
    gaming_patterns = [
        "steampowered.com", "steamcommunity.com", "steamserver.net", "steamcontent.com",
        "steamstatic.com", "steam-chat.com", "valve.net", "valvesoftware.com",
        "playstation.com", "playstation.net", "sonyentertainmentnetwork.com",
        "playfabapi.com", "playfab.com", "playfab.net", "trafficmanager.net",
        "arrowheadgs.com", "helldivers2.dev", "nprotect.net", "nprotect.com",
        "inca.co.kr", "gameguard.des", "gameguard.co.kr", "battleye.com", "easyanticheat.net"
    ]
    return any(p in h for p in gaming_patterns)


def is_telegram_host(host: Optional[str]) -> bool:
    """Проверяет, относится ли хост к инфраструктуре Telegram (MTProto DC, Web, API)."""
    if not host:
        return False
    h = str(host).lower().rstrip(".")
    return (
        "telegram" in h
        or h.endswith(".t.me") or h == "t.me"
        or "telegra.ph" in h
        or "tdesktop.com" in h
        or h.startswith("149.154.")
        or h.startswith("91.108.")
    )



class ThreadSafeBoundedCache:
    """Потокобезопасный кэш с ограничением максимального размера (FIFO вытеснение) и поддержкой TTL."""

    def __init__(self, maxsize: int = 1024, default_ttl: Optional[float] = None):
        self._maxsize = maxsize
        self._default_ttl = default_ttl
        self._lock = threading.Lock()
        self._cache: Dict[str, Any] = {}
        self._timestamps: Dict[str, float] = {}
        self._ttls: Dict[str, float] = {}

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            if key in self._cache:
                item_ttl = self._ttls.get(key, self._default_ttl)
                if item_ttl is not None:
                    ts = self._timestamps.get(key, 0)
                    if time.time() - ts > item_ttl:
                        self._cache.pop(key, None)
                        self._timestamps.pop(key, None)
                        self._ttls.pop(key, None)
                        return default
                return self._cache[key]
            return default

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        with self._lock:
            if len(self._cache) >= self._maxsize and key not in self._cache:
                try:
                    first_key = next(iter(self._cache))
                    del self._cache[first_key]
                    self._timestamps.pop(first_key, None)
                    self._ttls.pop(first_key, None)
                except (StopIteration, KeyError):
                    pass
            self._cache[key] = value
            self._timestamps[key] = time.time()
            if ttl is not None:
                self._ttls[key] = ttl
            elif key in self._ttls:
                del self._ttls[key]

    def pop(self, key: str, default: Any = None) -> Any:
        with self._lock:
            self._timestamps.pop(key, None)
            self._ttls.pop(key, None)
            return self._cache.pop(key, default)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            self._timestamps.clear()
            self._ttls.clear()

    def __contains__(self, key: str) -> bool:
        return self.get(key) is not None

    def __getitem__(self, key: str) -> Any:
        val = self.get(key)
        if val is None:
            raise KeyError(key)
        return val

    def __setitem__(self, key: str, value: Any) -> None:
        self.set(key, value)

    def __len__(self) -> int:
        with self._lock:
            return len(self._cache)


_FALLBACK_DNS_SERVERS = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "9.9.9.9", "77.88.8.8"]
_DNS_CACHE = ThreadSafeBoundedCache(maxsize=1024, default_ttl=300)
_RESOLVED_IPS_CACHE = ThreadSafeBoundedCache(maxsize=1024, default_ttl=300)
_WORKING_IP_CACHE = ThreadSafeBoundedCache(maxsize=1024)
_DEAD_IP_CACHE = ThreadSafeBoundedCache(maxsize=2048)
_IP_DEAD_STRIKES: Dict[str, int] = {}
_IP_FAILURES: Dict[str, Set[str]] = {}
_IP_DEAD_STRIKES_LOCK = threading.Lock()
_IP_FAILURES_LOCK = threading.Lock()
# Предустановленные blackhole IP (Cymru/Tor blackholes, блокирующие TLS в РФ)
for _dead_ip in ("204.8.99.144", "204.8.99.146"):
    _DEAD_IP_CACHE.set(_dead_ip, time.time() + 86400.0)


def is_bogon_or_sinkhole_ip(ip: Optional[str]) -> bool:
    """Проверяет, является ли IP bogon/loopback/sinkhole заглушкой провайдера."""
    if not ip or not isinstance(ip, str):
        return True
    ip = ip.strip()
    if not ip:
        return True
    if ip in ("0.0.0.0", "255.255.255.255", "::1", "192.144.59.14", "94.232.43.149"):
        return True
    if ip.startswith("127."):
        return True
    # Провайдерские sinkhole-подсети (РФ блокировки мобильных операторов: МТС, Билайн, Мегафон, Tele2)
    if ip.startswith("8.47.69.") or ip.startswith("8.6.112."):
        return True
    # Приватные подсети RFC 1918, RFC 2544 (198.18.0.0/15) и CGNAT (подменяемые DNS-заглушками провайдеров / VPN Fake-IP)
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("169.254.") or ip.startswith("198.18.") or ip.startswith("198.19."):
        return True
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) >= 2 and parts[1].isdigit():
            val = int(parts[1])
            if 16 <= val <= 31:
                return True
    if ip.startswith("100."):
        parts = ip.split(".")
        if len(parts) >= 2 and parts[1].isdigit():
            val = int(parts[1])
            if 64 <= val <= 127:
                return True
    return False


def is_ip_dead(ip: str) -> bool:
    """Проверяет, помечен ли IP как нерабочий / сбрасывающий соединения (с TTL 10 минут)."""
    if is_bogon_or_sinkhole_ip(ip):
        return True
    dead_until = _DEAD_IP_CACHE.get(ip)
    if dead_until is not None:
        if time.time() < dead_until:
            return True
        else:
            _DEAD_IP_CACHE.pop(ip, None)
    return False


def mark_ip_dead(ip: Optional[str], duration: float = 600.0) -> None:
    """Помечает IP как нерабочий на заданное время (по умолчанию 10 минут)."""
    if ip and is_plain_ip(ip):
        _DEAD_IP_CACHE.set(ip, time.time() + duration)


def mark_ip_working(ip: Optional[str], host: Optional[str] = None) -> None:
    """Помечает IP как проверенный и рабочий, снимая флаг нерабочего."""
    if ip:
        _DEAD_IP_CACHE.pop(ip, None)
        with _IP_DEAD_STRIKES_LOCK:
            _IP_DEAD_STRIKES.pop(ip, None)
        with _IP_FAILURES_LOCK:
            _IP_FAILURES.pop(ip, None)
        if host:
            if is_googlevideo_host(host) and ip in GOOGLE_EDGE_ANYCAST_IPS:
                return
            if is_google_or_youtube_host(host) and not is_googlevideo_host(host) and ip in GOOGLE_VIDEO_ANYCAST_IPS:
                return
            if is_discord_host(host) and (is_cloudflare_anycast_ip(ip) or is_discord_ip(ip)):
                _WORKING_IP_CACHE.set(host, ip, ttl=300.0)
                return
            _WORKING_IP_CACHE.set(host, ip)


def record_ip_strategy_failure(ip: str, strategy: str, domain: Optional[str] = None) -> bool:
    """Регистрирует сбой стратегии на IP для PathHealth. При 2 сбоях разных стратегий помечает IP мертвым."""
    if not ip:
        return False
    with _IP_FAILURES_LOCK:
        strats = _IP_FAILURES.setdefault(ip, set())
        strats.add(strategy)
        fail_count = len(strats)
    if fail_count >= 2:
        with _IP_DEAD_STRIKES_LOCK:
            strikes = _IP_DEAD_STRIKES.get(ip, 0) + 1
            _IP_DEAD_STRIKES[ip] = strikes
        duration = min(3600.0, 300.0 * (2 ** (strikes - 1)))
        mark_ip_dead(ip, duration=duration)
        with _IP_FAILURES_LOCK:
            _IP_FAILURES.pop(ip, None)
        return True
    return False


def resolve_fallback_dns(domain: str, config: Optional[Any] = None) -> Optional[str]:
    """Резервный резолвинг доменов через независимые DNS-серверы, если оператор блокирует DNS."""
    domain_clean = domain.lower().strip(".")
    if "dns.msftncsi.com" in domain_clean:
        return "131.107.255.255"
    if "dc-telemetry.net" in domain_clean:
        return None
    cached = _DNS_CACHE.get(domain_clean)
    if cached:
        return cached

    # Пробуем DoH Failover Manager
    mgr = get_dns_failover_manager(config)
    if mgr:
        try:
            res_ip = mgr.resolve_one(domain_clean)
            if res_ip:
                ipv6_mode = getattr(config, "ipv6_mode", "disabled") if config else "disabled"
                if ":" in res_ip and ipv6_mode == "disabled":
                    return None
                _DNS_CACHE.set(domain_clean, res_ip)
                return res_ip
        except Exception:
            pass

    # Пробуем разобрать IP, если уже передан IP
    try:
        socket.inet_aton(domain_clean)
        return domain_clean
    except Exception:
        pass

    # Для известных блокируемых доменов не раскрываем запрос через обычный DNS.
    protected_host = is_discord_host(domain_clean) or is_google_or_youtube_host(domain_clean)
    for pattern in MAJOR_BLOCKED_PATTERNS:
        if domain_clean == pattern or domain_clean.endswith("." + pattern) or pattern in domain_clean.split("."):
            protected_host = True
            break
    if protected_host:
        return None

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
                    if not is_bogon_or_sinkhole_ip(ip):
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


_HOST_RESOLVE_LOCKS: Dict[str, threading.Lock] = {}
_SINGLE_FLIGHT_LOCK = threading.Lock()

def _get_host_lock(host: str) -> threading.Lock:
    """Возвращает Single-Flight замок для предотвращения лавины одновременных DNS-запросов к одному хосту."""
    h = (host or "").lower().rstrip(".")
    with _SINGLE_FLIGHT_LOCK:
        if len(_HOST_RESOLVE_LOCKS) >= 2048:
            for k in list(_HOST_RESOLVE_LOCKS.keys()):
                if not _HOST_RESOLVE_LOCKS[k].locked():
                    _HOST_RESOLVE_LOCKS.pop(k, None)
        if h not in _HOST_RESOLVE_LOCKS:
            _HOST_RESOLVE_LOCKS[h] = threading.Lock()
        return _HOST_RESOLVE_LOCKS[h]

_FAILOVER_MANAGERS: Dict[str, Any] = {}
_FAILOVER_MANAGERS_LOCK = threading.Lock()

def get_dns_failover_manager(config=None, force_new: bool = False):
    try:
        try:
            from Floweryguard.doh_resolver import DNSFailoverManager, DNS_PRESETS, DoHProvider
        except ImportError:
            from flowguard.doh_resolver import DNSFailoverManager, DNS_PRESETS, DoHProvider
        server = None
        if config:
            if hasattr(config, "_overrides") and "server" in config._overrides:
                server = config._overrides["server"]
            elif hasattr(config, "_overrides") and "dns_server" in config._overrides:
                server = config._overrides["dns_server"]
            elif hasattr(config, "dns_server") and config.dns_server:
                server = config.dns_server
            elif hasattr(config, "server") and config.server:
                server = config.server
            elif hasattr(config, "get_str"):
                server = config.get_str("dns", "server")
            elif isinstance(config, dict):
                server = config.get("server") or config.get("dns_server")
            elif hasattr(config, "get"):
                server = config.get("server")
        if not server:
            server = "cloudflare"
        server_key = str(server).lower().strip()
        primary = DNS_PRESETS.get(server_key)
        if not primary:
            for k, v in DNS_PRESETS.items():
                if k.lower() == server_key or (v.name and v.name.lower() == server_key):
                    primary = v
                    break
        if not primary:
            from .doh_resolver import provider_from_config
            primary = provider_from_config(config) if config else DNS_PRESETS["cloudflare"]

        cache_key = (primary.doh_host, primary.doh_path, primary.server_ips, primary.port)
        with _FAILOVER_MANAGERS_LOCK:
            if force_new or cache_key not in _FAILOVER_MANAGERS:
                _FAILOVER_MANAGERS[cache_key] = DNSFailoverManager(primary_provider=primary)
            return _FAILOVER_MANAGERS[cache_key]
    except Exception:
        return None

GOOGLE_VIDEO_ANYCAST_IPS: List[str] = [
    "173.194.178.225", "173.194.180.92", "142.251.155.119"
]

YOUTUBE_WEB_ANYCAST_IPS: List[str] = [
    "142.251.150.4", "142.251.156.4", "209.85.233.136", "142.250.74.110",
    "142.250.185.174", "172.217.16.142", "64.233.161.190", "74.125.111.166",
    "209.85.233.119", "142.250.150.119", "64.233.163.119", "64.233.164.198", "64.233.162.198"
]

GOOGLE_EDGE_ANYCAST_IPS: List[str] = YOUTUBE_WEB_ANYCAST_IPS + GOOGLE_VIDEO_ANYCAST_IPS

DISCORD_CORE_ANYCAST_IPS: List[str] = [
    # Discord Gateway Anycast (.234) - 162.159.134.234 verified working on TSPU
    "162.159.134.234", "162.159.136.234", "162.159.130.234", "162.159.133.234", "162.159.128.234",
    # Discord Web / API Anycast (.232, .233) - 162.159.136.232 verified working on TSPU
    "162.159.136.232", "162.159.137.232", "162.159.138.232",
    "162.159.128.233", "162.159.129.233", "162.159.130.233"
]

# Узел Cloudflare, на котором загрузка не обрывается после 16 КБ (Discord, X).
CLOUDFLARE_VERIFIED_EDGE_IP = "162.159.136.232"

DISCORD_CDN_ANYCAST_IPS: List[str] = [
    # Discord CDN Anycast (.232 - Head priority expected by tests and fast-path)
    "162.159.128.232", "162.159.129.232", "162.159.130.232", "162.159.136.232",
    # Discord CDN Anycast (.233 - Native Cloudflare edge nodes for cdn.discordapp.com)
    "162.159.130.233", "162.159.129.233", "162.159.133.233", "162.159.134.233", "162.159.135.233", "162.159.128.233",
    "162.159.137.232"
]

DISCORD_MEDIA_ANYCAST_IPS: List[str] = [
    # Discord Media Anycast (.232 - Native Cloudflare edge nodes for media.discordapp.net, images-ext)
    "162.159.128.232", "162.159.129.232", "162.159.130.232", "162.159.136.232", "162.159.137.232",
    # Discord Media Anycast (.233 - Secondary edge nodes)
    "162.159.130.233", "162.159.129.233", "162.159.133.233", "162.159.134.233", "162.159.128.233"
]

DISCORD_CLOUDFLARE_ANYCAST_IPS: List[str] = [
    "162.159.128.232", "162.159.129.232", "162.159.130.232", "162.159.136.232",
    "162.159.137.232", "162.159.138.232",
    "162.159.129.233", "162.159.130.233", "162.159.133.233", "162.159.133.232",
    "162.159.134.233", "162.159.134.232", "162.159.134.234",
    "162.159.135.233", "162.159.135.232",
    "162.159.136.234", "162.159.130.234", "162.159.133.234", "162.159.128.234",
    "162.159.128.233"
]

_RECENT_DISCORD_IPS = ThreadSafeBoundedCache(maxsize=256, default_ttl=30.0)
_DISCORD_IP_ROTATION_INDEX: int = 0
_DISCORD_IP_ROTATION_LOCK = threading.Lock()

_SOCKET_META = ThreadSafeBoundedCache(maxsize=2048)

def _set_socket_meta(sock: socket.socket, target_ip: str, connect_rtt: float) -> None:
    """Сохраняет метаданные подключения (IP, RTT) для сокета в потокобезопасный ограниченный кэш."""
    try:
        _SOCKET_META.set(id(sock), {
            "socket_ref": weakref.ref(sock),
            "target_ip": target_ip,
            "connect_rtt": connect_rtt,
        })
    except Exception:
        pass

def _get_socket_meta(sock: Optional[socket.socket]) -> Dict[str, Any]:
    """Возвращает метаданные подключения для сокета."""
    if not sock:
        return {}
    meta = _SOCKET_META.get(id(sock), {})
    owner = meta.get("socket_ref")
    if owner is None or owner() is not sock:
        return {}
    return {"target_ip": meta["target_ip"], "connect_rtt": meta["connect_rtt"]}

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
            scores = self.strategy_engine.get_scores_for_key(host, ip)
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
        test_strat = "combo_tlsrec_tcpsplit" if is_yt else ("combo_tlsrec_tcpsplit" if not is_dc else "direct")
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
        self.route_health = RouteHealth()
        self.host = config.proxy_host
        self.port = config.proxy_port
        self.buffer_size = config.buffer_size
        self.timeout = config.timeout
        self.is_running = False
        self.server_sock: Optional[socket.socket] = None
        self._lock = threading.Lock()
        self._whitelist_lock = threading.Lock()
        self._concurrency_sem = threading.BoundedSemaphore(1024)
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
        self.warmup_harvester = WarmUpHarvester(
            self.strategy_engine,
            whitelist_domains=self.whitelist_domains
        ) if (config.auto_strategy and WarmUpHarvester is not None) else None
        try:
            try:
                from flowguard.doh_resolver import MultiDoHHarvester
            except ImportError:
                from Floweryguard.doh_resolver import MultiDoHHarvester
            self.doh_harvester = MultiDoHHarvester(config)
        except Exception:
            self.doh_harvester = None
        try:
            self.dns_failover = get_dns_failover_manager(config)
        except Exception:
            self.dns_failover = None
        self._logged_whitelisted: Set[str] = set()
        self._logged_whitelisted_lock = threading.Lock()
        self.bytes_tx = 0
        self.bytes_rx = 0

    @staticmethod
    def _is_ncsi_request(host: str, path: str = "/") -> bool:
        h = (host or "").lower()
        return "msftncsi" in h or "msftconnecttest" in h

    @staticmethod
    def _handle_ncsi_response(host: str, path: str = "/") -> bytes:
        h = (host or "").lower()
        if "connecttest" in h or "connecttest" in (path or "").lower():
            body = b"Microsoft Connect Test"
        else:
            body = b"Microsoft NCSI"
        return b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" + body

    def _mask_user_agent(self, req: bytes) -> bytes:
        if b"Windows NT" in req:
            return req.replace(b"Windows NT 10.0; Win64; x64", b"Android 14; Mobile").replace(b"Windows NT", b"Android 14")
        return req

    def _check_reload_whitelist(self) -> None:
        """Проверяет изменение whitelist.txt и перезагружает на лету (hot-reload)."""
        now = time.time()
        last_check = getattr(self, "_whitelist_last_check", 0.0)
        if now - last_check < 2.0:
            return
        self._whitelist_last_check = now
        whitelist_path = getattr(self, "whitelist_path", None)
        if whitelist_path and os.path.exists(whitelist_path):
            try:
                mtime = os.path.getmtime(whitelist_path)
                if mtime != getattr(self, "_whitelist_mtime", 0.0):
                    new_domains, _ = load_whitelist_domains(whitelist_path)
                    wl_lock = getattr(self, "_whitelist_lock", None)
                    if wl_lock:
                        with wl_lock:
                            self.whitelist_domains = new_domains
                            self._whitelist_mtime = mtime
                    else:
                        self.whitelist_domains = new_domains
                        self._whitelist_mtime = mtime
                    print(f"\033[96m[*] Whitelist обновлён на лету ({len(new_domains)} доменов из {os.path.basename(whitelist_path)})\033[0m")
            except Exception:
                pass
                pass

    def start(self) -> None:
        """Запускает слушающий сокет прокси сервера."""
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_sock.bind((self.host, self.port))
        except OSError:
            self.server_sock.close()
            self.server_sock = None
            logger.error("Не удалось открыть %s:%s; проверьте, не занят ли порт другой программой", self.host, self.port)
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

        if self.warmup_harvester:
            self.warmup_harvester.start()

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
        if self.warmup_harvester:
            try:
                self.warmup_harvester.stop()
            except Exception:
                pass
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

    def revive_if_needed(self) -> bool:
        """Проверяет слушающий сокет и при необходимости перезапускает прокси."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.4)
            res = s.connect_ex((self.host, self.port))
            s.close()
            if res == 0:
                return False
        except Exception:
            pass

        logger.warning("[Proxy] Слушающий сокет %s:%s не отвечает, выполняется перезапуск...", self.host, self.port)
        try:
            self.stop()
        except Exception:
            pass
        self.start()
        return True

    def _handle_client(self, client_sock: socket.socket, client_addr: Tuple[str, int]) -> None:
        """Обрабатывает одно клиентское подключение."""
        target_sock: Optional[socket.socket] = None
        try:
            client_sock.settimeout(self.timeout)
            try:
                client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)  # scaled from 524288 to 1MB
                client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1048576)  # scaled from 524288 to 1MB
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

                route_network = getattr(getattr(self, 'strategy_engine', None), '_current_network', 'default')
                target_sock = self._connect_target(target_host, target_port)
                if not target_sock:
                    try:
                        client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                        client_sock.shutdown(socket.SHUT_WR)
                    except Exception:
                        pass
                    return

                # Сообщаем клиенту об успешном установлении туннеля
                client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

                # Читаем первый пакет рукопожатия от клиента (TLS ClientHello)
                # Заголовки CONNECT и начало туннеля могут прийти одним чтением.
                separator = b"\r\n\r\n" if b"\r\n\r\n" in raw_req else b"\n\n"
                first_packet = raw_req.partition(separator)[2]
                if not first_packet:
                    first_packet = client_sock.recv(self.buffer_size)
                if not first_packet:
                    return

                # Гарантируем считывание минимум 9 байт для надежного распознавания TLS ClientHello
                first_packet = collect_client_hello(client_sock, first_packet, float(self.timeout))

                target_sock, strat_used, effective_host, init_resp = self._handshake_with_fast_fallback(
                    client_sock, target_sock, target_host, target_port, first_packet
                )
                if not target_sock:
                    _safe_close_socket(client_sock)
                    return

                if init_resp:
                    client_sock.sendall(init_resp)

                # Переходим к двунаправленной пересылке трафика
                self._pipe_sockets(
                    client_sock,
                    target_sock,
                    host=effective_host,
                    strategy=strat_used,
                    got_initial_response=bool(init_resp),
                    tls_tunnel=is_tls_client_hello(first_packet), target_port=target_port,
                    route_network=route_network
                )

            else:
                # Обычный HTTP запрос (не CONNECT)
                self._handle_http_request(client_sock, raw_req, target)
                return

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

    def _handle_http_request(self, client_sock: socket.socket, raw_req: bytes, target: str) -> None:
        """Обрабатывает входящий незашифрованный HTTP-запрос (порт 80).
        
        Если клиент обращается по HTTP к заблокированному или whitelisted хосту (например, http://rutracker.org/),
        немедленно возвращает HTTP 301 Moved Permanently на https://{host}{path},
        чтобы браузер мгновенно перешел на HTTPS без зависания на дропах ТСПУ на 80 порту.
        """
        target_sock = None
        try:
            target_host, target_port, path = self._parse_http_target(raw_req, target)
            if not target_host:
                try:
                    client_sock.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    client_sock.shutdown(socket.SHUT_WR)
                except Exception:
                    pass
                return

            effective_host = target_host
            lower_host = target_host.lower()
            lower_path = path.lower()

            self._check_reload_whitelist()
            is_whitelisted = is_host_in_whitelist(target_host, self.whitelist_domains)
            is_tracker = any(t in lower_host for t in ("rutracker", "nnmclub", "rutor", "kinozal", "t-ru.org"))
            is_yt = is_google_or_youtube_host(lower_host)
            if self.config.ncsi_spoof and self._is_ncsi_request(target_host, path):
                resp = self._handle_ncsi_response(target_host, path)
                try:
                    client_sock.sendall(resp)
                    client_sock.shutdown(socket.SHUT_WR)
                except Exception:
                    pass
                return

            is_ocsp_or_crl = (
                "ocsp" in lower_host
                or "crl" in lower_host
                or lower_host.endswith(".crl")
                or lower_path.endswith(".crl")
                or "/ocsp" in lower_path
            )

            if target_port == 80 and not is_ocsp_or_crl and (is_whitelisted or (not is_plain_ip(target_host) and not is_captive_portal_host(target_host))):
                if not path.startswith("/"):
                    path = "/" + path
                host_part = f"[{target_host}]" if (":" in target_host and not target_host.startswith("[")) else target_host
                redirect_target = f"https://{host_part}{path}"
                resp = (
                    f"HTTP/1.1 301 Moved Permanently\r\n"
                    f"Location: {redirect_target}\r\n"
                    f"Content-Length: 0\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode("latin1")
                try:
                    client_sock.sendall(resp)
                    client_sock.shutdown(socket.SHUT_WR)
                except Exception:
                    pass
                return

            strat_used = "http"
            target_sock = self._connect_target(target_host, target_port)
            if not target_sock:
                try:
                    client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    client_sock.shutdown(socket.SHUT_WR)
                except Exception:
                    pass
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
            mod_req = self._obfuscate_http_request(clean_req, host=target_host)
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
        finally:
            if target_sock:
                _safe_close_socket(target_sock)

    def _try_direct_connect(self, ip: str, port: int, timeout: float = 2.0) -> Optional[socket.socket]:
        """Быстрое прямое подключение к известному рабочему IP без DNS-запроса."""
        s = None
        try:
            family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            s = socket.socket(family, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)  # scaled from 524288 to 1MB
            s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1048576)  # scaled from 524288 to 1MB
            t0 = time.time()
            s.connect((ip, port))
            _set_socket_meta(s, ip, max(0.001, time.time() - t0))
            return s
        except Exception:
            if s:
                _safe_close_socket(s)
            return None

    def flush_stale_caches(self) -> None:
        """Сброс кэша рабочих, мертвых и разрешенных IP."""
        _DEAD_IP_CACHE.clear()
        _WORKING_IP_CACHE.clear()
        _DNS_CACHE.clear()
        _RESOLVED_IPS_CACHE.clear()
        with _SINGLE_FLIGHT_LOCK:
            _HOST_RESOLVE_LOCKS.clear()

    def _resolved_cache_key(self, host):
        """Адреса из DNS одной сети не переносятся в другую при смене профиля на лету."""
        network = getattr(getattr(self, 'strategy_engine', None), '_current_network', 'default')
        return network, host.lower().rstrip('.')

    def _cloudflare_alternatives(self, network, port, candidates):
        """Узлы Cloudflare из той же /16, что и адреса из DNS: узел другой подсети может не обслуживать домен."""
        prefixes = {ip.rsplit('.', 2)[0] for ip in candidates if ':' not in ip and is_cloudflare_anycast_ip(ip)}
        if not prefixes:
            return []
        pool = [CLOUDFLARE_VERIFIED_EDGE_IP] + self.route_health.proven_ips(network, port)
        return [ip for ip in dict.fromkeys(pool)
                if ip not in candidates and ':' not in ip and is_cloudflare_anycast_ip(ip)
                and ip.rsplit('.', 2)[0] in prefixes]

    def _record_route_failure(self, host, port, ip, network=None):
        if not getattr(self, "route_health", None):
            self.route_health = RouteHealth()
        if network is None:
            network = getattr(getattr(self, "strategy_engine", None), "_current_network", "default")
        self.route_health.record(network, host, port, ip, "suspect")

    def _connect_target(self, host: str, port: int, exclude_ip: Optional[Any] = None, target_ip: Optional[str] = None, timeout: Optional[float] = None) -> Optional[socket.socket]:
        """Устанавливает соединение с целевым сервером с авто-перебором IP, фильтрацией мертвых IP и Happy Eyeballs.
        
        Параметр exclude_ip позволяет ротировать IP при блокировках со стороны ТСПУ.
        """
        if "dc-telemetry.net" in host.lower():
            return None

        ipv6_enabled = getattr(getattr(self, "config", None), "ipv6_mode", "disabled") != "disabled"
        if ":" in host and not ipv6_enabled:
            return None

        def available(ip):
            return (ipv6_enabled or ":" not in str(ip)) and not is_ip_dead(ip)

        t_connect_start = time.time()
        candidate_ips = []
        if target_ip and available(target_ip):
            candidate_ips.append(target_ip)
        excluded_set = set()
        if exclude_ip:
            if isinstance(exclude_ip, (set, list, tuple)):
                excluded_set.update(str(x) for x in exclude_ip)
            else:
                excluded_set.add(str(exclude_ip))

        conn_to = timeout if timeout is not None else min(5.0, float(self.timeout))
        health = getattr(self, 'route_health', None)
        network = getattr(getattr(self, 'strategy_engine', None), '_current_network', 'default')

        # 1. Zero-Latency Fast-Path: проверяем кэш известных рабочих IP
        cached_ip = _WORKING_IP_CACHE.get(host)
        if cached_ip and is_googlevideo_host(host) and cached_ip in GOOGLE_EDGE_ANYCAST_IPS:
            _WORKING_IP_CACHE.pop(host, None)
            cached_ip = None
        if cached_ip and is_google_or_youtube_host(host) and not is_googlevideo_host(host) and cached_ip in GOOGLE_VIDEO_ANYCAST_IPS:
            _WORKING_IP_CACHE.pop(host, None)
            cached_ip = None
        if cached_ip and "discord" in str(host).lower():
            h_low = str(host).lower()
            if "cdn" in h_low and cached_ip not in DISCORD_CDN_ANYCAST_IPS:
                _WORKING_IP_CACHE.pop(host, None)
                cached_ip = None
            elif ("media" in h_low or "images-ext" in h_low or "attachments" in h_low) and cached_ip not in DISCORD_MEDIA_ANYCAST_IPS:
                _WORKING_IP_CACHE.pop(host, None)
                cached_ip = None
        if cached_ip and not available(cached_ip):
            _WORKING_IP_CACHE.pop(host, None)
            cached_ip = None
        if cached_ip and health and health.status(network, host, port, cached_ip) != 'progress':
            cached_ip = None
        if cached_ip and cached_ip not in excluded_set and available(cached_ip):
            fast_sock = self._try_direct_connect(cached_ip, port, timeout=min(2.0, conn_to))
            if fast_sock:
                if is_discord_host(host):
                    _RECENT_DISCORD_IPS.set(cached_ip, time.time())
                return fast_sock
            self._record_route_failure(host, port, cached_ip, network)
            _WORKING_IP_CACHE.pop(host, None)

        resolve_key = self._resolved_cache_key(host)

        # 1.1 Zero-Latency RAM-кэш адресов: проверяем _RESOLVED_IPS_CACHE (минуя блокирующий getaddrinfo)
        cached_entry = _RESOLVED_IPS_CACHE.get(resolve_key)
        if cached_entry:
            if isinstance(cached_entry, tuple) and len(cached_entry) == 2:
                c_time, c_ips = cached_entry
                if time.time() - c_time < 300.0:
                    for ip in c_ips:
                        if ip not in candidate_ips and ip not in excluded_set and available(ip):
                            candidate_ips.append(ip)
            elif isinstance(cached_entry, str):
                if cached_entry not in candidate_ips and cached_entry not in excluded_set and available(cached_entry):
                    candidate_ips.append(cached_entry)

        # 2. DNS/DoH резолвинг с Single-Flight блокировкой для исключения лавины параллельных запросов
        if not candidate_ips and not is_plain_ip(host):
            with _get_host_lock(host):
                # Double-check кэш внутри блокировки
                cached_entry = _RESOLVED_IPS_CACHE.get(resolve_key)
                if cached_entry:
                    if isinstance(cached_entry, tuple) and len(cached_entry) == 2:
                        c_time, c_ips = cached_entry
                        if time.time() - c_time < 300.0:
                            for ip in c_ips:
                                if ip not in candidate_ips and ip not in excluded_set and available(ip):
                                    candidate_ips.append(ip)
                    elif isinstance(cached_entry, str):
                        if cached_entry not in candidate_ips and cached_entry not in excluded_set and available(cached_entry):
                            candidate_ips.append(cached_entry)

                # 2.1 Получаем IP-адреса хоста через getaddrinfo (Dual-Stack IPv4 + IPv6)
                if not candidate_ips:
                    try:
                        addr_infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
                        v4_ips = []
                        v6_ips = []
                        for ai in addr_infos:
                            ip_addr = ai[4][0]
                            if ip_addr not in candidate_ips and ip_addr not in excluded_set and not is_bogon_or_sinkhole_ip(ip_addr):
                                if ai[0] == socket.AF_INET:
                                    if ip_addr not in v4_ips:
                                        v4_ips.append(ip_addr)
                                elif ai[0] == socket.AF_INET6 and ipv6_enabled:
                                    if ip_addr not in v6_ips:
                                        v6_ips.append(ip_addr)
                        # В РФ на мобильном интернете IPv4 основной, IPv6 дополнительный
                        for ip in v4_ips:
                            if ip not in candidate_ips and not is_bogon_or_sinkhole_ip(ip):
                                candidate_ips.append(ip)
                        for ip in v6_ips:
                            if ip not in candidate_ips and not is_bogon_or_sinkhole_ip(ip):
                                candidate_ips.append(ip)
                        candidate_ips = [ip for ip in candidate_ips if not is_bogon_or_sinkhole_ip(ip)]
                    except Exception:
                        pass

                # 2.2 Проверка whitelist
                self._check_reload_whitelist()
                wl_lock = getattr(self, "_whitelist_lock", None)
                if wl_lock:
                    with wl_lock:
                        wl = getattr(self, "whitelist_domains", set())
                else:
                    wl = getattr(self, "whitelist_domains", set())
                is_whitelisted = is_host_in_whitelist(host, wl) and not is_googlevideo_host(host)

                # 2.3 DoH / Failover DNS:
                # Если candidate_ips уже имеет валидные IP (из кэша или getaddrinfo),
                # НЕ выполняем синхронный DoH для предотвращения сетевой лавины (особенно для Discord CDN).
                # Исключение: для заблокированных доменов из whitelist (кроме Discord) или при отсутствии IP / кастомном DNS
                # запрашиваем DoH и ставим чистые DoH адреса в НАЧАЛО candidate_ips, обходя отравленные оператором IP.
                need_doh = False
                has_custom_dns = getattr(getattr(self, "config", None), "enable_custom_dns", False)
                if not candidate_ips or has_custom_dns or host in _DNS_CACHE:
                    need_doh = True
                elif is_whitelisted and not is_discord_network_host(host):
                    need_doh = True

                if need_doh:
                    doh_resolved = []
                    if self.doh_harvester:
                        try:
                            harvested = self.doh_harvester.harvest(host)
                            for hip in (harvested or []):
                                if hip not in doh_resolved and hip not in excluded_set and available(hip) and not is_bogon_or_sinkhole_ip(hip):
                                    doh_resolved.append(hip)
                        except Exception:
                            pass
                    if not doh_resolved and self.dns_failover:
                        try:
                            failover_ips = self.dns_failover.resolve(host)
                            for fip in (failover_ips or []):
                                if fip not in doh_resolved and fip not in excluded_set and available(fip) and not is_bogon_or_sinkhole_ip(fip):
                                    doh_resolved.append(fip)
                            if failover_ips:
                                valid_fips = [ip for ip in failover_ips if not is_bogon_or_sinkhole_ip(ip)]
                                if valid_fips:
                                    _DNS_CACHE.set(host.lower().strip("."), valid_fips[0])
                        except Exception:
                            pass

                    if doh_resolved and host.lower().strip(".") not in _DNS_CACHE:
                        _DNS_CACHE.set(host.lower().strip("."), doh_resolved[0])

                    if doh_resolved:
                        if is_whitelisted:
                            # Для whitelist ставим чистые DoH адреса в НАЧАЛО candidate_ips, обходя отравленные оператором IP
                            candidate_ips = doh_resolved + [ip for ip in candidate_ips if ip not in doh_resolved]
                        else:
                            for hip in doh_resolved:
                                if hip not in candidate_ips:
                                    candidate_ips.append(hip)

                    if not candidate_ips:
                        fallback_ip = resolve_fallback_dns(host, self.config)
                        if fallback_ip:
                            flattened = []
                            if isinstance(fallback_ip, (list, tuple)):
                                for item in fallback_ip:
                                    if isinstance(item, (list, tuple)):
                                        flattened.extend(str(x) for x in item if isinstance(x, str))
                                    elif isinstance(item, str):
                                        flattened.append(item)
                            elif isinstance(fallback_ip, str):
                                flattened.append(fallback_ip)
                            for fip in flattened:
                                if fip not in candidate_ips and fip not in excluded_set and available(fip) and not is_bogon_or_sinkhole_ip(fip):
                                    candidate_ips.append(fip)

                if candidate_ips:
                    _RESOLVED_IPS_CACHE.set(resolve_key, (time.time(), list(candidate_ips)))

        # 4. Фильтруем заведомо мёртвые / сбрасывающие IP и исключенные адреса
        raw_candidates = [ip for ip in candidate_ips if (ipv6_enabled or ":" not in ip) and not is_bogon_or_sinkhole_ip(ip)]
        candidate_ips = [ip for ip in candidate_ips if available(ip) and ip not in excluded_set and not is_bogon_or_sinkhole_ip(ip)]

        if is_googlevideo_host(host) and not is_plain_ip(host):
            for a_ip in GOOGLE_VIDEO_ANYCAST_IPS:
                if a_ip not in candidate_ips and a_ip not in excluded_set and available(a_ip):
                    candidate_ips.append(a_ip)
        elif is_google_or_youtube_host(host) and not is_plain_ip(host):
            h_thumb = str(host).lower().rstrip(".")
            is_thumbnail = any(p in h_thumb for p in ("ytimg.com", "ggpht.com", "googleusercontent.com"))
            healthy_yt_anycast = [ip for ip in YOUTUBE_WEB_ANYCAST_IPS if ip not in excluded_set and available(ip)]
            if is_thumbnail:
                # Для хостов обложек и аватарок (ytimg.com, ggpht.com, googleusercontent.com) ставим проверенные Anycast IP в начало списка,
                # исключая зависания на заблокированных провайдерских DNS IP (108.177.14.119, 74.125.131.198)
                candidate_ips = healthy_yt_anycast + [ip for ip in candidate_ips if ip not in healthy_yt_anycast]
            else:
                for a_ip in healthy_yt_anycast:
                    if a_ip not in candidate_ips:
                        candidate_ips.append(a_ip)

        h_disc = str(host).lower().strip() if host else ""
        if h_disc.startswith("[") and "]" in h_disc:
            h_disc = h_disc[1:h_disc.find("]")]
        elif ":" in h_disc:
            h_disc = h_disc.split(":")[0]
        h_disc = h_disc.rstrip(".")

        is_net_discord = is_discord_network_host(h_disc)
        is_core_discord = (
            h_disc in ("discord.com", "gateway.discord.gg")
            or h_disc.endswith(".discord.com")
            or h_disc.endswith(".discord.gg")
        ) and not h_disc.endswith(".discord.media")
        is_media_dc = is_discord_media_host(h_disc)
        is_discord_media_target = is_media_dc and (
            "discord" in h_disc or h_disc.endswith(".discordapp.com") or h_disc.endswith(".discordapp.net") or h_disc.endswith(".discordcdn.com")
        )

        # NXDOMAIN Trap: несуществующие поддомены не должны подменять DNS на Anycast IP Cloudflare.
        # Если DNS/DoH не вернул адресов для домена, разрешаем Anycast-пул только для известных базовых хостов Discord.
        KNOWN_DISCORD_ANYCAST_DOMAINS = (
            "discord.com", "www.discord.com", "gateway.discord.gg",
            "cdn.discordapp.com", "media.discordapp.net", "attachments.discord.net"
        )
        if (is_net_discord or is_discord_media_target) and not raw_candidates and not is_plain_ip(host):
            if not (h_disc in KNOWN_DISCORD_ANYCAST_DOMAINS or h_disc.startswith("images-ext-") or "attachments" in h_disc):
                return None

        target_discord_pool = []
        if (is_net_discord or is_discord_media_target) and not is_plain_ip(host):
            if "gateway" in h_disc or h_disc.endswith(".discord.gg") or h_disc == "discord.gg":
                target_discord_pool = [ip for ip in DISCORD_CORE_ANYCAST_IPS if ip.endswith(".234")]
            elif h_disc.endswith("cdn.discordapp.com") or h_disc == "cdn.discordapp.com":
                target_discord_pool = DISCORD_CDN_ANYCAST_IPS
            elif "media" in h_disc or "images-ext" in h_disc or "attachments" in h_disc or is_discord_media_target:
                target_discord_pool = DISCORD_MEDIA_ANYCAST_IPS
            elif is_core_discord or h_disc in ("discord.com", "www.discord.com"):
                target_discord_pool = [
                    "162.159.136.232", "162.159.137.232", "162.159.138.232",
                    "162.159.128.233", "162.159.129.233", "162.159.130.233"
                ]
            else:
                target_discord_pool = DISCORD_CLOUDFLARE_ANYCAST_IPS

            verified_candidates = [
                ip for ip in target_discord_pool
                if ip not in excluded_set and available(ip)
            ]
            other_candidates = [
                ip for ip in candidate_ips
                if ip not in verified_candidates and ip not in excluded_set and available(ip)
            ]
            candidate_ips = verified_candidates + other_candidates if verified_candidates else other_candidates

        if not candidate_ips:
            if is_googlevideo_host(host) and not is_plain_ip(host):
                service_pool = list(GOOGLE_VIDEO_ANYCAST_IPS)
            elif is_google_or_youtube_host(host) and not is_plain_ip(host):
                service_pool = list(YOUTUBE_WEB_ANYCAST_IPS)
            elif (is_net_discord or is_discord_media_target) and not is_plain_ip(host):
                service_pool = list(target_discord_pool)
            else:
                service_pool = []
            potential = [
                ip for ip in (list(dict.fromkeys(service_pool + raw_candidates)) if service_pool else raw_candidates)
                if ip not in excluded_set and not is_bogon_or_sinkhole_ip(ip)
            ]
            if potential:
                now = time.time()
                for ip in potential:
                    d_until = _DEAD_IP_CACHE.get(ip)
                    if d_until is not None and now >= d_until:
                        _DEAD_IP_CACHE.pop(ip, None)
                alive_now = [ip for ip in potential if available(ip)]
                if alive_now:
                    candidate_ips = alive_now
                elif service_pool:
                    # Для ключевых сервисов (Discord/YouTube Anycast): предотвращаем Deadlock / 502 Bad Gateway
                    # Оживляем наименее недавний сбой (с наименьшим dead_until / старейший бан)
                    potential.sort(key=lambda ip: _DEAD_IP_CACHE.get(ip) or 0)
                    best_ip = potential[0]
                    _DEAD_IP_CACHE.pop(best_ip, None)
                    candidate_ips = [best_ip]
                    if len(potential) > 1:
                        second_ip = potential[1]
                        _DEAD_IP_CACHE.pop(second_ip, None)
                        candidate_ips.append(second_ip)
                else:
                    return None
            elif host not in excluded_set and not is_bogon_or_sinkhole_ip(host):
                candidate_ips.append(host)
            else:
                return None

        # 4.1 Happy Eyeballs IP Rotation для Discord:
        # Для Gateway и Core Web Discord (discord.com) приоритетом #1 ВСЕГДА являются доказанно
        # работающие через ТСПУ узлы (162.159.134.234 для gateway и 162.159.136.232 для discord.com).
        # Ротация на вторичные узлы выполняется ТОЛЬКО если первичный узел помечен как мертвый (dead).
        # Для Media/CDN сначала используем тот же узел: остальные адреса могут пройти TLS,
        # но зависнуть после 14–16 КБ. Мёртвые и явно исключённые адреса остаются вне выбора.
        if (is_net_discord or is_discord_media_target) and len(candidate_ips) > 1:
            global _DISCORD_IP_ROTATION_INDEX
            is_gw_host = ("gateway" in h_disc or h_disc.endswith(".discord.gg") or h_disc == "discord.gg")
            if is_gw_host:
                pool = ["162.159.134.234", "162.159.136.234", "162.159.130.234", "162.159.133.234", "162.159.128.234"]
                pinned_primary = "162.159.134.234"
            elif is_core_discord or h_disc in ("discord.com", "www.discord.com"):
                pool = [
                    "162.159.136.232", "162.159.137.232", "162.159.138.232",
                    "162.159.128.233", "162.159.129.233", "162.159.130.233"
                ]
                pinned_primary = "162.159.136.232"
            elif h_disc.endswith("cdn.discordapp.com") or h_disc == "cdn.discordapp.com":
                pool = DISCORD_CDN_ANYCAST_IPS
                pinned_primary = "162.159.136.232"
            elif "media" in h_disc or "images-ext" in h_disc or "attachments" in h_disc or is_discord_media_target:
                pool = DISCORD_MEDIA_ANYCAST_IPS
                pinned_primary = "162.159.136.232"
            else:
                pool = DISCORD_CLOUDFLARE_ANYCAST_IPS
                pinned_primary = None
            verified = [ip for ip in pool if ip in candidate_ips]
            non_verified = [ip for ip in candidate_ips if ip not in verified]
            if pinned_primary and pinned_primary in verified and available(pinned_primary):
                other_v = [ip for ip in verified if ip != pinned_primary]
                candidate_ips = [pinned_primary] + other_v + non_verified
            elif verified:
                fresh_v = [ip for ip in verified if ip not in _RECENT_DISCORD_IPS]
                stale_v = [ip for ip in verified if ip in _RECENT_DISCORD_IPS]
                with _DISCORD_IP_ROTATION_LOCK:
                    is_media_flow = ("cdn" in h_disc or "media" in h_disc or "images-ext" in h_disc or "attachments" in h_disc or is_discord_media_target)
                    golden_ips = (
                        "162.159.130.233", "162.159.129.233", "162.159.133.233", "162.159.134.233", "162.159.128.233",
                        "162.159.128.232", "162.159.129.232", "162.159.130.232", "162.159.136.232", "162.159.137.232"
                    )
                    if fresh_v:
                        if is_media_flow:
                            pref_v = [ip for ip in golden_ips if ip in fresh_v]
                            tail_v = [ip for ip in fresh_v if ip not in pref_v and not ("162.159.135." in ip or (ip.startswith("162.159.134.") and not ip.endswith(".234")))]
                        else:
                            pref_v = [ip for ip in fresh_v if not ("162.159.135." in ip or (ip.startswith("162.159.134.") and not ip.endswith(".234")))]
                            tail_v = [ip for ip in fresh_v if ip not in pref_v]
                        if pref_v:
                            _DISCORD_IP_ROTATION_INDEX = (_DISCORD_IP_ROTATION_INDEX + 1) % len(pref_v)
                            rot = _DISCORD_IP_ROTATION_INDEX
                            candidate_ips = pref_v[rot:] + pref_v[:rot] + tail_v + stale_v + non_verified
                        else:
                            _DISCORD_IP_ROTATION_INDEX = (_DISCORD_IP_ROTATION_INDEX + 1) % len(fresh_v)
                            rot = _DISCORD_IP_ROTATION_INDEX
                            candidate_ips = fresh_v[rot:] + fresh_v[:rot] + stale_v + non_verified
                    else:
                        if is_media_flow:
                            pref_all = [ip for ip in golden_ips if ip in verified]
                            tail_all = [ip for ip in verified if ip not in pref_all and not ("162.159.135." in ip or (ip.startswith("162.159.134.") and not ip.endswith(".234")))]
                        else:
                            pref_all = [ip for ip in verified if not ("162.159.135." in ip or (ip.startswith("162.159.134.") and not ip.endswith(".234")))]
                            tail_all = [ip for ip in verified if ip not in pref_all]
                        if pref_all:
                            _DISCORD_IP_ROTATION_INDEX = (_DISCORD_IP_ROTATION_INDEX + 1) % len(pref_all)
                            rot = _DISCORD_IP_ROTATION_INDEX
                            candidate_ips = pref_all[rot:] + pref_all[:rot] + tail_all + non_verified
                        else:
                            _DISCORD_IP_ROTATION_INDEX = (_DISCORD_IP_ROTATION_INDEX + 1) % len(verified)
                            rot = _DISCORD_IP_ROTATION_INDEX
                            candidate_ips = verified[rot:] + verified[:rot] + non_verified
            else:
                fresh = [ip for ip in candidate_ips if ip not in _RECENT_DISCORD_IPS]
                stale = [ip for ip in candidate_ips if ip in _RECENT_DISCORD_IPS]
                with _DISCORD_IP_ROTATION_LOCK:
                    if fresh:
                        _DISCORD_IP_ROTATION_INDEX = (_DISCORD_IP_ROTATION_INDEX + 1) % len(fresh)
                        rot = _DISCORD_IP_ROTATION_INDEX
                        candidate_ips = fresh[rot:] + fresh[:rot] + stale
                    else:
                        _DISCORD_IP_ROTATION_INDEX = (_DISCORD_IP_ROTATION_INDEX + 1) % len(candidate_ips)
                        rot = _DISCORD_IP_ROTATION_INDEX
                        candidate_ips = candidate_ips[rot:] + candidate_ips[:rot]

        # Cloudflare обслуживает домен и на других узлах своей сети, а ТСПУ обрывает передачу
        # лишь на части адресов: при зависании адресов из DNS пробуем узлы той же /16,
        # через которые в этой сети уже прошли данные.
        if health and not is_plain_ip(host):
            candidate_ips += [ip for ip in self._cloudflare_alternatives(network, port, candidate_ips)
                              if ip not in excluded_set and available(ip)]

        # Передача данных важнее доступности TCP и начального приоритета Anycast.
        if health:
            candidate_ips = health.rank(network, host, port, candidate_ips)

        # 5. Если кандидат всего один - прямое подключение
        if len(candidate_ips) == 1:
            primary_ip = candidate_ips[0]
            s = None
            has_doh = not is_plain_ip(host) and bool(self.dns_failover or self.doh_harvester or getattr(getattr(self, "config", None), "enable_custom_dns", False))
            primary_to = min(1.5, conn_to) if has_doh else conn_to
            try:
                family = socket.AF_INET6 if ":" in primary_ip else socket.AF_INET
                s = socket.socket(family, socket.SOCK_STREAM)
                s.settimeout(primary_to)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1048576)
                t_conn = time.time()
                s.connect((primary_ip, port))
                _set_socket_meta(s, primary_ip, max(0.001, time.time() - t_conn))
                if is_discord_host(host):
                    _RECENT_DISCORD_IPS.set(primary_ip, time.time())
                return s
            except Exception:
                if s:
                    _safe_close_socket(s)
                self._record_route_failure(host, port, primary_ip, network)
                _WORKING_IP_CACHE.pop(host, None)

                # Немедленный DoH Failover на случай мертвого / отравленного IP (local hosts, DNS poisoning)
                doh_candidates = []
                if self.dns_failover:
                    try:
                        resolved = self.dns_failover.resolve(host)
                        for dip in (resolved or []):
                            if dip and dip != primary_ip and dip not in excluded_set and available(dip) and not is_bogon_or_sinkhole_ip(dip):
                                if dip not in doh_candidates:
                                    doh_candidates.append(dip)
                    except Exception:
                        pass
                if self.doh_harvester:
                    try:
                        harvested = self.doh_harvester.harvest(host)
                        for hip in (harvested or []):
                            if hip and hip != primary_ip and hip not in excluded_set and available(hip) and not is_bogon_or_sinkhole_ip(hip):
                                if hip not in doh_candidates:
                                    doh_candidates.append(hip)
                    except Exception:
                        pass

                if doh_candidates:
                    for dip in doh_candidates:
                        s_doh = None
                        try:
                            f_doh = socket.AF_INET6 if ":" in dip else socket.AF_INET
                            s_doh = socket.socket(f_doh, socket.SOCK_STREAM)
                            s_doh.settimeout(min(2.5, conn_to))
                            s_doh.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                            s_doh.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                            s_doh.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
                            s_doh.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1048576)
                            t_conn2 = time.time()
                            s_doh.connect((dip, port))
                            _set_socket_meta(s_doh, dip, max(0.001, time.time() - t_conn2))
                            if is_discord_host(host):
                                _RECENT_DISCORD_IPS.set(dip, time.time())
                            _DNS_CACHE.set(host.lower().strip("."), dip)
                            return s_doh
                        except Exception:
                            if s_doh:
                                _safe_close_socket(s_doh)
                            self._record_route_failure(host, port, dip, network)

                # Резервная попытка через fallback DNS перед отказом
                fallback_ip = resolve_fallback_dns(host, self.config)
                if fallback_ip:
                    if isinstance(fallback_ip, (list, tuple)):
                        fallback_ip = fallback_ip[0] if fallback_ip else None
                    if fallback_ip and fallback_ip != primary_ip and fallback_ip not in excluded_set and available(fallback_ip):
                        s2 = None
                        try:
                            family2 = socket.AF_INET6 if ":" in fallback_ip else socket.AF_INET
                            s2 = socket.socket(family2, socket.SOCK_STREAM)
                            s2.settimeout(conn_to)
                            s2.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                            s2.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                            s2.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
                            s2.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1048576)
                            t_conn = time.time()
                            s2.connect((fallback_ip, port))
                            _set_socket_meta(s2, fallback_ip, max(0.001, time.time() - t_conn))
                            if is_discord_host(host):
                                _RECENT_DISCORD_IPS.set(fallback_ip, time.time())
                            return s2
                        except Exception:
                            if s2:
                                _safe_close_socket(s2)
                            self._record_route_failure(host, port, fallback_ip, network)
                return None

        # 6. Happy Eyeballs (RFC 8305): каскадный опрос нескольких IP с задержкой 120 мс
        connecting = {}
        stagger_delay = 0.12
        end_time = time.time() + conn_to

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
                        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
                        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1048576)
                    except Exception:
                        pass
                    _set_socket_meta(s, target_ip, max(0.001, time.time() - t_conn))
                    if is_discord_host(host):
                        _RECENT_DISCORD_IPS.set(target_ip, time.time())
                    for other in connecting:
                        try:
                            other.close()
                        except Exception:
                            pass
                    return s
                elif err in (10035, 115, 11):  # WSAEWOULDBLOCK, EINPROGRESS, EAGAIN
                    connecting[s] = (target_ip, t_conn)
                else:
                    # Немедленный отказ (WSAECONNREFUSED 10061, WSAENETUNREACH и др.)
                    self._record_route_failure(host, port, target_ip, network)
                    try:
                        s.close()
                    except Exception:
                        pass
                    continue
            except Exception:
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass
                continue

            wait_time = stagger_delay if i < len(candidate_ips) - 1 else max(0.1, end_time - time.time())
            try:
                _, writable, exceptional = select.select([], list(connecting.keys()), list(connecting.keys()), max(0.01, wait_time))
            except Exception:
                writable, exceptional = [], []

            for es in exceptional:
                info = connecting.pop(es, None)
                failed_ip = info[0] if isinstance(info, tuple) else info
                if failed_ip:
                    self._record_route_failure(host, port, failed_ip, network)
                try:
                    es.close()
                except Exception:
                    pass

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
                        ws.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
                        ws.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1048576)
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
                    if is_discord_host(host):
                        _RECENT_DISCORD_IPS.set(win_ip, time.time())
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
                        self._record_route_failure(host, port, failed_ip, network)
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
                        ws.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
                        ws.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1048576)
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
                    if is_discord_host(host):
                        _RECENT_DISCORD_IPS.set(win_ip, time.time())
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
                        self._record_route_failure(host, port, failed_ip, network)
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

        # Если все candidate_ips провалились, пробуем DoH Failover перед окончательным отказом
        doh_candidates = []
        if self.dns_failover:
            try:
                resolved = self.dns_failover.resolve(host)
                for dip in (resolved or []):
                    if dip and dip not in candidate_ips and dip not in excluded_set and available(dip) and not is_bogon_or_sinkhole_ip(dip):
                        if dip not in doh_candidates:
                            doh_candidates.append(dip)
            except Exception:
                pass
        if self.doh_harvester:
            try:
                harvested = self.doh_harvester.harvest(host)
                for hip in (harvested or []):
                    if hip and hip not in candidate_ips and hip not in excluded_set and available(hip) and not is_bogon_or_sinkhole_ip(hip):
                        if hip not in doh_candidates:
                            doh_candidates.append(hip)
            except Exception:
                pass

        for dip in doh_candidates:
            s_doh = None
            try:
                family_doh = socket.AF_INET6 if ":" in dip else socket.AF_INET
                s_doh = socket.socket(family_doh, socket.SOCK_STREAM)
                s_doh.settimeout(min(2.5, conn_to))
                s_doh.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                s_doh.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                s_doh.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
                s_doh.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1048576)
                t_conn2 = time.time()
                s_doh.connect((dip, port))
                _set_socket_meta(s_doh, dip, max(0.001, time.time() - t_conn2))
                if is_discord_host(host):
                    _RECENT_DISCORD_IPS.set(dip, time.time())
                _DNS_CACHE.set(host.lower().strip("."), dip)
                return s_doh
            except Exception:
                if s_doh:
                    _safe_close_socket(s_doh)
                self._record_route_failure(host, port, dip, network)

        return None

    def _safe_execute_strategy(self, strategy: str, sock: socket.socket, data: bytes, host: Optional[str] = None) -> bool:
        """Безопасное применение стратегии обхода DPI к сокету с перехватом возможных сетевых ошибок."""
        try:
            if strategy == "direct":
                sock.sendall(data)
                return True
            execute_strategy(strategy, sock, data, delay=self.config.fragment_delay)
            return True
        except (socket.error, OSError, ConnectionResetError) as e:
            logger.debug(f"Ошибка при выполнении стратегии {strategy}: {e}")
            return False

    def _probe_socket_response(self, sock: socket.socket, t_send: float, base_rtt: float, strat: str, probe_timeout: Optional[float] = None) -> Tuple[str, Optional[bytes], float]:
        """Опрашивает сокет на предмет ответа сервера или сброса ТСПУ.
        
        Возвращает кортеж: (статус, данные_ответа, задержка_мс).
        Статусы: 'success', 'rst_fast', 'rst_server', 'silent_drop', 'error'.
        """
        if probe_timeout is None:
            probe_timeout = min(1.8, max(0.60, base_rtt * 3.5))
        try:
            readable, _, exceptional = select.select([sock], [], [sock], probe_timeout)
        except Exception:
            readable, exceptional = [], [sock]

        delta = time.time() - t_send
        delta_ms = delta * 1000.0

        if exceptional:
            if delta < base_rtt * 0.4 or delta < 0.015:
                return "rst_fast", None, delta_ms
            return "rst_server", None, delta_ms

        if readable:
            try:
                resp = sock.recv(self.buffer_size)
            except (ConnectionResetError, socket.error):
                resp = b""

            if resp:
                if resp[0] == 0x15:
                    # TLS Alert (handshake failure / protocol error от сервера или инъекция ТСПУ)
                    return "rst_server", None, delta_ms
                if resp.startswith((b"HTTP/1.1 4", b"HTTP/1.0 4", b"HTTP/1.1 5", b"HTTP/1.0 5", b"HTTP/1.1 3", b"HTTP/1.0 3")):
                    # Инъекция plain text HTTP заглушки блокировки провайдером
                    return "rst_server", None, delta_ms
                return "success", resp, delta_ms
            else:
                if delta < base_rtt * 0.5 or delta < 0.020:
                    return "rst_fast", None, delta_ms
                return "rst_server", None, delta_ms

        return "silent_drop", None, delta_ms

    def _fixed_strategy(self, host):
        """Стратегия, которую не меняют ни обучение, ни Fast-Fallback; None — выбор адаптивный."""
        config = getattr(self, "config", None)
        if config is None:
            return None
        if is_gaming_host(host) or is_telegram_host(host):
            return "direct"
        is_discord = is_discord_host(host)
        is_youtube = is_google_or_youtube_host(host.lower())
        if config.only_target_domains and not (is_discord or is_youtube):
            with self._whitelist_lock:
                if not is_host_in_whitelist(host, self.whitelist_domains):
                    return "direct"
        if not config.auto_strategy:
            strategy = config.default_strategy
            if is_youtube:
                strategy = "combo_tlsrec_tcpsplit"
            elif not is_discord and strategy in ("disoob_sni", "boringssl_split", "dummy_record_prepend"):
                strategy = "tcp_split_sni_mid"
            return self.strategy_engine.allowed_strategy(strategy)
        return None

    def _strategy_after_stall(self, host, port, ip, selected, excluded=()):
        """После зависания пробует иную технику только для этой сети и сайта."""
        health = getattr(self, 'route_health', None)
        if health is None or self._fixed_strategy(host) is not None:
            return selected
        if self.strategy_engine.get_user_override(host):
            return selected
        network = getattr(self.strategy_engine, '_current_network', 'default')
        stalled = health.stalled_strategies(network, host, port)
        avoid = stalled | set(excluded)
        for candidate in health.progressing_strategies(network, host, port):
            if candidate not in avoid and self.strategy_engine.allowed_strategy(candidate) == candidate:
                return candidate
        if selected not in stalled:
            return selected
        with self._whitelist_lock:
            whitelisted = is_host_in_whitelist(host, self.whitelist_domains)
        alternative = self.strategy_engine.get_fallback_strategy(
            host, failed_strategy=selected, failed_strategies=avoid, ip=ip,
            is_youtube=is_google_or_youtube_host(host), is_discord=is_discord_host(host),
            is_whitelisted=whitelisted, is_tspu=False)
        alternative = self.strategy_engine.allowed_strategy(alternative)
        logger.info('[Передача] %s:%s: после зависания %s пробуем %s', host, port, selected, alternative)
        return alternative

    def _send_tls_client_hello_with_bypass(
        self,
        target_sock: socket.socket,
        data: bytes,
        target_host: str,
        ip: Optional[str] = None,
        target_port: int = 443
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

        fixed = self._fixed_strategy(sni_name)
        if fixed is not None:
            self._safe_execute_strategy(fixed, target_sock, data, host=sni_name)
            return fixed, sni_name

        # Тандем с zapret: первая попытка без десинка Flowery, чтобы не было двойного десинка.
        # Если zapret сайт не пробил, Fast-Fallback переходит к обходу Flowery.
        # Для Discord всегда сохраняем TLS-десинк Flowery.
        try:
            winws_tcp = not is_discord and is_winws_tcp_filtering_active(strict=True)
        except Exception:
            winws_tcp = False
        if winws_tcp:
            target_sock.sendall(data)
            return "direct", sni_name

        if self.config.whitelist_fake_sni_record and not is_discord:
            if self.sni_spoofer.send_with_fake_sni_desync(target_sock, data):
                return "fake_sni_record", sni_name
            target_sock.sendall(data)
            return "direct", sni_name

        # Движок адаптивных стратегий (Thompson Sampling в стиле Nova)
        strategy = self.strategy_engine.select_strategy(
            sni_name,
            is_youtube=is_youtube,
            is_discord=is_discord,
            ip=ip,
            is_whitelisted=is_whitelisted
        )
        strategy = self._strategy_after_stall(sni_name, target_port, ip, strategy)
        self._safe_execute_strategy(strategy, target_sock, data, host=sni_name)
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
        MAX_FALLBACK_BUDGET = 8.0
        start_time = time.time()

        def remaining_budget() -> float:
            return max(0.05, MAX_FALLBACK_BUDGET - (time.time() - start_time))

        meta = _get_socket_meta(current_sock)
        current_ip = meta.get("target_ip")
        base_rtt = meta.get("connect_rtt", 0.050)

        # 1. Первая попытка отправки ClientHello (strat1)
        strat1, effective_host = self._send_tls_client_hello_with_bypass(
            current_sock, first_packet, target_host, ip=current_ip, target_port=target_port
        )
        fixed_strategy = self._fixed_strategy(effective_host)
        t_send1 = time.time()

        is_dc = is_discord_host(effective_host)
        if is_discord_media_host(effective_host) or is_dc:
            min_floor = 0.65
            adaptive_floor1 = max(0.25, min(0.95, base_rtt * 3.0 + min_floor))
        else:
            adaptive_floor1 = max(0.18, min(0.65, base_rtt * 3.0 + 0.35))
        timeout1 = min(remaining_budget() * 0.55, max(adaptive_floor1, min(1.20, base_rtt * 3.0 + 0.20)))
        status1, resp1, delta_ms1 = self._probe_socket_response(current_sock, t_send1, base_rtt, strat1, probe_timeout=timeout1)
        is_tspu = False

        if status1 == "success":
            if self.shadow_prober:
                self.shadow_prober.maybe_enqueue(effective_host, ip=current_ip)
            return current_sock, strat1, effective_host, resp1
        elif status1 in ("rst_fast", "rst_server"):
            is_tspu = True
            logger.warning(
                f"[!] RST детекция ({status1}): {effective_host} ({current_ip or 'IP'}) "
                f"сброс за {delta_ms1:.1f}мс (базовый RTT {base_rtt*1000:.1f}мс, strat={strat1}) -> Fast-Fallback..."
            )
        elif status1 == "silent_drop":
            is_yt = is_google_or_youtube_host(effective_host.lower())
            is_tspu = True
            if strat1 in ("direct", "boringssl_split", "tcp_split_sni_start") or is_yt:
                logger.warning(
                    f"[!] ТСПУ Silent Drop: {effective_host} ({current_ip or 'IP'}) "
                    f"тишина > {delta_ms1:.0f}мс (strat={strat1}) -> Мгновенный обход..."
                )
            else:
                logger.info(
                    f"[!] Drop на стратегию ({strat1}): {effective_host} "
                    f"тишина > {delta_ms1:.0f}мс -> Fallback на альтернативу..."
                )
        else:
            is_tspu = False
            logger.info(
                f"[*] Ошибка сокета на первой попытке ({status1}): {effective_host} ({current_ip or 'IP'}) "
                f"-> Fast-Fallback..."
            )

        # 2. Неуспешная первая попытка: Запускаем Transparent Fast-Fallback
        _safe_close_socket(current_sock)
        _WORKING_IP_CACHE.pop(effective_host, None)

        is_yt = is_google_or_youtube_host(effective_host.lower())
        is_dc = is_discord_host(effective_host)
        is_gm = is_gaming_host(effective_host)
        with self._whitelist_lock:
            is_wl = is_host_in_whitelist(effective_host, self.whitelist_domains)
        is_whitelisted = is_wl

        # Fast-Path: при мертвом узле GGC IP (silent_drop на YouTube) или для Discord Media
        # пропускаем Attempt 2, сразу ротируя IP на Попытке 3 (combo_tlsrec_tcpsplit - единственный рабочий режим).
        skip_attempt2_fast_path = (is_yt and status1 == "silent_drop") or is_discord_media_host(effective_host)

        if skip_attempt2_fast_path and current_ip and is_dc:
            _RECENT_DISCORD_IPS.set(current_ip, time.time())

        self.strategy_engine.record_failure(effective_host, strat1, ip=current_ip, is_tspu=is_tspu)

        strat2 = self.strategy_engine.get_fallback_strategy(
            effective_host,
            failed_strategy=strat1,
            is_youtube=is_yt,
            is_discord=is_dc,
            ip=current_ip,
            is_tspu=is_tspu,
            is_whitelisted=is_wl
        )
        if fixed_strategy is not None:
            strat2 = fixed_strategy
        if is_gm:
            strat2 = "direct"
            skip_attempt2_fast_path = False

        strat2 = self._strategy_after_stall(effective_host, target_port, current_ip, strat2, (strat1,))

        # Попытка 2: тот же IP, альтернативная стратегия (если не пропущена через Fast-Path)
        strat2_executed = False
        if not skip_attempt2_fast_path and current_ip:
            if is_dc or is_yt or is_whitelisted:
                adaptive_floor2 = max(0.85, min(1.50, base_rtt * 3.0 + 0.60))
                timeout2 = max(1.20, min(remaining_budget() * 0.45, max(adaptive_floor2, min(2.50, base_rtt * 2.5 + 0.60))))
            else:
                adaptive_floor2 = max(0.25, min(0.60, base_rtt * 3.0 + 0.10))
                timeout2 = min(remaining_budget() * 0.45, max(adaptive_floor2, min(1.20, base_rtt * 2.5 + 0.25)))
            sock2 = self._connect_target(target_host, target_port, target_ip=current_ip, timeout=timeout2)
            if sock2:
                meta2 = _get_socket_meta(sock2)
                base_rtt2 = meta2.get("connect_rtt", base_rtt)
                t_send2 = time.time()
                if self._safe_execute_strategy(strat2, sock2, first_packet, host=effective_host):
                    strat2_executed = True
                    status2, resp2, delta_ms2 = self._probe_socket_response(sock2, t_send2, base_rtt2, strat2, probe_timeout=timeout2)
                    if status2 == "success":
                        return sock2, strat2, effective_host, resp2
                _safe_close_socket(sock2)
                self._record_route_failure(effective_host, target_port, meta2.get("target_ip", current_ip))

        # Попытка 3: ДРУГОЙ живой IP
        if is_dc or is_yt or is_whitelisted:
            adaptive_floor3 = max(0.85, min(1.50, base_rtt * 3.0 + 0.60))
        else:
            adaptive_floor3 = max(0.25, min(0.60, base_rtt * 3.0 + 0.10))
        connect_to3 = min(2.5, remaining_budget() * 0.7)
        exclude_set = {current_ip} if current_ip else set()
        new_sock = self._connect_target(target_host, target_port, exclude_ip=exclude_set, timeout=connect_to3)
        if not new_sock:
            new_sock = self._connect_target(target_host, target_port, timeout=connect_to3)

        if not new_sock:
            target_err_ip = current_ip
            if target_err_ip:
                self._record_route_failure(effective_host, target_port, target_err_ip)
            return None, strat1, effective_host, None

        meta_new = _get_socket_meta(new_sock)
        new_ip = meta_new.get("target_ip", current_ip)
        base_rtt_new = meta_new.get("connect_rtt", base_rtt)

        failed_so_far = {strat1}
        if strat2_executed:
            failed_so_far.add(strat2)

        if new_ip and current_ip:
            is_rotated_ip = (new_ip != current_ip)
        else:
            is_rotated_ip = bool(new_sock and new_sock is not current_sock and (is_yt or is_dc))

        if is_rotated_ip or ("combo_tlsrec_tcpsplit" not in failed_so_far and (is_yt or is_dc or strat1 == "direct")):
            strat3 = "combo_tlsrec_tcpsplit"
        else:
            strat3 = self.strategy_engine.get_fallback_strategy(
                effective_host,
                failed_strategy=strat1,
                failed_strategies=failed_so_far,
                ip=new_ip,
                is_tspu=is_tspu,
                is_whitelisted=is_wl
            )
        logger.info(
            f"[+] Fast-Fallback: {effective_host} -> стратегия '{strat3}' "
            f"(IP: {current_ip} -> {new_ip})"
        )

        strat3 = self.strategy_engine.allowed_strategy(fixed_strategy if fixed_strategy is not None else strat3)
        strat3 = self._strategy_after_stall(effective_host, target_port, new_ip, strat3, failed_so_far)
        t_send3 = time.time()
        if not self._safe_execute_strategy(strat3, new_sock, first_packet, host=effective_host):
            _safe_close_socket(new_sock)
            return None, strat3, effective_host, None

        if is_dc or is_yt or is_whitelisted:
            adaptive_floor3 = max(0.85, min(1.50, base_rtt_new * 3.0 + 0.60))
            timeout3 = max(1.20, min(remaining_budget() * 0.50, max(adaptive_floor3, min(2.50, base_rtt_new * 2.5 + 0.60))))
        else:
            timeout3 = min(remaining_budget() * 0.50, max(adaptive_floor3, min(1.20, base_rtt_new * 2.5 + 0.25)))
        status3, resp3, _ = self._probe_socket_response(new_sock, t_send3, base_rtt_new, strat3, probe_timeout=timeout3)
        if status3 == "success":
            return new_sock, strat3, effective_host, resp3
        _safe_close_socket(new_sock)
        return None, strat3, effective_host, None
    def _obfuscate_http_request(self, raw_req: bytes, host: Optional[str] = None) -> bytes:
        """Техника 4: HTTP Host Obfuscation & Whitelist Spoofing."""
        if host and is_gaming_host(host):
            return raw_req

        if self.config.whitelist_spoof_sni:
            return self.sni_spoofer.obfuscate_http_request(raw_req)

        if not self.config.http_host_obfuscation:
            return raw_req

        try:
            separator = b"\r\n\r\n" if b"\r\n\r\n" in raw_req else b"\n\n"
            headers, boundary, body = raw_req.partition(separator)
            headers = headers.replace(b"\r\nHost: ", b"\r\nhoSt: ").replace(b"\nHost: ", b"\nhoSt: ")
            return headers + boundary + body
        except Exception:
            pass
        return raw_req

    def _parse_http_target(self, raw_req: bytes, target_url: str) -> Tuple[str, int, str]:
        """Извлекает хост, порт и путь из HTTP-запроса."""
        port = 80
        host = ""
        path = "/"

        if target_url.startswith("http://") or target_url.startswith("https://"):
            scheme_len = 8 if target_url.startswith("https://") else 7
            default_port = 443 if target_url.startswith("https://") else 80
            url_no_scheme = target_url[scheme_len:]
            delim_idx = -1
            for d in ("/", "?", "#"):
                idx = url_no_scheme.find(d)
                if idx != -1 and (delim_idx == -1 or idx < delim_idx):
                    delim_idx = idx
            if delim_idx != -1:
                host_port = url_no_scheme[:delim_idx]
                path = url_no_scheme[delim_idx:]
            else:
                host_port = url_no_scheme
                path = "/"
            if host_port.startswith("["):
                bracket_end = host_port.find("]")
                if bracket_end != -1:
                    h = host_port[1:bracket_end]
                    rest = host_port[bracket_end + 1:]
                    if rest.startswith(":"):
                        try:
                            port = int(rest[1:])
                        except ValueError:
                            port = default_port
                    else:
                        port = default_port
                    host = h
                else:
                    host = host_port
                    port = default_port
            elif ":" in host_port:
                h, p = host_port.rsplit(":", 1)
                host = h
                try:
                    port = int(p)
                except ValueError:
                    port = default_port
            else:
                host = host_port
                port = default_port
        else:
            if target_url.startswith("/"):
                path = target_url
            for line in raw_req.split(b"\r\n"):
                if line.lower().startswith(b"host:"):
                    h_val = line[5:].strip().decode("latin1", errors="ignore")
                    if h_val.startswith("["):
                        bracket_end = h_val.find("]")
                        if bracket_end != -1:
                            h = h_val[1:bracket_end]
                            rest = h_val[bracket_end + 1:]
                            if rest.startswith(":"):
                                try:
                                    port = int(rest[1:])
                                except ValueError:
                                    port = 80
                            else:
                                port = 80
                            host = h
                        else:
                            host = h_val
                            port = 80
                    elif ":" in h_val:
                        h, p = h_val.rsplit(":", 1)
                        host = h
                        try:
                            port = int(p)
                        except ValueError:
                            port = 80
                    else:
                        host = h_val
                        port = 80
                    break

        return host.strip().rstrip("."), port, path

    def _pipe_tls(self, client_sock, target_sock, host, strategy, port, long_lived, network):
        """Учитывает прогресс TLS отдельно от HTTP-статуса, который прокси не видит."""
        target_ip = _get_socket_meta(target_sock).get('target_ip')
        if not target_ip:
            try:
                target_ip = target_sock.getpeername()[0]
            except OSError:
                target_ip = None
        suspect_recorded = False

        def account(direction, count):
            if direction == 'rx':
                self.bytes_rx += count
            else:
                self.bytes_tx += count

        def record_progress():
            self.route_health.record(network, host, port, target_ip, 'progress')
            self.route_health.record_strategy(network, host, port, strategy, 'progress')
            # Старое соединение не должно обучать новую сеть после смены профиля.
            if network != getattr(self.strategy_engine, '_current_network', 'default'):
                return
            mark_ip_working(target_ip, host)
            if host and strategy and strategy not in ('direct', 'http'):
                self.strategy_engine.record_success(host, strategy, ip=target_ip)

        def record_suspect(progress, reason):
            nonlocal suspect_recorded
            if suspect_recorded or long_lived:
                return
            suspect_recorded = True
            self.route_health.record(network, host, port, target_ip, 'suspect')
            self.route_health.record_strategy(network, host, port, strategy, 'suspect')
            logger.info(
                '[Маршрут] %s:%s через %s: нет прогресса после %s байт (%s); '
                'приоритет адреса временно снижен для новых соединений',
                host, port, target_ip, progress.server_bytes, reason)

        try:
            progress, reason = relay_tls(
                client_sock, target_sock, lambda: self.is_running, float(self.timeout),
                self.buffer_size, account, record_progress, long_lived=long_lived,
                on_suspect=record_suspect)
            outcome = progress.finish(reason, time.monotonic())
            if outcome == 'suspect':
                record_suspect(progress, reason)
        finally:
            _safe_close_socket(client_sock)
            _safe_close_socket(target_sock)

    def _pipe_sockets(
        self,
        client_sock: socket.socket,
        target_sock: socket.socket,
        host: str = "",
        strategy: str = "",
        got_initial_response: bool = False,
        tls_tunnel: bool = False,
        target_port: int = 443,
        route_network: Optional[str] = None
    ) -> None:
        """Двунаправленная надёжная пересылка трафика между клиентом и целевым сервером."""
        h_clean = (host or "").split(":")[0].lower()
        effective_host = h_clean
        is_ws = (
            "gateway" in h_clean
            or "discord.gg" in h_clean
            or "remote-auth" in h_clean
            or h_clean.endswith(".discord.media")
            or "wss://" in (host or "").lower()
            or is_discord_ip(h_clean)
        )
        is_dc = is_discord_host(host) or is_discord_host(h_clean)
        is_core_dc = (
            h_clean in ("discord.com", "gateway.discord.gg")
            or h_clean.endswith(".discord.com")
            or h_clean.endswith(".discord.gg")
        ) and not h_clean.endswith(".discord.media")
        is_discord = is_dc or is_core_dc
        is_discord_media = is_discord and (
            is_discord_media_host(host) or is_discord_media_host(h_clean)
        )
        is_tg = is_telegram_host(host) or is_telegram_host(h_clean)
        is_long_lived = is_ws or is_tg

        if tls_tunnel:
            network = route_network if route_network is not None else getattr(self.strategy_engine, '_current_network', 'default')
            self._pipe_tls(client_sock, target_sock, host, strategy, target_port, is_long_lived, network)
            return

        pipe_timeout = 3600.0 if is_long_lived else 60.0
        try:
            client_sock.settimeout(pipe_timeout)
            target_sock.settimeout(pipe_timeout)
        except Exception:
            pass

        sockets = [client_sock, target_sock]
        client_sent_app_data = False
        client_bytes_piped = 0
        server_replied_app_data = bool(got_initial_response)
        server_replied_in_pipe = False
        pending_client_request = False
        client_closed_normally = False
        is_client_stalled_abort = False
        has_socket_error = False
        is_error_response = False
        is_bundle_flow = False
        total_server_bytes = 1 if got_initial_response else 0
        last_server_byte_time = time.time()
        success_recorded = False
        meta_target = _get_socket_meta(target_sock)
        target_ip = meta_target.get("target_ip")
        if not target_ip:
            try:
                target_ip = target_sock.getpeername()[0]
            except Exception:
                pass

        try:
            while self.is_running:
                # WebSockets (Gateway/RTC) и MTProto (Telegram) требуют непрерывного долгоживущего туннеля (3600с).
                # Для HTTP/2 и активных туннелей используем 300с (соответствует таймауту пула Chromium).
                if is_long_lived:
                    select_timeout = 3600.0
                elif client_sock not in sockets:
                    # Клиент закрыл сокет на запись (half-close): ожидаем ответ сервера не более 1.0с во избежание зомби-потоков
                    select_timeout = min(1.0, float(self.timeout))
                elif not server_replied_in_pipe:
                    if is_discord_media:
                        select_timeout = max(15.0, float(self.timeout))
                    elif is_dc:
                        select_timeout = max(15.0, float(self.timeout))
                    else:
                        select_timeout = float(self.timeout)
                else:
                    select_timeout = 300.0

                try:
                    readable, _, _ = select.select(sockets, [], [], select_timeout)
                except (socket.error, ValueError):
                    break

                if not readable:
                    if client_sent_app_data and not server_replied_in_pipe:
                        # Клиент ожидал ответ от сервера, но наступил таймаут (TSPU дроп / блокировка)
                        client_closed_normally = False
                        has_socket_error = True
                        is_client_stalled_abort = True
                        if is_discord:
                            _WORKING_IP_CACHE.pop(host, None)
                            _WORKING_IP_CACHE.pop(effective_host, None)
                            if is_discord_media:
                                if host and strategy and strategy not in ("direct", "http"):
                                    self.strategy_engine.record_failure(host, strategy, ip=target_ip, is_tspu=False)
                                if target_ip:
                                    _RECENT_DISCORD_IPS.set(target_ip, time.time())
                            else:
                                if host and strategy and strategy not in ("direct", "http"):
                                    self.strategy_engine.record_failure(host, strategy, ip=target_ip, is_tspu=False)
                                if target_ip:
                                    self._record_route_failure(host, target_port, target_ip)
                                    _RECENT_DISCORD_IPS.set(target_ip, time.time())
                        elif host and strategy and strategy not in ("direct", "http"):
                            self.strategy_engine.record_failure(host, strategy, ip=target_ip, is_tspu=False)
                        break
                    elif not is_long_lived and not client_sent_app_data:
                        # Клиент держал пустое соединение в пуле (pre-connect) и не отправлял запрос
                        # Это нормальный keep-alive таймаут, закрываем сокет без ошибки
                        client_closed_normally = True
                        break
                    elif total_server_bytes > 0 or server_replied_app_data:
                        # Сервер уже ответил ранее; таймаут неактивности в keep-alive пуле является штатным завершением.
                        # В HTTP/2 (Chromium/Discord) клиент шлет служебные фреймы (WINDOW_UPDATE/PING),
                        # поэтому наличие pending_client_request при уже полученном ответе не является ошибкой или зависанием.
                        client_closed_normally = True
                        is_upload_flow = total_server_bytes > 0 and (client_bytes_piped > total_server_bytes or client_bytes_piped > 1024) and not is_error_response
                        is_discord_ready = (total_server_bytes > 0 or is_upload_flow or is_discord_media) if is_discord else True
                        if not success_recorded and not is_error_response and is_discord_ready:
                            success_recorded = True
                            if is_discord:
                                mark_ip_working(target_ip, host)
                            if host and strategy and strategy not in ("direct", "http"):
                                self.strategy_engine.record_success(host, strategy, ip=target_ip)
                        break
                    elif pending_client_request and not server_replied_app_data and total_server_bytes == 0:
                        # Клиент отправил последующий запрос в keep-alive соединении, но сервер не ответил
                        client_closed_normally = False
                        has_socket_error = True
                        is_client_stalled_abort = True
                        if is_discord:
                            _WORKING_IP_CACHE.pop(host, None)
                            _WORKING_IP_CACHE.pop(effective_host, None)
                            if host and strategy and strategy not in ("direct", "http"):
                                self.strategy_engine.record_failure(host, strategy, ip=target_ip, is_tspu=False)
                            if target_ip:
                                self._record_route_failure(host, target_port, target_ip)
                                _RECENT_DISCORD_IPS.set(target_ip, time.time())
                        elif host and strategy and strategy not in ("direct", "http"):
                            self.strategy_engine.record_failure(host, strategy, ip=target_ip, is_tspu=False)
                        break
                    elif is_long_lived:
                        # Таймаут неактивности долгоживущего туннеля (3600с)
                        break
                    break

                client_disconnected = False
                for s in readable:
                    other = target_sock if s is client_sock else client_sock
                    is_client_error = False
                    try:
                        if s is client_sock:
                            try:
                                data = s.recv(self.buffer_size)
                            except (socket.error, OSError, TimeoutError) as ce:
                                is_client_error = True
                                raise ce
                        else:
                            data = s.recv(self.buffer_size)
                        if not data:
                            if s is client_sock:
                                try:
                                    other.shutdown(socket.SHUT_WR)
                                except Exception:
                                    pass

                                now = time.time()
                                is_upload_flow = total_server_bytes > 0 and (client_bytes_piped > total_server_bytes or client_bytes_piped > 1024) and not is_error_response
                                if is_upload_flow:
                                    # Успешный upload: клиент передал запрос/тело, сервер ответил (200 OK / etc), сокет штатно закрыт
                                    client_closed_normally = True
                                    if not success_recorded:
                                        success_recorded = True
                                        mark_ip_working(target_ip, host)
                                        if host and strategy and strategy not in ("direct", "http"):
                                            self.strategy_engine.record_success(host, strategy, ip=target_ip)
                                    client_disconnected = True
                                    break
                                elif is_discord and not is_discord_media and (total_server_bytes > 0 or client_sent_app_data) and total_server_bytes < 32768:
                                    # Проверяем, является ли это зависанием TSPU при загрузке web-бандла discord.com или WebSocket Gateway
                                    is_gateway_flow = (is_ws or "gateway" in host.lower() or host.lower().endswith(".discord.gg") or host.lower() == "discord.gg")
                                    is_stalled = (
                                        (client_sent_app_data and not server_replied_app_data and total_server_bytes == 0)
                                        or (is_gateway_flow and total_server_bytes > 0 and (now - last_server_byte_time >= 3.0))
                                        or (is_bundle_flow and total_server_bytes > 0 and (now - last_server_byte_time >= 3.0))
                                    )
                                    if is_stalled:
                                        client_closed_normally = False
                                        has_socket_error = True
                                        is_client_stalled_abort = True
                                        _WORKING_IP_CACHE.pop(host, None)
                                        _WORKING_IP_CACHE.pop(effective_host, None)
                                        if host and strategy and strategy not in ("direct", "http"):
                                            self.strategy_engine.record_failure(host, strategy, ip=target_ip, is_tspu=False)
                                        if target_ip:
                                            self._record_route_failure(host, target_port, target_ip)
                                            _RECENT_DISCORD_IPS.set(target_ip, now)
                                    else:
                                        client_closed_normally = True
                                        if not success_recorded and not is_error_response and not is_upload_flow and (total_server_bytes > 0 or server_replied_app_data):
                                            success_recorded = True
                                            if is_discord:
                                                mark_ip_working(target_ip, host)
                                            if host and strategy and strategy not in ("direct", "http"):
                                                self.strategy_engine.record_success(host, strategy, ip=target_ip)
                                    client_disconnected = True
                                    break
                                elif is_discord_media:
                                    if success_recorded or (server_replied_in_pipe and total_server_bytes > 0):
                                        client_closed_normally = True
                                        if not success_recorded and not is_error_response:
                                            success_recorded = True
                                            mark_ip_working(target_ip, host)
                                            if host and strategy and strategy not in ("direct", "http"):
                                                self.strategy_engine.record_success(host, strategy, ip=target_ip)
                                    elif (pending_client_request or client_sent_app_data) and not server_replied_in_pipe:
                                        # Клиент закрыл соединение до ответа сервера (отмена запроса аватарки/медиа при скролле)
                                        client_closed_normally = True
                                        if target_ip:
                                            _RECENT_DISCORD_IPS.set(target_ip, now)
                                    elif got_initial_response and not client_sent_app_data:
                                        client_closed_normally = True
                                        if not success_recorded and not is_error_response:
                                            success_recorded = True
                                            mark_ip_working(target_ip, host)
                                            if host and strategy and strategy not in ("direct", "http"):
                                                self.strategy_engine.record_success(host, strategy, ip=target_ip)
                                    else:
                                        client_closed_normally = True
                                    client_disconnected = True
                                    break
                                elif total_server_bytes > 0:
                                    # Клиент штатно закрыл сокет после получения ответа (например, скачал аватар, изображение, HTML или бандл)
                                    client_closed_normally = True
                                    if not success_recorded and not is_error_response:
                                        success_recorded = True
                                        if is_discord:
                                            mark_ip_working(target_ip, host)
                                        if host and strategy and strategy not in ("direct", "http"):
                                            self.strategy_engine.record_success(host, strategy, ip=target_ip)
                                    if is_discord:
                                        client_disconnected = True
                                        break
                                elif is_discord and client_sent_app_data and not server_replied_app_data and total_server_bytes == 0:
                                    # Клиент закрыл соединение до ответа сервера (отмена запроса / скролл / смена каналов) - не баним Anycast IP
                                    client_closed_normally = True
                                    client_disconnected = True
                                    break
                                else:
                                    client_closed_normally = True

                                if s in sockets:
                                    sockets.remove(s)
                                if not sockets:
                                    return
                                continue
                            else:
                                # Сервер закрыл соединение (EOF) - сессия завершена, не держим клиентский сокет
                                is_upload_flow = total_server_bytes > 0 and (client_bytes_piped > total_server_bytes or client_bytes_piped > 1024) and not is_error_response
                                is_discord_ready = (total_server_bytes > 0 or is_upload_flow or is_discord_media) if is_discord else True
                                if not success_recorded and total_server_bytes > 0 and not is_error_response:
                                    success_recorded = True
                                    if is_discord:
                                        mark_ip_working(target_ip, host)
                                    if host and strategy and strategy not in ("direct", "http"):
                                        self.strategy_engine.record_success(host, strategy, ip=target_ip)
                                try:
                                    client_sock.shutdown(socket.SHUT_WR)
                                except Exception:
                                    pass
                                return

                        if s is client_sock:
                            if data:
                                if b"bundle" in data or (b"/assets/" in data and b".js" in data) or b"GET /app" in data:
                                    is_bundle_flow = True
                                client_sent_app_data = True
                                pending_client_request = True
                                self.bytes_tx += len(data)
                                client_bytes_piped += len(data)
                        elif s is target_sock:
                            total_server_bytes += len(data)
                            if data:
                                server_replied_in_pipe = True
                                last_server_byte_time = time.time()
                                self.bytes_rx += len(data)
                                if data.startswith((b"HTTP/1.1 4", b"HTTP/1.0 4", b"HTTP/1.1 5", b"HTTP/1.0 5")) or data.startswith(b"\x15"):
                                    is_error_response = True

                                if not server_replied_app_data:
                                    server_replied_app_data = True
                                    if not is_error_response:
                                        if not is_discord or is_discord_media:
                                            mark_ip_working(target_ip, host)
                                pending_client_request = False

                            # Фиксируем успех: получение ответа от сервера доказывает успешный обход DPI (не на 4xx/5xx/Alert).
                            is_upload_flow = total_server_bytes > 0 and (client_bytes_piped > total_server_bytes or client_bytes_piped > 1024) and not is_error_response
                            is_discord_ready = (total_server_bytes >= 32768 or is_upload_flow or is_discord_media) if is_discord else True
                            if not success_recorded and total_server_bytes > 0 and not is_error_response and is_discord_ready:
                                success_recorded = True
                                if is_discord and not is_error_response:
                                    mark_ip_working(target_ip, host)
                                if host and strategy and strategy not in ("direct", "http"):
                                    self.strategy_engine.record_success(host, strategy, ip=target_ip)

                        if other is client_sock:
                            try:
                                other.sendall(data)
                            except (socket.error, OSError, TimeoutError) as ce:
                                is_client_error = True
                                raise ce
                        else:
                            other.sendall(data)
                    except (socket.error, OSError, TimeoutError):
                        has_socket_error = True
                        now = time.time()
                        is_upload_flow = total_server_bytes > 0 and (client_bytes_piped > total_server_bytes or client_bytes_piped > 1024) and not is_error_response
                        if is_upload_flow:
                            if not success_recorded:
                                success_recorded = True
                                mark_ip_working(target_ip, host)
                                if host and strategy and strategy not in ("direct", "http"):
                                    self.strategy_engine.record_success(host, strategy, ip=target_ip)
                        elif is_discord_media:
                            if success_recorded or (server_replied_in_pipe and total_server_bytes > 0):
                                client_closed_normally = True
                                if not success_recorded and not is_error_response:
                                    success_recorded = True
                                    mark_ip_working(target_ip, host)
                                    if host and strategy and strategy not in ("direct", "http"):
                                        self.strategy_engine.record_success(host, strategy, ip=target_ip)
                            elif is_client_error or s is client_sock:
                                # Сброс / отключение со стороны клиента (Chromium отменил загрузку аватарки/медиа при скролле/смене канала)
                                # Не помечаем IP мертвым и не регистрируем сбой стратегии
                                client_closed_normally = True
                                has_socket_error = False
                                if target_ip:
                                    _RECENT_DISCORD_IPS.set(target_ip, now)
                            elif (pending_client_request or client_sent_app_data) and not server_replied_in_pipe:
                                # Сбой со стороны сервера (target_sock таймаут / RST) при ожидании ответа
                                client_closed_normally = False
                                has_socket_error = True
                                is_client_stalled_abort = True
                                _WORKING_IP_CACHE.pop(host, None)
                                _WORKING_IP_CACHE.pop(effective_host, None)
                                if host and strategy and strategy not in ("direct", "http"):
                                    self.strategy_engine.record_failure(host, strategy, ip=target_ip, is_tspu=False)
                                if target_ip:
                                    self._record_route_failure(host, target_port, target_ip)
                                    _RECENT_DISCORD_IPS.set(target_ip, now)
                            elif got_initial_response and not client_sent_app_data:
                                client_closed_normally = True
                                if not success_recorded and not is_error_response:
                                    success_recorded = True
                                    mark_ip_working(target_ip, host)
                                    if host and strategy and strategy not in ("direct", "http"):
                                        self.strategy_engine.record_success(host, strategy, ip=target_ip)
                            else:
                                client_closed_normally = True
                        elif is_discord and not is_discord_media and (total_server_bytes > 0 or client_sent_app_data) and total_server_bytes < 32768:
                            is_gateway_flow = (is_ws or "gateway" in host.lower() or host.lower().endswith(".discord.gg") or host.lower() == "discord.gg")
                            is_stalled = (
                                (client_sent_app_data and not server_replied_app_data and total_server_bytes == 0)
                                or (is_gateway_flow and total_server_bytes > 0 and (now - last_server_byte_time >= 3.0))
                                or (is_bundle_flow and total_server_bytes > 0 and (now - last_server_byte_time >= 3.0))
                            )
                            if is_stalled:
                                client_closed_normally = False
                                has_socket_error = True
                                is_client_stalled_abort = True
                                _WORKING_IP_CACHE.pop(host, None)
                                _WORKING_IP_CACHE.pop(effective_host, None)
                                if host and strategy and strategy not in ("direct", "http"):
                                    self.strategy_engine.record_failure(host, strategy, ip=target_ip, is_tspu=False)
                                if target_ip:
                                    self._record_route_failure(host, target_port, target_ip)
                                    _RECENT_DISCORD_IPS.set(target_ip, now)
                            else:
                                client_closed_normally = True
                                if not success_recorded and not is_error_response and not is_upload_flow and (total_server_bytes > 0 or server_replied_app_data):
                                    success_recorded = True
                                    if is_discord:
                                        mark_ip_working(target_ip, host)
                                    if host and strategy and strategy not in ("direct", "http"):
                                        self.strategy_engine.record_success(host, strategy, ip=target_ip)
                        return

                if client_disconnected:
                    break
        finally:
            _safe_close_socket(client_sock)
            _safe_close_socket(target_sock)
            # Завершение сессии: анализ результата работы стратегии
            if has_socket_error and not client_closed_normally:
                if not is_client_stalled_abort:
                    # Ошибка (таймаут/RST сервера) фиксируется только если клиент реально отправил запрос, а сервер так и не ответил
                    if client_sent_app_data and not server_replied_app_data and total_server_bytes == 0:
                        if host and strategy and strategy not in ("direct", "http"):
                            self.strategy_engine.record_failure(host, strategy, ip=target_ip, is_tspu=False)
                    elif client_sent_app_data and is_discord and not is_discord_media and total_server_bytes == 0:
                        _WORKING_IP_CACHE.pop(host, None)
                        _WORKING_IP_CACHE.pop(effective_host, None)
                        if host and strategy and strategy not in ("direct", "http"):
                            self.strategy_engine.record_failure(host, strategy, ip=target_ip, is_tspu=False)
                        if target_ip:
                            self._record_route_failure(host, target_port, target_ip)
                            _RECENT_DISCORD_IPS.set(target_ip, time.time())
            elif not is_client_stalled_abort and (not has_socket_error or client_closed_normally) and (client_closed_normally or total_server_bytes > 0 or server_replied_app_data) and not is_error_response:
                # Сессия завершилась штатно или данные получены: подтверждаем успех, если не был подтвержден ранее
                is_upload_flow = total_server_bytes > 0 and (client_bytes_piped > total_server_bytes or client_bytes_piped > 1024) and not is_error_response
                is_discord_ready = (total_server_bytes >= 32768 or is_upload_flow or is_discord_media) if is_discord else True
                if not success_recorded and total_server_bytes > 0 and client_sent_app_data and (is_discord_ready or (client_closed_normally and not is_discord)) and host and strategy and strategy not in ("direct", "http"):
                    if is_discord:
                        mark_ip_working(target_ip, host)
                    self.strategy_engine.record_success(host, strategy, ip=target_ip)


# Алиасы и вспомогательные функции для обратной совместимости модульных тестов:

def set_use_hosts_file(val: bool) -> None:
    pass

def get_custom_host_ip(host: str) -> Optional[str]:
    hosts = load_custom_hosts()
    return hosts.get(host)

def format_speed(bps: float) -> str:
    if bps >= 1024 * 1024:
        return f"{bps / (1024 * 1024):.2f} MB/s"
    elif bps >= 1024:
        return f"{bps / 1024:.2f} KB/s"
    return f"{bps:.0f} B/s"

def load_custom_hosts(filepath: str = "hosts.txt") -> Dict[str, str]:
    try:
        try:
            from flowguard.config import load_custom_hosts as _lch
        except ImportError:
            from Floweryguard.config import load_custom_hosts as _lch
        return _lch(filepath)
    except Exception:
        return {}

def is_plain_ip(host: Optional[str]) -> bool:
    if not host or not isinstance(host, str):
        return False
    import re
    return bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host) or ":" in host)


def is_captive_portal_host(host: Optional[str]) -> bool:
    """Проверяет, является ли хост системным зондом проверки связности (NCSI/Captive Portal)."""
    if not host or not isinstance(host, str):
        return False
    h = host.lower().strip().rstrip(".")
    return (
        "msftncsi" in h
        or "msftconnecttest" in h
        or "connectivitycheck" in h
        or "captive.apple.com" in h
        or "detectportal.firefox.com" in h
        or any(k in h for k in ("captive", "hotspot-login", "routerlogin"))
    )


