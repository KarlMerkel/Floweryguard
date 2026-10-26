"""Модуль адаптивных стратегий обхода DPI (Strategy Engine).
Реализация алгоритма Thompson Sampling для подбора
наиболее эффективных техник обхода под каждого конкретного провайдера и целевой сервис.
Строго стандартная библиотека Python.
"""

import os
import json
import random
import socket
import time
import threading
import uuid
import sys
from typing import Dict, List, Optional, Callable, Set, Iterable, Any

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception as e:
        sys.stderr.write(f"[Strategy init] Ошибка reconfigure: {e}\n")
try:
    from flowguard.config import get_app_base_dir
    from flowguard.logger import get_logger
    from flowguard.tls_parser import (
        get_sni_offsets,
        create_tls_record_fragments,
    )
except ImportError:
    from Floweryguard.config import get_app_base_dir
    from Floweryguard.logger import get_logger
    from Floweryguard.tls_parser import (
        get_sni_offsets,
        create_tls_record_fragments,
    )

logger = get_logger("Strategy")


class StrategyExecutor:
    """Исполнитель конкретных техник обхода на сокете."""

    @staticmethod
    def direct(sock: socket.socket, data: bytes, delay: float = 0.0) -> None:
        """Прямая отправка без фрагментации (для согласованной работы с zapret WinDivert)."""
        sock.sendall(data)

    @staticmethod
    def boringssl_split(sock: socket.socket, data: bytes, delay: float = 0.002) -> None:
        """Специализированный TCP Split для Google/YouTube BoringSSL.
        Разбивает TCP-поток ровно по середине SNI хоста с отключением Nagle (TCP_NODELAY),
        что гарантирует физическое разделение сегментов на канальном уровне сетевой карты.
        """
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception as e:
            logger.debug("setsockopt TCP_NODELAY failed in boringssl_split: %s", e)
        offsets = get_sni_offsets(data)
        split_pos = offsets[1] if offsets else min(40, len(data) // 2)
        split_pos = max(1, min(split_pos, len(data) - 1))
        sock.sendall(data[:split_pos])
        if delay > 0:
            time.sleep(delay)
        sock.sendall(data[split_pos:])

    @staticmethod
    def tcp_split_sni_start(sock: socket.socket, data: bytes, delay: float = 0.002) -> None:
        """TCP Split ровно по первому байту имени хоста SNI (+s)."""
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception as e:
            logger.debug("setsockopt TCP_NODELAY failed in tcp_split_sni_start: %s", e)
        offsets = get_sni_offsets(data)
        split_pos = offsets[0] if offsets else min(40, len(data) // 2)
        split_pos = max(1, min(split_pos, len(data) - 1))
        sock.sendall(data[:split_pos])
        if delay > 0:
            time.sleep(delay)
        sock.sendall(data[split_pos:])

    @staticmethod
    def tcp_split_sni_mid(sock: socket.socket, data: bytes, delay: float = 0.002) -> None:
        """TCP Split ровно по середине имени хоста SNI (+sm)."""
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception as e:
            logger.debug("setsockopt TCP_NODELAY failed in tcp_split_sni_mid: %s", e)
        offsets = get_sni_offsets(data)
        split_pos = offsets[1] if offsets else min(40, len(data) // 2)
        split_pos = max(1, min(split_pos, len(data) - 1))
        sock.sendall(data[:split_pos])
        if delay > 0:
            time.sleep(delay)
        sock.sendall(data[split_pos:])

    @staticmethod
    def multi_split(sock: socket.socket, data: bytes, delay: float = 0.002) -> None:
        """Каскадный TCP Split на 3-5 фрагментов (заголовок + части SNI + хвост)."""
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception as e:
            logger.debug("setsockopt TCP_NODELAY failed in multi_split: %s", e)
        offsets = get_sni_offsets(data)
        if offsets:
            start, mid, end = offsets
            # Точки нарезки: конец заголовка TLS Record (5), начало SNI, середина SNI, конец SNI
            raw_points = [5, start, mid, end]
        else:
            l = len(data)
            raw_points = [5, l // 4, l // 2, (3 * l) // 4]

        points = sorted(list(set([max(1, min(p, len(data) - 1)) for p in raw_points])))
        prev = 0
        for p in points:
            if p > prev:
                sock.sendall(data[prev:p])
                if delay > 0:
                    time.sleep(delay)
                prev = p
        if prev < len(data):
            sock.sendall(data[prev:])

    @staticmethod
    def tls_record_frag(sock: socket.socket, data: bytes, delay: float = 0.002) -> None:
        """TLS Record Fragmentation: разбиение на 2 валидных TLS Record."""
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception as e:
            logger.debug("setsockopt TCP_NODELAY failed in tls_record_frag: %s", e)
        offsets = get_sni_offsets(data)
        split_offset = offsets[1] if offsets else None
        fragments = create_tls_record_fragments(data, split_offset)
        if len(fragments) == 2:
            sock.sendall(fragments[0])
            if delay > 0:
                time.sleep(delay)
            sock.sendall(fragments[1])
        else:
            sock.sendall(data)

    @staticmethod
    def combo_tlsrec_tcpsplit(sock: socket.socket, data: bytes, delay: float = 0.002) -> None:
        """Двойная фрагментация: TLS Record Fragmentation + TCP Split каждой записи."""
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception as e:
            logger.debug("setsockopt TCP_NODELAY failed in combo_tlsrec_tcpsplit: %s", e)
        offsets = get_sni_offsets(data)
        split_offset = offsets[1] if offsets else None
        fragments = create_tls_record_fragments(data, split_offset)
        if len(fragments) == 2:
            # Отправляем фрагмент 1, разбив его TCP-уровнем внутри полезной нагрузки,
            # исключая изолированную отправку 5-байтного заголовка TLS Record,
            # которая вызывает зависания оконного управления TCP на Cloudflare Anycast.
            f1 = fragments[0]
            p1 = max(10, min(len(f1) - 1, len(f1) // 2))
            sock.sendall(f1[:p1])
            if delay > 0:
                time.sleep(delay)
            sock.sendall(f1[p1:])

            if delay > 0:
                time.sleep(delay)

            # Отправляем фрагмент 2
            f2 = fragments[1]
            p2 = max(10, min(len(f2) - 1, len(f2) // 2))
            sock.sendall(f2[:p2])
            if delay > 0:
                time.sleep(delay)
            sock.sendall(f2[p2:])
        else:
            StrategyExecutor.multi_split(sock, data, delay)

    # Безопасные алиасы обратной совместимости (без мутации полезной нагрузки TLS 1.3):
    dummy_record_prepend = tcp_split_sni_mid
    disoob_sni = tcp_split_sni_mid
    mixed_case_tcpsplit = tcp_split_sni_mid
    tcp_overlap_sni = tcp_split_sni_mid
    tls_padding_split = tcp_split_sni_mid



# Доступные стратегии в порядке их эффективности (только криптографически чистые фрагментации)
ALL_STRATEGIES = [
    "combo_tlsrec_tcpsplit",
    "tcp_split_sni_mid",
    "tcp_split_sni_start",
    "multi_split",
    "tls_record_frag",
    "boringssl_split",
    "direct",
]


# Порядок предпочтения при равных оценках для целевых сервисов: direct — последний.
_STABLE_ORDER = (
    "combo_tlsrec_tcpsplit",
    "tcp_split_sni_mid",
    "multi_split",
    "tls_record_frag",
    "tcp_split_sni_start",
    "boringssl_split",
    "direct",
)


MAX_SCORES_ENTRIES = 2000
MAX_LOGGED_ENTRIES = 500

# ---------------------------------------------------------------------------
# Кластеризация инфраструктуры CDN для переноса обучения (Transfer Learning)
# ---------------------------------------------------------------------------

CDN_CLUSTERS: Dict[str, Set[str]] = {
    "google": {
        "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com",
        "google.com", "google.ru", "googleapis.com", "gstatic.com", "googleusercontent.com",
        "youtube-nocookie.com", "yt.be", "gvt1.com"
    },
    "discord": {
        "discord.com", "discord.gg", "discordapp.com", "discordapp.net",
        "discord.media", "dis.gd", "discord.co", "discordcdn.com", "discord.dev", "discord.net",
        "tenor.com", "c.tenor.com", "media.tenor.com", "api.tenor.com", "t.tenor.com",
        "tenor.googleapis.com",
        "giphy.com", "media.giphy.com"
    },
    "cloudflare": {
        "rutracker.org", "rutracker.net", "rutracker.cc", "rutracker.wiki", "t-ru.org",
        "nnmclub.to", "rutor.info", "kinozal.tv",
        "cloudflare.com", "cloudflare-ech.com", "medium.com", "patreon.com",
        "ntc.party", "zona.media", "meduza.io", "holod.media", "themoscowtimes.com",
        "novayagazeta.eu", "tvrain.tv", "flibusta.is", "archive.org", "waybackmachine.org",
        "fandom.com", "modrinth.com", "curseforge.com", "notion.so",
        "torproject.org", "istories.media", "svoboda.org", "hdrezka"
    },
    "akamai_fastly": {
        "x.com", "twitter.com", "twimg.com", "instagram.com", "facebook.com",
        "fbcdn.net", "reddit.com", "twitch.tv", "github.com", "steamcommunity.com",
        "bbc.com", "dw.com", "currenttime.tv", "linkedin.com", "pornhub.com"
    }
}

MAJOR_BLOCKED_PATTERNS = (
    # Discord Media & GIF Providers
    "tenor.com", "giphy.com", "tenor.googleapis.com",
    # Social & Media: Twitter / X, Meta
    "x.com", "twitter.com", "twimg.com", "instagram.com", "facebook.com",
    # News & Independent Media
    "bbc.com", "bbci.co.uk", "svoboda.org", "dw.com", "currenttime.tv",
    "tvrain.tv", "novayagazeta.eu", "themoscowtimes.com", "zona.media",
    "istories.media", "holod.media", "meduza", "mdza", "gulagu.net", "theins.ru",
    # Cinema, Streaming & Literature
    "baskino", "flibusta", "filmix", "kinogo", "animego", "hdrezka",
    # Adult, Networking & Privacy / Tools
    "pornhub.com", "linkedin.com", "torproject.org", "ntc.party",
    "proton.me", "protonweb.com", "signal.org",
    # Audio & Streaming
    "soundcloud.com", "sndcdn.com",
    # Creator & Crowdfunding
    "patreon.com",
    # Torrent Trackers
    "rutracker", "nnmclub", "rutor", "kinozal", "t-ru.org", "lostfilm",
)

CLOUDFLARE_IP_PREFIXES = (
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.23.",
    "104.24.", "104.25.", "104.26.", "104.27.", "104.28.", "172.64.", "172.65.", "172.66.",
    "172.67.", "162.159."
)


def classify_cdn_cluster(host: str, ip: Optional[str] = None) -> Optional[str]:
    """Определяет инфраструктурный кластер CDN для мгновенного переноса опыта обучения (Transfer Learning).
    
    Поддерживает как чистые доменные имена, так и составные ключи вида domain:IP/24.
    """
    h = host.lower().strip(".")
    # Отсекаем суффикс :IP/24 из составных ключей (domain:IP/24 -> domain)
    colon_pos = h.find(":")
    if colon_pos > 0:
        extracted_ip = h[colon_pos + 1:].split("/")[0]
        if not ip and extracted_ip:
            ip = extracted_ip
        h = h[:colon_pos]

    # Специфичные хосты проверяем ДО общих масок (tenor.googleapis.com не должен попадать в google cluster)
    if (
        h == "tenor.googleapis.com"
        or h == "tenor.com"
        or h.endswith(".tenor.com")
        or h == "giphy.com"
        or h.endswith(".giphy.com")
    ):
        return "discord"

    for cluster, domains in CDN_CLUSTERS.items():
        for d in domains:
            if h == d or h.endswith("." + d):
                return cluster
    if ip and ip.startswith(CLOUDFLARE_IP_PREFIXES):
        return "cloudflare"
    return None


def is_domestic_domain(host: str) -> bool:
    """Определяет, относится ли хост к российскому сегменту интернета (.ru, .su, .рф) или отечественным сервисам."""
    if not host:
        return False
    h = host.lower().strip(".")
    colon_pos = h.find(":")
    if colon_pos > 0:
        h = h[:colon_pos]
    if (
        h.endswith(".ru")
        or h.endswith(".su")
        or h.endswith(".рф")
        or h.endswith(".xn--p1ai")
    ):
        return True
    domestic_services = (
        "vk.com",
        "userapi.com",
        "vk-cdn.net",
        "yandex.net",
        "yastatic.net",
        "dzen.ru",
        "ok.ru",
        "mail.ru",
        "my.com",
        "tinkoff.ru",
        "tbank.ru",
        "sberbank.ru",
        "sber.ru",
        "vtb.ru",
        "alfabank.ru",
        "gosuslugi.ru",
        "nalog.ru",
        "mos.ru",
        "avito.ru",
        "ozon.ru",
        "wildberries.ru",
        "rutube.ru",
    )
    for dom in domestic_services:
        if h == dom or h.endswith("." + dom):
            return True
    return False


class ThompsonStrategySelector:
    """Движок адаптивного контекстного автоподбора стратегий через Thompson Sampling (Multi-Armed Bandit).
    
    Поддерживает:
    1. Контекстное разделение весов по отпечатку сети (Mobile Tethering vs Home Wi-Fi).
    2. CDN Cluster Transfer Learning: мгновенный перенос обученных весов на новые домены того же кластера.
    3. RTT-Aware Continuous Reward: взвешивание успехов с учетом реального пинга и времени TLS Handshake.
    4. Temporal Discounting: экспоненциальное затухание для быстрой адаптации к изменениям фильтров ТСПУ.
    5. Dual-Tier Root & Subnet Learning: сквозное обучение базового домена и IP/24 подсетей.
    """

    def __init__(self, enabled: bool = True, cache_file: Optional[str] = None, scores_file: Optional[str] = None):
        self.enabled = enabled
        self._lock = threading.RLock()
        self._save_lock = threading.Lock()
        self._current_network: str = "default"
        # {network_id: {composite_key: {strategy_name: [alpha, beta]}}}
        self._scores: Dict[str, Dict[str, Dict[str, List[float]]]] = {"default": {}}
        # {network_id: {cluster_name: {strategy_name: [alpha, beta]}}}
        self._cluster_scores: Dict[str, Dict[str, Dict[str, List[float]]]] = {"default": {}}
        self._network_champion_wins: Dict[str, int] = {s: 0 for s in ALL_STRATEGIES}
        self._logged_strategies: Dict[str, str] = {}
        self._dirty = False
        self._last_save = time.time()
        self._last_decay_time = time.time()

        actual_file = scores_file or cache_file
        if actual_file is None:
            base_dir = get_app_base_dir()
            self.cache_file = os.path.join(base_dir, "strategy_scores.json")
            self.overrides_file = os.path.join(base_dir, "strategy_overrides.json")
        else:
            self.cache_file = actual_file
            self.overrides_file = None

        self._strategy_overrides: Dict[str, str] = {}
        self._allowed_strategies: Optional[Set[str]] = None
        self._load_scores()
        self._load_overrides()

    def set_network_context(self, network_fp: str) -> None:
        """Устанавливает отпечаток активной сети (ISP/интерфейс) для контекстной изоляции моделей."""
        with self._lock:
            fp = network_fp.strip() if network_fp else "default"
            if fp and fp != self._current_network:
                logger.info(f"[Auto-Strategy] Смена контекста сети: {self._current_network} -> {fp}")
                self._current_network = fp
                if fp not in self._scores:
                    self._scores[fp] = {}
                if fp not in self._cluster_scores:
                    self._cluster_scores[fp] = {}

    def _load_overrides(self) -> None:
        """Загружает жесткие пользовательские привязки стратегий к доменам (strategy_overrides.json)."""
        if not self.overrides_file or not os.path.exists(self.overrides_file):
            return
        try:
            with open(self.overrides_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                with self._lock:
                    self._strategy_overrides = {k.lower().strip("."): str(v) for k, v in data.items()}
        except Exception as e:
            logger.warning("Failed to load strategy overrides from %s: %s", self.overrides_file, e)

    def get_user_override(self, host: str) -> Optional[str]:
        """Возвращает принудительную стратегию из strategy_overrides.json, если задана."""
        if not host:
            return None
        h_clean = host.lower().strip(".")
        d_clean = self._get_domain_key(host)
        with self._lock:
            if h_clean in self._strategy_overrides:
                return self._strategy_overrides[h_clean]
            if d_clean in self._strategy_overrides:
                return self._strategy_overrides[d_clean]
        return None

    def configure_allowed(self, tcp_split: bool = True, tls_record_frag: bool = True, oob_data: bool = True) -> None:
        """Связывает тумблеры из config.ini с движком диспетчеризации стратегий."""
        allowed = set(ALL_STRATEGIES)
        if not tcp_split:
            allowed.discard("tcp_split_sni_start")
            allowed.discard("tcp_split_sni_mid")
            allowed.discard("multi_split")
            allowed.discard("boringssl_split")
            allowed.discard("combo_tlsrec_tcpsplit")
        if not tls_record_frag:
            allowed.discard("tls_record_frag")
            allowed.discard("combo_tlsrec_tcpsplit")
        if not oob_data:
            allowed.discard("disoob_sni")
        with self._lock:
            self._allowed_strategies = allowed

    def _apply_temporal_decay_locked(self) -> None:
        """Экспоненциальное затухание устаревших наблюдений с периодом полураспада 7 дней (604800с),
        предотвращающее залипание модели при смене правил DPI оператора.
        """
        now = time.time()
        if now - self._last_decay_time < 21600.0:  # Проверка каждые 6 часов
            return
        dt = max(0.0, now - self._last_decay_time)
        self._last_decay_time = now
        gamma = 0.5 ** (dt / 604800.0)
        for net, domains in self._scores.items():
            for dom, strats in domains.items():
                for s, ab in strats.items():
                    ab[0] = max(0.1, ab[0] * gamma)
                    ab[1] = max(0.1, ab[1] * gamma)
        for net, clusters in self._cluster_scores.items():
            for cl, strats in clusters.items():
                for s, ab in strats.items():
                    ab[0] = max(0.1, ab[0] * gamma)
                    ab[1] = max(0.1, ab[1] * gamma)
        self._dirty = True

    def _load_scores(self) -> None:
        """Загружает сохраненную статистику обучения из JSON-файла с поддержкой метаданных версионирования."""
        if not self.cache_file or not os.path.exists(self.cache_file):
            return
        try:
            with open(self.cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return

            with self._lock:
                decay = 1.0
                meta = data.get("_metadata")
                if isinstance(meta, dict) and "saved_at" in meta:
                    try:
                        dt = max(0.0, time.time() - float(meta["saved_at"]))
                        decay = 0.5 ** (dt / 604800.0)
                    except Exception:
                        decay = 1.0

                if isinstance(meta, dict) and "network_champion_wins" in meta:
                    for s, count in meta["network_champion_wins"].items():
                        if s in ALL_STRATEGIES:
                            try:
                                self._network_champion_wins[s] = int(count)
                            except Exception:
                                pass

                # 1. Проверяем наличие структурированных метаданных v2
                if isinstance(meta, dict) and meta.get("networks"):
                    for net, domains in meta["networks"].items():
                        if isinstance(domains, dict):
                            self._scores.setdefault(net, {})
                            for dom, strats in domains.items():
                                scores_map = {}
                                for s, ab in strats.items():
                                    if isinstance(ab, list) and len(ab) == 2 and s in ALL_STRATEGIES:
                                        scores_map[s] = [max(0.5, float(ab[0]) * decay), min(12.0, max(0.1, float(ab[1]) * decay))]
                                self._scores[net][dom] = scores_map
                    if meta.get("clusters"):
                        for net, clusters in meta["clusters"].items():
                            if isinstance(clusters, dict):
                                self._cluster_scores.setdefault(net, {})
                                for cl, strats in clusters.items():
                                    if isinstance(strats, dict):
                                        self._cluster_scores[net][cl] = {
                                            s: [max(0.5, float(ab[0]) * decay), min(12.0, max(0.1, float(ab[1]) * decay))]
                                            for s, ab in strats.items()
                                            if isinstance(ab, list) and len(ab) == 2 and s in ALL_STRATEGIES
                                        }

                # 2. Обратная совместимость: импортируем корневые домены в default пул
                default_dict = self._scores.setdefault("default", {})
                for domain, strats in data.items():
                    if domain == "_metadata":
                        continue
                    if isinstance(strats, dict):
                        d_scores = {}
                        for s_name, ab in strats.items():
                            if isinstance(ab, list) and len(ab) == 2 and s_name in ALL_STRATEGIES:
                                d_scores[s_name] = [max(0.5, float(ab[0]) * decay), min(12.0, max(0.1, float(ab[1]) * decay))]
                        default_dict[domain] = d_scores
                self._trim_capacity_locked()
        except Exception as e:
            logger.warning("Failed to load strategy scores from %s: %s", self.cache_file, e)

    def _get_network_champion_locked(self) -> str:
        """Возвращает текущую стратегию-чемпиона сети (без захвата лока)."""
        non_direct = {k: v for k, v in self._network_champion_wins.items() if k != "direct"}
        if non_direct:
            best = max(non_direct.items(), key=lambda x: x[1])
            if best[1] > 0 and best[0] in ALL_STRATEGIES:
                return best[0]
        return "combo_tlsrec_tcpsplit"

    def get_network_champion(self) -> str:
        """Возвращает текущую стратегию-чемпиона сети (наибольшее количество побед, исключая direct)."""
        with self._lock:
            return self._get_network_champion_locked()

    def save_scores(self, force: bool = False) -> None:
        with self._save_lock:
            self._save_scores(force)

    def _save_scores(self, force: bool = False) -> None:
        """Атомарно сохраняет накопленную статистику обучения в JSON-файл."""
        now = time.time()
        with self._lock:
            if not self._dirty and not force:
                return
            if not force and (now - self._last_save < 15.0):
                return

            # Формируем плоскую проекцию текущей/дефолтной сети для полной обратной совместимости
            snapshot = {}
            active_net = self._current_network
            primary_net_scores = self._scores.get(active_net) or self._scores.get("default", {})
            for d, strats in primary_net_scores.items():
                snapshot[d] = {s: list(ab) for s, ab in strats.items()}

            # Полные контекстные метаданные
            snapshot["_metadata"] = {
                "version": 2,
                "saved_at": now,
                "current_network": active_net,
                "network_champion_wins": dict(self._network_champion_wins),
                "networks": {
                    net: {d: {s: list(ab) for s, ab in strats.items()} for d, strats in domains.items()}
                    for net, domains in self._scores.items()
                },
                "clusters": {
                    net: {c: {s: list(ab) for s, ab in strats.items()} for c, strats in cl.items()}
                    for net, cl in self._cluster_scores.items()
                }
            }
            self._dirty = False
            self._last_save = now

        if not self.cache_file or not snapshot:
            return

        try:
            tmp_path = self.cache_file + "." + uuid.uuid4().hex + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, indent=2, ensure_ascii=False)
            os.replace(tmp_path, self.cache_file)
        except Exception as e:
            logger.error("Failed to save strategy scores to %s: %s", self.cache_file, e)
            with self._lock:
                self._dirty = True
                self._last_save = 0.0
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception as re:
                logger.debug("Failed removing temp scores file %s: %s", tmp_path, re)

    def _trim_capacity_locked(self) -> None:
        """Ограничивает максимальный размер кэша в памяти, предотвращая утечки дескрипторов."""
        for net in list(self._scores.keys()):
            if len(self._scores[net]) > MAX_SCORES_ENTRIES:
                sorted_items = sorted(
                    self._scores[net].items(),
                    key=lambda item: sum(sum(ab) for ab in item[1].values()),
                    reverse=True
                )
                self._scores[net] = dict(sorted_items[:MAX_SCORES_ENTRIES // 2])

        if len(self._logged_strategies) > MAX_LOGGED_ENTRIES:
            self._logged_strategies.clear()

    def _get_domain_key(self, host: str) -> str:
        """Приводит хост к базовой зоне (например, cdn.discordapp.com -> discordapp.com)."""
        h = host.lower().strip(".")
        parts = h.split(".")
        if len(parts) >= 3 and parts[-2] in ("co", "com", "net", "org", "gov", "edu"):
            return ".".join(parts[-3:])
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return h

    def _get_composite_key(self, host: str, ip: Optional[str] = None) -> str:
        """Создает составной ключ (домен + подсеть /24) для исключения CDN-аномалий."""
        domain = self._get_domain_key(host)
        if not ip:
            return domain
        try:
            parts = ip.split(".")
            if len(parts) == 4:
                return f"{domain}:{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except Exception as e:
            logger.debug("_get_composite_key parse error for IP %s: %s", ip, e)
        return domain

    def _init_domain_priors(self, domain_key: str, is_youtube: bool = False, is_discord: bool = False) -> Dict[str, List[float]]:
        """Инициализирует априорные веса (priors) с поддержкой переноса знаний CDN (Transfer Learning)."""
        cluster = classify_cdn_cluster(domain_key)
        net = self._current_network

        # 1. Проверяем накопленные знания по этому кластеру в активной или default сети
        cluster_data = None
        for n in (net, "default"):
            if n in self._cluster_scores and cluster in self._cluster_scores[n]:
                cand = self._cluster_scores[n][cluster]
                if sum(ab[0] + ab[1] for ab in cand.values()) >= 8.0:
                    cluster_data = cand
                    break

        d_lower = (domain_key or "").lower()
        is_media_discord = (
            cluster == "discord_media"
            or d_lower in ("discordapp.com", "discordapp.net", "discord.net")
            or any(m in d_lower for m in (
                "discordapp.com", "discordapp.net", "attachments.discord.net", "images-ext",
                "discord.net", "tenor.com", "giphy.com", "tenor.googleapis.com"
            ))
            or d_lower.endswith(".discordapp.com")
            or d_lower.endswith(".discordapp.net")
            or d_lower.endswith(".discord.net")
            or d_lower.endswith(".tenor.com")
            or d_lower.endswith(".giphy.com")
        ) and not (
            "gateway" in d_lower or d_lower == "discord.gg" or d_lower.endswith(".discord.gg")
        )
        is_tracker = any(t in d_lower for t in ("rutracker", "nnmclub", "rutor", "kinozal", "t-ru.org"))
        is_major_blocked = any(b in d_lower for b in MAJOR_BLOCKED_PATTERNS)

        if cluster_data:
            # Transfer Learning: наследуем прогретые веса кластера со сглаживанием
            scores = {}
            for s in ALL_STRATEGIES:
                c_ab = cluster_data.get(s, [1.0, 3.0])
                a = max(0.5, c_ab[0] * 0.4)
                b = max(0.5, c_ab[1] * 0.4)
                if a + b > 10.0:
                    scale = 10.0 / (a + b)
                    a = max(0.5, a * scale)
                    b = max(0.5, b * scale)
                scores[s] = [a, b]
            # Для зарубежных доменов гарантируем базовые экспертные приоритеты при переносе знаний
            if not is_domestic_domain(domain_key):
                if is_media_discord:
                    scores["combo_tlsrec_tcpsplit"] = [12.0, 1.0]
                    scores["tcp_split_sni_mid"] = [1.0, 5.0]
                elif is_major_blocked or is_tracker:
                    scores["combo_tlsrec_tcpsplit"] = [8.0, 2.0]
                    scores["tcp_split_sni_mid"] = [1.0, 5.0]
                else:
                    if scores.get("combo_tlsrec_tcpsplit", [0, 0])[0] < 8.0:
                        scores["combo_tlsrec_tcpsplit"] = [8.0, 2.0]
                    if scores.get("tcp_split_sni_mid", [0, 0])[0] > 4.0:
                        scores["tcp_split_sni_mid"] = [4.0, 2.0]
            if is_youtube or cluster == "google":
                if scores.get("boringssl_split", [0, 0])[0] < 6.0:
                    scores["boringssl_split"] = [6.0, 2.0]
            return scores

        # 2. Экспертные стартовые априорные распределения (Priors)
        # B1: Слабые начальные априорные веса (alpha + beta <= 10) для быстрой адаптации MAB
        scores = {}
        for s in ALL_STRATEGIES:
            scores[s] = [1.0, 3.0]

        if is_youtube or cluster == "google":
            scores["combo_tlsrec_tcpsplit"] = [8.0, 2.0]
            scores["boringssl_split"] = [6.0, 2.0]
            scores["tcp_split_sni_mid"] = [5.0, 2.0]
            scores["multi_split"] = [4.0, 2.0]
            scores["tcp_split_sni_start"] = [3.0, 2.0]
            scores["tls_record_frag"] = [1.0, 5.0]
            scores["direct"] = [1.0, 5.0]
        elif is_media_discord:
            # Для медиа-контента Discord (cdn, media, images) combo_tlsrec_tcpsplit гарантированно пробивает ТСПУ
            scores["combo_tlsrec_tcpsplit"] = [12.0, 1.0]
            scores["tcp_split_sni_mid"] = [1.0, 5.0]
            scores["multi_split"] = [1.0, 4.0]
            scores["tcp_split_sni_start"] = [1.0, 4.0]
            scores["tls_record_frag"] = [1.0, 4.0]
            scores["direct"] = [1.0, 5.0]
            scores["boringssl_split"] = [1.0, 5.0]
        elif is_major_blocked or is_tracker:
            # Для всех крупных заблокированных ресурсов и торрент-трекеров combo_tlsrec_tcpsplit имеет наивысший приоритет
            scores["combo_tlsrec_tcpsplit"] = [8.0, 2.0]
            scores["tcp_split_sni_mid"] = [4.0, 2.0]
            scores["multi_split"] = [3.0, 2.0]
            scores["tcp_split_sni_start"] = [2.0, 3.0]
            scores["tls_record_frag"] = [2.0, 3.0]
            scores["direct"] = [1.0, 5.0]
            scores["boringssl_split"] = [1.0, 5.0]
        elif is_discord or cluster == "discord":
            # combo_tlsrec_tcpsplit гарантированно проходит ТСПУ для Discord HTTPS
            scores["combo_tlsrec_tcpsplit"] = [8.0, 2.0]
            scores["tls_record_frag"] = [6.0, 2.0]
            scores["multi_split"] = [5.0, 2.0]
            scores["tcp_split_sni_mid"] = [3.0, 3.0]
            scores["tcp_split_sni_start"] = [2.0, 4.0]
            scores["direct"] = [1.0, 5.0]
            scores["boringssl_split"] = [1.0, 5.0]
        elif is_domestic_domain(domain_key):
            # Для отечественных доменов РФ/RU/SU и сервисов приоритет direct
            scores["direct"] = [8.0, 1.0]
            scores["combo_tlsrec_tcpsplit"] = [2.0, 3.0]
            scores["tcp_split_sni_mid"] = [2.0, 3.0]
            scores["multi_split"] = [1.0, 3.0]
            scores["tls_record_frag"] = [1.0, 4.0]
            scores["tcp_split_sni_start"] = [1.0, 4.0]
            scores["boringssl_split"] = [1.0, 5.0]
        else:
            # Для всех зарубежных доменов / CDN:
            # Сетевой чемпион combo_tlsrec_tcpsplit [8.0, 2.0] и раннер-ап tcp_split_sni_mid [4.0, 2.0]
            scores["combo_tlsrec_tcpsplit"] = [8.0, 2.0]
            scores["tcp_split_sni_mid"] = [4.0, 2.0]
            scores["tcp_split_sni_start"] = [3.0, 2.0]
            scores["multi_split"] = [3.0, 2.0]
            scores["tls_record_frag"] = [2.0, 3.0]
            scores["direct"] = [1.0, 4.0]
            scores["boringssl_split"] = [1.0, 5.0]

        return scores

    def _init_key_scores_locked(
        self,
        net_scores: Dict[str, Any],
        key: str,
        host: str,
        is_youtube: bool = False,
        is_discord: bool = False
    ) -> Dict[str, List[float]]:
        """Инициализирует веса для ключа. Если составной ключ (/24) холодный,
        наследует 100% обученных весов базового домена из текущей или default сети."""
        net = self._current_network
        domain = self._get_domain_key(host)

        # 1. Если составной ключ уже сохранен в default сети
        if net != "default" and "default" in self._scores and key in self._scores["default"]:
            return {s: list(ab) for s, ab in self._scores["default"][key].items()}

        # 2. Если составной ключ подсети (/24) холодный, наследуем 100% весов базового домена
        if key != domain:
            if domain in net_scores:
                return {s: list(ab) for s, ab in net_scores[domain].items()}
            if "default" in self._scores and domain in self._scores["default"]:
                return {s: list(ab) for s, ab in self._scores["default"][domain].items()}

        # 3. Базовые priors
        self._trim_capacity_locked()
        return self._init_domain_priors(domain, is_youtube, is_discord)

    def allowed_strategy(self, preferred: str) -> str:
        """Применяет ограничения техник ко всем специальным веткам выбора."""
        aliases = {"disoob_sni", "dummy_record_prepend", "mixed_case_tcpsplit", "tcp_overlap_sni", "tls_padding_split"}
        effective = "tcp_split_sni_mid" if preferred in aliases else preferred
        with self._lock:
            allowed = self._allowed_strategies
            if allowed is None or effective in allowed:
                return preferred
            return next((name for name in ALL_STRATEGIES if name in allowed), "direct")

    def select_strategy(self, host: str, is_youtube: bool = False, is_discord: bool = False,
                        ip: Optional[str] = None, is_whitelisted: bool = False) -> str:
        return self.allowed_strategy(self._select_strategy(host, is_youtube, is_discord, ip, is_whitelisted))

    def _select_strategy(
        self,
        host: str,
        is_youtube: bool = False,
        is_discord: bool = False,
        ip: Optional[str] = None,
        is_whitelisted: bool = False
    ) -> str:
        """Выбирает оптимальную стратегию для данного хоста с использованием Contextual Thompson Sampling."""
        # 1. Проверяем ручные переопределения пользователя (strategy_overrides.json)
        override = self.get_user_override(host)
        if override:
            return override

        cluster = classify_cdn_cluster(host, ip)
        h_lower = host.lower() if host else ""
        if not is_youtube and (cluster == "google" or any(p in h_lower for p in ("youtube", "googlevideo", "youtu.be", "ytimg", "ggpht", "gvt1"))):
            is_youtube = True

        is_media_discord = (
            cluster == "discord_media"
            or any(m in h_lower for m in (
                "cdn.discordapp.com", "media.discordapp.net", "attachments.discord.net",
                "discordapp.net", "discordapp.com", "images-ext", "discord.net",
                "tenor.com", "giphy.com", "tenor.googleapis.com"
            ))
            or h_lower.endswith(".discordapp.com")
            or h_lower.endswith(".discordapp.net")
            or h_lower.endswith(".discord.net")
            or h_lower.endswith(".tenor.com")
            or h_lower.endswith(".giphy.com")
        ) and not (
            "gateway" in h_lower or h_lower == "discord.gg" or h_lower.endswith(".discord.gg")
        )
        is_core_discord = not is_media_discord and (
            cluster == "discord"
            or is_discord
            or "discord" in h_lower
            or "dis.gd" in h_lower
        )

        is_major_blocked = any(b in h_lower for b in MAJOR_BLOCKED_PATTERNS)

        if not self.enabled:
            return "combo_tlsrec_tcpsplit" if (is_youtube or is_core_discord) else "tcp_split_sni_mid"

        key = self._get_composite_key(host, ip)
        net = self._current_network

        with self._lock:
            self._apply_temporal_decay_locked()
            net_scores = self._scores.setdefault(net, {})
            if key not in net_scores:
                net_scores[key] = self._init_key_scores_locked(net_scores, key, host, is_youtube, is_discord)
                self._dirty = True

            candidates = net_scores[key]

            # Ограничения несовместимости протоколов
            excluded = set()
            if not is_youtube:
                excluded.update(["boringssl_split"])
            if is_core_discord:
                # Для Core Discord на Cloudflare стабильно работает исключительно combo_tlsrec_tcpsplit
                excluded.update(["direct", "boringssl_split"])
            if is_media_discord:
                # Для Discord Media исключаем несовместимые техники; tcp_split_sni_mid гарантированно блокируется ТСПУ на Cloudflare
                excluded.update(["boringssl_split", "direct", "tcp_split_sni_mid"])
            if is_youtube:
                excluded.update(["direct", "tls_record_frag"])

            # Принудительное исключение техник, отключенных в config.ini ([bypass])
            if self._allowed_strategies is not None:
                excluded.update(set(candidates.keys()) - self._allowed_strategies)

            available = [s for s in candidates.keys() if s not in excluded]
            if not available:
                available = [
                    s for s in ALL_STRATEGIES
                    if s not in excluded and (self._allowed_strategies is None or s in self._allowed_strategies)
                ]

            best_strategy = available[0] if available else ("combo_tlsrec_tcpsplit" if (is_youtube or is_core_discord) else "tcp_split_sni_mid")
            max_sample = -1.0
            # Для целевых сервисов без случайной разведки: новые техники пробуются в Fast-Fallback
            # после реального сбоя, а основной выбор следует накопленным наблюдениям.
            stable = is_whitelisted or is_youtube or is_discord or is_core_discord or is_media_discord or is_major_blocked
            if stable:
                available = sorted(available, key=lambda s: _STABLE_ORDER.index(s) if s in _STABLE_ORDER else len(_STABLE_ORDER))

            for strat_name in available:
                if strat_name not in candidates:
                    continue
                alpha, beta = candidates[strat_name]
                if stable:
                    # Затухшие оценки без наблюдений не должны выглядеть успешнее проверенной техники.
                    sample = alpha / (alpha + beta) if alpha + beta >= 3.0 else 0.25
                else:
                    sample = random.betavariate(max(0.1, alpha), max(0.1, beta))
                if sample > max_sample:
                    max_sample = sample
                    best_strategy = strat_name

            if best_strategy not in candidates and candidates:
                for k in candidates:
                    if k not in excluded:
                        best_strategy = k
                        break

            if best_strategy not in candidates:
                candidates[best_strategy] = [1.0, 1.0]

            # Логируем выбор стратегии при первом использовании или смене
            log_key = f"{net}::{key}"
            prev = self._logged_strategies.get(log_key)
            if prev != best_strategy:
                self._logged_strategies[log_key] = best_strategy
                logger.info(f"[Auto-Strategy] [{net}] {key:<28} -> {best_strategy} (alpha={candidates[best_strategy][0]:.1f}, beta={candidates[best_strategy][1]:.1f})")

            return best_strategy

    def get_fallback_strategy(self, host: str, failed_strategy: str = "", is_youtube: bool = False,
                              is_discord: bool = False, ip: Optional[str] = None,
                              failed_strategies: Optional[Iterable[str]] = None,
                              is_tspu: bool = True, is_whitelisted: bool = False) -> str:
        return self.allowed_strategy(self._get_fallback_strategy(
            host, failed_strategy, is_youtube, is_discord, ip, failed_strategies, is_tspu, is_whitelisted))

    def _get_fallback_strategy(
        self,
        host: str,
        failed_strategy: str = "",
        is_youtube: bool = False,
        is_discord: bool = False,
        ip: Optional[str] = None,
        failed_strategies: Optional[Iterable[str]] = None,
        is_tspu: bool = True,
        is_whitelisted: bool = False,
    ) -> str:
        """Возвращает сильнейшую альтернативную стратегию обхода при подтвержденном сбросе ТСПУ.
        
        Выбирает кандидата с наивысшим статистическим рейтингом успеха (Thompson Sampling),
        исключая упавшую стратегию failed_strategy и список failed_strategies.
        """
        cluster = classify_cdn_cluster(host, ip)
        if not is_youtube and cluster == "google":
            is_youtube = True
        if not is_discord and cluster == "discord":
            is_discord = True

        h_lower = (host or "").lower()
        is_media_dc = (
            cluster in ("discord_media", "discord")
            or any(m in h_lower for m in (
                "cdn.discordapp.com", "media.discordapp.net", "attachments.discord.net",
                "discordapp.net", "discordapp.com", "images-ext", "discord.net",
                "tenor.com", "giphy.com", "tenor.googleapis.com"
            ))
            or h_lower.endswith(".discordapp.com")
            or h_lower.endswith(".discordapp.net")
            or h_lower.endswith(".discord.net")
            or h_lower.endswith(".tenor.com")
            or h_lower.endswith(".giphy.com")
        ) and not (
            "gateway" in h_lower or h_lower == "discord.gg" or h_lower.endswith(".discord.gg")
        )

        excluded_early = {failed_strategy} if failed_strategy else set()
        if failed_strategies:
            excluded_early.update(failed_strategies)

        # Для Discord Media единственной рабочей техникой против ТСПУ на Cloudflare
        # является combo_tlsrec_tcpsplit (при сбое выполняется ротация IP, а не смена техники на блокируемую).
        if is_media_dc and "combo_tlsrec_tcpsplit" not in excluded_early:
            return "combo_tlsrec_tcpsplit"

        is_major_blocked = any(b in h_lower for b in MAJOR_BLOCKED_PATTERNS)
        is_tracker = any(t in h_lower for t in ("rutracker", "nnmclub", "rutor", "kinozal", "t-ru.org"))
        if (is_whitelisted or is_major_blocked or is_tracker) and "combo_tlsrec_tcpsplit" not in excluded_early:
            return "combo_tlsrec_tcpsplit"

        if is_youtube:
            candidates = [
                "combo_tlsrec_tcpsplit",
                "tcp_split_sni_mid",
                "multi_split",
                "tcp_split_sni_start",
                "boringssl_split",
            ]
        elif is_discord:
            candidates = [
                "combo_tlsrec_tcpsplit",
                "tls_record_frag",
                "tcp_split_sni_mid",
                "multi_split",
            ]
        else:
            candidates = [
                "combo_tlsrec_tcpsplit",
                "tcp_split_sni_mid",
                "tcp_split_sni_start",
                "multi_split",
                "tls_record_frag",
                "direct",
            ]

        # Фильтруем упавшую стратегию, несовместимые с протоколом и отключенные в config.ini
        excluded = {failed_strategy} if failed_strategy else set()
        if failed_strategies:
            excluded.update(failed_strategies)
        if not is_youtube:
            excluded.add("boringssl_split")
        if is_discord:
            excluded.add("direct")
        if is_tracker:
            excluded.add("direct")
        if is_major_blocked:
            excluded.add("direct")
        if is_media_dc:
            excluded.update(["boringssl_split", "direct", "tcp_split_sni_mid"])
        if is_youtube:
            excluded.update(["direct", "tls_record_frag"])

        valid_candidates = [
            s for s in candidates
            if s not in excluded and s in ALL_STRATEGIES
            and (self._allowed_strategies is None or s in self._allowed_strategies)
        ]
        if not valid_candidates:
            fallback_pool = [
                s for s in ALL_STRATEGIES
                if s not in excluded and (self._allowed_strategies is None or s in self._allowed_strategies)
            ]
            valid_candidates = fallback_pool if fallback_pool else (["combo_tlsrec_tcpsplit"] if (is_discord or is_youtube) else ["tcp_split_sni_mid"])

        # Если доступна статистика Thompson Sampling по текущей сети и хосту/подсети:
        key = self._get_composite_key(host, ip)
        domain = self._get_domain_key(host)
        net = self._current_network

        with self._lock:
            net_scores = self._scores.get(net, {})
            scores = net_scores.get(key)
            if not scores and "default" in self._scores:
                scores = self._scores["default"].get(key)
            if not scores and key != domain:
                scores = net_scores.get(domain) or (self._scores.get("default", {}).get(domain))

        if not scores:
            scores = self._init_domain_priors(domain, is_youtube, is_discord)

        if scores:
            # Сортируем валидных кандидатов по математическому ожиданию вероятности успеха: alpha / (alpha + beta)
            def score_strat(s: str) -> float:
                if s in scores:
                    a, b = scores[s]
                    return a / max(0.1, (a + b))
                return 0.5

            # При сбросе ТСПУ отдаем приоритет combo_tlsrec_tcpsplit, если он не был опробован,
            # кроме случаев, когда альтернатива имеет подтвержденные победы (alpha >= 15.0).
            if "combo_tlsrec_tcpsplit" in valid_candidates and is_tspu:
                combo_exp = score_strat("combo_tlsrec_tcpsplit")
                has_dominant = False
                for c in valid_candidates:
                    if c != "combo_tlsrec_tcpsplit":
                        c_a, c_b = scores.get(c, [1.0, 3.0])
                        if c_a >= 15.0 and (c_a / max(0.1, c_a + c_b)) > combo_exp:
                            has_dominant = True
                            break
                if not has_dominant:
                    return "combo_tlsrec_tcpsplit"

            ranked = sorted(valid_candidates, key=score_strat, reverse=True)
            return ranked[0]

        if "combo_tlsrec_tcpsplit" in valid_candidates and is_tspu:
            return "combo_tlsrec_tcpsplit"

        return valid_candidates[0]

    def get_scores_for_key(self, host: str, ip: Optional[str] = None) -> Optional[Dict[str, List[float]]]:
        """Возвращает текущие веса стратегий для хоста/подсети с учетом активной сети."""
        key = self._get_composite_key(host, ip)
        domain = self._get_domain_key(host)
        with self._lock:
            net_scores = self._scores.get(self._current_network, {})
            if key in net_scores:
                return net_scores[key]
            if "default" in self._scores and key in self._scores["default"]:
                return self._scores["default"][key]
            if key != domain:
                if domain in net_scores:
                    return net_scores[domain]
                if "default" in self._scores and domain in self._scores["default"]:
                    return self._scores["default"][domain]
        return None

    def soften_calibration_priors(self, factor: float = 0.75) -> None:
        """Смягчает экстремумы весов (Variance Protection) перед повторной калибровкой.
        
        Предотвращает зацементирование параметров и устраняет перекос при частом запуске калибровки.
        Веса мягко стягиваются к доверительному интервалу (soft prior pulling).
        """
        with self._lock:
            for net, domains in self._scores.items():
                for dom, strats in domains.items():
                    for s, ab in strats.items():
                        ab[0] = max(0.5, ab[0] * factor)
                        ab[1] = max(0.5, ab[1] * factor)
            for net, clusters in self._cluster_scores.items():
                for cl, strats in clusters.items():
                    for s, ab in strats.items():
                        ab[0] = max(0.5, ab[0] * factor)
                        ab[1] = max(0.5, ab[1] * factor)
            self._dirty = True
        self.save_scores(force=True)

    def record_success(
        self,
        host: str,
        strategy: str,
        ip: Optional[str] = None,
        rtt_ms: Optional[float] = None,
        is_calibration: bool = False
    ) -> None:
        """Фиксирует успешное соединение и ответ сервера с непрерывной RTT-наградой."""
        if is_calibration:
            logger.debug("Синтетическая TLS-проба %s: %s (не оценка загрузки)", host, strategy)
            return
        if not host or not strategy or strategy == "http":
            return

        # Непрерывная функция полезности (QoE / Latency Utility):
        # При RTT <= 45мс: reward ~ 2.2 (очень быстрый обход)
        # При RTT ~ 150мс: reward ~ 1.3 (стандарт)
        # При RTT ~ 350мс: reward ~ 0.7
        # При RTT >= 800мс: reward ~ 0.3
        if rtt_ms is not None and rtt_ms > 0:
            reward = max(0.2, min(2.5, 2.0 * (150.0 / (rtt_ms + 75.0))))
        else:
            reward = 1.0

        if is_calibration:
            # Калибровка — синтетический зонд. Награда демпфируется, чтобы не раздувать веса
            reward = min(reward, 1.2)

        cluster = classify_cdn_cluster(host, ip)
        key = self._get_composite_key(host, ip)
        domain = self._get_domain_key(host)
        net = self._current_network

        with self._lock:
            self._network_champion_wins[strategy] = self._network_champion_wins.get(strategy, 0) + 1
            self._apply_temporal_decay_locked()
            net_scores = self._scores.setdefault(net, {})
            is_yt = cluster == "google"
            is_dc = cluster == "discord"

            # 1. Запись в активный ключ (domain:IP/24 или domain)
            if key not in net_scores:
                net_scores[key] = self._init_key_scores_locked(net_scores, key, host, is_yt, is_dc)

            if strategy in net_scores[key]:
                net_scores[key][strategy][0] += reward

                # Capping: сохранение адаптивности и дисперсии
                total = net_scores[key][strategy][0] + net_scores[key][strategy][1]
                if total > 100.0:
                    net_scores[key][strategy][0] = max(0.1, net_scores[key][strategy][0] * 0.5)
                    net_scores[key][strategy][1] = max(0.1, net_scores[key][strategy][1] * 0.5)

            # 2. Dual-Tier Root Learning: обновляем также корневой ключ домена (net_scores[net][domain])
            if key != domain:
                if domain not in net_scores:
                    net_scores[domain] = self._init_key_scores_locked(net_scores, domain, host, is_yt, is_dc)
                if strategy in net_scores[domain]:
                    net_scores[domain][strategy][0] += reward
                    d_total = net_scores[domain][strategy][0] + net_scores[domain][strategy][1]
                    if d_total > 100.0:
                        net_scores[domain][strategy][0] = max(0.1, net_scores[domain][strategy][0] * 0.5)
                        net_scores[domain][strategy][1] = max(0.1, net_scores[domain][strategy][1] * 0.5)

            # 3. Перенос знаний в кластер CDN (Transfer Learning damping factor 0.35)
            if cluster:
                net_clusters = self._cluster_scores.setdefault(net, {})
                if cluster not in net_clusters:
                    net_clusters[cluster] = {s: [1.0, 1.0] for s in ALL_STRATEGIES}
                if strategy in net_clusters[cluster]:
                    net_clusters[cluster][strategy][0] += (reward * 0.35)
                    c_total = net_clusters[cluster][strategy][0] + net_clusters[cluster][strategy][1]
                    if c_total > 150.0:
                        net_clusters[cluster][strategy][0] = max(0.1, net_clusters[cluster][strategy][0] * 0.5)
                        net_clusters[cluster][strategy][1] = max(0.1, net_clusters[cluster][strategy][1] * 0.5)

            self._dirty = True

        logger.debug("ThompsonSampling success recorded: [%s] %s -> %s (reward=%.2f, rtt=%.1fms)", net, key, strategy, reward, rtt_ms or 0.0)
        self.save_scores(force=False)

    def record_failure(
        self,
        host: str,
        strategy: str,
        ip: Optional[str] = None,
        is_tspu: bool = True,
        is_calibration: bool = False
    ) -> None:
        """Фиксирует сбой соединения. При подтвержденном ТСПУ налагается штраф."""
        if is_calibration:
            logger.debug("Синтетическая TLS-проба %s: %s (не оценка загрузки)", host, strategy)
            return
        if not host or not strategy or strategy == "http":
            return

        if ip:
            try:
                try:
                    from Floweryguard.proxy import is_ip_dead
                except ImportError:
                    from flowguard.proxy import is_ip_dead
                if is_ip_dead(ip):
                    logger.debug("Skipping strategy penalty for %s (IP %s is dead)", strategy, ip)
                    return
            except (ImportError, Exception):
                pass

        # Адаптивный штраф с защитой от выгорания (Anti-Extinction MAB):
        # Предотвращает катастрофическое зацементирование стратегий при временных сетевых флуктуациях
        if is_calibration:
            penalty = 2.0 if is_tspu else 1.0
            alpha_mult = 0.85 if is_tspu else 0.90
        else:
            penalty = 5.0 if is_tspu else 2.0
            alpha_mult = 0.70 if is_tspu else 0.85

        cluster = classify_cdn_cluster(host, ip)
        key = self._get_composite_key(host, ip)
        domain = self._get_domain_key(host)
        net = self._current_network

        with self._lock:
            self._apply_temporal_decay_locked()
            net_scores = self._scores.setdefault(net, {})
            is_yt = cluster == "google"
            is_dc = cluster == "discord"

            # 1. Запись штрафа в активный ключ
            if key not in net_scores:
                net_scores[key] = self._init_key_scores_locked(net_scores, key, host, is_yt, is_dc)

            if strategy in net_scores[key]:
                # Ограничение beta <= 12.0 гарантирует сохранение исследования (exploration floor)
                net_scores[key][strategy][1] = min(12.0, net_scores[key][strategy][1] + penalty)
                net_scores[key][strategy][0] = max(0.8, net_scores[key][strategy][0] * alpha_mult)

                total = net_scores[key][strategy][0] + net_scores[key][strategy][1]
                if total > 80.0:
                    net_scores[key][strategy][0] = max(0.8, net_scores[key][strategy][0] * 0.5)
                    net_scores[key][strategy][1] = max(0.8, net_scores[key][strategy][1] * 0.5)

            # 2. Dual-Tier Root Learning: обновляем также корневой ключ домена
            if key != domain:
                if domain not in net_scores:
                    net_scores[domain] = self._init_key_scores_locked(net_scores, domain, host, is_yt, is_dc)
                if strategy in net_scores[domain]:
                    net_scores[domain][strategy][1] = min(12.0, net_scores[domain][strategy][1] + penalty)
                    net_scores[domain][strategy][0] = max(0.8, net_scores[domain][strategy][0] * alpha_mult)
                    d_total = net_scores[domain][strategy][0] + net_scores[domain][strategy][1]
                    if d_total > 80.0:
                        net_scores[domain][strategy][0] = max(0.8, net_scores[domain][strategy][0] * 0.5)
                        net_scores[domain][strategy][1] = max(0.8, net_scores[domain][strategy][1] * 0.5)

            # 3. Перенос штрафа в кластер CDN
            if cluster:
                net_clusters = self._cluster_scores.setdefault(net, {})
                if cluster in net_clusters and strategy in net_clusters[cluster]:
                    net_clusters[cluster][strategy][1] = min(12.0, net_clusters[cluster][strategy][1] + (penalty * 0.25))
                    net_clusters[cluster][strategy][0] = max(0.8, net_clusters[cluster][strategy][0] * alpha_mult)

            self._dirty = True

        logger.debug("ThompsonSampling failure recorded: [%s] %s -> %s (penalty=%.1f, is_tspu=%s)", net, key, strategy, penalty, is_tspu)
        self.save_scores(force=False)

    def get_top_strategies(self, host: str, ip: Optional[str] = None, count: int = 3) -> List[str]:
        """Возвращает топ N наиболее результативных стратегий для хоста по матожиданию Beta E[X]=a/(a+b)."""
        key = self._get_composite_key(host, ip)
        cluster = classify_cdn_cluster(host, ip)
        net = self._current_network
        with self._lock:
            net_scores = self._scores.get(net) or self._scores.get("default", {})
            if key not in net_scores:
                is_yt = cluster == "google"
                is_dc = cluster == "discord"
                net_scores[key] = self._init_key_scores_locked(net_scores, key, host, is_yt, is_dc)
            ranked = sorted(
                net_scores[key].items(),
                key=lambda item: item[1][0] / max(0.1, item[1][0] + item[1][1]),
                reverse=True
            )
            return [s for s, _ in ranked[:count]]

    def get_cluster_name(self, host: str, ip: Optional[str] = None) -> Optional[str]:
        """Возвращает название CDN-кластера для домена (или None)."""
        return classify_cdn_cluster(host, ip)

    def get_domain_scores(self, host: str, ip: Optional[str] = None) -> Dict[str, Dict[str, float]]:
        """Возвращает текущие веса alpha/beta для всех стратегий указанного домена в активной сети."""
        key = self._get_composite_key(host, ip)
        cluster = classify_cdn_cluster(host, ip)
        net = self._current_network
        with self._lock:
            net_scores = self._scores.setdefault(net, {})
            if key not in net_scores:
                is_yt = cluster == "google"
                is_dc = cluster == "discord"
                net_scores[key] = self._init_key_scores_locked(net_scores, key, host, is_yt, is_dc)
            return {
                s: {"alpha": ab[0], "beta": ab[1]}
                for s, ab in net_scores[key].items()
            }

    _get_domain_scores = get_domain_scores


# Таблица быстрой диспетчеризации стратегий O(1)
STRATEGY_DISPATCH: Dict[str, Callable[[socket.socket, bytes, float], None]] = {
    "direct": StrategyExecutor.direct,
    "boringssl_split": StrategyExecutor.boringssl_split,
    "tcp_split_sni_start": StrategyExecutor.tcp_split_sni_start,
    "tcp_split_sni_mid": StrategyExecutor.tcp_split_sni_mid,
    "tcp_overlap_sni": StrategyExecutor.tcp_overlap_sni,
    "tls_padding_split": StrategyExecutor.tls_padding_split,
    "multi_split": StrategyExecutor.multi_split,
    "tls_record_frag": StrategyExecutor.tls_record_frag,
    "combo_tlsrec_tcpsplit": StrategyExecutor.combo_tlsrec_tcpsplit,
    "dummy_record_prepend": StrategyExecutor.dummy_record_prepend,
    "disoob_sni": StrategyExecutor.disoob_sni,
    "mixed_case_tcpsplit": StrategyExecutor.mixed_case_tcpsplit,
}

# Глобальный синглтон селектора стратегий
_GLOBAL_ENGINE = ThompsonStrategySelector(enabled=True)


def get_strategy_engine() -> ThompsonStrategySelector:
    return _GLOBAL_ENGINE


def execute_strategy(
    strategy_name: str,
    sock: socket.socket,
    data: bytes,
    delay: float = 0.001
) -> None:
    """Выполняет отправку пакета ClientHello в соответствии с выбранной стратегией."""
    handler = STRATEGY_DISPATCH.get(strategy_name, StrategyExecutor.tcp_split_sni_mid)
    handler(sock, data, delay)
