"""Модуль адаптивных стратегий обхода DPI (Strategy Engine).
Реализация алгоритма Thompson Sampling (в стиле Nova/confeden) для подбора
наиболее эффективных техник обхода под каждого конкретного провайдера и целевой сервис.
Строго стандартная библиотека Python.
"""

import os
import json
import random
import socket
import struct
import time
import threading
import sys
from typing import Dict, List, Optional, Tuple, Callable

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
from Floweryguard.config import get_app_base_dir
from Floweryguard.tls_parser import (
    is_tls_client_hello,
    parse_sni,
    get_sni_offsets,
    create_tls_record_fragments,
    create_multi_tls_record_fragments,
    create_dummy_tls_record,
)


class StrategyExecutor:
    """Исполнитель конкретных техник обхода на сокете."""

    @staticmethod
    def direct(sock: socket.socket, data: bytes, delay: float = 0.0) -> None:
        """Прямая отправка без фрагментации (для согласованной работы с zapret WinDivert)."""
        sock.sendall(data)

    @staticmethod
    def boringssl_split(sock: socket.socket, data: bytes, delay: float = 0.005) -> None:
        """Специализированный TCP Split (pos=40) для Google/YouTube BoringSSL."""
        split_pos = min(40, max(1, len(data) - 1))
        sock.sendall(data[:split_pos])
        if delay > 0:
            time.sleep(delay)
        sock.sendall(data[split_pos:])

    @staticmethod
    def tcp_split_sni_start(sock: socket.socket, data: bytes, delay: float = 0.005) -> None:
        """TCP Split ровно по первому байту имени хоста SNI (+s)."""
        offsets = get_sni_offsets(data)
        split_pos = offsets[0] if offsets else min(40, len(data) // 2)
        split_pos = max(1, min(split_pos, len(data) - 1))
        sock.sendall(data[:split_pos])
        if delay > 0:
            time.sleep(delay)
        sock.sendall(data[split_pos:])

    @staticmethod
    def tcp_split_sni_mid(sock: socket.socket, data: bytes, delay: float = 0.005) -> None:
        """TCP Split ровно по середине имени хоста SNI (+sm)."""
        offsets = get_sni_offsets(data)
        split_pos = offsets[1] if offsets else min(40, len(data) // 2)
        split_pos = max(1, min(split_pos, len(data) - 1))
        sock.sendall(data[:split_pos])
        if delay > 0:
            time.sleep(delay)
        sock.sendall(data[split_pos:])

    @staticmethod
    def multi_split(sock: socket.socket, data: bytes, delay: float = 0.003) -> None:
        """Каскадный TCP Split на 3-5 фрагментов (заголовок + части SNI + хвост)."""
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
    def tls_record_frag(sock: socket.socket, data: bytes, delay: float = 0.005) -> None:
        """TLS Record Fragmentation: разбиение на 2 валидных TLS Record."""
        offsets = get_sni_offsets(data)
        split_offset = (offsets[0] + 1) if offsets else None
        fragments = create_tls_record_fragments(data, split_offset)
        if len(fragments) == 2:
            sock.sendall(fragments[0])
            if delay > 0:
                time.sleep(delay)
            sock.sendall(fragments[1])
        else:
            sock.sendall(data)

    @staticmethod
    def combo_tlsrec_tcpsplit(sock: socket.socket, data: bytes, delay: float = 0.003) -> None:
        """Двойная фрагментация: TLS Record Fragmentation + TCP Split каждой записи."""
        offsets = get_sni_offsets(data)
        split_offset = (offsets[0] + 1) if offsets else None
        fragments = create_tls_record_fragments(data, split_offset)
        if len(fragments) == 2:
            # Отправляем фрагмент 1, разбив его TCP-уровнем
            f1 = fragments[0]
            p1 = max(1, min(5, len(f1) - 1))
            sock.sendall(f1[:p1])
            if delay > 0:
                time.sleep(delay)
            sock.sendall(f1[p1:])

            if delay > 0:
                time.sleep(delay)

            # Отправляем фрагмент 2
            f2 = fragments[1]
            p2 = max(1, min(5, len(f2) - 1))
            sock.sendall(f2[:p2])
            if delay > 0:
                time.sleep(delay)
            sock.sendall(f2[p2:])
        else:
            StrategyExecutor.multi_split(sock, data, delay)

    @staticmethod
    def dummy_record_prepend(sock: socket.socket, data: bytes, delay: float = 0.003) -> None:
        """Внедрение безобидного TLS Alert/Dummy Record перед настоящим ClientHello."""
        dummy = create_dummy_tls_record("alert")
        try:
            sock.sendall(dummy)
            if delay > 0:
                time.sleep(delay)
        except Exception:
            pass
        # После dummy отправляем реальный ClientHello со сплитом
        StrategyExecutor.tcp_split_sni_mid(sock, data, delay)

    @staticmethod
    def disoob_sni(sock: socket.socket, data: bytes, delay: float = 0.003) -> None:
        """Внедрение TCP Urgent (MSG_OOB) ровно по середине имени SNI (+sm)."""
        offsets = get_sni_offsets(data)
        split_pos = offsets[1] if offsets else min(40, len(data) // 2)
        split_pos = max(1, min(split_pos, len(data) - 1))

        sock.sendall(data[:split_pos])
        if delay > 0:
            time.sleep(delay)
        try:
            sock.send(b"a", socket.MSG_OOB)
        except Exception:
            pass
        sock.sendall(data[split_pos:])


# Доступные стратегии в порядке их эффективности
ALL_STRATEGIES = [
    "direct",
    "disoob_sni",
    "combo_tlsrec_tcpsplit",
    "dummy_record_prepend",
    "tcp_split_sni_mid",
    "multi_split",
    "tls_record_frag",
    "boringssl_split",
    "tcp_split_sni_start",
]


MAX_SCORES_ENTRIES = 2000
MAX_LOGGED_ENTRIES = 500


class ThompsonStrategySelector:
    """Движок адаптивного автоподбора стратегий через Thompson Sampling (Multi-Armed Bandit).
    
    Для каждой пары (домен, стратегия) ведётся бета-распределение Beta(alpha, beta):
    - alpha: количество подтверждённых успешных ответов сервера
    - beta: количество сбоев/таймаутов
    
    Алгоритм семплирует случайные величины из Beta-распределения и выбирает стратегию
    с максимальным значением, балансируя между изучением новых путей и эксплуатацией рабочих.
    """

    def __init__(self, enabled: bool = True, cache_file: Optional[str] = None):
        self.enabled = enabled
        self._lock = threading.Lock()
        # {domain: {strategy_name: [alpha, beta]}}
        self._scores: Dict[str, Dict[str, List[float]]] = {}
        self._logged_strategies: Dict[str, str] = {}
        self._dirty = False
        self._last_save = time.time()

        if cache_file is None:
            base_dir = get_app_base_dir()
            self.cache_file = os.path.join(base_dir, "strategy_scores.json")
        else:
            self.cache_file = cache_file

        self._load_scores()

    def _load_scores(self) -> None:
        """Загружает сохраненную статистику обучения из JSON-файла."""
        if not self.cache_file or not os.path.exists(self.cache_file):
            return
        try:
            with open(self.cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                cleaned = {}
                for domain, strats in data.items():
                    if isinstance(strats, dict):
                        cleaned[domain] = {}
                        for s_name, ab in strats.items():
                            if isinstance(ab, list) and len(ab) == 2:
                                a = max(0.1, float(ab[0]))
                                b = max(0.1, float(ab[1]))
                                cleaned[domain][s_name] = [a, b]
                with self._lock:
                    self._scores.update(cleaned)
                    self._trim_capacity_locked()
        except Exception:
            pass

    def save_scores(self, force: bool = False) -> None:
        """Атомарно сохраняет накопленную статистику обучения в JSON-файл."""
        now = time.time()
        with self._lock:
            if not self._dirty and not force:
                return
            if not force and (now - self._last_save < 15.0):
                return
            snapshot = {d: {s: list(ab) for s, ab in strats.items()} for d, strats in self._scores.items()}
            self._dirty = False
            self._last_save = now

        if not self.cache_file or not snapshot:
            return

        try:
            tmp_path = self.cache_file + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, indent=2, ensure_ascii=False)
            os.replace(tmp_path, self.cache_file)
        except Exception:
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass

    def _trim_capacity_locked(self) -> None:
        """Ограничивает максимальный размер кэша в памяти, предотвращая утечки дескрипторов."""
        if len(self._scores) > MAX_SCORES_ENTRIES:
            # Сортируем по суммарному числу испытаний и оставляем наиболее активные
            sorted_items = sorted(
                self._scores.items(),
                key=lambda item: sum(sum(ab) for ab in item[1].values()),
                reverse=True
            )
            self._scores = dict(sorted_items[:MAX_SCORES_ENTRIES // 2])

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

    def _init_domain_priors(self, domain_key: str, is_youtube: bool, is_discord: bool) -> Dict[str, List[float]]:
        """Инициализирует априорные веса (priors) для известных типов сервисов."""
        scores = {}
        for s in ALL_STRATEGIES:
            scores[s] = [1.0, 10.0]

        if is_youtube:
            # Для YouTube OOB по середине SNI пробивает ТСПУ за 33 мс без zapret!
            scores["disoob_sni"] = [80.0, 1.0]
            scores["tcp_split_sni_mid"] = [3.0, 5.0]
            scores["boringssl_split"] = [3.0, 5.0]
            scores["multi_split"] = [2.0, 5.0]
            # Занижаем то, что ломает BoringSSL
            scores["tls_record_frag"] = [1.0, 20.0]
            scores["combo_tlsrec_tcpsplit"] = [1.0, 20.0]
            scores["dummy_record_prepend"] = [1.0, 20.0]
        elif is_discord:
            # Для Discord: Cloudflare блокирует OOB Urgent данные и dummy records.
            # Если zapret запущен в системе — direct отправка дает 70-120 мс без double-desync.
            # Автономно — combo_tlsrec_tcpsplit дает чистый обход без конфликтов.
            try:
                from Floweryguard.voice_helper import is_system_winws_running
                winws_active = is_system_winws_running()
            except Exception:
                winws_active = False

            if winws_active:
                scores["direct"] = [80.0, 1.0]
                scores["combo_tlsrec_tcpsplit"] = [20.0, 1.0]
            else:
                scores["combo_tlsrec_tcpsplit"] = [80.0, 1.0]
                scores["direct"] = [10.0, 2.0]

            scores["tls_record_frag"] = [5.0, 5.0]
            scores["tcp_split_sni_mid"] = [1.0, 10.0]
            scores["multi_split"] = [1.0, 10.0]
            scores["disoob_sni"] = [0.1, 50.0]
            scores["dummy_record_prepend"] = [0.1, 50.0]
            scores["boringssl_split"] = [0.1, 50.0]
        else:
            # Универсальный приоритет для остальных ресурсов (Cloudflare, NTC, X, Rutracker и др.)
            # combo_tlsrec_tcpsplit наиболее совместима с Cloudflare и современными CDN
            scores["combo_tlsrec_tcpsplit"] = [25.0, 1.0]
            scores["tcp_split_sni_mid"] = [10.0, 1.0]
            scores["tls_record_frag"] = [8.0, 2.0]
            scores["disoob_sni"] = [5.0, 2.0]
            scores["multi_split"] = [2.0, 5.0]
            scores["dummy_record_prepend"] = [1.0, 5.0]

        return scores

    def select_strategy(self, host: str, is_youtube: bool = False, is_discord: bool = False) -> str:
        """Выбирает оптимальную стратегию для данного хоста с использованием Thompson Sampling."""
        if not self.enabled:
            return "direct" if is_discord else "disoob_sni"

        domain_key = self._get_domain_key(host)

        with self._lock:
            if domain_key not in self._scores:
                self._trim_capacity_locked()
                self._scores[domain_key] = self._init_domain_priors(domain_key, is_youtube, is_discord)
                self._dirty = True

            candidates = self._scores[domain_key]

            # Ограничения несовместимости протоколов
            excluded = set()
            if is_youtube:
                excluded.update(["tls_record_frag", "combo_tlsrec_tcpsplit", "dummy_record_prepend"])
            if is_discord:
                # Cloudflare отклоняет соединения с посторонними записями перед ClientHello
                # и сбрасывает TCP при наличии OOB Urgent данных (disoob_sni)
                excluded.update(["dummy_record_prepend", "boringssl_split", "disoob_sni"])

            best_strategy = "direct" if is_discord else "disoob_sni"
            max_sample = -1.0

            for strat_name, (alpha, beta) in candidates.items():
                if strat_name in excluded:
                    continue
                # Семплируем из Beta-распределения
                sample = random.betavariate(max(0.1, alpha), max(0.1, beta))
                if sample > max_sample:
                    max_sample = sample
                    best_strategy = strat_name

            # Логируем выбор стратегии при первом использовании или смене
            prev = self._logged_strategies.get(domain_key)
            if prev != best_strategy:
                self._logged_strategies[domain_key] = best_strategy
                print(f"\033[95m[Auto-Strategy]\033[0m {domain_key:<20} -> \033[93m{best_strategy}\033[0m (alpha={candidates[best_strategy][0]:.1f}, beta={candidates[best_strategy][1]:.1f})")

            return best_strategy

    def record_success(self, host: str, strategy: str) -> None:
        """Фиксирует успешное соединение и ответ сервера."""
        domain_key = self._get_domain_key(host)
        with self._lock:
            if domain_key not in self._scores:
                self._trim_capacity_locked()
                self._scores[domain_key] = self._init_domain_priors(domain_key, False, False)
            if strategy in self._scores[domain_key]:
                self._scores[domain_key][strategy][0] += 1.0  # Увеличиваем alpha
                # Decay / capping при накоплении статистики для сохранения адаптивности
                total = self._scores[domain_key][strategy][0] + self._scores[domain_key][strategy][1]
                if total > 200.0:
                    self._scores[domain_key][strategy][0] = max(0.1, self._scores[domain_key][strategy][0] * 0.5)
                    self._scores[domain_key][strategy][1] = max(0.1, self._scores[domain_key][strategy][1] * 0.5)
                self._dirty = True
        self.save_scores(force=False)

    def record_failure(self, host: str, strategy: str) -> None:
        """Фиксирует ошибку соединения (сброс ТСПУ, таймаут)."""
        domain_key = self._get_domain_key(host)
        with self._lock:
            if domain_key not in self._scores:
                self._trim_capacity_locked()
                self._scores[domain_key] = self._init_domain_priors(domain_key, False, False)
            if strategy in self._scores[domain_key]:
                self._scores[domain_key][strategy][1] += 20.0  # Моментально пенализируем (beta += 20)
                self._scores[domain_key][strategy][0] = max(0.1, self._scores[domain_key][strategy][0] * 0.4)
                # Decay / capping при накоплении статистики для сохранения адаптивности
                total = self._scores[domain_key][strategy][0] + self._scores[domain_key][strategy][1]
                if total > 200.0:
                    self._scores[domain_key][strategy][0] = max(0.1, self._scores[domain_key][strategy][0] * 0.5)
                    self._scores[domain_key][strategy][1] = max(0.1, self._scores[domain_key][strategy][1] * 0.5)
                self._dirty = True
        self.save_scores(force=False)


# Таблица быстрой диспетчеризации стратегий O(1)
STRATEGY_DISPATCH: Dict[str, Callable[[socket.socket, bytes, float], None]] = {
    "direct": StrategyExecutor.direct,
    "boringssl_split": StrategyExecutor.boringssl_split,
    "tcp_split_sni_start": StrategyExecutor.tcp_split_sni_start,
    "tcp_split_sni_mid": StrategyExecutor.tcp_split_sni_mid,
    "multi_split": StrategyExecutor.multi_split,
    "tls_record_frag": StrategyExecutor.tls_record_frag,
    "combo_tlsrec_tcpsplit": StrategyExecutor.combo_tlsrec_tcpsplit,
    "dummy_record_prepend": StrategyExecutor.dummy_record_prepend,
    "disoob_sni": StrategyExecutor.disoob_sni,
}

# Глобальный синглтон селектора стратегий
_GLOBAL_ENGINE = ThompsonStrategySelector(enabled=True)


def get_strategy_engine() -> ThompsonStrategySelector:
    return _GLOBAL_ENGINE


def execute_strategy(
    strategy_name: str,
    sock: socket.socket,
    data: bytes,
    delay: float = 0.005
) -> None:
    """Выполняет отправку пакета ClientHello в соответствии с выбранной стратегией."""
    handler = STRATEGY_DISPATCH.get(strategy_name, StrategyExecutor.tcp_split_sni_mid)
    handler(sock, data, delay)
