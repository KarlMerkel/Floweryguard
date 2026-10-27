"""Модуль «Калибровка» (Calibration Engine) для Flowery (Glue).

Обеспечивает активное форсированное обучение и прогрев адаптивного ML-механизма 
(Thompson Sampling) под конкретного интернет-провайдера пользователя.

Поддерживает два режима:
1. Быстрая калибровка (~10-15 сек): 10 ключевых ресурсов (YouTube, Discord, X, ECH, Twitch).
2. Полная калибровка (~30-45 сек): 95 заблокированных сервисов (СМИ, торренты, VPN, кинотеатры).
Строго стандартная библиотека Python (socket, struct, concurrent.futures, threading, time).
"""

import os
import sys
import time
import socket
import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional, Any, Callable, Iterable, Set

# Обеспечиваем доступность корневого каталога пакета при прямом запуске скрипта
base_pkg_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if base_pkg_dir not in sys.path:
    sys.path.insert(0, base_pkg_dir)

# Импорт необходимых компонентов Flowery
from flowguard.sni_spoofer import build_fake_client_hello
from flowguard.strategy import (
    STRATEGY_DISPATCH,
    StrategyExecutor,
    ThompsonStrategySelector,
    get_strategy_engine
)
from flowguard.logger import get_logger
try:
    from flowguard.proxy import resolve_fallback_dns
except ImportError:
    resolve_fallback_dns = None

logger = get_logger("Calibration")

# ---------------------------------------------------------------------------
# 1. Пул целевых доменов для калибровки
# ---------------------------------------------------------------------------

FAST_CALIBRATION_DOMAINS: List[str] = [
    "www.youtube.com",
    "rr1---sn-4g5ednks.googlevideo.com",
    "discord.com",
    "gateway.discord.gg",
    "x.com",
    "instagram.com",
    "cloudflare-ech.com",
    "rutracker.org",
    "steamcommunity.com",
    "twitch.tv",
]

FULL_CALIBRATION_DOMAINS: List[str] = [
    # Соцсети и коммуникации
    "instagram.com",
    "facebook.com",
    "twitter.com",
    "x.com",
    "discord.com",
    "discord.gg",
    "linkedin.com",
    # Торрент-трекеры и онлайн-библиотеки
    "rutracker.org",
    "nnmclub.to",
    "rutor.info",
    "kinozal.tv",
    "flibusta.is",
    "archive.org",
    "waybackmachine.org",
    # Онлайн-кинотеатры и аниме
    "lostfilm.tv",
    "animego.org",
    "seasonvar.ru",
    "baskino.me",
    "hdrezka.ag",
    # Информационные порталы и независимые СМИ
    "meduza.io",
    "bbc.com",
    "dw.com",
    "svoboda.org",
    "currenttime.tv",
    "novayagazeta.eu",
    "themoscowtimes.com",
    "tvrain.tv",
    "echofm.online",
    "holod.media",
    "zona.media",
    "istories.media",
    "agentura.ru",
    "bellona.ru",
    "kasparov.ru",
    "grani.ru",
    "charter97.org",
    "unian.net",
    "pravda.com.ua",
    "censor.net",
    "korrespondent.net",
    "tsn.ua",
    "telegraf.com.ua",
    "obozrevatel.com",
    "rbc.ua",
    "gordonua.com",
    "nv.ua",
    "hromadske.ua",
    # Правозащита и гражданские инициативы
    "amnesty.org",
    "hrw.org",
    "rsf.org",
    "memohrc.org",
    "gulagu.net",
    "ovd.info",
    "navalny.com",
    # Взрослый контент
    "pornhub.com",
    "xvideos.com",
    "xnxx.com",
    "redtube.com",
    "youporn.com",
    "chaturbate.com",
    "stripchat.com",
    "bonga-cams.com",
    # Дизайн, творчество и донаты
    "canva.com",
    "patreon.com",
    "boosty.to",
    "soundcloud.com",
    # Безопасность, VPN и анонимайзеры
    "proton.me",
    "protonvpn.com",
    "protonmail.com",
    "nordvpn.com",
    "expressvpn.com",
    "surfshark.com",
    "mullvad.net",
    "windscribe.com",
    "hidemy.name",
    "cyberghostvpn.com",
    "vpngate.net",
    "torproject.org",
    "i2pproject.net",
    "tailscale.com",
    # Мессенджеры и голосовая связь
    "signal.org",
    "viber.com",
    "line.me",
    "zello.com",
    # Игры, графические стоки, музыка
    "chess.com",
    "metacritic.com",
    "boardgamegeek.com",
    "deviantart.com",
    "shutterstock.com",
    "pixabay.com",
    "unsplash.com",
    "quora.com",
    "scribd.com",
    "genius.com",
    "last.fm",
    # Видео, стриминг и гейминг
    "youtube.com",
    "googlevideo.com",
    "twitch.tv",
    "steamcommunity.com",
    "steampowered.com",
    "roblox.com",
    # ИИ, разработка, базы знаний и сервисы
    "openai.com",
    "chatgpt.com",
    "claude.ai",
    "anthropic.com",
    "github.com",
    "reddit.com",
    "wikipedia.org",
    "notion.so",
    "figma.com",
    "spotify.com",
    "reuters.com",
    "bloomberg.com",
]

# Ключевые стратегии, участвующие в бенчмарке калибровки
CALIBRATION_CANDIDATE_STRATEGIES: List[str] = [
    "combo_tlsrec_tcpsplit",
    "tcp_split_sni_mid",
    "tcp_overlap_sni",
    "tls_padding_split",
    "multi_split",
    "tls_record_frag",
    "disoob_sni",
    "boringssl_split",
    "direct",
]


# ---------------------------------------------------------------------------
# 2. Низкоуровневый зонд стратегий
# ---------------------------------------------------------------------------

def probe_tls_strategy(
    domain: str,
    strategy: str,
    ip: Optional[str] = None,
    timeout: float = 2.5
) -> Tuple[bool, float, str]:
    """Отправляет тестовый TLS ClientHello с указанной стратегией к целевому домену.
    
    Возвращает: (success: bool, latency_ms: float, error_detail: str).
    """
    t0 = time.time()
    target_ip = ip
    if not target_ip:
        try:
            # Сначала пробуем встроенный DoH fallback прокси
            if resolve_fallback_dns is not None:
                try:
                    target_ip = resolve_fallback_dns(domain)
                except Exception:
                    target_ip = None
            if not target_ip:
                target_ip = socket.gethostbyname(domain)
        except Exception as de:
            return False, 0.0, f"DNS error: {de}"

    family = socket.AF_INET6 if ":" in str(target_ip) else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception as e:
            logger.debug("Failed setting TCP_NODELAY on probe socket: %s", e)

        # Органический джиттер: размывает всплески параллельных запросов во времени (10-50 мс)
        # для защиты от обнаружения сигнатур массового сканирования со стороны ТСПУ/IDS (B17)
        time.sleep(random.uniform(0.010, 0.050))

        try:
            sock.connect((target_ip, 443))
        except (socket.timeout, TimeoutError):
            return False, (time.time() - t0) * 1000.0, "Connect timeout (TSPU drop)"
        except ConnectionResetError:
            return False, (time.time() - t0) * 1000.0, "Connect TCP RST (TSPU block)"
        except Exception as ce:
            return False, (time.time() - t0) * 1000.0, f"Connect failed: {ce}"

        try:
            ch = build_fake_client_hello(domain)
        except Exception as be:
            return False, (time.time() - t0) * 1000.0, f"ClientHello build failed: {be}"

        executor = STRATEGY_DISPATCH.get(strategy, StrategyExecutor.direct)
        try:
            executor(sock, ch, delay=random.uniform(0.001, 0.003))
        except Exception as se:
            return False, (time.time() - t0) * 1000.0, f"Send error: {se}"

        # Ожидаем ответ сервера (ServerHello: 0x16 0x03 0x01/0x03 ...)
        try:
            resp = sock.recv(2048)
            latency = (time.time() - t0) * 1000.0

            if resp and len(resp) >= 5 and resp[0] == 0x16:
                return True, latency, "TLS ServerHello OK"
            elif resp and resp[0] == 0x15:
                # TLS Alert (например, handshake_failure / unrecognized_name / illegal_parameter)
                alert_desc = f"0x{resp[-1]:02x}" if len(resp) >= 2 else "unknown"
                return False, latency, f"TLS Alert ({alert_desc})"
            elif resp and resp.startswith(b"HTTP/"):
                # Провайдерская инъекция plain text HTTP заглушки блокировки на порту 443
                return False, latency, "HTTP block page injection"
            elif resp and len(resp) >= 5 and resp[0] == 0x17:
                return True, latency, "TLS Application Data OK"
            else:
                return False, latency, "Invalid TLS response (Silent drop / DPI block)"
        except (socket.timeout, TimeoutError):
            return False, (time.time() - t0) * 1000.0, "TSPU Timeout"
        except ConnectionResetError:
            return False, (time.time() - t0) * 1000.0, "TSPU TCP RST"
        except Exception as re:
            return False, (time.time() - t0) * 1000.0, str(re)
    finally:
        try:
            sock.close()
        except Exception as e:
            logger.debug("Error closing probe socket: %s", e)


# ---------------------------------------------------------------------------
# 3. Диспетчер процесса калибровки и обучения
# ---------------------------------------------------------------------------

class StrategyCalibrator:
    """Управляет процедурой калибровки и ускоренного обучения Thompson Sampling."""

    CALIBRATION_MIN_INTERVAL: float = 45.0  # Минимальный интервал между калибровками (сек)
    _last_calibration_time: float = 0.0

    def __init__(self, engine: Optional[ThompsonStrategySelector] = None, max_workers: int = 4):
        self.engine = engine or get_strategy_engine()
        # Лимит параллелизма для защиты от сброса сессий мобильным оператором (B17)
        self.max_workers = min(6, max(1, max_workers))
        self._cancel_flag = threading.Event()

    def cancel(self) -> None:
        """Сигнал прерывания калибровки."""
        self._cancel_flag.set()

    def run_calibration(
        self,
        mode: str = "fast",
        progress_callback: Optional[Callable[[int, int, str, str, bool], None]] = None,
        reset_cancel: bool = False
    ) -> Dict[str, Any]:
        """Запускает калибровку ('fast' или 'full') с одновременным обучением ML-модели.
        
        progress_callback: fn(current, total, domain, strategy, success)
        Возвращает сводный отчет по стратегиям и сервисам.
        """
        if reset_cancel:
            self._cancel_flag.clear()

        now = time.time()
        is_frequent_run = (now - StrategyCalibrator._last_calibration_time < StrategyCalibrator.CALIBRATION_MIN_INTERVAL)
        StrategyCalibrator._last_calibration_time = now

        # Защита от перекоса и зацементирования при повторной/частой калибровке:
        # Смягчаем прошлые экстремумы, чтобы случайные сетевые таймауты не накапливали штрафы
        if self.engine and hasattr(self.engine, "soften_calibration_priors"):
            self.engine.soften_calibration_priors(factor=0.75 if is_frequent_run else 0.90)

        target_domains = FAST_CALIBRATION_DOMAINS if mode == "fast" else FULL_CALIBRATION_DOMAINS
        strategies_to_test = CALIBRATION_CANDIDATE_STRATEGIES

        if self._cancel_flag.is_set():
            return {
                "mode": mode,
                "total_domains": len(target_domains),
                "completed_probes": 0,
                "ranked_strategies": [],
                "winning_strategy": "combo_tlsrec_tcpsplit",
                "domain_matrix": {},
                "cancelled": True,
            }

        total_probes = len(target_domains) * len(strategies_to_test)
        completed_probes = 0

        # Статистика по стратегиям: {strat: {"success": int, "total": int, "latency_sum": float}}
        strat_stats: Dict[str, Dict[str, Any]] = {
            s: {"success": 0, "total": 0, "latency_sum": 0.0, "domains_won": 0}
            for s in strategies_to_test
        }
        # Результаты по каждому домену: {domain: {strat: (success, latency)}}
        domain_matrix: Dict[str, Dict[str, Tuple[bool, float]]] = {d: {} for d in target_domains}

        logger.info(f"[Калибровка] Старт режима '{mode}': {len(target_domains)} доменов x {len(strategies_to_test)} стратегий")

        # Формируем задачи
        tasks = []
        for d in target_domains:
            for s in strategies_to_test:
                tasks.append((d, s))

        # Выполняем параллельное зондирование через ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_probe = {
                executor.submit(probe_tls_strategy, domain, strategy): (domain, strategy)
                for domain, strategy in tasks
            }

            for future in as_completed(future_to_probe):
                if self._cancel_flag.is_set():
                    logger.warning("[Калибровка] Прервано пользователем")
                    break

                domain, strategy = future_to_probe[future]
                completed_probes += 1

                try:
                    success, latency, detail = future.result()
                except Exception as e:
                    success, latency, detail = False, 0.0, str(e)

                # Запись в статистику
                domain_matrix[domain][strategy] = (success, latency)
                strat_stats[strategy]["total"] += 1
                if success:
                    strat_stats[strategy]["success"] += 1
                    strat_stats[strategy]["latency_sum"] += latency

                # --- ОБУЧЕНИЕ ML-ДВИЖКА THOMPSON SAMPLING (С ЗАЩИТОЙ DAMPING) ---
                if self.engine:
                    if success:
                        self.engine.record_success(domain, strategy, rtt_ms=latency, is_calibration=True)
                    else:
                        is_tspu = "TSPU" in detail or "RST" in detail or "Timeout" in detail
                        self.engine.record_failure(domain, strategy, is_tspu=is_tspu, is_calibration=True)

                if progress_callback:
                    progress_callback(completed_probes, total_probes, domain, strategy, success)

        # Сохраняем обновленные веса модели
        if self.engine:
            self.engine.save_scores(force=True)
            logger.info("[Калибровка] strategy_scores.json успешно сохранен с новыми весами обучения")

        # Определение лучшей стратегии для каждого домена и общего лидера
        for domain, strats in domain_matrix.items():
            successful = [(s, lat) for s, (succ, lat) in strats.items() if succ]
            if successful:
                # Лучшая — с наименьшей задержкой
                best_for_domain = min(successful, key=lambda x: x[1])[0]
                strat_stats[best_for_domain]["domains_won"] += 1

        # Формирование итогового рейтинга
        ranked_strategies = []
        for s, data in strat_stats.items():
            tot = data["total"] or 1
            succ = data["success"]
            rate = (succ / tot) * 100.0
            avg_lat = (data["latency_sum"] / succ) if succ > 0 else 999.0
            ranked_strategies.append({
                "strategy": s,
                "success_count": succ,
                "total_count": tot,
                "success_rate": rate,
                "avg_latency": avg_lat,
                "domains_won": data["domains_won"],
            })

        # Сортировка: сначала процент успеха, затем средний пинг
        ranked_strategies.sort(key=lambda x: (-x["success_rate"], x["avg_latency"]))

        winner = ranked_strategies[0]["strategy"] if ranked_strategies else "combo_tlsrec_tcpsplit"

        report = {
            "mode": mode,
            "total_domains": len(target_domains),
            "completed_probes": completed_probes,
            "ranked_strategies": ranked_strategies,
            "winning_strategy": winner,
            "domain_matrix": domain_matrix,
        }
        return report


class WarmUpHarvester:
    """Проактивный фоновый сборщик (Warm-Up Harvester) для предварительного прогрева стратегий.
    
    Запускается в низкоприоритетном фоновом потоке через несколько секунд после старта прокси.
    Берет топ заблокированных доменов (из whitelist.txt и калибровочного списка),
    выполняет легковесное зондирование с интервалом 1.5 с и прогревает веса Thompson Sampling,
    чтобы к моменту открытия браузера пользователем победные стратегии уже были подобраны с нулевой задержкой.
    """

    def __init__(
        self,
        strategy_engine,
        whitelist_domains: Optional[Iterable[str]] = None,
        delay_start: float = 3.0,
        interval: float = 1.5,
    ):
        self.strategy_engine = strategy_engine
        self.whitelist_domains = set(whitelist_domains or ())
        self.delay_start = delay_start
        self.interval = interval
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        """Запускает фоновый поток прогрева, если он еще не запущен."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="WarmUpHarvester")
        self._thread.start()

    def stop(self) -> None:
        """Останавливает сборщик прогрева."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
        self._thread = None

    def _get_target_domains(self) -> List[str]:
        """Формирует список ключевых заблокированных доменов для прогрева."""
        targets = []
        priority_domains = [
            "www.youtube.com",
            "rr1---sn-4g5ednks.googlevideo.com",
            "discord.com",
            "gateway.discord.gg",
            "x.com",
            "instagram.com",
            "rutracker.org",
            "meduza.io",
            "lostfilm.tv",
            "nnmclub.to",
            "archive.org",
            "cloudflare-ech.com",
            "twitch.tv",
        ]
        targets.extend(priority_domains)

        try:
            from flowguard.strategy import is_domestic_domain
        except ImportError:
            try:
                from Floweryguard.strategy import is_domestic_domain
            except ImportError:
                is_domestic_domain = lambda d: False

        for d in sorted(self.whitelist_domains):
            if d and not is_domestic_domain(d) and d not in targets:
                targets.append(d)

        return targets[:25]

    def _run(self) -> None:
        """Основной цикл низкоприоритетного прогрева."""
        if self._stop_event.wait(self.delay_start):
            return

        targets = self._get_target_domains()
        logger.info("[WarmUpHarvester] Запуск проактивного прогрева стратегий для %d доменов...", len(targets))

        for domain in targets:
            if self._stop_event.is_set():
                break

            try:
                scores = self.strategy_engine.get_scores_for_key(domain)
                if scores:
                    top_alpha = max(ab[0] for ab in scores.values())
                    if top_alpha >= 5.0:
                        continue

                strat = self.strategy_engine.select_strategy(domain)
                success, latency, _ = probe_tls_strategy(domain, strat, timeout=2.0)
                if success:
                    self.strategy_engine.record_success(domain, strat, rtt_ms=latency, is_calibration=True)
                    logger.debug("[WarmUpHarvester] Прогрет %s -> %s (latency=%.1fms)", domain, strat, latency)
                else:
                    fb_strat = self.strategy_engine.get_fallback_strategy(domain, failed_strategy=strat)
                    if fb_strat != strat:
                        success_fb, lat_fb, _ = probe_tls_strategy(domain, fb_strat, timeout=2.0)
                        if success_fb:
                            self.strategy_engine.record_success(domain, fb_strat, rtt_ms=lat_fb, is_calibration=True)
                            self.strategy_engine.record_failure(domain, strat, is_tspu=True, is_calibration=True)
                            logger.debug("[WarmUpHarvester] Fallback прогрет %s -> %s", domain, fb_strat)
            except Exception as e:
                logger.debug("[WarmUpHarvester] Ошибка зондирования %s: %s", domain, e)

            if self._stop_event.wait(self.interval):
                break

        logger.info("[WarmUpHarvester] Проактивный прогрев стратегий успешно завершен.")


def print_calibration_report(report: Dict[str, Any], elapsed: float) -> None:
    """Форматированный вывод отчета калибровки в консоль с ANSI-цветами."""
    ranked = report.get("ranked_strategies", [])
    winner = report.get("winning_strategy", "combo_tlsrec_tcpsplit")

    print("\033[1;92m" + "=" * 74 + "\033[0m")
    print(f"\033[1;97m       РЕЗУЛЬТАТЫ КАЛИБРОВКИ ML ({elapsed:.1f} сек, {report.get('completed_probes', 0)} проверок)\033[0m")
    print("\033[1;92m" + "=" * 74 + "\033[0m\n")
    print(f"  {'Стратегия':<24} {'Успех':<14} {'Ср. пинг':<10} {'Доменов выиграно':<18} {'Рейтинг'}")
    print("  " + "-" * 72)

    for i, r in enumerate(ranked):
        s_name = r["strategy"]
        rate_str = f"{r['success_rate']:.1f}% ({r['success_count']}/{r['total_count']})"
        lat_str = f"{r['avg_latency']:.0f} ms" if r["success_count"] > 0 else "—"
        won_str = str(r["domains_won"])

        if r["success_rate"] >= 90.0:
            stars = "\033[92m★★★★★\033[0m"
        elif r["success_rate"] >= 75.0:
            stars = "\033[92m★★★★☆\033[0m"
        elif r["success_rate"] >= 50.0:
            stars = "\033[93m★★★☆☆\033[0m"
        elif r["success_rate"] >= 25.0:
            stars = "\033[91m★★☆☆☆\033[0m"
        else:
            stars = "\033[91m★☆☆☆☆\033[0m"

        marker = "\033[1;92m🏆 [ЛИДЕР]\033[0m" if i == 0 else ""
        print(f"  {s_name:<24} {rate_str:<14} {lat_str:<10} {won_str:<18} {stars} {marker}")

    print("\n\033[92m[+] База знаний ML-движка успешно обучена и сохранена в strategy_scores.json!\033[0m")
    print(f"\033[96m[+] Оптимальная универсальная стратегия: \033[1;97m{winner}\033[0m\n")
    logger.info("Калибровка завершена за %.1fs (%d проверок). Оптимальная стратегия: %s", elapsed, report.get('completed_probes', 0), winner)
    for r in ranked[:3]:
        logger.info("  Стратегия %s: успех %.1f%% (%d/%d), средний пинг: %.0f ms", r['strategy'], r['success_rate'], r['success_count'], r['total_count'], r['avg_latency'])


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Калибровка и обучение ML-движка Flowery")
    parser.add_argument("--mode", choices=["fast", "quick", "full"], default="full", help="Режим калибровки: fast (10 сайтов) или full (110+ сайтов)")
    parser.add_argument("--workers", type=int, default=16, help="Количество параллельных сокет-воркеров")
    args = parser.parse_args()

    m = "fast" if args.mode in ("fast", "quick") else "full"
    engine = get_strategy_engine()
    calibrator = StrategyCalibrator(engine=engine, max_workers=args.workers)

    last_len = [0]
    def on_progress(current: int, total: int, domain: str, strategy: str, success: bool):
        pct = int((current / total) * 100) if total else 0
        bar_len = 20
        filled = int(bar_len * (current / total)) if total else 0
        bar = "█" * filled + "░" * (bar_len - filled)
        status_icon = "\033[92m✓\033[0m" if success else "\033[91m✗\033[0m"
        line = f"\r\033[96m[{bar}] {pct:>3}%\033[0m ({current}/{total}) {status_icon} {domain:<24} -> {strategy:<22}"
        pad = max(0, last_len[0] - len(line))
        sys.stdout.write(line + " " * pad)
        sys.stdout.flush()
        last_len[0] = len(line)

    desc = "Быстрая (10 сервисов)" if m == "fast" else f"Полная ({len(FULL_CALIBRATION_DOMAINS)} сервисов)"
    print(f"\033[1;96m[*] Запуск калибровки: {desc} (потоков: {args.workers})...\033[0m")
    t0 = time.time()
    report = calibrator.run_calibration(mode=m, progress_callback=on_progress)
    elapsed = time.time() - t0
    print("\n")
    print_calibration_report(report, elapsed)


if __name__ == "__main__":
    main()
