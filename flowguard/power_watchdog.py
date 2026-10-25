"""Модуль мониторинга электропитания и автоматического восстановления после гибернации/сна.
Гарантирует бесперебойную работу Flowery (Glue) после выхода Windows из спящего режима,
гибернации (S4), Connected/Modern Standby (S0ix) или смены сетевого подключения.

Архитектура защиты:
1. Win32 Power Events (WM_POWERBROADCAST: PBT_APMRESUMEAUTOMATIC / PBT_APMRESUMESUSPEND).
2. Universal Heartbeat Watchdog (детекция скачков времени sleep-цикла для работы без GUI/окон).
3. Network Adapter Re-enumeration (мониторинг восстановления IP-стека и шлюзов Windows).
4. Self-Healing Engine:
   - Автоматический перезапуск слушающего сокета прокси (127.0.0.1:8118) при разрыве дескрипторов.
   - Сброс устаревших кэшей IP/DNS, накопленных до сна.
   - Повторная активация и WinINet refresh системного прокси Windows.
   - Повторное применение DefaultTTL (маскировка тетеринга) и блокировки QUIC.
   - Автоматическое переключение сетевого профиля (если ноутбук открыли в другой сети).
   - Восстановление Discord Voice UDP Helper.
"""

import time
import socket
import threading
import logging
from typing import Optional, Any

from flowguard.ttl_fix import is_admin

logger = logging.getLogger("Flowery.PowerWatchdog")


class PowerWatchdog:
    """Сторожевой таймер и менеджер самовосстановления при сне и гибернации."""

    def __init__(
        self,
        app: Any,
        check_interval: float = 1.5,
        time_jump_threshold: float = 4.0,
    ):
        self.app = app
        self.check_interval = check_interval
        self.time_jump_threshold = time_jump_threshold

        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self._recovery_lock = threading.Lock()
        self._last_recovery_time = 0.0
        self._recovery_cooldown = 3.0  # Защита от дребезга при множественных событиях

        # Метрики мониторинга
        self._start_time = time.time()
        self._last_wall_time = time.time()
        self._last_mono_time = time.monotonic()
        self._in_suspend = False
        self.recoveries_count = 0

    def start(self) -> None:
        """Запускает фоновый сторожевой поток мониторинга питания и сетевого стека."""
        if self.is_running:
            return
        self.is_running = True
        self._start_time = time.time()
        self._last_wall_time = time.time()
        self._last_mono_time = time.monotonic()
        self._thread = threading.Thread(
            target=self._watchdog_loop,
            daemon=True,
            name="FloweryPowerWatchdog"
        )
        self._thread.start()
        logger.info("[PowerWatchdog] Монитор сна и гибернации успешно активирован.")

    def stop(self) -> None:
        """Останавливает сторожевой поток."""
        self.is_running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
        self._thread = None

    def on_power_broadcast(self, event_type: int) -> None:
        """Обработчик системных сообщений WM_POWERBROADCAST от Win32 окна."""
        # PBT_APMSUSPEND = 0x0004
        if event_type == 0x0004:
            self._in_suspend = True
            logger.info("[PowerWatchdog] Windows переходит в спящий режим / гибернацию...")
            # Сохраняем веса стратегий перед уходом в сон
            try:
                if hasattr(self.app, "proxy_server") and self.app.proxy_server:
                    if hasattr(self.app.proxy_server, "strategy_engine") and self.app.proxy_server.strategy_engine:
                        self.app.proxy_server.strategy_engine.save_scores(force=True)
            except Exception as e:
                logger.warning("Failed saving strategy scores on sleep: %s", e)
            return

        # PBT_APMRESUMEAUTOMATIC = 0x0012, PBT_APMRESUMESUSPEND = 0x0007
        if event_type in (0x0012, 0x0007):
            logger.info(f"[PowerWatchdog] Win32 Power Event: пробуждение из сна/гибернации (code 0x{event_type:04X})!")
            self._in_suspend = False
            self.trigger_recovery(reason=f"Win32 Power Event 0x{event_type:04X}")

    def trigger_recovery(self, reason: str = "Unknown") -> bool:
        """Инициирует процесс полного восстановления всех компонентов Flowery.
        Имеет встроенную защиту от дребезга (debounce cooldown).
        """
        now = time.time()
        with self._recovery_lock:
            if now - self._last_recovery_time < self._recovery_cooldown:
                # Слишком частые вызовы (например, пришло и событие окна, и сработал time jump)
                return False
            self._last_recovery_time = now
            self.recoveries_count += 1

        logger.warning(f"[PowerWatchdog] Запуск самовосстановления системы после гибернации/сна (Причина: {reason})...")
        
        # Запускаем в отдельном потоке, чтобы не блокировать цикл событий
        t = threading.Thread(
            target=self._execute_recovery_sequence,
            args=(reason,),
            daemon=True,
            name="FloweryRecoveryThread"
        )
        t.start()
        return True

    def _execute_recovery_sequence(self, reason: str) -> None:
        """Последовательность гарантированного оживления всех компонентов."""
        try:
            # 1. Даем сетевому стеку Windows 1.2 секунды на восстановление DHCP и физического линка Wi-Fi
            time.sleep(1.2)

            if not getattr(self.app, "_is_active", False):
                logger.info("[PowerWatchdog] Flowery в данный момент остановлен пользователем, пропуск восстановления.")
                return

            print(f"\n\033[96m[*] Обнаружен выход из спящего режима / гибернации!\033[0m")
            print("  \033[93m[*] Выполняется автоматическое самовосстановление компонентов Flowery...\033[0m")

            # 2. Оживление и проверка локального сокета прокси сервера
            proxy_revived = False
            if hasattr(self.app, "proxy_server") and self.app.proxy_server:
                proxy = self.app.proxy_server
                try:
                    proxy_revived = proxy.revive_if_needed()
                    proxy.flush_stale_caches()
                except Exception as pe:
                    logger.error(f"[PowerWatchdog] Ошибка оживления прокси: {pe}")

            if proxy_revived:
                print("  \033[92m[✓]\033[0m Локальный прокси-сервер (127.0.0.1:8118) перезапущен и готов к приёму трафика")
            else:
                print("  \033[92m[✓]\033[0m Слушающий сокет прокси в норме, кэши устаревших IP очищены")

            # 3. Восстановление системного прокси Windows (WinINet / Internet Settings)
            if hasattr(self.app, "proxy_mgr") and self.app.proxy_mgr:
                pm = self.app.proxy_mgr
                cfg = getattr(self.app, "config", None)
                if cfg and getattr(cfg, "auto_system_proxy", True):
                    try:
                        pm.ensure_active()
                        print("  \033[92m[✓]\033[0m Системный прокси Windows перепроверен и обновлён в WinINet")
                    except Exception as pme:
                        logger.error(f"[PowerWatchdog] Ошибка проверки системного прокси: {pme}")

            # 4. Восстановление системных настроек Windows (TTL и QUIC)
            if is_admin():
                cfg = getattr(self.app, "config", None)
                if cfg:
                    # TTL Fix
                    if cfg.fix_ttl and hasattr(self.app, "ttl_mgr") and self.app.ttl_mgr:
                        try:
                            self.app.ttl_mgr.apply_ttl()
                            print(f"  \033[92m[✓]\033[0m Реестр DefaultTTL={cfg.default_ttl} подтверждён")
                        except Exception as te:
                            logger.error(f"[PowerWatchdog] Ошибка повторной фиксации TTL: {te}")

                    # Блокировка QUIC
                    if cfg.block_quic and hasattr(self.app, "quic_blocker") and self.app.quic_blocker:
                        try:
                            self.app.quic_blocker.block_quic()
                            print("  \033[92m[✓]\033[0m Правило блокировки QUIC (UDP 443) в брандмауэре активно")
                        except Exception as qe:
                            logger.error(f"[PowerWatchdog] Ошибка проверки правила QUIC: {qe}")

                    # Защищённый DNS
                    if cfg.enable_custom_dns and hasattr(self.app, "dns_mgr") and self.app.dns_mgr:
                        try:
                            self.app.dns_mgr.set_secure_dns()
                        except Exception as de:
                            logger.error("[PowerWatchdog] Ошибка повторной установки защищённого DNS: %s", de)

            # 5. Авто-определение сети и смена профиля (если пользователь перешёл на другую сеть во время сна)
            if hasattr(self.app, "profile_mgr") and self.app.profile_mgr:
                try:
                    cfg = getattr(self.app, "config", None)
                    if cfg:
                        prof_name, fp = self.app.profile_mgr.auto_detect_and_apply(cfg)
                        self.app.active_profile_name = prof_name
                        self.app.current_network_fp = fp
                        if hasattr(self.app, "tray_icon") and self.app.tray_icon:
                            self.app.tray_icon.update_tooltip(f"Flowery (Glue) — {prof_name}")
                        print(f"  \033[92m[✓]\033[0m Сетевой профиль: '{prof_name}' ({fp})")
                except Exception as pre:
                    logger.error(f"[PowerWatchdog] Ошибка переключения профиля: {pre}")

            # 6. Оживление Discord Voice UDP Helper
            if hasattr(self.app, "voice_helper") and self.app.voice_helper:
                vh = self.app.voice_helper
                cfg = getattr(self.app, "config", None)
                if cfg and getattr(cfg, "discord_voice_udp", True):
                    try:
                        if not vh.is_running():
                            vh.start()
                            print("  \033[92m[✓]\033[0m Discord Voice UDP Helper перезапущен")
                    except Exception as vhe:
                        logger.error(f"[PowerWatchdog] Ошибка оживления voice helper: {vhe}")

            # 7. Финальное повторное обновление WinINet через 1.5 секунды (гарантия применения в Chrome/Edge)
            def _delayed_wininet_refresh():
                time.sleep(1.5)
                try:
                    from flowguard.system_proxy import refresh_system_proxy_settings
                    refresh_system_proxy_settings()
                except Exception as we:
                    logger.debug("[PowerWatchdog] Ошибка отложенного обновления WinINet: %s", we)

            threading.Thread(target=_delayed_wininet_refresh, daemon=True).start()

            print("\033[1;92m[+] Все службы Flowery успешно адаптированы после пробуждения!\033[0m\n")
            logger.info(f"[PowerWatchdog] Восстановление после гибернации успешно завершено ({reason}).")

        except Exception as e:
            logger.error(f"[PowerWatchdog] Непредвиденная ошибка в процедуре восстановления: {e}", exc_info=True)

    def _is_proxy_socket_alive(self, host: str = "127.0.0.1", port: int = 8118) -> bool:
        """Проверяет, отвечает ли слушающий сокет локального прокси."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            res = s.connect_ex((host, port))
            s.close()
            return res == 0
        except Exception as e:
            logger.debug("_is_proxy_socket_alive exception: %s", e)
            return False

    def _watchdog_loop(self) -> None:
        """Основной цикл сторожевого таймера.
        Работает полностью автономно, не требуя оконных сообщений.
        """
        self._last_wall_time = time.time()
        self._last_mono_time = time.monotonic()
        health_check_counter = 0

        while self.is_running:
            try:
                time.sleep(self.check_interval)
            except Exception as e:
                logger.debug("PowerWatchdog sleep interrupted: %s", e)
                break

            if not self.is_running:
                break

            now_wall = time.time()
            now_mono = time.monotonic()

            dt_wall = now_wall - self._last_wall_time
            dt_mono = now_mono - self._last_mono_time

            self._last_wall_time = now_wall
            self._last_mono_time = now_mono

            # Проверка 1: Скачок времени (Time Jump Detection).
            # Если ПК уходил в сон / гибернацию, интервал между итерациями значительно превышает check_interval
            expected_interval = self.check_interval
            time_drift = dt_wall - expected_interval

            if time_drift >= self.time_jump_threshold or abs(dt_wall - dt_mono) >= self.time_jump_threshold:
                logger.info(
                    f"[PowerWatchdog] Зафиксирован скачок времени: dt_wall={dt_wall:.2f}с, "
                    f"dt_mono={dt_mono:.2f}с (ожидалось ~{expected_interval:.1f}с) -> Компьютер выходил из сна/гибернации!"
                )
                self.trigger_recovery(reason=f"Time Jump Detected (dt={dt_wall:.1f}s)")
                continue

            # Проверка 2: Периодический Healthcheck активных служб (каждые ~6 секунд)
            health_check_counter += 1
            if health_check_counter >= 4:
                health_check_counter = 0

                if getattr(self.app, "_is_active", False):
                    # Защита от ложных срабатываний в первые 15 секунд холодного запуска приложения
                    if time.time() - self._start_time < 15.0:
                        continue

                    # Проверяем, жив ли порт прокси
                    cfg = getattr(self.app, "config", None)
                    p_host = getattr(cfg, "proxy_host", "127.0.0.1") if cfg else "127.0.0.1"
                    p_port = getattr(cfg, "proxy_port", 8118) if cfg else 8118

                    if not self._is_proxy_socket_alive(p_host, p_port):
                        logger.warning(f"[PowerWatchdog] Сокет прокси {p_host}:{p_port} не отвечает! Перезапуск...")
                        self.trigger_recovery(reason="Proxy Socket Dead")
                        continue

                    # Проверяем системный прокси Windows в реестре
                    if cfg and getattr(cfg, "auto_system_proxy", True):
                        if hasattr(self.app, "proxy_mgr") and self.app.proxy_mgr:
                            en, srv, _ = self.app.proxy_mgr.get_current_settings()
                            target_srv = f"{p_host}:{p_port}"
                            if en != 1 or target_srv not in (srv or ""):
                                logger.warning(
                                    f"[PowerWatchdog] Системный прокси Windows был изменен сторонним ПО! "
                                    f"(Реестр: ProxyEnable={en}, ProxyServer='{srv}'; ожидалось: ProxyEnable=1, ProxyServer='{target_srv}') "
                                    f"Восстановление..."
                                )
                                self.app.proxy_mgr.ensure_active()
