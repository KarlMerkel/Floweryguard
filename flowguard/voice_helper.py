"""Модуль интеграции WinDivert / winws (Discord Voice UDP & TCP Fake SNI Desync).

Запускает десинхронизацию zapret winws.exe с использованием передовой техники:
- Чистый fake десинк для мобильного тетеринга (--dpi-desync=fake, repeats=6)
- Безопасная сегментация портов Discord UDP (19294-19344, 50000-65535 [Сетевые онлайн-игры / P2P])
- Фейковый STUN и Discord UDP пейлоад (ACTIVE_DISCORD_UDP.bin)
- Опциональный TCP Fake SNI Desync (порты 80, 443) через поддельные ClientHello
"""

import os
import sys
import time
import tempfile
import threading
import subprocess
from typing import Optional, List, Tuple, Dict

try:
    from Floweryguard.ttl_fix import is_admin
    from Floweryguard.config import get_app_base_dir
    from Floweryguard.logger import get_logger
except ImportError:
    from flowguard.ttl_fix import is_admin
    from flowguard.config import get_app_base_dir
    from flowguard.logger import get_logger

logger = get_logger("VoiceHelper")

PID_FILE = os.path.join(tempfile.gettempdir(), "flowery_winws.pid")

_ACTIVE_VOICE_HELPER: Optional["VoiceHelper"] = None
_WINWS_TCP_STATUS_CACHE: Dict[bool, Tuple[float, bool]] = {}
_WINWS_TCP_STATUS_LOCK = threading.Lock()


def get_active_voice_helper() -> Optional["VoiceHelper"]:
    """Возвращает текущий активный экземпляр VoiceHelper."""
    return _ACTIVE_VOICE_HELPER


def set_active_voice_helper(helper: Optional["VoiceHelper"]) -> None:
    """Устанавливает текущий активный экземпляр VoiceHelper."""
    global _ACTIVE_VOICE_HELPER
    _ACTIVE_VOICE_HELPER = helper


def is_system_winws_running() -> bool:
    """Проверяет, запущен ли процесс winws.exe в системе (например, внешний zapret)."""
    try:
        creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        output = subprocess.check_output(
            ["tasklist", "/FI", "IMAGENAME eq winws.exe", "/NH"],
            creationflags=creationflags,
        )
        return b"winws.exe" in output.lower()
    except Exception as e:
        logger.debug("is_system_winws_running check failed: %s", e)
        return False


def get_winws_command_lines() -> List[str]:
    """Возвращает список аргументов командной строки всех запущенных процессов winws.exe."""
    cmdlines = []
    if sys.platform != "win32":
        return cmdlines
    try:
        creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        import base64
        ps_script = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; $ProgressPreference = 'SilentlyContinue'; (Get-CimInstance Win32_Process -Filter \"Name LIKE '%winws%'\").CommandLine"
        encoded = base64.b64encode(ps_script.encode("utf-16le")).decode("ascii")
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            creationflags=creationflags,
            timeout=2.5,
        ).decode("utf-8", errors="ignore")
        for line in out.splitlines():
            line = line.strip()
            if line:
                cmdlines.append(line)
    except Exception as e:
        logger.debug("get_winws_command_lines failed: %s", e)
    return cmdlines


def is_windivert_driver_running() -> bool:
    """Проверяет, запущен ли драйвер WinDivert в системе (службы WinDivert / WinDivert14)."""
    if sys.platform != "win32":
        return False
    try:
        creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        for svc in ("WinDivert", "WinDivert14"):
            try:
                out = subprocess.check_output(
                    ["sc.exe", "query", svc],
                    creationflags=creationflags,
                    timeout=1.5,
                ).decode("utf-8", errors="ignore")
                out_up = out.upper()
                if "RUNNING" in out_up or " 4 " in out or "РАБОТАЕТ" in out_up:
                    return True
            except Exception:
                continue
    except Exception as e:
        logger.debug("is_windivert_driver_running failed: %s", e)
    return False


def is_winws_tcp_filtering_active(
    voice_helper: Optional["VoiceHelper"] = None,
    force_refresh: bool = False,
    cache_ttl: float = 30.0,
    strict: bool = False,
) -> bool:
    """Проверяет, активен ли winws.exe с перехватом/десинком TCP (порты 80, 443).
    
    Результат кэшируется во избежание накладных расходов при каждом соединении.
    """
    global _WINWS_TCP_STATUS_CACHE
    now = time.time()
    with _WINWS_TCP_STATUS_LOCK:
        if isinstance(_WINWS_TCP_STATUS_CACHE, tuple) and len(_WINWS_TCP_STATUS_CACHE) == 2:
            last_t, last_val = _WINWS_TCP_STATUS_CACHE
        elif isinstance(_WINWS_TCP_STATUS_CACHE, dict):
            last_t, last_val = _WINWS_TCP_STATUS_CACHE.get(strict, (0.0, False))
        else:
            last_t, last_val = 0.0, False
        if not force_refresh and (now - last_t < cache_ttl):
            return last_val

    # Проверяем, запущен ли вообще winws.exe в системе
    if not is_system_winws_running():
        active = False
    else:
        vh = voice_helper or get_active_voice_helper()
        is_flowery_proc = False
        if vh is not None:
            is_flowery_proc = getattr(vh, "managed_by_us", False)
        elif os.path.exists(PID_FILE):
            try:
                with open(PID_FILE, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                if content.isdigit():
                    saved_pid = int(content)
                    if sys.platform == "win32":
                        import ctypes
                        kernel32 = ctypes.windll.kernel32
                        h_proc = kernel32.OpenProcess(0x1000, False, saved_pid)
                        if h_proc:
                            kernel32.CloseHandle(h_proc)
                            is_flowery_proc = True
                    else:
                        os.kill(saved_pid, 0)
                        is_flowery_proc = True
            except Exception:
                pass

        if is_flowery_proc:
            # Процесс winws запущен Flowery — в proxy режиме TCP НЕ фильтруется
            is_mode_tcp_allowed = str(getattr(vh, "mode", "proxy")).lower() in ("packet", "hybrid") if vh else False
            active = bool(getattr(vh, "tcp_desync", False) and is_mode_tcp_allowed) if vh else False
        else:
            # Внешний zapret!
            cmdlines = get_winws_command_lines()
            if cmdlines:
                has_tcp = False
                for cmd in cmdlines:
                    cmd_low = cmd.lower()
                    if any(flag in cmd_low for flag in ("--wf-tcp", "--filter-tcp", "filter-l7=http", "filter-l7=tls", "filter-tcp", "--wf-l3")):
                        has_tcp = True
                        break
                active = has_tcp
            else:
                # Внешний winws запущен, но аргументы не удалось прочитать (UAC / таймаут).
                # В strict режиме (вызывается из proxy) НЕ предполагаем TCP десинк активным,
                # чтобы Flowery не отключал свой высокоэффективный TLS десинк (combo_tlsrec_tcpsplit).
                # В fallback режиме (без strict) проверяем статус службы WinDivert для обратной совместимости.
                if strict:
                    active = False
                else:
                    active = is_windivert_driver_running()

    with _WINWS_TCP_STATUS_LOCK:
        if isinstance(_WINWS_TCP_STATUS_CACHE, dict):
            _WINWS_TCP_STATUS_CACHE[strict] = (now, active)
        else:
            _WINWS_TCP_STATUS_CACHE = {strict: (now, active)}
    return active


def cleanup_orphaned_winws() -> None:
    """Завершает зависшие процессы winws.exe от Flowery, не затрагивая внешние zapret."""
    if sys.platform != "win32":
        return

    # 1. Сначала проверяем сохранённый PID Flowery winws
    if os.path.exists(PID_FILE):
        pid_handled = False
        try:
            with open(PID_FILE, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if content.isdigit():
                pid = int(content)
                ps_pid = (
                    f"$proc = Get-CimInstance Win32_Process -Filter \"ProcessId = {pid}\"; "
                    f"if ($proc -and $proc.Name -eq 'winws.exe') {{ Stop-Process -Id {pid} -Force }}"
                )
                creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_pid],
                    capture_output=True,
                    creationflags=creationflags,
                    timeout=5
                )
                pid_handled = True
        except Exception as e:
            logger.debug("cleanup_orphaned_winws by PID failed: %s", e)
        finally:
            try:
                if os.path.exists(PID_FILE):
                    os.remove(PID_FILE)
            except Exception:
                pass
        if pid_handled:
            return

    # 2. Fallback: если PID_FILE отсутствует, ищем процессы winws.exe СТРОГО по уникальным маркерам Flowery
    try:
        ps_cmd = (
            "$p = Get-CimInstance Win32_Process -Filter \"Name = 'winws.exe'\"; "
            "foreach ($proc in $p) { "
            "if ($proc.CommandLine -like '*discord-ip-discovery.bin*' -or $proc.CommandLine -like '*ACTIVE_DISCORD_UDP.bin*' -or $proc.ExecutablePath -like '*\\_MEI*\\zapret_bin\\winws.exe*') { "
            "Stop-Process -Id $proc.ProcessId -Force } }"
        )
        creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True,
            creationflags=creationflags,
            timeout=5
        )
    except Exception as e:
        logger.debug("cleanup_orphaned_winws fallback failed: %s", e)


class VoiceHelper:
    """Управление запуском WinDivert/winws с поддержкой точечного Discord UDP и TCP desync."""

    def __init__(
        self,
        bin_dir: Optional[str] = None,
        fooling: str = "none",
        autottl: bool = False,
        autottl_delta: int = 2,
        ttl: int = 0,
        repeats: int = 6,
        tcp_desync: bool = False,
        fake_tls_file: Optional[str] = "tls_clienthello_www_google_com.bin",
        split_seqovl: int = 0,
        mode: str = "proxy",
        tcp_fooling: Optional[str] = None,
        tcp_autottl: Optional[bool] = None,
        tcp_ttl: Optional[int] = None,
        udp_filter: Optional[str] = None,
    ):
        base_dir = get_app_base_dir()
        candidate = os.path.join(base_dir, "zapret_bin")
        if not os.path.exists(candidate) and hasattr(sys, "_MEIPASS"):
            meipass_candidate = os.path.join(sys._MEIPASS, "zapret_bin")
            if os.path.exists(meipass_candidate):
                candidate = meipass_candidate
        self.bin_dir = bin_dir or candidate
        self.winws_path = os.path.join(self.bin_dir, "winws.exe")
        discord_fake = os.path.join(self.bin_dir, "ACTIVE_DISCORD_UDP.bin")
        if not os.path.exists(discord_fake):
            discord_fake = os.path.join(self.bin_dir, "discord-ip-discovery.bin")
        self.fake_discord = discord_fake
        self.fake_stun = discord_fake
        self.fake_tls_file = fake_tls_file or "tls_clienthello_www_google_com.bin"
        self.fooling = fooling or "none"
        self.autottl = autottl
        self.autottl_delta = autottl_delta
        self.ttl = ttl
        self.repeats = repeats
        self.tcp_desync = tcp_desync
        self.split_seqovl = split_seqovl
        self.mode = mode
        self.tcp_fooling = tcp_fooling
        self.tcp_autottl = tcp_autottl
        self.tcp_ttl = tcp_ttl
        self.udp_filter = udp_filter

        self.process: Optional[subprocess.Popen] = None
        self.managed_by_us = False
        set_active_voice_helper(self)

    def is_available(self) -> bool:
        """Проверяет наличие бинарников winws.exe и фейковых пакетов."""
        return os.path.exists(self.winws_path) and (
            os.path.exists(self.fake_discord) or os.path.exists(os.path.join(self.bin_dir, "ACTIVE_DISCORD_UDP.bin"))
        )

    def is_running(self) -> bool:
        """Проверяет, активен ли winws (наш или внешний)."""
        if self.process is not None and self.process.poll() is None:
            return True
        return is_system_winws_running()

    def build_winws_args(
        self,
        fooling: Optional[str] = None,
        autottl: Optional[bool] = None,
        autottl_delta: Optional[int] = None,
        ttl: Optional[int] = None,
        repeats: Optional[int] = None,
        split_seqovl: Optional[int] = None,
        tcp_desync: Optional[bool] = None,
        tcp_fooling: Optional[str] = None,
        tcp_autottl: Optional[bool] = None,
        tcp_ttl: Optional[int] = None,
        udp_filter: Optional[str] = None,
    ) -> List[str]:
        """Формирует аргументы запуска winws для Discord Voice & Screenshare UDP и опционального TCP."""
        effective_fooling = self.fooling if fooling is None else fooling
        effective_autottl = self.autottl if autottl is None else autottl
        effective_autottl_delta = self.autottl_delta if autottl_delta is None else autottl_delta
        effective_ttl = self.ttl if ttl is None else ttl
        effective_repeats = self.repeats if repeats is None else repeats
        effective_split_seqovl = self.split_seqovl if split_seqovl is None else split_seqovl
        effective_tcp_desync = self.tcp_desync if tcp_desync is None else tcp_desync
        effective_tcp_fooling = self.tcp_fooling if tcp_fooling is None else tcp_fooling
        effective_tcp_autottl = self.tcp_autottl if tcp_autottl is None else tcp_autottl
        effective_tcp_ttl = self.tcp_ttl if tcp_ttl is None else tcp_ttl

        effective_udp_filter = (
            udp_filter
            if udp_filter is not None
            else (self.udp_filter if self.udp_filter is not None else "19294-19344,50000-52811,52841-57607,57609-65535")
        )

        fake_unknown = os.path.join(self.bin_dir, "ACTIVE_DISCORD_UDP.bin")
        if not os.path.exists(fake_unknown):
            fake_unknown = self.fake_discord

        args = [
            self.winws_path,
            f"--wf-udp={effective_udp_filter}",
            f"--filter-udp={effective_udp_filter}",
            "--filter-l7=discord,stun,unknown",
            "--dpi-desync=fake",
            "--dpi-desync-any-protocol=1",
            "--dpi-desync-cutoff=n4",
            f"--dpi-desync-fake-discord={self.fake_discord}",
            f"--dpi-desync-fake-stun={self.fake_stun}",
            f"--dpi-desync-fake-unknown-udp={fake_unknown}",
        ]

        # Парсинг и добавление режимов спуфинга (badsum, md5sig, badseq)
        fool_modes = []
        if effective_fooling and str(effective_fooling).lower() != "none":
            for mode in str(effective_fooling).split(","):
                m = mode.strip().lower()
                if m in ("badsum", "md5sig", "badseq", "datanoack", "hopbyhop", "hopbyhop2"):
                    fool_modes.append(m)

        # Для UDP голосового трафика Discord на мобильном тетеринге категорически
        # запрещены badsum (дропается Linux netfilter NAT смартфона) и autottl
        # (убивает фейки на 2-м транзитном хопе до ТСПУ).
        # Поэтому fool_modes и autottl добавляются в UDP секцию ТОЛЬКО если
        # НЕ активирован TCP desync и они были явно переданы в тест/вызов.
        if not effective_tcp_desync:
            if fool_modes:
                args.append(f"--dpi-desync-fooling={','.join(fool_modes)}")

            if effective_autottl or ("autottl" in str(effective_fooling).lower()):
                args.append(f"--dpi-desync-autottl={effective_autottl_delta}")
            elif effective_ttl > 0:
                args.append(f"--dpi-desync-ttl={effective_ttl}")

            if effective_split_seqovl > 0:
                args.append(f"--dpi-desync-split-seqovl={effective_split_seqovl}")

        args.append(f"--dpi-desync-repeats={effective_repeats}")

        # Опциональный TCP Fake SNI Desync через winws:
        # Добавляется только если режим явно packet или hybrid, и НИКОГДА в режиме proxy (B2)
        is_mode_tcp_allowed = str(getattr(self, "mode", "proxy")).lower() in ("packet", "hybrid")
        if effective_tcp_desync and is_mode_tcp_allowed:
            tls_path = os.path.join(self.bin_dir, self.fake_tls_file)
            if os.path.exists(tls_path):
                args.extend([
                    "--new",
                    "--wf-tcp=80,443",
                    "--filter-tcp=80,443",
                    "--dpi-desync=fake,split2",
                    f"--dpi-desync-fake-tls={tls_path}",
                ])
                tcp_fool_str = effective_tcp_fooling if effective_tcp_fooling is not None else effective_fooling
                tcp_fool_modes = []
                if tcp_fool_str and str(tcp_fool_str).lower() != "none":
                    for mode in str(tcp_fool_str).split(","):
                        m = mode.strip().lower()
                        if m in ("badsum", "md5sig", "badseq", "datanoack", "hopbyhop", "hopbyhop2"):
                            tcp_fool_modes.append(m)
                if tcp_fool_modes:
                    args.append(f"--dpi-desync-fooling={','.join(tcp_fool_modes)}")

                tcp_autottl_val = effective_tcp_autottl if effective_tcp_autottl is not None else effective_autottl
                tcp_ttl_val = effective_tcp_ttl if effective_tcp_ttl is not None else effective_ttl

                if tcp_autottl_val or ("autottl" in str(tcp_fool_str).lower()):
                    args.append(f"--dpi-desync-autottl={effective_autottl_delta}")
                elif tcp_ttl_val > 0:
                    args.append(f"--dpi-desync-ttl={tcp_ttl_val}")

                if effective_split_seqovl > 0:
                    args.append(f"--dpi-desync-split-seqovl={effective_split_seqovl}")
                args.append(f"--dpi-desync-repeats={min(4, effective_repeats)}")

        return args

    def start(self) -> bool:
        """Запускает winws с точечным фильтром Discord UDP или подключается к существующему."""
        # 0. Очищаем зависшие процессы winws от прошлых сессий Flowery во избежание захвата игровых портов
        cleanup_orphaned_winws()

        # 1. Если zapret уже запущен в системе — не плодим дубликаты
        if is_system_winws_running():
            print("\033[92m[+] Обнаружен активный zapret (winws) — Discord Voice UDP защищён\033[0m")
            self.managed_by_us = False
            return True

        if not self.is_available():
            print("\033[90m[-] Бинарники zapret_bin не найдены (пропуск автозапуска UDP войса)\033[0m")
            return False

        if not is_admin():
            print("\033[93m[!] Требуются права Администратора для загрузки драйвера WinDivert (UDP войс)\033[0m")
            return False

        args = self.build_winws_args()

        try:
            creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

            self.process = subprocess.Popen(
                args,
                cwd=self.bin_dir,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creationflags,
            )
            self.managed_by_us = True
            try:
                with open(PID_FILE, "w", encoding="utf-8") as f:
                    f.write(str(self.process.pid))
            except Exception as pe:
                logger.debug("Failed to write winws PID_FILE: %s", pe)

            # Ожидание загрузки WinDivert64.sys в ядро (до 2 секунд).
            # Без этой паузы параллельные потоки прокси могут вызвать WinDivertOpen
            # до инициализации драйвера, что приведёт к BSOD.
            import time
            for _wait in range(8):
                if self.process.poll() is not None:
                    break  # Процесс уже завершился (ошибка запуска)
                if is_system_winws_running():
                    break  # winws.exe виден в системе — драйвер загружен
                time.sleep(0.25)

            if self.process.poll() is not None:
                logger.error("[VoiceHelper] Процесс winws.exe аварийно завершился сразу после старта!")
                return False

            msg = (
                "\033[92m[+] WinDivert Desync запущен в фоне (порты 19294-19344, 50000-65535 [Сетевые онлайн-игры])\033[0m"
            )
            print(msg)
            logger.info(f"WinDivert zapret запущен: args={' '.join(args)}")
            return True
        except Exception as e:
            print(f"\033[91m[!] Ошибка запуска winws UDP voice: {e}\033[0m")
            logger.error(f"Ошибка запуска winws: {e}")
            return False

    def stop(self) -> None:
        """Останавливает процесс winws, только если мы его запускали."""
        if self.process and self.managed_by_us:
            print("  [*] Остановка фонового процесса Discord Voice (winws)...")
            try:
                self.process.terminate()
                self.process.wait(timeout=2)
            except Exception as e:
                logger.debug("Terminate winws failed: %s, attempting kill", e)
                try:
                    self.process.kill()
                except Exception as ke:
                    logger.debug("Kill winws failed: %s", ke)
            self.process = None
            self.managed_by_us = False
            try:
                if os.path.exists(PID_FILE):
                    os.remove(PID_FILE)
            except Exception as pe:
                logger.debug("Failed to remove winws PID_FILE: %s", pe)
            global _WINWS_TCP_STATUS_CACHE
            with _WINWS_TCP_STATUS_LOCK:
                if isinstance(_WINWS_TCP_STATUS_CACHE, dict):
                    _WINWS_TCP_STATUS_CACHE.clear()
                else:
                    _WINWS_TCP_STATUS_CACHE = {}

            # Выгрузка драйвера WinDivert, если он остался активным и нет другого активного winws в системе
            if sys.platform == "win32" and is_admin() and not is_system_winws_running():
                for svc in ["WinDivert", "WinDivert14"]:
                    try:
                        creationflags = subprocess.CREATE_NO_WINDOW
                        subprocess.run(
                            ["sc", "stop", svc],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            creationflags=creationflags,
                            check=False
                        )
                    except Exception as se:
                        logger.debug("sc stop %s failed: %s", svc, se)
