"""Flowery (Glue) — Главная точка входа.
DPI bypass инструмент для мобильного тетеринга поверх zapret.
"""

import sys
import os
import signal
import time
import argparse
import atexit
import shutil
import ctypes
from ctypes import wintypes
import threading
try:
    threading.stack_size(262144)  # 256 KB stack size to prevent RAM/virtual memory exhaustion on Windows
except Exception:
    pass
import subprocess
from typing import Any, List

class StderrToLogger:
    """Перенаправляет поток stderr в файл логов сессии в Документах,
    полностью предотвращая появление технического мусора и предупреждений в терминальном меню.
    Реализует полный интерфейс текстового потока для предотвращения сбоев runtime CPython.
    Критические ошибки (Traceback, Error, Exception) дублируются в оригинальный stderr.
    """
    def __init__(self, orig_stderr):
        self._orig = orig_stderr
        self.encoding = getattr(orig_stderr, "encoding", "utf-8") or "utf-8"
        self.errors = getattr(orig_stderr, "errors", "replace") or "replace"
        self._in_traceback = False

    def write(self, message):
        msg = str(message).strip() if message else ""
        if msg:
            try:
                try:
                    from Floweryguard.logger import logger
                except ImportError:
                    from flowguard.logger import logger
                logger.debug(f"[stderr] {msg}")
            except Exception as e:
                pass

            if "Traceback (most recent call last):" in msg:
                self._in_traceback = True

            is_critical = (
                self._in_traceback
                or any(kw in msg for kw in ("Traceback", "Error", "Exception", "CRITICAL", "Fatal"))
            )
            if self._orig and is_critical:
                try:
                    self._orig.write(message)
                    self._orig.flush()
                except Exception as e:
                    sys.__stderr__.write(f"[StderrToLogger orig write error] {e}\n")

            if self._in_traceback and any(msg.endswith(e) or f"{e}:" in msg for e in ("Error", "Exception")):
                self._in_traceback = False

    def flush(self):
        if self._orig and hasattr(self._orig, "flush"):
            try:
                self._orig.flush()
            except Exception as e:
                sys.__stderr__.write(f"[StderrToLogger flush error] {e}\n")

    def fileno(self):
        if self._orig and hasattr(self._orig, "fileno"):
            try:
                return self._orig.fileno()
            except Exception:
                return 2
        return 2

    def isatty(self):
        return False

    def readable(self):
        return False

    def writable(self):
        return True

    def reconfigure(self, *args, **kwargs):
        """Реализует метод reconfigure() для полной совместимости с CPython sys.stderr."""
        if "encoding" in kwargs and kwargs["encoding"]:
            self.encoding = kwargs["encoding"]
        if "errors" in kwargs and kwargs["errors"]:
            self.errors = kwargs["errors"]
        if self._orig and hasattr(self._orig, "reconfigure"):
            try:
                self._orig.reconfigure(*args, **kwargs)
            except Exception as e:
                _ = e


def _handle_uncaught_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    import traceback
    tb_text = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
    try:
        try:
            from Floweryguard.logger import logger
        except ImportError:
            from flowguard.logger import logger
        logger.critical(f"Необработанное исключение (CRASH):\n{tb_text}")
    except Exception as e:
        sys.__stderr__.write(f"Failed to log crash: {e}\n")
    print("\n\033[91m" + "=" * 70)
    print("[X] КРИТИЧЕСКАЯ НЕОБРАБОТАННАЯ ОШИБКА FLOWERY (CRASH)")
    print("=" * 70)
    print(f"{exc_type.__name__}: {exc_value}\033[0m\n")
    try:
        try:
            from Floweryguard.logger import get_current_log_path
        except ImportError:
            from flowguard.logger import get_current_log_path
        print(f"Подробности ошибки записаны в файл логов:\n  {get_current_log_path()}\n")
    except Exception as e:
        sys.__stderr__.write(f"Failed to get log path: {e}\n")
    sys.__excepthook__(exc_type, exc_value, exc_traceback)


# Включение поддержки ANSI цветов (VT100), кодировки UTF-8 и правильного заголовка консоли в Windows
def init_terminal():
    """Инициализация консоли: UTF-8, ANSI VT100 и заголовок окна."""
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

        try:
            sys.stdin.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

        # Установка заголовка окна
        try:
            ctypes.windll.kernel32.SetConsoleTitleW("Flowery (Glue) — Обход DPI и маскировка тетеринга для Windows")
        except Exception:
            pass

        # Пустой системный вызов включает эмуляцию VT100 в cmd.exe
        try:
            os.system("")
        except Exception:
            pass

        # Прямой вызов Win32 API для гарантированного включения цветов ANSI
        try:
            kernel32 = ctypes.windll.kernel32
            hOut = kernel32.GetStdHandle(-11)
            if hOut and hOut != -1:
                mode = ctypes.c_uint32()
                if kernel32.GetConsoleMode(hOut, ctypes.byref(mode)):
                    kernel32.SetConsoleMode(hOut, mode.value | 0x0004 | 0x0008)

            hCon = kernel32.CreateFileW("CONOUT$", 0xC0000000, 3, None, 3, 0, None)
            if hCon and hCon != -1:
                mode2 = ctypes.c_uint32()
                if kernel32.GetConsoleMode(hCon, ctypes.byref(mode2)):
                    kernel32.SetConsoleMode(hCon, mode2.value | 0x0004 | 0x0008)
                kernel32.CloseHandle(hCon)
        except Exception:
            pass

def set_app_icon():
    """Принудительно устанавливает фирменную иконку Flowery на окно консоли и панель задач Windows."""
    if sys.platform != "win32":
        return

    # Ищем иконку icon.ico
    try:
        base_dirs = [
            getattr(sys, "_MEIPASS", ""),
            os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__)),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..")),
            os.getcwd(),
        ]
        icon_path = None
        for b in base_dirs:
            if b:
                p = os.path.join(b, "icon.ico")
                if os.path.isfile(p):
                    icon_path = p
                    break

        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        IMAGE_ICON = 1
        LR_LOADFROMFILE = 0x00000010

        user32.LoadImageW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint, ctypes.c_int, ctypes.c_int, ctypes.c_uint]
        user32.LoadImageW.restype = ctypes.c_void_p
        user32.SendMessageW.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
        user32.SendMessageW.restype = ctypes.c_longlong

        h_icon_sm = None
        h_icon_lg = None

        if icon_path:
            h_icon_sm = user32.LoadImageW(None, icon_path, IMAGE_ICON, 16, 16, LR_LOADFROMFILE)
            h_icon_lg = user32.LoadImageW(None, icon_path, IMAGE_ICON, 32, 32, LR_LOADFROMFILE)

        if not h_icon_lg:
            h_inst = kernel32.GetModuleHandleW(None)
            h_icon_sm = user32.LoadImageW(h_inst, 1, IMAGE_ICON, 16, 16, 0)
            h_icon_lg = user32.LoadImageW(h_inst, 1, IMAGE_ICON, 32, 32, 0)

        # 3. Отправляем WM_SETICON окну консоли (заголовок + панель задач)
        h_con = kernel32.GetConsoleWindow()
        if h_con and h_icon_lg:
            WM_SETICON = 0x0080
            ICON_SMALL = 0
            ICON_BIG = 1
            if h_icon_sm:
                user32.SendMessageW(h_con, WM_SETICON, ICON_SMALL, h_icon_sm)
            user32.SendMessageW(h_con, WM_SETICON, ICON_BIG, h_icon_lg)
    except Exception as e:
        sys.__stderr__.write(f"set_app_icon failed: {e}\n")

def global_exception_handler(exc_type, exc_value, exc_traceback):
    """Глобальный перехватчик необработанных исключений — гарантирует вывод ошибки и предотвращает вылет окна."""
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    import traceback
    err_msg = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
    try:
        try:
            from Floweryguard.logger import logger, get_current_log_path
        except ImportError:
            from flowguard.logger import logger, get_current_log_path
        logger.critical(f"Необработанное исключение (Crash):\n{err_msg}")
        log_path = get_current_log_path()
    except Exception:
        log_path = "в папке Документы / Flowery / logs"

    try:
        if sys.platform == "win32":
            h_con = ctypes.windll.kernel32.GetConsoleWindow()
            if h_con:
                ctypes.windll.user32.ShowWindow(h_con, 9)  # SW_RESTORE
                ctypes.windll.user32.SetForegroundWindow(h_con)
    except Exception as e:
        sys.__stderr__.write(f"Restore console window failed: {e}\n")

    print("\n\033[1;91m" + "=" * 70 + "\033[0m")
    print("\033[1;91m[X] КРИТИЧЕСКАЯ ОШИБКА FLOWERY (CRASH)\033[0m")
    print("\033[1;91m" + "=" * 70 + "\033[0m")
    print(f"\033[93m{exc_type.__name__}: {exc_value}\033[0m\n")
    print(f"\033[90mПодробности ошибки записаны в файл логов:\033[0m\n{log_path}\n")
    print("\033[90m" + err_msg + "\033[0m\n")
    if sys.stdin and hasattr(sys.stdin, "isatty") and sys.stdin.isatty():
        try:
            input("\033[97mНажмите Enter для выхода...\033[0m")
        except Exception:
            if sys.platform == "win32":
                try:
                    os.system("pause")
                except Exception as e:
                    sys.__stderr__.write(f"Pause fallback failed: {e}\n")


_SINGLE_INSTANCE_MUTEX = None

def acquire_single_instance_mutex() -> bool:
    """Проверяет, запущен ли уже экземпляр Flowery в системе.
    Если да — выводит окно существующего экземпляра на передний план и возвращает False.
    """
    global _SINGLE_INSTANCE_MUTEX
    if sys.platform != "win32":
        return True
    try:
        ERROR_ALREADY_EXISTS = 183
        kernel32 = ctypes.windll.kernel32
        user32 = ctypes.windll.user32
        mutex_name = "Local\\FloweryGlueSingleInstanceMutex"
        _SINGLE_INSTANCE_MUTEX = kernel32.CreateMutexW(None, True, mutex_name)
        last_error = kernel32.GetLastError()
        if last_error == ERROR_ALREADY_EXISTS:
            found_hwnds = []
            def enum_proc(hwnd, lParam):
                length = user32.GetWindowTextLengthW(hwnd)
                if length > 0:
                    buff = ctypes.create_unicode_buffer(length + 1)
                    user32.GetWindowTextW(hwnd, buff, length + 1)
                    title = buff.value
                    if "Flowery" in title:
                        user32.ShowWindow(hwnd, 9)  # SW_RESTORE
                        user32.SetForegroundWindow(hwnd)
                        found_hwnds.append(hwnd)
                return True

            WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
            try:
                user32.EnumWindows(WNDENUMPROC(enum_proc), 0)
            except Exception as e:
                sys.__stderr__.write(f"EnumWindows failed: {e}\n")
            return False
        return True
    except Exception as e:
        sys.__stderr__.write(f"acquire_single_instance_mutex failed: {e}\n")
        return True


def release_single_instance_mutex() -> None:
    """Освобождает и закрывает дескриптор мьютекса одного экземпляра."""
    global _SINGLE_INSTANCE_MUTEX
    if sys.platform == "win32" and _SINGLE_INSTANCE_MUTEX:
        try:
            if isinstance(_SINGLE_INSTANCE_MUTEX, int):
                ctypes.windll.kernel32.CloseHandle(_SINGLE_INSTANCE_MUTEX)
        except Exception as e:
            sys.__stderr__.write(f"release_single_instance_mutex failed: {e}\n")
        _SINGLE_INSTANCE_MUTEX = None


atexit.register(release_single_instance_mutex)

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from flowguard.config import Config, load_whitelist_domains
from flowguard.ttl_fix import TTLManager, MTUManager, is_admin, check_admin_or_elevate
from flowguard.system_proxy import SystemProxyManager, build_proxy_override
from flowguard.quic_block import QUICBlocker
from flowguard.dns_config import DNSManager
from flowguard.proxy import DPIBypassProxy, format_speed
from flowguard.tester import test_proxy_connection
from flowguard.detector import NetworkDetector
from flowguard.voice_helper import VoiceHelper
from flowguard.profiles import ProfileManager
from flowguard.tray import FloweryTrayIcon
from flowguard.logger import logger, open_current_log_file, get_current_log_path
from flowguard.calibration import StrategyCalibrator
from flowguard.doh_resolver import (
    DoHResolver,
    build_custom_provider,
)
from flowguard.log_sender import LogSender
from flowguard.power_watchdog import PowerWatchdog

# Полный ASCII-арт цветка (120 колонок, полноэкранный режим)
FLOWER_FULL = r"""
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+.          =%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*.          =%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*.              =%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%+.                  =%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@%%@@@@@@@@@@@@@@@@*.                      =%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@#:  -*%%%@@@@@@@@@@@*.                          =%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@#:      -*%%%@@@@@@@*.                              =%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@%%%*:          :*%%%%%%+.                                  =%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@#:                                                                  =##########%%@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@#:                                                                             .+##%%@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@#:                                                                      .:::.      .+##%%@@@@@@@@@@@@@@@@@@@
@@@@@@@#:                                                                  .::-*@@%=          .=###%@@@@@@@@@@@@@@@
@@@@@@@#:                                                              .::-+###%@@%=              .*@@@@@@@@@@@@@@@
@@@@@@@#=:::.                                                  .:::::::+##*-  .+@@%=              .=###%@@@@@@@@@@@
@@@@@@@@@@@#:                                              .---+*******-      .+@@%=                  :*@@@@@@@@@@@
@@@@@@@@@@@#=--:.                                  .-------+***-           :---+***-               :---+**#%@@@@@@@
@@@@@@@@@@@%#**+-----------:.          .:----------=*******-       .-------+***-                  .*@@#-  :*@@@@@@@
@@@@@@@@@@@#:  -#@@@@@@@@@@#=----------=+**********-           :---*@@@@@@@*---------------.      .*@@#-  :*@@@@@@@
@@@@@@@@@@@#:  -#@@@@@@@@@@%***********=.                      -***********************%@@%*---.  .*@@#-  :*@@@@@@@
@@@@@@@@@@@#:  -#@@@@@@%***=.                                                         .=***%@@%-  .*@@#-  :*@@@@@@@
@@@@@@@@@@@#:  -#@@@@@@*:      -%@@@@@@@@@@@@@@+.                  +@@@@@@@@@@@@@@%=      .*@@@@@@@@@@#-  :*@@@@@@@
@@@@@@@@@@@#:  -#@@*:      -#@@*.              =%@@+.          +@@@+              .+@@%-      .*@@@@@@#-  :*@@@@@@@
@@@@@@@@@@@@@@@@@@@*:  -#@@*:                                                         .*@@%-  .*@@@@@@@@@@@@@@@@@@@
@@@@@@@#:      :#@@@@@@*:                                                                         .*@@@@@@#-      :*@@@
@@@@@@@#:      :#@@@@@@*:      :=++#@@@#+======*@@@#+++-           -+++#@@@*=======#@@@#++=:      .*@@@@@@#-      :*@@@
@@@@@@@#:      :#@@@@@@*:  :=++*%@@#+==:       :===*@@@+.          +@@@*===:       :===#@@@#++=:  .*@@@@@@#-      :*@@@
@@@@@@@#:      :#@@@@@@*:  .-======:               :===:           :===:               :======-.  .*@@@@@@#-      :*@@@
@@@@@@@%***=.  :#@@@@@@*:                              =%@@+.                                     .*@@@@@@#-  .=***%@@@
@@@@@@@@@@@#:  :#@@@@@@*:                              =%@@+.                                     .*@@@@@@#-  :*@@@@@@@
@@@@@@@@@@@#=--+%@@*:                          -***#@@@+.                                     .*@@%+--=#@@@@@@@@@@@
@@@@@@@@@@@%#**+---+%@@*:                  .---*@@@%***-                                  .*@@%+---+**#%@@@@@@@@@@@
@@@@@@@@@@@@@@@*:  -#@@*:                      .:::+@@@%###-                              .*@@%-  .*@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@%####@@@*:          -*##=.          .:::::::.               =##*-          .*@@@%###%@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@%###+.      -%@@%###################################%@@%=      .=###%@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@*:      ..::=%@@@@@@*:::::::::::::::::::::::+@@@+:::.      .*@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@%##+.      ..::+@@@%###=               =###+:::.       =##%%@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*:          .:::+@@@%###############+:::.          .+@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%+.           ....................           =%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%+.          -#%%%%%%%%%%=           =%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%=        ............       =%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%+.                  =%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%+.          =%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
"""

# Компактный ASCII-арт цветка (78 колонок, стандартный 80-символьный терминал)
FLOWER_COMPACT = r"""
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+.       %@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@*       =@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@*.         =%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@%%.            =@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@%@@@@@@@@@@@*.              =%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@#  *%%@@@@@@@*.                  %%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@#    -*%%@@@@*.                    =%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@%%*       :%%%%%.                       =%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@#:                                            =#######%@@@@@@@@@@@@@@@@@@
@@@@@#:                                                    .##%@@@@@@@@@@@@@@@
@@@@@#:                                               .::     +#%%@@@@@@@@@@@@
@@@@@#:                                            .:-*@%       .=##@@@@@@@@@@
@@@@@#:                                          ::+##%@%          .@@@@@@@@@@
@@@@@#=::                                  .:::::##- .+@%          .##%@@@@@@@
@@@@@@@@#                                --+*****    .+@%             *@@@@@@@
@@@@@@@@#--.                       .-----**-       :--+**           --+*#%@@@@
@@@@@@@@%**--------.       .-------=*****     .----+**-            .@#- :*@@@@
@@@@@@@@#  #@@@@@@#=-------=*******-       :--*@@@@*----------.    .@#- :*@@@@
@@@@@@@@#  #@@@@@@%********=               -****************@%*--. .@#- :*@@@@
@@@@@@@@#  #@@@@%**.                                       .**%@%- .@#- :*@@@@
@@@@@@@@#  #@@@@*     %@@@@@@@@@+.            +@@@@@@@@@%     *@@@@@@#- :*@@@@
@@@@@@@@#  #@*:    #@*.         =%@+       +@@+         .@@%    .*@@@#- :*@@@@
@@@@@@@@@@@@@*: -@*:                                       .@%- .*@@@@@@@@@@@@
@@@@@#:    #@@@@*                                                  .@@@@#-    
@@@@@#:    #@@@@*     =+#@@#====*@@#++        -++@@*=====@@#++:    .@@@@#-    
@@@@@#:    #@@@@*  =++%@#+=:    :==*@+.       +@*==:     ===@@#+=: .@@@@#-    
@@@@@#:    #@@@@*  -====:          :==        :==           ====-. .@@@@#-    
@@@@@%**=  #@@@@*                     %@+.                         .@@@@#- .**
@@@@@@@@#  #@@@@*                     %@+.                         .@@@@#- :@@
@@@@@@@@#--%@*:                 -**#@+.                         .*@%--#@@@@@@@
@@@@@@@@%**--+%@*             --*@@%**                        *@%+--**%@@@@@@@
@@@@@@@@@@*: -#@*               .::+@%###                     *@%- .@@@@@@@@@@
@@@@@@@@@@%###@@*       -*#=       .:::::          =#*-       *@@%##@@@@@@@@@@
@@@@@@@@@@@@@@@@%##.    -%@%#######################%@%=    .##%@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@*:    ..:=@@@@*::::::::::::::::@@+::.    .@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@%##.    .::@@%##=          =##::.     ##%@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@*:       ::+@@%##########+::       .@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@%%+.       ..............       =%%@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@%%+       -%%%%%%%=       =%%@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%      ........     %%@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%.            =%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%+.       %%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
"""

# Стилизованная надпись GLUE
GLUE_ASCII = r"""
.::----::.        -++:             :++:       :++:     .============:
       -#@@@@@@@@%-       *@@*             +@@+       *@@*     =@@@@@@@@@@@@#
      +@@#=    .::-       *@@*             +@@+       *@@*     =@@#::::::::::
      @@@+   .====-.      *@@*             +@@+       *@@*     =@@@@@@@@@@@@#
      @@@+   -#@@@@#      *@@*             +@@+       *@@*     =@@#::::::::::
      +@@#=    :@@@#      *@@*             +@@+       *@@*     =@@#          
       -#@@@@@@@@@@#      *@@@@@@@@@@@+    -#@@@@@@@@@@*       =@@@@@@@@@@@@#
        .::====::...      :===========:     .::======::.       :============:
"""

# Flowey ASCII-арт для интерактивного меню (52 колонки в ширину)
FLOWEY_ART = [
    '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@',
    '@@@@@@@@@@@@@@@@@@%:::::::%@@@@@@@@@@@@@@@@@@@@@@@@@',
    '@@@@@@@@@@@@@@@@#--::::=##@@@@@@@@@@@@@@@@@@@@@@@@@@',
    '@@@@@@@@@@@@@@@@*::::::=@@@@@@@@@@@@@@@@@@@@@@@@@@@@',
    '@@@@@%%%%@@@@@%%+::::::=%%@@@@@@@@@@@@@@@@@@@@@@@@@@',
    '@@@@#::::+@@@@-:::::::::::%@@@@@@@@@@@@@@@@@@@@@@@@@',
    '@@+::::%@@@@@@-:::::::::::::*@@@@@@@@@@@@@@@@@@@@@@@',
    '@@+::::::+@%:::::::::::::::::::::%@@@@@@@@@@@@@@@@@@',
    '@@+::::::::::::::::::::::::::::::::::-@@@@@@@@@@@@@@',
    '@@+:::::::::::::::::::::::::::::::::::==%@@@@@@@@@@@',
    '@@+::::::::::::::::::::::::::::::::-==::+*#@@@@@@@@@',
    '@@+-::::::::::::::::::::::::::::::-*@%::::=%%@@@@@@@',
    '@@@@#::::::::::::::::::::::::::::%@@@%::::::-@@@@@@@',
    '@@@@#:::::::::::::::::::::::*@@@@-:+@%::::::-@@@@@@@',
    '@@@@@@@-:::::::::::::::=@@@@+::::%@+:::::::::::#@@@@',
    '@@@@@@@@@+::::::+@@@@@@*::::::-@@-:::::::::::::#@@@@',
    '@@@@@@@+=+******+======-::::=*#@@#******-::::**+=*@@',
    '@@@@%**+=#@@@@#*=:::::::::::=********#@@*=-:-@@=:=@@',
    '@@@@#::%@@@@@@=::::::::::::::::::::::-@@@@*:-@@=:=@@',
    '@@@@#::%@@@%::#@@@@@@=::::::::-@@@@@@%::#@*:-@@=:=@@',
    '@@@@#::%@+:-@@-::::::#@*::::*@#::::::-@@-:+@@@@=:=@@',
    '@@@@#::%@+::::::::::::::::::::::::::::::::+@@@@=:=@@',
    '@@@@@%%@@+::::*%%%%%%=::::::::-%%%%%%#::::+@@@@%%%@@',
    '@@#++++%@+::**%@#+++++*=::::=**++++#@%**-:+@%++++*@@',
    '@@+::::%@+:-@@##=::::#@*::::*@#::::=##@@-:+@%::::=@@',
    '@@+::::%@+:-@@-::::::#@*::::*@#::::::-@@-:+@%::::=@@',
    '@@+::::%@+:::::::::::::=@@-:::::::::::::::+@%::::=@@',
    '@@+::::%@+:::::::::::::=@@-:::::::::::::::+@%::::=@@',
    '@@@@#::%@+:::::::::::#@@@@-:::::::::::::::+@%::#@@@@',
    '@@@@@%%@@+:::::::::::#@#--::::::::::::::::+@@%%@@@@@',
    '@@@@@@@*++*+:::::::::=++*+::::::::::::::+*+++@@@@@@@',
    '@@@@@@@-:+@%:::::--::::=##:::::::---::::#@*:-@@@@@@@',
    '@@@@@@@-:+@%::::+@%::::::::::::::%@+::::#@*:-@@@@@@@',
    '@@@@@@@@@@@%::::+@@@@@@@@@@@@@@@@@@+::::#@@@@@@@@@@@',
    '@@@@@@@@@@@@@@-:::-@@=::::::::-@@-:::-@@@@@@@@@@@@@@',
    '@@@@@@@@@@@@@@-::::::#@@@@@@@@#::::::-@@@@@@@@@@@@@@',
    '@@@@@@@@@@@@@@%%+::::----------::::+%%@@@@@@@@@@@@@@',
    '@@@@@@@@@@@@@@@@#++::::-++++-::::++#@@@@@@@@@@@@@@@@',
    '@@@@@@@@@@@@@@@@@@%--::=%%%%=::--%@@@@@@@@@@@@@@@@@@',
    '@@@@@@@@@@@@@@@@@@@@@=::::::::-@@@@@@@@@@@@@@@@@@@@@',
    '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@'
]

FLOWERY_BANNER = (
    "\033[1;95m  ╔══════════════════════════════════════════════════════════════════════════════╗\033[0m\n"
    "\033[1;95m  ║   \033[1;93m✿ FLOWERY (GLUE) v1.3.0\033[1;95m — Высокоэффективный обход DPI для Windows         ║\033[0m\n"
    "\033[1;95m  ║   \033[90mYouTube 4K • Discord Voice & Экран • Сетевые онлайн-игры (Steam, P2P)\033[1;95m     ║\033[0m\n"
    "\033[1;95m  ╚══════════════════════════════════════════════════════════════════════════════╝\033[0m\n"
)

class FloweryApp:
    """Главный оркестратор приложения Flowery (Glue)."""

    def __init__(self):
        self.config = Config()
        self.profile_mgr = ProfileManager()
        self.active_profile_name, self.current_network_fp = self.profile_mgr.auto_detect_and_apply(self.config)
        self.ttl_mgr = TTLManager(
            target_ttl=self.config.default_ttl,
            enable_timestamps=self.config.enable_timestamps
        )
        cfg_mtu = getattr(self.config, "target_mtu", 1420)
        self.mtu_mgr = MTUManager(
            target_mtu=1380 if cfg_mtu == 1420 else cfg_mtu
        )
        self.proxy_mgr = SystemProxyManager(
            proxy_address=f"{self.config.proxy_host}:{self.config.proxy_port}",
            proxy_override=build_proxy_override(
                proxy_discord=self.config.proxy_discord,
                proxy_youtube=self.config.proxy_youtube
            )
        )
        self.quic_blocker = QUICBlocker()
        self.dns_mgr = DNSManager(self.config.dns_primary, self.config.dns_secondary)
        self.proxy_server = DPIBypassProxy(self.config)
        if hasattr(self.proxy_server, "strategy_engine") and self.proxy_server.strategy_engine:
            self.proxy_server.strategy_engine.set_network_context(self.current_network_fp)
        self.detector = NetworkDetector()
        self.voice_helper = VoiceHelper(
            fooling="none",
            autottl=False,
            autottl_delta=self.config.packet_desync_autottl_delta,
            ttl=self.config.packet_desync_ttl if not self.config.packet_desync_autottl else 0,
            repeats=6,
            tcp_desync=self.config.packet_desync_tcp,
            fake_tls_file=self.config.packet_desync_fake_tls,
            mode=self.config.mode_kind,
            tcp_fooling=self.config.packet_desync_fooling,
            tcp_autottl=self.config.packet_desync_autottl,
            tcp_ttl=self.config.packet_desync_ttl,
            udp_filter="19294-19344,50000-65535",
        )
        self.power_watchdog = PowerWatchdog(self)
        self.tray_icon = FloweryTrayIcon(
            app_name="Flowery (Glue)",
            on_exit_callback=lambda: self.cleanup(force=True),
            get_profile_name_callback=lambda: self.active_profile_name,
            on_power_event_callback=self.power_watchdog.on_power_broadcast
        )
        self._is_active = False
        self._cleanup_lock = threading.Lock()
        self._cleaned_up = False
        self._timer_period_active = False

    def apply_setting(self, section: str, key: str, value: Any) -> None:
        """Устанавливает параметр в конфигурации и сохраняет его в config.ini (B8)."""
        self.config.set_value(section, key, value)
        self.config.set_override(key, value)
        self.config.save()

    def _on_profile_switched(self, prof_id: str, prof_name: str, network_fp: str) -> None:
        """Динамическое переключение профиля при смене сети на лету."""
        self.active_profile_name = prof_name
        self.current_network_fp = network_fp
        if hasattr(self.proxy_server, "strategy_engine") and self.proxy_server.strategy_engine:
            self.proxy_server.strategy_engine.set_network_context(network_fp)
        self.tray_icon.update_tooltip(f"Flowery (Glue) — {prof_name}")
        logger.info(f"Динамическая смена сети ({network_fp}) -> применён профиль '{prof_name}'")
        if self._is_active:
            if self.config.fix_ttl and is_admin():
                self.ttl_mgr.target_ttl = self.config.default_ttl
                self.ttl_mgr.apply_ttl()
            elif not self.config.fix_ttl and is_admin():
                self.ttl_mgr.restore_ttl()

            if getattr(self.config, "clamp_mss", True) and is_admin():
                cfg_mtu = getattr(self.config, "target_mtu", 1420)
                self.mtu_mgr.target_mtu = 1380 if cfg_mtu == 1420 else cfg_mtu
                self.mtu_mgr.apply_mtu()
            elif not getattr(self.config, "clamp_mss", True) and is_admin():
                self.mtu_mgr.restore_mtu()

            if self.config.block_quic and is_admin():
                self.quic_blocker.block_quic()
            elif not self.config.block_quic and is_admin():
                self.quic_blocker.unblock_quic()

            self.proxy_mgr.proxy_override = build_proxy_override(
                proxy_discord=self.config.proxy_discord,
                proxy_youtube=self.config.proxy_youtube
            )
            if self.config.auto_system_proxy:
                self.proxy_mgr.enable()

            # Обновление режима десинхронизации пакетов winws при смене профиля
            if "packet_desync_fooling" in self.config._overrides:
                new_fooling = self.config._overrides["packet_desync_fooling"]
                if new_fooling != self.voice_helper.fooling:
                    self.voice_helper.fooling = new_fooling
                    if self.voice_helper.is_running() and self.voice_helper.managed_by_us:
                        logger.info(f"Динамическая смена fooling winws: -> {new_fooling}")
                        # Закрываем WinDivert handle badsum_injector перед перезапуском winws,
                        # иначе stale handle к перезагружаемому драйверу вызовет BSOD
                        try:
                            from flowguard.badsum_injector import get_badsum_controller
                            get_badsum_controller().close()
                        except Exception as e:
                            logger.debug("[Main] badsum controller close exception: %s", e)
                        self.voice_helper.stop()
                        self.voice_helper.start()

    def reset_system(self) -> None:
        """Полный принудительный сброс всех сетевых параметров Windows в дефолтное состояние."""
        print("\033[96m[*] Запуск сброса параметров Windows (прокси, QUIC, TTL, DNS)...\033[0m")
        self.proxy_mgr.force_cleanup()
        print("  \033[92m[+]\033[0m Системный прокси Windows отключен")
        if is_admin():
            if self.quic_blocker.is_rule_present():
                self.quic_blocker.unblock_quic()
                print("  \033[92m[+]\033[0m Правило блокировки QUIC удалено из Windows Firewall")
            if self.ttl_mgr.restore_ttl():
                print("  \033[92m[+]\033[0m Значение DefaultTTL восстановлено")
            if self.mtu_mgr.restore_mtu():
                print("  \033[92m[+]\033[0m Значение MTU сетевых адаптеров восстановлено")
            self.dns_mgr.restore_dns(force_all=True)
            print("  \033[92m[+]\033[0m Сетевые DNS возвращены к DHCP")
        else:
            print("  \033[93m[!]\033[0m Для сброса брандмауэра и TTL требуются права Администратора")
        self.voice_helper.stop()
        print("\033[92m[+] Все параметры успешно возвращены к дефолтным значениям.\033[0m")

    def run_tests_tool(self) -> None:
        """Инструмент экспресс-тестирования доступности сервисов через Flowery."""
        import socket
        print("\033[96m[*] Проверка доступности заблокированных ресурсов через Flowery...\033[0m\n")
        proxy_already_running = False
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(0.5)
            test_sock.connect((self.config.proxy_host, self.config.proxy_port))
            test_sock.close()
            proxy_already_running = True
        except Exception as e:
            logger.debug("[Main] Proxy connection check before test tool failed: %s", e)
            proxy_already_running = False

        if not proxy_already_running:
            print("[*] Временный запуск локального прокси Flowery для тестирования...")
            self.proxy_server.start()
            time.sleep(0.5)

        try:
            test_proxy_connection(self.config.proxy_host, self.config.proxy_port)
        finally:
            if not proxy_already_running:
                self.proxy_server.stop()

    def choose_profile_interactive(self) -> None:
        """Интерактивный выбор и переключение сетевого профиля."""
        if sys.platform == "win32":
            os.system("cls")
        print("\033[1;96m[=== ВЫБОР СЕТЕВОГО ПРОФИЛЯ FLOWERY ===]\033[0m\n")
        print(f"Текущая сеть: \033[93m{self.current_network_fp}\033[0m")
        print(f"Активный профиль: \033[92m{self.active_profile_name}\033[0m\n")

        all_profiles = self.profile_mgr.get_all_profiles()
        keys = list(all_profiles.keys())
        for idx, k in enumerate(keys, 1):
            p = all_profiles[k]
            mark = " \033[92m(активен)\033[0m" if k == self.profile_mgr.active_profile_id else ""
            print(f"  \033[93m{idx}.\033[0m \033[1;97m{p['name']}\033[0m{mark}")
            print(f"     \033[90m{p['description']}\033[0m")
            print()

        print("  \033[93m0.\033[0m Назад в главное меню")
        try:
            p_choice = input(f"\n\033[1;93mВыберите профиль (0-{len(keys)}):\033[0m ").strip()
            if p_choice.isdigit():
                val = int(p_choice)
                if 1 <= val <= len(keys):
                    selected_key = keys[val - 1]
                    self.profile_mgr.apply_profile(selected_key, self.config)
                    self.profile_mgr.associate_current_network(selected_key)
                    prof_obj = all_profiles[selected_key]
                    self.active_profile_name = prof_obj.get("name", selected_key)
                    self.tray_icon.update_tooltip(f"Flowery (Glue) — {self.active_profile_name}")

                    # Немедленное применение параметров профиля
                    if self._is_active:
                        if self.config.fix_ttl and is_admin():
                            self.ttl_mgr.target_ttl = self.config.default_ttl
                            self.ttl_mgr.apply_ttl()
                        elif not self.config.fix_ttl and is_admin():
                            self.ttl_mgr.restore_ttl()

                        if self.config.block_quic and is_admin():
                            self.quic_blocker.block_quic()
                        elif not self.config.block_quic and is_admin():
                            self.quic_blocker.unblock_quic()

                        self.proxy_mgr.proxy_override = build_proxy_override(
                            proxy_discord=self.config.proxy_discord,
                            proxy_youtube=self.config.proxy_youtube
                        )
                        if self.config.auto_system_proxy:
                            self.proxy_mgr.enable()

                    print(f"\n\033[92m[+] Профиль '{self.active_profile_name}' успешно активирован!\033[0m")
                    time.sleep(1.2)
        except (KeyboardInterrupt, EOFError):
            logger.debug("[Interactive] Меню переключения профилей закрыто пользователем (Ctrl+C / EOF)")

    def configure_custom_dns_interactive(self) -> None:
        """Интерактивная настройка собственного DNS-сервера (DoH) с выбором пресетов и ручным вводом."""
        if sys.platform == "win32":
            os.system("cls")

        print("\033[1;96m" + "=" * 68 + "\033[0m")
        print("\033[1;97m       НАСТРОЙКА ПОЛЬЗОВАТЕЛЬСКОГО DNS-СЕРВЕРА (DoH)\033[0m")
        print("\033[1;96m" + "=" * 68 + "\033[0m\n")

        cur_p = self.config.dns_primary
        cur_s = self.config.dns_secondary
        cur_u = self.config.dns_doh_url
        cur_n = self.config.dns_doh_name or "Custom"
        cur_srv = self.config.dns_server or cur_p
        status_str = f"\033[92mВКЛЮЧЕН ({cur_n}: {cur_srv})\033[0m" if self.config.enable_custom_dns else "\033[90mВЫКЛЮЧЕН (стандартный DNS провайдера)\033[0m"

        print(f"  Текущий статус: {status_str}")
        if self.config.enable_custom_dns:
            print(f"  Активный сервер: \033[96m{cur_srv}\033[0m")
            if cur_p and cur_p != cur_srv:
                print(f"  IP адрес:        \033[96m{cur_p}\033[0m")
        print()

        print("\033[1;93mВыберите вариант настройки:\033[0m")
        print("  \033[93m1.\033[0m \033[97mQuad9\033[0m       — 9.9.9.9        \033[92m[Рекомендуется в РФ]\033[0m")
        print("  \033[93m2.\033[0m \033[97mCloudflare\033[0m  — 1.1.1.1        \033[90m(Быстрый глобальный)\033[0m")
        print("  \033[93m3.\033[0m \033[97mGoogle\033[0m      — 8.8.8.8        \033[90m(Максимальная стабильность)\033[0m")
        print("  \033[93m4.\033[0m \033[97mAdGuard\033[0m     — 94.140.14.14   \033[90m(Фильтрация рекламы)\033[0m")
        print("  \033[93m5.\033[0m \033[97mСвой сервер\033[0m — ввести IP или домен \033[92m[Автоматическая настройка]\033[0m")
        print("  \033[93m6.\033[0m \033[91mОтключить шифрованный DNS\033[0m (вернуть стандартный от оператора)")
        print("  \033[93m0.\033[0m \033[90mНазад в главное меню\033[0m\n")

        try:
            choice = input("\033[1;93mВаш выбор (0-6):\033[0m ").strip()
            if choice == "0" or choice == "":
                return

            if choice == "6":
                # Отключение пользовательского DNS
                self.config.set_value("dns", "enable_custom_dns", False)
                self.config.save()
                if is_admin():
                    self.dns_mgr.restore_dns()
                print("\n\033[92m[+] Пользовательский DNS выключен. Восстановлены стандартные настройки сети.\033[0m")
                time.sleep(1.2)
                return

            provider_name = ""
            ip1 = ""
            ip2 = ""
            doh_url = ""
            target_str = ""

            if choice == "1":
                provider_name = "Quad9"
                ip1 = "9.9.9.9"
                ip2 = "149.112.112.112"
                doh_url = "https://dns.quad9.net/dns-query"
                target_str = "Quad9"
            elif choice == "2":
                provider_name = "Cloudflare"
                ip1 = "1.1.1.1"
                ip2 = "1.0.0.1"
                doh_url = "https://cloudflare-dns.com/dns-query"
                target_str = "Cloudflare"
            elif choice == "3":
                provider_name = "Google"
                ip1 = "8.8.8.8"
                ip2 = "8.8.4.4"
                doh_url = "https://dns.google/dns-query"
                target_str = "Google"
            elif choice == "4":
                provider_name = "AdGuard"
                ip1 = "94.140.14.14"
                ip2 = "94.140.15.15"
                doh_url = "https://dns.adguard-dns.com/dns-query"
                target_str = "AdGuard"
            elif choice == "5":
                print("\n\033[96m--- ВВОД СВОЕГО DNS-СЕРВЕРА ---\033[0m")
                print("\033[97mВам НЕ нужно разбираться в протоколах или шаблонах.\033[0m")
                print("\033[90mПросто введите IP-адрес (например: 192.144.59.14) или сайт (например: dns-ai.ru).\033[0m")
                print("\033[90mFlowery сам подключится, проверит сертификаты и настроит безопасный DNS.\033[0m\n")
                prompt_srv = f"Адрес вашего сервера [{cur_srv or '192.144.59.14'}]: "
                srv_input = input(f"\033[93m{prompt_srv}\033[0m").strip()
                target_str = srv_input if srv_input else (cur_srv or "192.144.59.14")

                print(f"\n\033[96m[*] Проверка сервера '{target_str}'...\033[0m")
                from flowguard.doh_resolver import auto_detect_dns_provider
                try:
                    provider = auto_detect_dns_provider(target_str)
                    ip1 = provider.server_ips[0] if provider.server_ips else target_str
                    ip2 = provider.server_ips[1] if len(provider.server_ips) > 1 else ""
                    doh_url = getattr(provider, "doh_url", f"https://{provider.doh_host}{provider.doh_path}")
                    provider_name = provider.name
                    print(f"  \033[92m[+] Сервер распознан: {provider.name} (IP: {', '.join(provider.server_ips)})\033[0m")
                except Exception as ve:
                    print(f"\n\033[91m[X] Ошибка: {ve}\033[0m")
                    input("\n\033[97mНажмите Enter для возврата в главное меню...\033[0m")
                    return
            else:
                print("\033[91mНеверный выбор. Введите число от 0 до 6.\033[0m")
                time.sleep(1.0)
                return

            if choice in ("1", "2", "3", "4"):
                ips = [ip for ip in (ip1, ip2) if ip]
                try:
                    provider = build_custom_provider(name=provider_name, doh_url=doh_url, ipv4_list=ips)
                except ValueError as ve:
                    print(f"\n\033[91m[X] Ошибка: {ve}\033[0m")
                    input("\n\033[97mНажмите Enter для возврата в главное меню...\033[0m")
                    return

            print(f"\n\033[96m[*] Проверка DNS: выполняю тестовый запрос к {provider.name}...\033[0m")
            resolver = DoHResolver(provider, timeout=4.0)
            test_success = False
            test_error = ""
            test_ips: List[str] = []
            try:
                test_ips = resolver.resolve("cloudflare.com", qtype=1)
                if test_ips:
                    test_success = True
            except Exception as e:
                test_error = str(e)

            if test_success:
                print(f"  \033[92m[+] Успешно! cloudflare.com -> {', '.join(test_ips)}\033[0m")
                print("  \033[92m[+] DNS-сервер проверен и готов к работе.\033[0m")
            else:
                print(f"  \033[91m[!] Не отвечает: {test_error or 'нет IP-адресов в ответе'}\033[0m")
                save_anyway = input("\033[93mСохранить настройки несмотря на ошибку? (y/N): \033[0m").strip().lower()
                if save_anyway not in ("y", "yes", "д", "да"):
                    print("\033[90m[*] Сохранение отменено.\033[0m")
                    input("\n\033[97mНажмите Enter для возврата в главное меню...\033[0m")
                    return

            # Сохранение строго через config.set_value() + config.save() (не set_override)
            self.config.set_value("dns", "server", target_str)
            self.config.set_value("dns", "primary", ip1)
            self.config.set_value("dns", "secondary", ip2)
            self.config.set_value("dns", "doh_url", doh_url)
            self.config.set_value("dns", "doh_name", provider.name)
            self.config.set_value("dns", "enable_custom_dns", True)
            if self.config.save():
                print("\n\033[92m[+] Настройки DNS успешно сохранены в config.ini!\033[0m")
            else:
                print("\n\033[91m[!] Не удалось сохранить изменения в config.ini.\033[0m")

            # Обновление рабочего менеджера failover в запущенном прокси
            if hasattr(self, "proxy_server") and self.proxy_server:
                try:
                    from Floweryguard.proxy import get_dns_failover_manager
                except ImportError:
                    from flowguard.proxy import get_dns_failover_manager
                self.proxy_server.dns_failover = get_dns_failover_manager(self.config, force_new=True)

            self.dns_mgr.primary_dns = ip1
            self.dns_mgr.secondary_dns = ip2 or "8.8.8.8"
            if is_admin():
                self.dns_mgr.set_secure_dns()

            time.sleep(1.0)
            input("\n\033[97mНажмите Enter для возврата в главное меню...\033[0m")
        except (KeyboardInterrupt, EOFError):
            logger.debug("[DNS Menu] Interrupted by user")
        except Exception as err:
            logger.error(f"[DNS Menu] Ошибка в меню: {err}", exc_info=True)
            print(f"\n\033[91m[!] Произошла ошибка: {err}\033[0m")
            try:
                input("\n\033[97mНажмите Enter для возврата в главное меню...\033[0m")
            except Exception as e:
                logger.debug("[DNS Menu] input exit error: %s", e)

    def run_calibration_interactive(self) -> None:
        """Интерактивный запуск калибровки и ускоренного обучения ML-движка Flowery."""
        if sys.platform == "win32":
            os.system("cls")
        else:
            os.system("clear")

        print("\033[1;96m" + "=" * 74 + "\033[0m")
        print("\033[1;97m       КАЛИБРОВКА ОБХОДА DPI — УСКОРЕННОЕ ОБУЧЕНИЕ ML-ДВИЖКА\033[0m")
        print("\033[1;96m" + "=" * 74 + "\033[0m\n")

        print("\033[97mКалибровка форсирует обучение алгоритма Thompson Sampling (Strategy Engine):\033[0m")
        print("  \033[92m●\033[0m Проверяет стратегии напрямую через сокеты без открытия браузеров.")
        print("  \033[92m●\033[0m Успешные стратегии моментально получают буст весов в strategy_scores.json.")
        print("  \033[92m●\033[0m Защита от перекалибровки: автоматическое демпфирование весов и Variance Guard.")
        print("  \033[91m●\033[0m Заблокированные ТСПУ стратегии отсекаются, исключая подвисания сайтов.\n")

        print("\033[1;93mВыберите режим калибровки:\033[0m")
        print("  \033[93m1.\033[0m \033[97mБыстрая калибровка\033[0m — 10 ключевых сервисов (YouTube, Discord, X, ECH... ~10 сек)")
        print("  \033[93m2.\033[0m \033[97mПолная калибровка\033[0m  — 110+ заблокированных сайтов (СМИ, торренты, VPN, кино... ~35 сек)")
        print("  \033[93m0.\033[0m \033[90mНазад в главное меню\033[0m\n")

        try:
            c = input("\033[1;93mВаш выбор (0-2):\033[0m ").strip()
            if c not in ("1", "2"):
                return
            mode = "fast" if c == "1" else "full"
            self.run_calibration(mode=mode, interactive=True)
        except (KeyboardInterrupt, EOFError):
            logger.debug("[Calibration] Interrupted by user")
        except Exception as err:
            logger.error(f"[Калибровка] Ошибка: {err}", exc_info=True)
            print(f"\n\033[91m[!] Произошла ошибка калибровки: {err}\033[0m")
            try:
                input("\n\033[97mНажмите Enter для возврата в главное меню...\033[0m")
            except Exception as e:
                logger.debug("[Calibration] input exit error: %s", e)

    def run_calibration(self, mode: str = "full", interactive: bool = False) -> None:
        """Запуск калибровки и ускоренного обучения ML-движка Flowery."""
        from flowguard.calibration import StrategyCalibrator, FULL_CALIBRATION_DOMAINS
        mode_desc = "Быстрая (10 сервисов)" if mode == "fast" else f"Полная ({len(FULL_CALIBRATION_DOMAINS)} сервисов)"
        print(f"\n\033[96m[*] Запуск калибровки: {mode_desc}...\033[0m\n")

        engine = self.proxy_server.strategy_engine if hasattr(self, "proxy_server") and self.proxy_server else None
        calibrator = StrategyCalibrator(engine=engine, max_workers=16)

        last_len = [0]

        def on_progress(current: int, total: int, domain: str, strategy: str, success: bool):
            pct = int((current / total) * 100) if total else 0
            bar_len = 20
            filled = int(bar_len * (current / total)) if total else 0
            bar = "█" * filled + "░" * (bar_len - filled)
            status_icon = "\033[92m✓\033[0m" if success else "\033[91m✗\033[0m"
            line = f"\r\033[96m[{bar}] {pct:>3}%\033[0m ({current}/{total}) {status_icon} {domain:<24} -> {strategy:<20}"
            pad = max(0, last_len[0] - len(line))
            sys.stdout.write(line + " " * pad)
            sys.stdout.flush()
            last_len[0] = len(line)

        t_start = time.time()
        report = calibrator.run_calibration(mode=mode, progress_callback=on_progress, reset_cancel=True)
        elapsed = time.time() - t_start
        print("\n")

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

        # Сохранение победителя
        self.config.set_value("strategy", "default_strategy", winner)
        self.config.save()
        if hasattr(self, "proxy_server") and self.proxy_server:
            self.proxy_server.strategy_executor = winner

        if interactive:
            try:
                input("\n\033[97mНажмите Enter для возврата в главное меню...\033[0m")
            except Exception as e:
                logger.debug("[Calibration] Interactive exit input error: %s", e)

    def update_whitelist_interactive(self) -> None:
        """Интерактивное обновление whitelist.txt из онлайн-источников."""
        if sys.platform == "win32":
            os.system("cls")
        else:
            os.system("clear")

        print("\033[1;96m" + "=" * 74 + "\033[0m")
        print("\033[1;97m          ОБНОВЛЕНИЕ СПИСКА ДОМЕНОВ WHITELIST.TXT\033[0m")
        print("\033[1;96m" + "=" * 74 + "\033[0m\n")

        print("\033[97mТекущий файл:\033[0m \033[96m" + str(self.config.whitelist_file) + "\033[0m")
        cur_domains, wl_path = load_whitelist_domains(self.config.whitelist_file)
        print(f"\033[97mЗагружено доменов в памяти:\033[0m \033[92m{len(cur_domains)}\033[0m\n")

        print("\033[1;93mВыберите источник обновления:\033[0m")
        print("  \033[93m1.\033[0m \033[97mFlowery Community List\033[0m (GitHub: Discord, YouTube, соцсети, СМИ, трекеры)")
        print("  \033[93m2.\033[0m \033[97mВвести свой URL\033[0m        (прямая ссылка на raw .txt список доменов)")
        print("  \033[93m0.\033[0m \033[90mНазад в главное меню\033[0m\n")

        try:
            c = input("\033[1;93mВаш выбор (0-2):\033[0m ").strip()
            if c not in ("1", "2"):
                return

            if c == "1":
                url = "https://raw.githubusercontent.com/Floweryguard/whitelist/main/whitelist.txt"
            else:
                url = input("\033[93mВведите URL списка доменов: \033[0m").strip()
                if not url:
                    return

            print(f"\n\033[96m[*] Загрузка списка из {url}...\033[0m")
            import urllib.request
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Flowery/1.2"}
            )
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                content = resp.read().decode("utf-8", errors="ignore")

            new_domains = set()
            for line in content.splitlines():
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    new_domains.add(line)

            if not new_domains:
                print("\033[91m[!] В загруженном файле не найдено ни одного валидного домена.\033[0m")
                input("\n\033[97mНажмите Enter для возврата...\033[0m")
                return

            print(f"  \033[92m[+] Успешно скачано: {len(new_domains)} доменов.\033[0m")
            mode = input("\033[93mОбъединить с текущими доменами (M) или Заменить полностью (R)? [M/r]: \033[0m").strip().lower()

            target_file = wl_path if (wl_path and os.path.exists(wl_path)) else "whitelist.txt"
            if mode in ("r", "replace", "з", "заменить"):
                final_domains = sorted(list(new_domains))
            else:
                final_domains = sorted(list(cur_domains.union(new_domains)))

            # Резервная копия
            if os.path.exists(target_file):
                import shutil as sh
                sh.copy2(target_file, target_file + ".bak")

            with open(target_file, "w", encoding="utf-8") as f:
                f.write(f"# Flowery Whitelist — обновлено {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Источник: {url}\n\n")
                for d in final_domains:
                    f.write(d + "\n")

            print(f"\n\033[92m[✓] Файл {target_file} успешно сохранён ({len(final_domains)} доменов).\033[0m")
            print(f"\033[90m    (Резервная копия сохранена в {target_file}.bak)\033[0m")

            # Мгновенная перезагрузка в прокси
            if hasattr(self, "proxy_server") and self.proxy_server:
                self.proxy_server.whitelist_domains = set(final_domains)
                print("\033[92m[+] Прокси Flowery мгновенно применил обновленный список!\033[0m")

            input("\n\033[97mНажмите Enter для возврата в главное меню...\033[0m")
        except Exception as err:
            logger.error(f"[Whitelist Update] Ошибка: {err}", exc_info=True)
            print(f"\n\033[91m[!] Ошибка обновления списка: {err}\033[0m")
            try:
                input("\n\033[97mНажмите Enter для возврата...\033[0m")
            except Exception as e:
                logger.debug("[Whitelist] input error: %s", e)

    def send_logs_interactive(self) -> None:
        """Интерактивная отправка диагностического лога сессии разработчику."""
        if sys.platform == "win32":
            os.system("cls")
        else:
            os.system("clear")

        print("\033[1;96m" + "=" * 74 + "\033[0m")
        print("\033[1;97m       ОТПРАВКА ДИАГНОСТИЧЕСКОГО ЛОГА СЕССИИ РАЗРАБОТЧИКУ\033[0m")
        print("\033[1;96m" + "=" * 74 + "\033[0m\n")

        print("  \033[97mВы можете отправить лог текущей сессии разработчику для анализа проблемы.\033[0m")
        print("  \033[90m● Лог автоматически очищается: личные пути пользователей маскируются.\033[0m")
        print("  \033[90m● Отправка выполняется через защищённый шлюз (без раскрытия токенов).\033[0m\n")

        sender = LogSender(self.config)

        try:
            confirm = input("\033[1;93mОтправить лог разработчику прямо сейчас? [Y/n]: \033[0m").strip().lower()
            if confirm in ("n", "no", "нет", "н"):
                print("\n\033[90m[*] Отправка отменена пользователем.\033[0m")
                time.sleep(1.0)
                return

            print()
            user_note = input("\033[93mКратко опишите проблему (Enter чтобы пропустить): \033[0m").strip()

            print("\n\033[96m[*] Формирование и анонимизация отчёта...\033[0m")
            print("\033[96m[*] Доставка отчёта разработчику через защищённый шлюз...\033[0m")

            ok, msg = sender.send_report(user_comment=user_note)
            if ok:
                print(f"\n\033[92m[✓] {msg}\033[0m")
                print("\033[90m    Спасибо за помощь в улучшении и поддержке Flowery!\033[0m")
            else:
                print(f"\n\033[91m[!] {msg}\033[0m")
                log_p = get_current_log_path()
                print(f"\033[93m[*] Файл логов сохранён на вашем ПК:\033[0m {log_p}")
                ask_open = input("\n\033[97mОткрыть файл логов в Блокноте? [Y/n]: \033[0m").strip().lower()
                if ask_open not in ("n", "no", "нет", "н"):
                    open_current_log_file()

            input("\n\033[97mНажмите Enter для возврата в главное меню...\033[0m")
        except (KeyboardInterrupt, EOFError):
            logger.debug("[SendLogs] Interrupted by user")

    def render_menu(self) -> None:
        """Отображает интерактивное меню Flowery Service Manager."""
        if sys.platform == "win32":
            os.system("cls")
        else:
            os.system("clear")

        try:
            cols = shutil.get_terminal_size((120, 50)).columns
        except Exception:
            cols = 120

        c_on = "[92m[включено][0m"
        c_off = "[90m[отключено][0m"

        ttl_tag = c_on if self.config.fix_ttl else c_off
        quic_tag = c_on if self.config.block_quic else c_off
        discord_tag = c_on if self.config.proxy_discord else c_off
        voice_tag = c_on if self.config.discord_voice_udp else c_off
        youtube_tag = c_on if self.config.proxy_youtube else c_off
        auto_strat_tag = c_on if self.config.auto_strategy else c_off
        dns_tag = f"[92m[{self.config.dns_primary}][0m" if self.config.enable_custom_dns else c_off

        status_line = "[92m● СТАТУС: АКТИВЕН (Обход включен)[0m" if self._is_active else "[91m○ СТАТУС: ОСТАНОВЛЕН[0m"
        svc_toggle = "Остановить службу Flowery" if self._is_active else "Запустить службу Flowery"

        traffic_info = ""
        if hasattr(self, "proxy_server") and self.proxy_server:
            try:
                stats = self.proxy_server.get_traffic_stats()
                try:
                    from flowguard.proxy import format_speed
                except ImportError:
                    from Floweryguard.proxy import format_speed
                rx_s = format_speed(stats.get("rx_speed", 0.0))
                tx_s = format_speed(stats.get("tx_speed", 0.0))
                conns = stats.get("active_connections", 0)
                sess = stats.get("total_sessions", 0)
                traffic_info = f"[90mТрафик:[0m [92m↓{rx_s}[0m [96m↑{tx_s}[0m | [90mСоед:[0m [97m{conns}[0m | [90mСессий:[0m [97m{sess}[0m"
            except Exception:
                pass

        sep = "[90m" + "-" * 50 + "[0m"

        right_lines = [
            "[1;97mМЕНЕДЖЕР СЛУЖБ FLOWERY v1.3.0 (GLUE)[0m",
            f"   {status_line}",
            f"   [90mПрофиль:[0m [96m{self.active_profile_name}[0m",
        ]
        if traffic_info:
            right_lines.append(f"   {traffic_info}")
        right_lines.extend([
            sep,
            "",
            "[1;96m:: СЛУЖБА И ПРОФИЛИ[0m",
            f"   [93m1.[0m [97m{svc_toggle}[0m",
            "   [93m2.[0m [97mСменить сетевой профиль[0m",
            "   [93m3.[0m [97mСвернуть в трей (фоновый режим)[0m",
            "   [93m4.[0m [97mПроверить статус компонентов[0m",
            "   [93m5.[0m [97mСбросить системные настройки[0m",
            "",
            "[1;96m:: НАСТРОЙКИ ОБХОДА[0m",
            f"   [93m6.[0m [97mМаскировка TTL тетеринга [0m {ttl_tag}",
            f"   [93m7.[0m [97mБлокировка QUIC (UDP 443)[0m {quic_tag}",
            f"   [93m8.[0m [97mОбход Discord            [0m {discord_tag}",
            f"   [93m9.[0m [97mГолосовые каналы Discord [0m {voice_tag}",
            f"   [93m10.[0m [97mОбход YouTube            [0m {youtube_tag}",
            f"   [93m11.[0m [97mАвто-стратегии (ML)      [0m {auto_strat_tag}",
            f"   [93m12.[0m [97mЗащищённый DNS (DoH)     [0m {dns_tag}",
            "",
            "[1;96m:: ИНСТРУМЕНТЫ[0m",
            "   [93m13.[0m [97mКалибровка обхода DPI    [0m [92m[Обучение ML][0m",
            "   [93m14.[0m [97mЗапуск диагностики сети  [0m",
            "   [93m15.[0m [97mТест доступности сайтов  [0m",
            "   [93m16.[0m [97mОткрыть лог-файл сессии  [0m",
            "   [93m17.[0m [97mОбновить базу доменов    [0m [90m(онлайн sync)[0m",
            "   [93m18.[0m [97mОтправить лог разработчику[0m [92m[Поддержка][0m",
            "",
            sep,
            "   [93m0.[0m [97mВыход (с восстановлением системы)[0m",
            "",
        ])

        if cols >= 105:
            # Двухколоночный режим: слева Flowey арт, справа меню
            for i in range(len(FLOWEY_ART)):
                line = FLOWEY_ART[i]
                if i < 17:
                    c_flowey = "[93m" + line + "[0m"
                elif i < 34:
                    c_flowey = "[97m" + line + "[0m"
                else:
                    c_flowey = "[92m" + line + "[0m"
                r = right_lines[i] if i < len(right_lines) else ""
                print(f"  {c_flowey}    {r}")
        else:
            # Адаптивный режим для узких терминалов
            for i in range(len(FLOWEY_ART)):
                line = FLOWEY_ART[i]
                if i < 17:
                    c_flowey = "[93m" + line + "[0m"
                elif i < 34:
                    c_flowey = "[97m" + line + "[0m"
                else:
                    c_flowey = "[92m" + line + "[0m"
                print(f"  {c_flowey}")
            print()
            for r in right_lines:
                print(f"  {r}")

    def run_menu(self) -> None:
        """Интерактивный цикл работы в меню управления Flowery Service Manager."""
        # Автоматический запуск комплекса при старте меню — пользователю не нужно думать об этом!
        if not self._is_active:
            self.start_services(quiet=True)

        # Запуск иконки в трее для возможности фонового управления
        self.tray_icon.start(hide_console=False)

        # Небольшая пауза для завершения системных broadcast'ов WinINet в Windows
        time.sleep(0.5)

        while True:
            self.render_menu()
            choice = ""
            try:
                choice = input("\033[1;93mВыберите пункт (0-18):\033[0m ").strip()
            except EOFError:
                try:
                    sys.stdin = open("CONIN$", "r", encoding="utf-8", errors="replace")
                    time.sleep(0.3)
                    choice = input("\033[1;93mВыберите пункт (0-18):\033[0m ").strip()
                except Exception as e:
                    logger.debug("[Menu] CONIN fallback read error: %s", e)
                    time.sleep(0.5)
                    continue
            except KeyboardInterrupt:
                print()
                self.cleanup(force=True)
                break

            if choice == "":
                # Очистка и перерисовка экрана по нажатию Enter без ошибки
                continue

            if choice == "0":
                if sys.platform == "win32":
                    os.system("cls")
                print("\033[92m[*] Завершение работы Flowery Service Manager...\033[0m")
                self.cleanup(force=True)
                time.sleep(0.8)
                break
            elif choice == "1":
                # Переключатель состояния службы (Stop / Start)
                if self._is_active:
                    self.stop_services()
                else:
                    self.start_services(quiet=True)
            elif choice == "2":
                self.choose_profile_interactive()
            elif choice == "3":
                # Свернуть в системный трей (фоновый режим)
                print("\033[96m[*] Flowery свёрнут в системный трей.\033[0m")
                print("\033[90m    Двойной клик по иконке в трее вернёт окно консоли.\033[0m")
                time.sleep(1.0)
                self.tray_icon.hide_console_window()
            elif choice == "4":
                if sys.platform == "win32":
                    os.system("cls")
                self.run_status()
                try:
                    input("\n\033[97mНажмите Enter для возврата в главное меню...\033[0m")
                except (KeyboardInterrupt, EOFError):
                    logger.debug("[Menu] status input interrupted")
            elif choice == "5":
                if sys.platform == "win32":
                    os.system("cls")
                self.reset_system()
                try:
                    input("\n\033[97mНажмите Enter для возврата в главное меню...\033[0m")
                except (KeyboardInterrupt, EOFError):
                    logger.debug("[Menu] reset input interrupted")
            elif choice == "6":
                new_val = not self.config.fix_ttl
                self.apply_setting("tethering", "fix_ttl", new_val)
                if is_admin():
                    if new_val:
                        self.ttl_mgr.apply_ttl()
                    else:
                        self.ttl_mgr.restore_ttl()
            elif choice == "7":
                new_val = not self.config.block_quic
                self.apply_setting("quic", "block_quic", new_val)
                if is_admin():
                    if new_val:
                        self.quic_blocker.block_quic()
                    else:
                        self.quic_blocker.unblock_quic()
            elif choice == "8":
                new_val = not self.config.proxy_discord
                self.apply_setting("proxy", "proxy_discord", new_val)
                self.proxy_mgr.proxy_override = build_proxy_override(
                    proxy_discord=self.config.proxy_discord,
                    proxy_youtube=self.config.proxy_youtube
                )
                if self._is_active and self.config.auto_system_proxy:
                    self.proxy_mgr.enable()
            elif choice == "9":
                new_val = not self.config.discord_voice_udp
                self.apply_setting("proxy", "discord_voice_udp", new_val)
                if new_val:
                    self.voice_helper.start()
                else:
                    self.voice_helper.stop()
            elif choice == "10":
                new_val = not self.config.proxy_youtube
                self.apply_setting("proxy", "proxy_youtube", new_val)
                self.proxy_mgr.proxy_override = build_proxy_override(
                    proxy_discord=self.config.proxy_discord,
                    proxy_youtube=self.config.proxy_youtube
                )
                if self._is_active and self.config.auto_system_proxy:
                    self.proxy_mgr.enable()
            elif choice == "11":
                new_val = not self.config.auto_strategy
                self.apply_setting("strategy", "auto_strategy", new_val)
                self.proxy_server.strategy_engine.enabled = new_val
            elif choice == "12":
                self.configure_custom_dns_interactive()
            elif choice == "13":
                self.run_calibration_interactive()
            elif choice == "14":
                if sys.platform == "win32":
                    os.system("cls")
                print("\033[96m[*] Запуск комплексной диагностики сети...\033[0m\n")
                self.detector.run_full_diagnosis()
                self.detector.print_report()
                try:
                    input("\n\033[97mНажмите Enter для возврата в главное меню...\033[0m")
                except (KeyboardInterrupt, EOFError):
                    logger.debug("[Menu] diagnosis input interrupted")
            elif choice == "15":
                if sys.platform == "win32":
                    os.system("cls")
                self.run_tests_tool()
                try:
                    input("\n\033[97mНажмите Enter для возврата в главное меню...\033[0m")
                except (KeyboardInterrupt, EOFError):
                    logger.debug("[Menu] tests input interrupted")
            elif choice == "16":
                log_p = get_current_log_path()
                print(f"\033[96m[*] Открытие файла логов сессии:\033[0m {log_p}")
                open_current_log_file()
                time.sleep(1.2)
            elif choice == "17":
                self.update_whitelist_interactive()
            elif choice == "18":
                self.send_logs_interactive()
            else:
                print("\033[91mНеверный выбор. Введите число от 0 до 18.\033[0m")
                time.sleep(1.0)

    def print_banner(self) -> None:
        """Отображает цветной стартовый баннер с автоматической подгонкой под ширину экрана."""
        try:
            cols = shutil.get_terminal_size((120, 50)).columns
        except Exception:
            cols = 120

        flower = FLOWER_FULL if cols >= 120 else FLOWER_COMPACT
        print("\033[95m" + flower.strip("\n") + "\033[0m")
        print("\033[96m" + GLUE_ASCII.strip("\n") + "\033[0m")
        indent = max(0, (min(cols, 80) - 47) // 2)
        print("\033[1;97m" + " " * indent + "FLOWERY (GLUE) v1.3.0 — ОБХОД DPI ДЛЯ ТЕТЕРИНГА\033[0m")
        print("\033[90m" + " " * indent + "YouTube 4K • Discord Voice & Экран • Сетевые онлайн-игры\033[0m\n")

    def run_status(self) -> None:
        """Отображает текущий статус компонентов в системе."""
        v4, v6 = self.ttl_mgr.get_current_ttl()
        admin = is_admin()
        proxy_en, proxy_srv, _ = self.proxy_mgr.get_current_settings()
        quic_active = self.quic_blocker.is_rule_present()

        admin_str = "\033[92mДА\033[0m" if admin else "\033[91mНЕТ (запустите от имени Админа)\033[0m"
        proxy_str = f"\033[92mВКЛ\033[0m ({proxy_srv})" if proxy_en else "\033[90mВЫКЛ\033[0m"
        quic_str = "\033[92mАКТИВНА\033[0m" if quic_active else "\033[90mВЫКЛЮЧЕНА\033[0m"

        print("\033[96m[=== ТЕКУЩИЙ СТАТУС СИСТЕМЫ ===]\033[0m")
        print(f"  - Права Администратора: {admin_str}")
        print(f"  - Реестр DefaultTTL (IPv4): \033[93m{v4 or '128 (default)'}\033[0m | IPv6: \033[93m{v6 or 'default'}\033[0m")
        print(f"  - Системный прокси Windows: {proxy_str}")
        print(f"  - Блокировка QUIC (UDP 443): {quic_str}")
        print(f"  - Пакетный десинк: \033[93m{self.voice_helper.fooling}\033[0m (AutoTTL: \033[93m{self.voice_helper.autottl_delta if self.voice_helper.autottl else 'выкл'}\033[0m, SeqOvl: \033[93m{self.voice_helper.split_seqovl}b\033[0m)")
        print(f"  - Маршрутизация IPv6: \033[93m{self.config.ipv6_mode.upper()}\033[0m (профиль: {self.active_profile_name})")
        print(f"  - Multi-DoH Harvester: \033[92mАКТИВЕН\033[0m (Anycast Cloudflare, Google, Quad9)")
        print(f"  - MTU/MSS Clamping: \033[93m{getattr(self.mtu_mgr, 'target_mtu', 1380)} (активно: {self.mtu_mgr._applied})\033[0m | ECH Stripping: \033[93m{'ВКЛ' if getattr(self.config, 'strip_ech', False) else 'ВЫКЛ'}\033[0m | TLS Padding: \033[93m{'ВКЛ' if getattr(self.config, 'tls_padding', False) else 'ВЫКЛ'}\033[0m")
        print()

    def cleanup(self, force: bool = False) -> bool:
        """Останавливает фоновые задачи до отката; неудачный откат можно повторить."""
        with self._cleanup_lock:
            if self._cleaned_up:
                return True
            if not force and not self._is_active:
                return False
            self._is_active = False
            failures = []

            def attempt(label, action):
                try:
                    if action() is False:
                        failures.append(label)
                except Exception as error:
                    failures.append(label)
                    logger.warning("Ошибка завершения %s: %s", label, error)

            # Восстановление после сна должно закончиться до отката реестра.
            attempt("монитор сна", self.power_watchdog.stop)
            attempt("монитор сети", self.profile_mgr.stop_network_monitor)
            if self.proxy_mgr._is_active:
                attempt("системный прокси", self.proxy_mgr.disable)
            attempt("локальный прокси", self.proxy_server.stop)
            attempt("голосовой помощник", self.voice_helper.stop)
            attempt("трей", self.tray_icon.stop)
            if self.quic_blocker._blocked:
                attempt("QUIC", self.quic_blocker.unblock_quic)
            if self.ttl_mgr._applied:
                attempt("TTL", self.ttl_mgr.restore_ttl)
            if self.mtu_mgr._applied:
                attempt("MTU", self.mtu_mgr.restore_mtu)
            if self.dns_mgr.has_pending_restore():
                attempt("DNS", self.dns_mgr.restore_dns)
            if sys.platform == "win32" and self._timer_period_active:
                try:
                    ctypes.windll.winmm.timeEndPeriod(1)
                    self._timer_period_active = False
                except Exception as error:
                    failures.append("таймер Windows")
                    logger.warning("Не удалось восстановить таймер: %s", error)
            self._cleaned_up = not failures
            if failures:
                message = "Не завершено восстановление: " + ", ".join(failures)
                logger.warning(message)
                print(message + ". Повторите остановку; исходные значения сохранены.")
            else:
                logger.info("Службы остановлены, применённые настройки восстановлены")
                print("[+] Службы остановлены, применённые настройки восстановлены.")
            return self._cleaned_up

    def start_services(self, quiet: bool = False) -> bool:
        """Запуск полного комплекса Flowery служб без блокировки потока."""
        with self._cleanup_lock:
            if self._is_active:
                return True
            self._is_active = True
            self._cleaned_up = False

        logger.info("[Main] Запуск служб Flowery...")

        if not quiet and not is_admin():
            print("\033[93m[!] ВНИМАНИЕ: Скрипт запущен без прав Администратора!\033[0m")
            print("    Для автоматической фиксации TTL и блокировки QUIC перезапустите start.bat от имени Администратора.\n")

        # 0. Монитор гибернации/сна и монитор смены сети для динамических профилей
        if is_admin() and self.dns_mgr.has_pending_restore():
            if not self.dns_mgr.restore_dns():
                self._is_active = False
                raise RuntimeError("Не удалось восстановить DNS прошлого сеанса")
        if sys.platform == "win32" and not self._timer_period_active:
            if ctypes.windll.winmm.timeBeginPeriod(1) == 0:
                self._timer_period_active = True

        # 1. TTL Fix (применяем ДО авто-диагностики сети, чтобы статус в отчёте был актуален)
        if self.config.fix_ttl:
            if is_admin():
                if self.ttl_mgr.apply_ttl() and not quiet:
                    print(f"\033[92m[+] TTL зафиксирован на {self.config.default_ttl} (обход ограничений тетеринга)\033[0m")
                    logger.info("[Main] TTLManager: зафиксирован TTL %s", self.config.default_ttl)
                elif not quiet:
                    print("\033[91m[!] Не удалось установить TTL в реестре.\033[0m")
                    logger.warning("[Main] TTLManager: не удалось установить TTL в реестре")
            elif not quiet:
                print("\033[90m[-] Пропуск TTL fix (требуются права админа)\033[0m")
                logger.debug("[Main] TTLManager: пропуск TTL (нет прав админа)")

        # 1.1. MSS / MTU Clamping Fix
        if getattr(self.config, "clamp_mss", True):
            if is_admin():
                if self.mtu_mgr.apply_mtu() and not quiet:
                    print(f"\033[92m[+] MTU Clamping ({self.mtu_mgr.target_mtu}) активирован на адаптерах (защита от потерь GTP/CGNAT)\033[0m")
                    logger.info("[Main] MTUManager: MTU %s активирован", self.mtu_mgr.target_mtu)
            elif not quiet:
                print("\033[90m[-] Пропуск настройки MTU (требуются права админа)\033[0m")

        # 1.2. Авто-диагностика сети (Белый список vs Blacklist DPI vs Тетеринг)
        if self.config.whitelist_auto_detect:
            diag_results = self.detector.run_full_diagnosis()
            if not quiet:
                self.detector.print_report()
            overrides = diag_results.get("profile_overrides", {})
            if overrides:
                self.config.apply_profile(overrides)

        # 2. QUIC Block
        if self.config.block_quic:
            if is_admin():
                if self.quic_blocker.block_quic() and not quiet:
                    print("\033[92m[+] Блокировка QUIC (UDP 443) активирована (принуждение браузеров к TCP)\033[0m")
                    logger.info("[Main] QUICBlocker: правило UDP 443 активировано")
            elif not quiet:
                print("\033[90m[-] Пропуск блокировки QUIC (требуются права админа)\033[0m")
        else:
            if is_admin() and self.quic_blocker.is_rule_present():
                self.quic_blocker.unblock_quic()
                if not quiet:
                    print("\033[92m[+] Блокировка QUIC снята (UDP 443 разблокирован)\033[0m")
                    logger.info("[Main] QUICBlocker: правило UDP 443 снято")

        # 3. Безопасный DNS
        if self.config.enable_custom_dns and is_admin():
            if self.dns_mgr.set_secure_dns() and not quiet:
                print(f"\033[92m[+] Установлены DNS: {self.config.dns_primary}, {self.config.dns_secondary}\033[0m")
                logger.info("[Main] DNSManager: установлены DNS %s, %s", self.config.dns_primary, self.config.dns_secondary)

        # 3.1. Проверка пользовательского DoH DNS резолвера при старте
        if self.config.enable_custom_dns and hasattr(self.proxy_server, "dns_failover") and self.proxy_server.dns_failover:
            self.proxy_server.dns_failover.check_primary_startup()

        # 4. Discord Voice UDP Helper (десинхронизация портов 19294-19344, 50000-65535 [Сетевые онлайн-игры / P2P])
        # ВАЖНО: запускается ДО прокси-сервера, чтобы winws.exe успел загрузить WinDivert64.sys
        # в ядро и появиться в tasklist. Иначе badsum_injector в потоках прокси может попытаться
        # открыть второй WinDivert handle одновременно с winws — это вызывает BSOD.
        if self.config.discord_voice_udp:
            self.voice_helper.start()
            logger.info("[Main] VoiceHelper запущен")
            # Даём WinDivert64.sys полностью инициализироваться в ядре перед запуском прокси
            import time
            time.sleep(0.8)

        # 5. Запуск прокси сервера
        self.proxy_server.start()
        logger.info("[Main] DPIBypassProxy запущен на %s:%s", self.config.proxy_host, self.config.proxy_port)

        # 6. Автоматическая привязка системного прокси
        if self.config.auto_system_proxy:
            if self.proxy_mgr.enable():
                logger.info("[Main] SystemProxyManager: системный прокси включен на %s:%s", self.config.proxy_host, self.config.proxy_port)
                if not quiet:
                    print(f"\033[92m[+] Системный прокси Windows перенаправлен на {self.config.proxy_host}:{self.config.proxy_port}\033[0m")
                    if self.config.proxy_discord:
                        print("    \033[92m-> Discord: Flowery САМ обходит блокировку (автономный режим)\033[0m")
                    else:
                        print("    \033[94m-> Discord: Исключен из прокси (тандем с zapret)\033[0m")
                    if self.config.proxy_youtube:
                        print("    \033[92m-> YouTube: Flowery САМ обходит блокировку (автономный режим)\033[0m")
                    else:
                        print("    \033[94m-> YouTube: Исключен из прокси (тандем с zapret)\033[0m")
                    print("    (Браузеры Chrome, Edge, Яндекс и программы работают автоматически без ручной настройки)")
            elif not quiet:
                print("\033[91m[!] Не удалось установить системный прокси Windows.\033[0m")
                logger.warning("[Main] SystemProxyManager: не удалось включить системный прокси Windows")

        self.power_watchdog.start()
        self.profile_mgr.start_network_monitor(self.config, on_switch_callback=self._on_profile_switched)
        return True

    def stop_services(self) -> None:
        """Остановка служб Flowery и восстановление параметров системы."""
        self.cleanup(force=True)

    def run_all(self, background: bool = False) -> None:
        """Запуск полного комплекса Flowery с блокирующим ожиданием."""
        self.print_banner()
        self.start_services(quiet=False)
        self.tray_icon.start(hide_console=background)

        print("\n\033[1;92m" + "="*70 + "\033[0m")
        print(f"\033[1;92m[+] Flowery (Glue) успешно активен! Профиль: {self.active_profile_name}\033[0m")
        print(f"\033[90m    Сеть: {self.current_network_fp}\033[0m")
        print("\033[97m    Иконка в системном трее активна. Правый клик -> Скрыть/показать окно или выйти.\033[0m")
        print("\033[97m    Нажмите \033[93mCtrl+C\033[0m\033[97m для остановки и корректного восстановления настроек.\033[0m")
        print("\033[1;92m" + "="*70 + "\033[0m\n")

        # Ожидание прерывания пользователем
        try:
            while self._is_active:
                time.sleep(0.5)
        except KeyboardInterrupt:
            logger.debug("[Main] run_all прерван пользователем (KeyboardInterrupt)")
        finally:
            self.cleanup()


def main():
    if not isinstance(sys.stderr, StderrToLogger):
        sys.stderr = StderrToLogger(sys.stderr)
    sys.excepthook = global_exception_handler
    init_terminal()
    set_app_icon()

    app_base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if os.path.isdir(app_base):
        try:
            os.chdir(app_base)
        except Exception as e:
            logger.debug("[Main] os.chdir to app_base failed: %s", e)
    elif getattr(sys, "frozen", False):
        try:
            os.chdir(os.path.dirname(sys.executable))
        except Exception as e:
            logger.debug("[Main] os.chdir to executable dir failed: %s", e)

    parser = argparse.ArgumentParser(description="Flowery (Glue) — DPI bypass tool для мобильного тетеринга")
    parser.add_argument("--menu", action="store_true", help="Запустить интерактивное меню (по умолчанию без параметров)")
    parser.add_argument("--all", action="store_true", default=False, help="Запустить полный комплекс без меню")
    parser.add_argument("--tray", "--background", dest="background", action="store_true", help="Фоновый режим работы (свернуть в трей)")
    parser.add_argument("--profile", type=str, default=None, help="Выбрать профиль сети (tethering, home_wifi, strict_whitelist, clean_gaming)")
    parser.add_argument("--status", action="store_true", help="Показать текущий статус сетевых параметров")
    parser.add_argument("--test", action="store_true", help="Проверить доступность заблокированных сайтов")
    parser.add_argument("--detect", action="store_true", help="Автоматический анализ типа ограничений сети")
    parser.add_argument("--fix-ttl", action="store_true", help="Только зафиксировать TTL")
    parser.add_argument("--clean", "--reset", dest="clean", action="store_true", help="Сбросить все системные настройки Windows (прокси, firewall, TTL, DNS) без запуска")
    parser.add_argument("--strategy", type=str, default=None, help="Принудительно зафиксировать стратегию обхода (combo_tlsrec_tcpsplit, multi_split, tcp_split_sni_mid, boringssl_split и др.)")
    parser.add_argument("--no-auto-strategy", action="store_true", help="Отключить адаптивный автоподбор стратегий Thompson Sampling")
    parser.add_argument("--calibrate", choices=["quick", "fast", "full"], nargs="?", const="full", default=None, help="Калибровка и экспресс-обучение ML-модели на базе сайтов (quick: 10 сайтов, full: 110+ сайтов)")
    parser.add_argument("extra_args", nargs="*", help=argparse.SUPPRESS)
    args, _ = parser.parse_known_args()

    # СТРОГАЯ ПРОВЕРКА ПРАВ АДМИНИСТРАТОРА (для меню, служб и TTL; для сброса/статуса/тестов не требуется)
    if not (args.status or args.detect or args.test or args.calibrate or args.clean):
        check_admin_or_elevate(auto_elevate=True)

    # Одиночный экземпляр: авто-перезапуск старых копий без необходимости ручного вызова stop.bat
    if not (args.clean or args.status or args.test or args.detect or args.fix_ttl or args.calibrate):
        if not acquire_single_instance_mutex():
            print("\033[93m[*] Обнаружен ранее запущенный процесс Flowery. Автоматический перезапуск...\033[0m")
            if sys.platform == "win32":
                try:
                    cur_pid = os.getpid()
                    target_im = os.path.basename(sys.executable) if getattr(sys, "frozen", False) else "Flowery.exe"
                    creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                    subprocess.run(
                        ["taskkill", "/f", "/fi", f"PID ne {cur_pid}", "/im", target_im],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=creationflags, check=False
                    )
                    if target_im.lower() != "flowery.exe":
                        subprocess.run(
                            ["taskkill", "/f", "/fi", f"PID ne {cur_pid}", "/im", "Flowery.exe"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=creationflags, check=False
                        )
                    time.sleep(0.5)
                except Exception as e:
                    logger.debug("[Main] taskkill for stale Flowery.exe failed: %s", e)
            # Повторный захват мьютекса после авто-очистки
            acquire_single_instance_mutex()

    app = FloweryApp()

    if args.profile:
        if app.profile_mgr.apply_profile(args.profile, app.config):
            prof = app.profile_mgr.get_profile(args.profile)
            app.active_profile_name = prof.get("name", args.profile) if prof else args.profile
            app.tray_icon.update_tooltip(f"Flowery (Glue) — {app.active_profile_name}")
            print(f"\033[92m[+] Применен профиль сети: {app.active_profile_name}\033[0m")
        else:
            print(f"\033[91m[!] Профиль '{args.profile}' не найден. Доступные: {list(app.profile_mgr.get_all_profiles().keys())}\033[0m")

    if args.strategy:
        app.config.set_override("default_strategy", args.strategy)
        app.config.set_override("auto_strategy", False)
        app.proxy_server.strategy_engine.enabled = False
        print(f"\033[93m[*] Принудительно зафиксирована стратегия: {args.strategy}\033[0m")
    elif args.no_auto_strategy:
        app.config.set_override("auto_strategy", False)
        app.proxy_server.strategy_engine.enabled = False
        print("\033[93m[*] Адаптивный автоподбор стратегий отключён\033[0m")
    atexit.register(app.cleanup)

    # Стандартный обработчик KeyboardInterrupt для мягкой остановки по Ctrl+C
    signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        signal.signal(signal.SIGTERM, lambda s, f: (app.cleanup(force=True), sys.exit(0)))
    except Exception as e:
        logger.debug("[Main] Failed to set SIGTERM handler: %s", e)

    # Регистрация обработчика закрытия консоли крестиком в Windows
    if sys.platform == "win32":
        try:
            HandlerRoutine = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_ulong)
            def win_ctrl_handler(ctrl_type):
                app.cleanup(force=True)
                return True
            global _ctrl_handler_ref
            _ctrl_handler_ref = HandlerRoutine(win_ctrl_handler)
            ctypes.windll.kernel32.SetConsoleCtrlHandler(_ctrl_handler_ref, True)
        except Exception as e:
            logger.debug("[Main] Failed to register SetConsoleCtrlHandler: %s", e)

    if args.clean:
        app.print_banner()
        app.reset_system()
    elif args.calibrate:
        app.print_banner()
        cal_mode = "fast" if args.calibrate in ("quick", "fast") else "full"
        app.run_calibration(mode=cal_mode, interactive=False)
    elif args.status:
        app.run_status()
    elif args.detect:
        app.print_banner()
        app.detector.run_full_diagnosis()
        app.detector.print_report()
    elif args.test:
        app.print_banner()
        app.run_tests_tool()
    elif args.fix_ttl:
        app.print_banner()
        if is_admin():
            app.ttl_mgr.apply_ttl()
            print(f"[+] TTL установлен в {app.config.default_ttl}")
        else:
            print("[!] Требуются права Администратора!")
    elif args.all or args.background:
        app.run_all(background=args.background)
    else:
        # По умолчанию без аргументов или с флагом --menu открывается интерактивное меню
        app.run_menu()


if __name__ == "__main__":
    main()
