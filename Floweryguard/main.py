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
import threading

class StderrToLogger:
    """Перенаправляет поток stderr в файл логов сессии в Документах,
    полностью предотвращая появление технического мусора и предупреждений в терминальном меню.
    """
    def __init__(self, orig_stderr):
        self._orig = orig_stderr

    def write(self, message):
        msg = message.strip()
        if msg:
            try:
                from Floweryguard.logger import logger
                logger.debug(f"[stderr] {msg}")
            except Exception:
                pass

    def flush(self):
        pass


# Перенаправляем sys.stderr до вызова основных библиотек
sys.stderr = StderrToLogger(sys.stderr)


# Включение поддержки ANSI цветов (VT100) и кодировки UTF-8 в Windows
def init_terminal():
    """Инициализация консоли: UTF-8, ANSI VT100, подавление stderr в NUL."""
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

        # Перенаправляем системный дескриптор stderr (fd 2) в NUL,
        # чтобы ошибки C/C++ библиотек, Electron и сторонних процессов не просачивались в консоль
        try:
            devnull_fd = os.open("NUL", os.O_WRONLY)
            os.dup2(devnull_fd, 2)
            os.close(devnull_fd)
        except Exception:
            pass

        # Пустой системный вызов включает эмуляцию VT100 в cmd.exe
        try:
            os.system("")
        except Exception:
            pass

        # Прямой вызов Win32 API для гарантированного включения цветов
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
    except Exception:
        pass

init_terminal()
set_app_icon()

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from Floweryguard.config import Config
from Floweryguard.ttl_fix import TTLManager, is_admin, check_admin_or_elevate
from Floweryguard.system_proxy import SystemProxyManager, build_proxy_override
from Floweryguard.quic_block import QUICBlocker
from Floweryguard.dns_config import DNSManager
from Floweryguard.proxy import DPIBypassProxy
from Floweryguard.tester import test_proxy_connection
from Floweryguard.detector import NetworkDetector
from Floweryguard.voice_helper import VoiceHelper
from Floweryguard.profiles import ProfileManager
from Floweryguard.tray import FloweryTrayIcon
from Floweryguard.logger import logger, open_current_log_file, get_current_log_path

# Полноразмерный ASCII-арт цветка (для терминалов шириной >= 120 символов)
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

# Компактный ASCII-арт цветка (78 символов, идеально подходит для стандартных 80-колоночных окон без переносов)
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

# Flowey ASCII-арт из Undertale для интерактивного меню (52 символа в ширину)
FLOWEY_ART = [
    "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@",
    "@@@@@@@@@@@@@@@@@@%:::::::%@@@@@@@@@@@@@@@@@@@@@@@@@",
    "@@@@@@@@@@@@@@@@#--::::=##@@@@@@@@@@@@@@@@@@@@@@@@@@",
    "@@@@@@@@@@@@@@@@*::::::=@@@@@@@@@@@@@@@@@@@@@@@@@@@@",
    "@@@@@%%%%@@@@@%%+::::::=%%@@@@@@@@@@@@@@@@@@@@@@@@@@",
    "@@@@#::::+@@@@-:::::::::::%@@@@@@@@@@@@@@@@@@@@@@@@@",
    "@@+::::%@@@@@@-:::::::::::::*@@@@@@@@@@@@@@@@@@@@@@@",
    "@@+::::::+@%:::::::::::::::::::::%@@@@@@@@@@@@@@@@@@",
    "@@+::::::::::::::::::::::::::::::::::-@@@@@@@@@@@@@@",
    "@@+:::::::::::::::::::::::::::::::::::==%@@@@@@@@@@@",
    "@@+::::::::::::::::::::::::::::::::-==::+*#@@@@@@@@@",
    "@@+-::::::::::::::::::::::::::::::-*@%::::=%%@@@@@@@",
    "@@@@#::::::::::::::::::::::::::::%@@@%::::::-@@@@@@@",
    "@@@@#:::::::::::::::::::::::*@@@@-:+@%::::::-@@@@@@@",
    "@@@@@@@-:::::::::::::::=@@@@+::::%@+:::::::::::#@@@@",
    "@@@@@@@@@+::::::+@@@@@@*::::::-@@-:::::::::::::#@@@@",
    "@@@@@@@+=+******+======-::::=*#@@#******-::::**+=*@@",
    "@@@@%**+=#@@@@#*=:::::::::::=********#@@*=-:-@@=:=@@",
    "@@@@#::%@@@@@@=::::::::::::::::::::::-@@@@*:-@@=:=@@",
    "@@@@#::%@@@%::#@@@@@@=::::::::-@@@@@@%::#@*:-@@=:=@@",
    "@@@@#::%@+:-@@-::::::#@*::::*@#::::::-@@-:+@@@@=:=@@",
    "@@@@#::%@+::::::::::::::::::::::::::::::::+@@@@=:=@@",
    "@@@@@%%@@+::::*%%%%%%=::::::::-%%%%%%#::::+@@@@%%%@@",
    "@@#++++%@+::**%@#+++++*=::::=**++++#@%**-:+@%++++*@@",
    "@@+::::%@+:-@@##=::::#@*::::*@#::::=##@@-:+@%::::=@@",
    "@@+::::%@+:-@@-::::::#@*::::*@#::::::-@@-:+@%::::=@@",
    "@@+::::%@+:::::::::::::=@@-:::::::::::::::+@%::::=@@",
    "@@+::::%@+:::::::::::::=@@-:::::::::::::::+@%::::=@@",
    "@@@@#::%@+:::::::::::#@@@@-:::::::::::::::+@%::#@@@@",
    "@@@@@%%@@+:::::::::::#@#--::::::::::::::::+@@%%@@@@@",
    "@@@@@@@*++*+:::::::::=++*+::::::::::::::+*+++@@@@@@@",
    "@@@@@@@-:+@%:::::--::::=##:::::::---::::#@*:-@@@@@@@",
    "@@@@@@@-:+@%::::+@%::::::::::::::%@+::::#@*:-@@@@@@@",
    "@@@@@@@@@@@%::::+@@@@@@@@@@@@@@@@@@+::::#@@@@@@@@@@@",
    "@@@@@@@@@@@@@@-:::-@@=::::::::-@@-:::-@@@@@@@@@@@@@@",
    "@@@@@@@@@@@@@@-::::::#@@@@@@@@#::::::-@@@@@@@@@@@@@@",
    "@@@@@@@@@@@@@@%%+::::----------::::+%%@@@@@@@@@@@@@@",
    "@@@@@@@@@@@@@@@@#++::::-++++-::::++#@@@@@@@@@@@@@@@@",
    "@@@@@@@@@@@@@@@@@@%--::=%%%%=::--%@@@@@@@@@@@@@@@@@@",
    "@@@@@@@@@@@@@@@@@@@@@=::::::::-@@@@@@@@@@@@@@@@@@@@@",
    "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
]

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
        self.detector = NetworkDetector()
        self.voice_helper = VoiceHelper()
        self.tray_icon = FloweryTrayIcon(
            app_name="Flowery (Glue)",
            on_exit_callback=lambda: self.cleanup(force=True),
            get_profile_name_callback=lambda: self.active_profile_name
        )
        self._is_active = False
        self._cleanup_lock = threading.Lock()
        self._cleaned_up = False
        self._timer_period_active = False
        if sys.platform == "win32":
            try:
                ctypes.windll.winmm.timeBeginPeriod(1)
                self._timer_period_active = True
            except Exception:
                pass

        # Защита от сбоев: авто-очистка брошенного системного прокси
        if self.proxy_mgr.is_stale_proxy_present():
            print("\033[93m[!] Обнаружен системный прокси от аварийно завершенного сеанса.\033[0m")
            print("\033[93m[*] Выполняется автоматическая нормализация сетевых настроек Windows...\033[0m")
            self.proxy_mgr.force_cleanup()

    def _on_profile_switched(self, prof_id: str, prof_name: str, network_fp: str) -> None:
        """Динамическое переключение профиля при смене сети на лету."""
        self.active_profile_name = prof_name
        self.current_network_fp = network_fp
        self.tray_icon.update_tooltip(f"Flowery (Glue) — {prof_name}")
        logger.info(f"Динамическая смена сети ({network_fp}) -> применён профиль '{prof_name}'")
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
            self.dns_mgr.restore_dns()
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
        except Exception:
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
            pass

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

        c_on = "\033[92m[enabled]\033[0m"
        c_off = "\033[90m[disabled]\033[0m"

        ttl_tag = c_on if self.config.fix_ttl else c_off
        quic_tag = c_on if self.config.block_quic else c_off
        discord_tag = c_on if self.config.proxy_discord else c_off
        voice_tag = c_on if self.config.discord_voice_udp else c_off
        youtube_tag = c_on if self.config.proxy_youtube else c_off
        auto_strat_tag = c_on if self.config.auto_strategy else c_off

        status_line = "\033[92m● STATUS: ACTIVE (Bypass is ON)\033[0m" if self._is_active else "\033[91m○ STATUS: STOPPED\033[0m"
        svc_toggle = "Stop Flowery Service" if self._is_active else "Start Flowery Service"

        sep = "\033[90m" + "-" * 50 + "\033[0m"

        right_lines = [
            "\033[1;97mFLOWERY SERVICE MANAGER v1.2.0 (GLUE)\033[0m",
            f"   {status_line}",
            f"   \033[90mProfile:\033[0m \033[96m{self.active_profile_name}\033[0m",
            sep,
            "",
            "\033[1;96m:: SERVICE & PROFILES\033[0m",
            f"   \033[93m1.\033[0m \033[97m{svc_toggle}\033[0m",
            "   \033[93m2.\033[0m \033[97mSwitch Network Profile\033[0m",
            "   \033[93m3.\033[0m \033[97mMinimize to Tray (Background)\033[0m",
            "   \033[93m4.\033[0m \033[97mCheck Status Details\033[0m",
            "   \033[93m5.\033[0m \033[97mReset System Settings\033[0m",
            "",
            "\033[1;96m:: SETTINGS\033[0m",
            f"   \033[93m6.\033[0m \033[97mTethering TTL Fix      \033[0m {ttl_tag}",
            f"   \033[93m7.\033[0m \033[97mQUIC Block (UDP 443)   \033[0m {quic_tag}",
            f"   \033[93m8.\033[0m \033[97mDiscord Bypass         \033[0m {discord_tag}",
            f"   \033[93m9.\033[0m \033[97mDiscord Voice UDP      \033[0m {voice_tag}",
            f"   \033[93m10.\033[0m \033[97mYouTube Bypass         \033[0m {youtube_tag}",
            f"   \033[93m11.\033[0m \033[97mAuto-Strategy (ML)     \033[0m {auto_strat_tag}",
            "",
            "\033[1;96m:: TOOLS\033[0m",
            "   \033[93m12.\033[0m \033[97mRun Diagnostics\033[0m",
            "   \033[93m13.\033[0m \033[97mRun Tests\033[0m",
            "   \033[93m14.\033[0m \033[97mOpen Session Log File\033[0m",
            "",
            sep,
            "   \033[93m0.\033[0m \033[97mExit (restore system)\033[0m",
            "",
        ]

        if cols >= 105:
            # Двухколоночный режим: слева Flowey арт, справа меню
            for i in range(len(FLOWEY_ART)):
                line = FLOWEY_ART[i]
                if i < 17:
                    c_flowey = "\033[93m" + line + "\033[0m"
                elif i < 34:
                    c_flowey = "\033[97m" + line + "\033[0m"
                else:
                    c_flowey = "\033[92m" + line + "\033[0m"
                r = right_lines[i] if i < len(right_lines) else ""
                print(f"  {c_flowey}    {r}")
        else:
            # Одноколоночный режим для узких терминалов
            for i in range(len(FLOWEY_ART)):
                line = FLOWEY_ART[i]
                if i < 17:
                    c_flowey = "\033[93m" + line + "\033[0m"
                elif i < 34:
                    c_flowey = "\033[97m" + line + "\033[0m"
                else:
                    c_flowey = "\033[92m" + line + "\033[0m"
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
            try:
                choice = input("\033[1;93mSelect option (0-14):\033[0m ").strip()
            except (KeyboardInterrupt, EOFError):
                print()
                self.cleanup(force=True)
                break

            if choice == "":
                # Очистка и перерисовка экрана по нажатию Enter без ошибки
                continue

            if choice == "0":
                if sys.platform == "win32":
                    os.system("cls")
                print("\033[92m[*] Завершение работы Flowery Service Manager.\033[0m")
                self.cleanup(force=True)
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
                    pass
            elif choice == "5":
                if sys.platform == "win32":
                    os.system("cls")
                self.reset_system()
                try:
                    input("\n\033[97mНажмите Enter для возврата в главное меню...\033[0m")
                except (KeyboardInterrupt, EOFError):
                    pass
            elif choice == "6":
                new_val = not self.config.fix_ttl
                self.config.set_override("fix_ttl", new_val)
                if is_admin():
                    if new_val:
                        self.ttl_mgr.apply_ttl()
                    else:
                        self.ttl_mgr.restore_ttl()
            elif choice == "7":
                new_val = not self.config.block_quic
                self.config.set_override("block_quic", new_val)
                if is_admin():
                    if new_val:
                        self.quic_blocker.block_quic()
                    else:
                        self.quic_blocker.unblock_quic()
            elif choice == "8":
                new_val = not self.config.proxy_discord
                self.config.set_override("proxy_discord", new_val)
                self.proxy_mgr.proxy_override = build_proxy_override(
                    proxy_discord=self.config.proxy_discord,
                    proxy_youtube=self.config.proxy_youtube
                )
                if self._is_active and self.config.auto_system_proxy:
                    self.proxy_mgr.enable()
            elif choice == "9":
                new_val = not self.config.discord_voice_udp
                self.config.set_override("discord_voice_udp", new_val)
                if new_val:
                    self.voice_helper.start()
                else:
                    self.voice_helper.stop()
            elif choice == "10":
                new_val = not self.config.proxy_youtube
                self.config.set_override("proxy_youtube", new_val)
                self.proxy_mgr.proxy_override = build_proxy_override(
                    proxy_discord=self.config.proxy_discord,
                    proxy_youtube=self.config.proxy_youtube
                )
                if self._is_active and self.config.auto_system_proxy:
                    self.proxy_mgr.enable()
            elif choice == "11":
                new_val = not self.config.auto_strategy
                self.config.set_override("auto_strategy", new_val)
                self.proxy_server.strategy_engine.enabled = new_val
            elif choice == "12":
                if sys.platform == "win32":
                    os.system("cls")
                print("\033[96m[*] Запуск комплексной диагностики сети...\033[0m\n")
                self.detector.run_full_diagnosis()
                self.detector.print_report()
                try:
                    input("\n\033[97mНажмите Enter для возврата в главное меню...\033[0m")
                except (KeyboardInterrupt, EOFError):
                    pass
            elif choice == "13":
                if sys.platform == "win32":
                    os.system("cls")
                self.run_tests_tool()
                try:
                    input("\n\033[97mНажмите Enter для возврата в главное меню...\033[0m")
                except (KeyboardInterrupt, EOFError):
                    pass
            elif choice == "14":
                log_p = get_current_log_path()
                print(f"\033[96m[*] Открытие файла логов сессии:\033[0m {log_p}")
                open_current_log_file()
                time.sleep(1.2)
            else:
                print("\033[91mНеверный выбор. Введите число от 0 до 14.\033[0m")
                time.sleep(1.0)

    def print_banner(self) -> None:
        """Отображает цветной стартовый баннер с автоматической подгонкой под ширину экрана."""
        try:
            cols = shutil.get_terminal_size((120, 50)).columns
        except Exception:
            cols = 120

        # Выбираем арт под ширину окна, чтобы исключить паразитные переносы строк
        flower = FLOWER_FULL if cols >= 120 else FLOWER_COMPACT

        # Цветок в фиолетово-пурпурном цвете
        print("\033[95m" + flower.strip("\n") + "\033[0m")
        # Логотип GLUE в неоновом бирюзовом цвете
        print("\033[96m" + GLUE_ASCII.strip("\n") + "\033[0m")

        indent = max(0, (min(cols, 80) - 47) // 2)
        print("\033[1;97m" + " "*indent + "FLOWERY (GLUE) v1.2.0 — DPI BYPASS FOR TETHERING" + "\033[0m")
        print("\033[90m" + " "*indent + "Работает в связке с Flowseal zapret (WinDivert)" + "\033[0m\n")

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
        print()

    def cleanup(self, force: bool = False) -> None:
        """Гарантированное восстановление всех системных параметров."""
        with self._cleanup_lock:
            if self._cleaned_up:
                return
            if not force and not self._is_active:
                return
            self._cleaned_up = True
            self._is_active = False

        print("\n\033[93m[*] Завершение работы Flowery, восстановление системы...\033[0m")

        # 0. Остановка системного трея и монитора сети
        try:
            self.tray_icon.stop()
        except Exception:
            pass
        try:
            self.profile_mgr.stop_network_monitor()
        except Exception:
            pass

        # 1. Отключаем прокси сервер
        try:
            self.proxy_server.stop()
        except Exception:
            pass

        # 1.5. Останавливаем Discord Voice UDP Helper
        try:
            self.voice_helper.stop()
        except Exception:
            pass

        # 2. Восстанавливаем системный прокси
        if self.config.auto_system_proxy:
            print("  [*] Отключение системного прокси Windows...")
            self.proxy_mgr.disable(force=True)

        # 3. Удаляем правило блокировки QUIC
        if is_admin() and (self.config.block_quic or self.quic_blocker._blocked or self.quic_blocker.is_rule_present()):
            print("  [*] Удаление правила QUIC в Windows Firewall...")
            self.quic_blocker.unblock_quic()

        # 4. Восстанавливаем TTL
        if is_admin() and (self.config.fix_ttl or self.ttl_mgr._applied):
            print("  [*] Восстановление DefaultTTL в реестре...")
            self.ttl_mgr.restore_ttl()

        # 5. Восстанавливаем DNS (если меняли)
        if self.config.enable_custom_dns:
            self.dns_mgr.restore_dns()

        # 6. Восстанавливаем разрешение таймера Windows
        if sys.platform == "win32" and self._timer_period_active:
            try:
                ctypes.windll.winmm.timeEndPeriod(1)
                self._timer_period_active = False
            except Exception:
                pass

        print("\033[92m[+] Все параметры системы успешно возвращены в исходное состояние.\033[0m")

    def start_services(self, quiet: bool = False) -> bool:
        """Запуск полного комплекса Flowery служб без блокировки потока."""
        with self._cleanup_lock:
            if self._is_active:
                return True
            self._is_active = True
            self._cleaned_up = False

        if not quiet and not is_admin():
            print("\033[93m[!] ВНИМАНИЕ: Скрипт запущен без прав Администратора!\033[0m")
            print("    Для автоматической фиксации TTL и блокировки QUIC перезапустите start.bat от имени Администратора.\n")

        # 0. Монитор смены сети для динамических профилей
        self.profile_mgr.start_network_monitor(self.config, on_switch_callback=self._on_profile_switched)

        # 0.5 Авто-диагностика сети (Белый список vs Blacklist DPI vs Тетеринг)
        if self.config.whitelist_auto_detect:
            diag_results = self.detector.run_full_diagnosis()
            if not quiet:
                self.detector.print_report()
            overrides = diag_results.get("profile_overrides", {})
            if overrides:
                self.config.apply_profile(overrides)

        # 1. TTL Fix
        if self.config.fix_ttl:
            if is_admin():
                if self.ttl_mgr.apply_ttl() and not quiet:
                    print(f"\033[92m[+] TTL зафиксирован на {self.config.default_ttl} (обход ограничений тетеринга)\033[0m")
                elif not quiet:
                    print("\033[91m[!] Не удалось установить TTL в реестре.\033[0m")
            elif not quiet:
                print("\033[90m[-] Пропуск TTL fix (требуются права админа)\033[0m")

        # 2. QUIC Block
        if self.config.block_quic:
            if is_admin():
                if self.quic_blocker.block_quic() and not quiet:
                    print("\033[92m[+] Блокировка QUIC (UDP 443) активирована (принуждение браузеров к TCP)\033[0m")
            elif not quiet:
                print("\033[90m[-] Пропуск блокировки QUIC (требуются права админа)\033[0m")
        else:
            if is_admin() and self.quic_blocker.is_rule_present():
                self.quic_blocker.unblock_quic()
                if not quiet:
                    print("\033[92m[+] Блокировка QUIC снята (UDP 443 разблокирован)\033[0m")

        # 3. Безопасный DNS
        if self.config.enable_custom_dns and is_admin():
            if self.dns_mgr.set_secure_dns() and not quiet:
                print(f"\033[92m[+] Установлены DNS: {self.config.dns_primary}, {self.config.dns_secondary}\033[0m")

        # 4. Запуск прокси сервера
        self.proxy_server.start()

        # 5. Автоматическая привязка системного прокси
        if self.config.auto_system_proxy:
            if self.proxy_mgr.enable():
                if not quiet:
                    print(f"\033[92m[+] Системный прокси Windows перенаправлен на {self.config.proxy_host}:{self.config.proxy_port}\033[0m")
                    if self.config.proxy_discord:
                        print("    \033[92m-> Discord: Flowery САМ обходит блокировку (TLS Record Frag + Happy Eyeballs)\033[0m")
                    else:
                        print("    \033[94m-> Discord: Исключен из прокси (обрабатывается Flowseal zapret)\033[0m")
                    if self.config.proxy_youtube:
                        print("    \033[92m-> YouTube: Проксируется через Flowery\033[0m")
                    else:
                        print("    \033[94m-> YouTube: Исключен из прокси (обрабатывается Flowseal zapret)\033[0m")
                    print("    (Браузеры Chrome, Edge, Яндекс и программы работают автоматически без ручной настройки)")
            elif not quiet:
                print("\033[91m[!] Не удалось установить системный прокси Windows.\033[0m")

        # 6. Discord Voice UDP Helper (десинхронизация портов 50000-50100 для войсов)
        if self.config.discord_voice_udp:
            self.voice_helper.start()

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
            pass
        finally:
            self.cleanup()


def main():
    init_terminal()
    set_app_icon()

    if getattr(sys, "frozen", False):
        try:
            os.chdir(os.path.dirname(sys.executable))
        except Exception:
            pass

    # СТРОГАЯ ПРОВЕРКА ПРАВ АДМИНИСТРАТОРА
    # Программа гарантированно не откроется без прав администратора!
    check_admin_or_elevate(auto_elevate=True)

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
    parser.add_argument("extra_args", nargs="*", help=argparse.SUPPRESS)
    args, _ = parser.parse_known_args()

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
    except Exception:
        pass

    # Регистрация обработчика закрытия консоли крестиком в Windows
    if sys.platform == "win32":
        try:
            HandlerRoutine = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_ulong)
            def win_ctrl_handler(ctrl_type):
                app.cleanup(force=True)
                return False
            global _ctrl_handler_ref
            _ctrl_handler_ref = HandlerRoutine(win_ctrl_handler)
            ctypes.windll.kernel32.SetConsoleCtrlHandler(_ctrl_handler_ref, True)
        except Exception:
            pass

    if args.clean:
        app.print_banner()
        app.reset_system()
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
