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

# Включение поддержки ANSI цветов (VT100) и кодировки UTF-8 в Windows
def init_terminal():
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

        # Пустой системный вызов включает эмуляцию VT100 в cmd.exe
        try:
            os.system("")
        except Exception:
            pass

        # Прямой вызов Win32 API для гарантированного включения цветов
        try:
            import ctypes
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

init_terminal()

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from Floweryguard.config import Config
from Floweryguard.ttl_fix import TTLManager, is_admin
from Floweryguard.system_proxy import SystemProxyManager, build_proxy_override
from Floweryguard.quic_block import QUICBlocker
from Floweryguard.dns_config import DNSManager
from Floweryguard.proxy import DPIBypassProxy
from Floweryguard.tester import test_proxy_connection
from Floweryguard.detector import NetworkDetector
from Floweryguard.voice_helper import VoiceHelper

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
        print("\033[1;97m" + " "*indent + "FLOWERY (GLUE) v1.1 — DPI BYPASS FOR TETHERING" + "\033[0m")
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

        print("\n\033[93m[*] Завершение работы Flowery, восстановление системы...\033[0m")

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

    def run_all(self) -> None:
        """Запуск полного комплекса Flowery."""
        self._is_active = True
        self.print_banner()

        if not is_admin():
            print("\033[93m[!] ВНИМАНИЕ: Скрипт запущен без прав Администратора!\033[0m")
            print("    Для автоматической фиксации TTL и блокировки QUIC перезапустите start.bat от имени Администратора.\n")

        # 0. Авто-диагностика сети (Белый список vs Blacklist DPI vs Тетеринг)
        if self.config.whitelist_auto_detect:
            diag_results = self.detector.run_full_diagnosis()
            self.detector.print_report()
            overrides = diag_results.get("profile_overrides", {})
            if overrides:
                self.config.apply_profile(overrides)

        # 1. TTL Fix
        if self.config.fix_ttl:
            if is_admin():
                if self.ttl_mgr.apply_ttl():
                    print(f"\033[92m[+] TTL зафиксирован на {self.config.default_ttl} (обход ограничений тетеринга)\033[0m")
                else:
                    print("\033[91m[!] Не удалось установить TTL в реестре.\033[0m")
            else:
                print("\033[90m[-] Пропуск TTL fix (требуются права админа)\033[0m")

        # 2. QUIC Block
        if self.config.block_quic:
            if is_admin():
                if self.quic_blocker.block_quic():
                    print("\033[92m[+] Блокировка QUIC (UDP 443) активирована (принуждение YouTube к TCP)\033[0m")
            else:
                print("\033[90m[-] Пропуск блокировки QUIC (требуются права админа)\033[0m")
        else:
            if is_admin() and self.quic_blocker.is_rule_present():
                self.quic_blocker.unblock_quic()
                print("\033[92m[+] Блокировка QUIC снята (UDP 443 разблокирован для Discord Voice WebRTC)\033[0m")

        # 3. Безопасный DNS
        if self.config.enable_custom_dns and is_admin():
            if self.dns_mgr.set_secure_dns():
                print(f"\033[92m[+] Установлены DNS: {self.config.dns_primary}, {self.config.dns_secondary}\033[0m")

        # 4. Запуск прокси сервера
        self.proxy_server.start()

        # 5. Автоматическая привязка системного прокси
        if self.config.auto_system_proxy:
            if self.proxy_mgr.enable():
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
            else:
                print("\033[91m[!] Не удалось установить системный прокси Windows.\033[0m")

        # 6. Discord Voice UDP Helper (десинхронизация портов 50000-50100 для войсов)
        if self.config.discord_voice_udp:
            self.voice_helper.start()

        print("\n\033[1;92m" + "="*70 + "\033[0m")
        print("\033[1;92m[+] Flowery (Glue) успешно активен! (Обход блокировок + Discord Voice активны)\033[0m")
        print("\033[97m    Нажмите \033[93mCtrl+C\033[0m\033[97m для остановки и корректного восстановления настроек.\033[0m")
        print("\033[1;92m" + "="*70 + "\033[0m\n")

        # Ожидание прерывания пользователем
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.cleanup()


def main():
    if getattr(sys, "frozen", False):
        try:
            os.chdir(os.path.dirname(sys.executable))
        except Exception:
            pass
    parser = argparse.ArgumentParser(description="Flowery (Glue) — DPI bypass tool для мобильного тетеринга")
    parser.add_argument("--all", action="store_true", default=False, help="Запустить полный комплекс (по умолчанию)")
    parser.add_argument("--status", action="store_true", help="Показать текущий статус сетевых параметров")
    parser.add_argument("--test", action="store_true", help="Проверить доступность заблокированных сайтов")
    parser.add_argument("--detect", action="store_true", help="Автоматический анализ типа ограничений сети")
    parser.add_argument("--fix-ttl", action="store_true", help="Только зафиксировать TTL")
    parser.add_argument("--clean", "--reset", dest="clean", action="store_true", help="Сбросить все системные настройки Windows (прокси, firewall, TTL, DNS) без запуска")
    parser.add_argument("--strategy", type=str, default=None, help="Принудительно зафиксировать стратегию обхода (combo_tlsrec_tcpsplit, multi_split, tcp_split_sni_mid, boringssl_split и др.)")
    parser.add_argument("--no-auto-strategy", action="store_true", help="Отключить адаптивный автоподбор стратегий Thompson Sampling")
    args = parser.parse_args()

    app = FloweryApp()
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

    def sig_handler(signum, frame):
        app.cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

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
        import socket
        app.print_banner()
        proxy_already_running = False
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(0.5)
            test_sock.connect((app.config.proxy_host, app.config.proxy_port))
            test_sock.close()
            proxy_already_running = True
        except Exception:
            proxy_already_running = False

        if not proxy_already_running:
            print("[*] Запуск локального прокси Flowery для тестирования...")
            app.proxy_server.start()
            time.sleep(0.5)

        try:
            test_proxy_connection(app.config.proxy_host, app.config.proxy_port)
        finally:
            if not proxy_already_running:
                app.proxy_server.stop()
    elif args.fix_ttl:
        app.print_banner()
        if is_admin():
            app.ttl_mgr.apply_ttl()
            print(f"[+] TTL установлен в {app.config.default_ttl}")
        else:
            print("[!] Требуются права Администратора!")
    else:
        app.run_all()


if __name__ == "__main__":
    main()
