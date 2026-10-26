"""Модуль управления сетевыми профилями Flowery (Glue).
Позволяет использовать единые профили настроек (тетеринг, домашний Wi-Fi, белый список)
с автоматическим переключением при смене сети (мобильный хотспот / домашний роутер).
"""

import os
import sys
import json
import socket
import subprocess
import threading
import time
from typing import Dict, Any, Optional, Tuple, Callable
try:
    from Floweryguard.config import get_app_base_dir
    from Floweryguard.logger import get_logger
except ImportError:
    from flowguard.config import get_app_base_dir
    from flowguard.logger import get_logger

logger = get_logger("Profiles")


def _decode_netsh(raw: bytes) -> str:
    """Декодирует вывод системных утилит Windows с перебором кодировок."""
    if not raw:
        return ""
    try:
        return raw.decode("utf-8")
    except (UnicodeDecodeError, LookupError) as e:
        logger.debug(f"Вывод утилиты не является UTF-8 ({e}), перебор альтернативных кодировок")

    import locale
    candidates = []
    enc_list = ["cp866", "cp1251"]
    pref = locale.getpreferredencoding()
    if pref and pref.lower() not in ("cp866", "cp1251", "utf-8"):
        enc_list.append(pref)

    for enc in enc_list:
        try:
            txt = raw.decode(enc)
            ru_letters = sum(1 for c in txt if 'а' <= c.lower() <= 'я' or c.lower() == 'ё')
            bad_chars = sum(1 for c in txt if c in '─│┌┐└┘├┤┬┴┼═║╒╓╔╕╖╗╘╙╚╛╜╝╞╟╠╡╢╣╤╥╦╧╨╩╪╫╬█▄▌▐▀ЃҐЇў¤­ №')
            candidates.append((ru_letters - bad_chars * 2, enc, txt))
        except Exception as e:
            logger.debug(f"Ошибка декодирования профиля через {enc}: {e}")

    if candidates:
        candidates.sort(key=lambda x: x[0], reverse=True)
        return candidates[0][2]
    return raw.decode("latin1", errors="replace")


# Встроенные стандартные профили сети
BUILTIN_PROFILES: Dict[str, Dict[str, Any]] = {
    "tethering": {
        "id": "tethering",
        "name": "Мобильная раздача (Тетеринг)",
        "description": "TTL=65, RFC1323 timestamps, обход ограничений оператора и ТСПУ",
        "settings": {
            "fix_ttl": True,
            "default_ttl": 65,
            "enable_timestamps": True,
            "block_quic": True,
            "proxy_discord": True,
            "proxy_youtube": True,
            "discord_voice_udp": True,
            "packet_desync_fooling": "badsum",
            "packet_desync_split_seqovl": 16,
            "ipv6_mode": "disabled",
            "auto_strategy": True,
            "default_strategy": "combo_tlsrec_tcpsplit",
            "only_target_domains": False,
        }
    },
    "home_wifi": {
        "id": "home_wifi",
        "name": "Домашний интернет / Wi-Fi",
        "description": "TTL=65 маскировка тетеринга, обход блокировок Discord и YouTube",
        "settings": {
            "fix_ttl": True,
            "default_ttl": 65,
            "enable_timestamps": True,
            "block_quic": True,
            "proxy_discord": True,
            "proxy_youtube": True,
            "discord_voice_udp": True,
            "packet_desync_fooling": "badsum",
            "packet_desync_split_seqovl": 16,
            "ipv6_mode": "disabled",
            "auto_strategy": True,
            "default_strategy": "combo_tlsrec_tcpsplit",
            "only_target_domains": False,
        }
    },
    "strict_whitelist": {
        "id": "strict_whitelist",
        "name": "Белые списки (ЧС / Изоляция)",
        "description": "Обход активируется только для доверенных ресурсов из whitelist.txt, агрессивный сплит",
        "settings": {
            "fix_ttl": True,
            "default_ttl": 65,
            "enable_timestamps": True,
            "block_quic": True,
            "proxy_discord": True,
            "proxy_youtube": True,
            "discord_voice_udp": True,
            "packet_desync_fooling": "badsum",
            "packet_desync_split_seqovl": 16,
            "ipv6_mode": "disabled",
            "auto_strategy": True,
            "default_strategy": "combo_tlsrec_tcpsplit",
            "only_target_domains": True,
        }
    },
    "clean_gaming": {
        "id": "clean_gaming",
        "name": "Гейминг / Минимальный пинг",
        "description": "Минимальная фрагментация для снижения задержек в сетевых играх и войсах",
        "settings": {
            "fix_ttl": True,
            "default_ttl": 65,
            "enable_timestamps": True,
            "block_quic": True,
            "proxy_discord": True,
            "proxy_youtube": True,
            "discord_voice_udp": True,
            "auto_strategy": True,
            "default_strategy": "tcp_split_sni_mid",
            "only_target_domains": False,
        }
    }
}


def get_default_gateway_ip() -> Optional[str]:
    """Определяет IP-адрес основного шлюза по умолчанию в Windows."""
    try:
        creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        res = subprocess.run(
            ["netsh", "interface", "ipv4", "show", "addresses"],
            capture_output=True,
            creationflags=creationflags,
            timeout=2
        )
        out = _decode_netsh(res.stdout)
        current_iface = ""
        for line in out.splitlines():
            line_clean = line.strip()
            line_lower = line_clean.lower()
            if "интерфейса" in line_lower or "interface" in line_lower:
                current_iface = line_lower
            if "Основной шлюз" in line_clean or "Default Gateway" in line_clean:
                parts = line_clean.split(":")
                if len(parts) >= 2:
                    gw = parts[1].strip()
                    if gw and gw != "0.0.0.0" and "." in gw:
                        is_virtual = any(v in current_iface for v in (
                            "virtual", "vmware", "vbox", "hyper-v", "loopback", "wsl",
                            "radmin", "hamachi", "tap-", "tailscale", "zerotier", "wireguard", "vpn"
                        ))
                        if is_virtual:
                            logger.debug(f"Пропуск шлюза виртуального адаптера ({current_iface}): {gw}")
                            continue
                        logger.debug(f"Определен основной шлюз (netsh): {gw}")
                        return gw
    except Exception as e:
        logger.debug(f"Ошибка определения шлюза через netsh: {e}")

    # Фолбэк через маршрутную таблицу
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.split(".")
        if len(parts) == 4:
            gw = f"{parts[0]}.{parts[1]}.{parts[2]}.1"
            logger.debug(f"Определен основной шлюз (фолбэк сокет): {gw}")
            return gw
    except Exception as e:
        logger.debug(f"Ошибка определения шлюза через сокет: {e}")
    return None


def get_wifi_ssid() -> Optional[str]:
    """Возвращает имя текущей Wi-Fi сети (SSID), если компьютер подключен по Wi-Fi."""
    try:
        creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        res = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            creationflags=creationflags,
            timeout=2
        )
        out = _decode_netsh(res.stdout)
        for line in out.splitlines():
            line_clean = line.strip()
            if line_clean.startswith("SSID") and "BSSID" not in line_clean:
                parts = line_clean.split(":", 1)
                if len(parts) >= 2:
                    ssid = parts[1].strip()
                    if ssid:
                        logger.debug(f"Обнаружен Wi-Fi SSID: {ssid}")
                        return ssid
    except Exception as e:
        logger.debug(f"Ошибка получения Wi-Fi SSID: {e}")
    return None


def get_network_fingerprint() -> str:
    """Формирует уникальный идентификатор текущей сети (SSID или подсеть шлюза)."""
    ssid = get_wifi_ssid()
    if ssid:
        return f"wifi:{ssid}"
    gw = get_default_gateway_ip()
    if gw:
        parts = gw.split(".")
        if len(parts) == 4:
            return f"gw:{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return f"gw:{gw}"
    return "default_network"


def guess_profile_for_network(fingerprint: str) -> str:
    """Автоматически подбирает наилучший профиль под текущую сеть."""
    fp_lower = fingerprint.lower()
    
    # 1. Признаки мобильной раздачи (Android hotspot 192.168.43.x, iPhone 172.20.10.x, USB tethering)
    if "192.168.43." in fp_lower or "172.20.10." in fp_lower or "192.168.44." in fp_lower or "192.168.42." in fp_lower:
        logger.debug(f"guess_profile_for_network({fingerprint}) -> tethering (по IP подсети)")
        return "tethering"
    
    # Имя сети похоже на телефон
    tether_keywords = ["phone", "iphone", "galaxy", "redmi", "xiaomi", "pixel", "honor", "huawei", "hotspot", "раздач", "tether"]
    if any(k in fp_lower for k in tether_keywords):
        logger.debug(f"guess_profile_for_network({fingerprint}) -> tethering (по ключевым словам)")
        return "tethering"

    # 2. По умолчанию для сетей — профиль домашнего интернета / Wi-Fi
    logger.debug(f"guess_profile_for_network({fingerprint}) -> home_wifi (дефолт)")
    return "home_wifi"


class ProfileManager:
    """Менеджер профилей конфигурации сети Flowery."""

    def __init__(self, profiles_file: Optional[str] = None):
        base_dir = get_app_base_dir()
        self.profiles_file = profiles_file or os.path.join(base_dir, "network_profiles.json")
        self._lock = threading.Lock()
        self.custom_profiles: Dict[str, Dict[str, Any]] = {}
        self.network_map: Dict[str, str] = {}
        self.active_profile_id = "home_wifi"
        self._monitor_running = False
        self._last_fingerprint = ""
        self._load()

    def _load(self) -> None:
        """Загружает сохраненные профили и привязки сетей."""
        if not os.path.exists(self.profiles_file):
            logger.debug(f"Файл профилей {self.profiles_file} не найден, используются встроенные")
            return
        try:
            with open(self.profiles_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                self.custom_profiles = data.get("custom_profiles", {})
                self.network_map = data.get("network_map", {})
                self.active_profile_id = data.get("last_active_profile", "home_wifi")
                logger.info(f"Профили сети загружены из {self.profiles_file}: активный={self.active_profile_id}")
        except Exception as e:
            logger.warning(f"Ошибка загрузки profiles.json: {e}")

    def save(self) -> bool:
        """Сохраняет профили и привязки сетей в JSON."""
        data = {
            "last_active_profile": self.active_profile_id,
            "network_map": self.network_map,
            "custom_profiles": self.custom_profiles
        }
        try:
            with open(self.profiles_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.debug(f"Профили сохранены в {self.profiles_file}")
            return True
        except Exception as e:
            logger.error(f"Ошибка сохранения profiles.json: {e}")
            return False

    def get_all_profiles(self) -> Dict[str, Dict[str, Any]]:
        """Возвращает все доступные профили (встроенные + пользовательские)."""
        profiles = dict(BUILTIN_PROFILES)
        profiles.update(self.custom_profiles)
        return profiles

    def get_profile(self, profile_id: str) -> Optional[Dict[str, Any]]:
        """Возвращает данные профиля по его ID."""
        return self.get_all_profiles().get(profile_id)

    def apply_profile(self, profile_id: str, config: Any) -> bool:
        """Применяет профиль к текущей конфигурации приложения."""
        prof = self.get_profile(profile_id)
        if not prof:
            logger.warning(f"Попытка применить несуществующий профиль: {profile_id}")
            return False

        settings = prof.get("settings", {})
        config.apply_profile(settings, replace=True)

        with self._lock:
            self.active_profile_id = profile_id
        self.save()
        logger.info(f"Применен сетевой профиль: '{prof.get('name', profile_id)}' ({profile_id})")
        return True

    def auto_detect_and_apply(self, config: Any) -> Tuple[str, str]:
        """Определяет текущую сеть и активирует соответствующий профиль.
        
        Возвращает (имя_профиля, отпечаток_сети).
        """
        fp = get_network_fingerprint()
        with self._lock:
            self._last_fingerprint = fp
            # Проверяем пользовательскую привязку сети к профилю
            if fp in self.network_map:
                prof_id = self.network_map[fp]
            else:
                prof_id = guess_profile_for_network(fp)
                self.network_map[fp] = prof_id

        self.apply_profile(prof_id, config)
        prof = self.get_profile(prof_id)
        prof_name = prof.get("name", prof_id) if prof else prof_id
        logger.info(f"Авто-детект сети: fingerprint={fp} -> профиль='{prof_name}' ({prof_id})")
        return prof_name, fp

    def associate_current_network(self, profile_id: str) -> None:
        """Связывает текущую сеть с выбранным профилем."""
        fp = get_network_fingerprint()
        with self._lock:
            self.network_map[fp] = profile_id
        self.save()
        logger.info(f"Сеть {fp} привязана к профилю {profile_id}")

    def start_network_monitor(self, config: Any, on_switch_callback: Optional[Callable] = None) -> None:
        """Запускает фоновый монитор смены сети (переключение профилей на лету)."""
        if self._monitor_running:
            return
        self._monitor_running = True
        logger.info("Запущен фоновый монитор сети (NetworkProfileMonitor)")

        def _monitor_loop():
            while self._monitor_running:
                time.sleep(5.0)
                try:
                    curr_fp = get_network_fingerprint()
                    with self._lock:
                        last_fp = self._last_fingerprint
                    if curr_fp != last_fp and curr_fp != "default_network":
                        with self._lock:
                            self._last_fingerprint = curr_fp
                        new_prof_id = self.network_map.get(curr_fp) or guess_profile_for_network(curr_fp)
                        if new_prof_id != self.active_profile_id:
                            self.apply_profile(new_prof_id, config)
                            prof_obj = self.get_profile(new_prof_id)
                            prof_name = prof_obj.get("name", new_prof_id) if prof_obj else new_prof_id
                            logger.info(f"Смена сети: {curr_fp} -> Активирован профиль '{prof_name}'")
                            print(f"\n\033[96m[*] Смена сети: {curr_fp} -> Активирован профиль '{prof_name}'\033[0m")
                            if on_switch_callback:
                                try:
                                    on_switch_callback(new_prof_id, prof_name, curr_fp)
                                except Exception as e:
                                    logger.debug(f"Ошибка вызова on_switch_callback: {e}")
                except Exception as e:
                    logger.debug(f"Исключение в цикле NetworkProfileMonitor: {e}")

        t = threading.Thread(target=_monitor_loop, daemon=True, name="NetworkProfileMonitor")
        t.start()

    def stop_network_monitor(self) -> None:
        """Останавливает фоновый монитор сети."""
        self._monitor_running = False
        logger.debug("Фоновый монитор сети остановлен")
