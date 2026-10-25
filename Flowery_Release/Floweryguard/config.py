"""Модуль конфигурации Flowery (Glue).
Чтение и валидация настроек из config.ini с поддержкой динамических переопределений авто-детектором.
"""

import os
import sys
import fnmatch
import configparser
from typing import Dict, Any, Tuple, Optional

try:
    from Floweryguard.logger import get_logger
except ImportError:
    from flowguard.logger import get_logger

logger = get_logger("Config")


def get_app_base_dir() -> str:
    """Get application base directory (safe for frozen .exe and .py)."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


DEFAULT_CONFIG: Dict[str, Dict[str, Any]] = {
    "proxy": {
        "host": "127.0.0.1",
        "port": 8118,
        "auto_system_proxy": True,
        "proxy_discord": True,
        "discord_voice_udp": True,
        "proxy_youtube": True,
        "timeout": 15,
        "buffer_size": 262144,
        "ipv6_mode": "disabled",
        "early_connect": True,
    },
    "bypass": {
        "tcp_split": True,
        "tls_record_frag": True,
        "oob_data": False,
        "http_host_obfuscation": True,
        "strip_ech": False,
        "tls_padding": False,
    },
    "fragmentation": {
        "fragment_size": 3,
        "fragment_delay": 0.001,  # 1 мс — гарантирует физическое разделение сегментов на мобильных сетях (Nagle/GSO)
        "tlsrec_split_at_sni": True,
    },
    "tethering": {
        "fix_ttl": True,
        "default_ttl": 65,
        "enable_timestamps": True,
        "mask_user_agent": True,
        "ncsi_spoof": True,
        "clamp_mss": True,
        "target_mtu": 1420,
    },
    "quic": {
        "block_quic": True,
    },
    "dns": {
        "server": "Quad9",
        "primary": "9.9.9.9",
        "secondary": "149.112.112.112",
        "enable_custom_dns": False,
        "doh_url": "https://dns.quad9.net/dns-query",
        "doh_name": "Quad9",
    },
    "whitelist_bypass": {
        "auto_detect": False,
        "spoof_sni": False,
        "whitelisted_sni": "gosuslugi.ru",
        "fake_sni_record": False,
    },
    "mode": {
        "kind": "proxy",
    },
    "targets": {
        "whitelist_file": "whitelist.txt",
        "only_target_domains": False,
        "use_hosts_file": False,
    },
    "strategy": {
        "auto_strategy": True,
        "default_strategy": "combo_tlsrec_tcpsplit",
    },
    "desync": {
        "enabled": True,
        "fooling": "badsum",
        "autottl": True,
        "autottl_delta": 2,
        "ttl": 8,
        "repeats": 6,
        "tcp_fake_desync": False,
        "fake_tls_file": "tls_clienthello_www_google_com.bin",
        "split_seqovl": 0,
    },
    "support": {
        "report_transport": "gateway",
        "report_gateway_url": "",
        "telegram_bot_token": "",
        "telegram_chat_id": "",
        "discord_webhook_url": "",
    },
}


class Config:
    """Класс управления конфигурацией приложения."""

    def __init__(self, config_path: str = "config.ini"):
        self.config_path = config_path
        self._parser = configparser.ConfigParser()
        self._overrides: Dict[str, Any] = {}
        self.load()

    def load(self) -> None:
        """Загружает настройки из файла config.ini, при отсутствии создаёт дефолтные."""
        search_paths = [
            self.config_path,
            os.path.join(os.getcwd(), self.config_path),
            os.path.join(get_app_base_dir(), self.config_path),
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), self.config_path),
        ]
        actual_path = None
        for p in search_paths:
            if p and os.path.exists(p) and os.path.isfile(p):
                actual_path = p
                break
        if actual_path:
            meipass = getattr(sys, "_MEIPASS", "")
            if getattr(sys, "frozen", False) and meipass and actual_path.startswith(meipass):
                self.config_path = os.path.join(get_app_base_dir(), os.path.basename(self.config_path))
            else:
                self.config_path = actual_path
            try:
                self._parser.read(actual_path, encoding="utf-8")
                logger.info(f"Конфигурация загружена: {actual_path}")
            except Exception as e:
                logger.warning(f"Ошибка чтения config.ini ({e}), используются стандартные параметры.")
                print(f"[!] Ошибка чтения config.ini ({e}), используются стандартные параметры.")
        else:
            logger.info("Файл config.ini не найден, используются параметры по умолчанию.")

    def set_override(self, key: str, value: Any) -> None:
        """Устанавливает динамическое переопределение параметра во время работы."""
        self._overrides[key] = value

    def set_value(self, section: str, key: str, value: Any) -> None:
        """Устанавливает значение параметра в конфиге и обновляет кэш."""
        if not self._parser.has_section(section):
            self._parser.add_section(section)
        str_val = str(value).lower() if isinstance(value, bool) else str(value)
        self._parser.set(section, key, str_val)
        self._overrides[key] = value

    def save(self, filepath: Optional[str] = None) -> bool:
        """Сохраняет текущую конфигурацию в файл config.ini."""
        target_path = filepath or self.config_path
        if not target_path:
            return False
        if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
            meipass = getattr(sys, "_MEIPASS", "")
            if meipass and target_path and target_path.startswith(meipass):
                target_path = os.path.join(get_app_base_dir(), "config.ini")
        try:
            with open(target_path, "w", encoding="utf-8") as f:
                self._parser.write(f)
            logger.info(f"Конфигурация сохранена: {target_path}")
            return True
        except Exception as e:
            logger.error(f"Ошибка сохранения config.ini ({target_path}): {e}")
            print(f"[!] Ошибка сохранения config.ini ({target_path}): {e}")
            return False

    def apply_profile(self, profile: Dict[str, Any]) -> None:
        """Применяет профиль настроек, сформированный авто-детектором сети."""
        for k, v in profile.items():
            self._overrides[k] = v

    def get_str(self, section: str, key: str) -> str:
        if key in self._overrides:
            return str(self._overrides[key])
        fallback = str(DEFAULT_CONFIG.get(section, {}).get(key, ""))
        try:
            return self._parser.get(section, key, fallback=fallback)
        except Exception as e:
            logger.debug(f"Ошибка get_str([{section}] {key}): {e}")
            return fallback

    def get_int(self, section: str, key: str) -> int:
        if key in self._overrides:
            try:
                return int(self._overrides[key])
            except (ValueError, TypeError) as e:
                logger.debug(f"Ошибка парсинга override get_int({key}): {e}")
        fallback = int(DEFAULT_CONFIG.get(section, {}).get(key, 0))
        try:
            return self._parser.getint(section, key, fallback=fallback)
        except Exception as e:
            logger.debug(f"Ошибка get_int([{section}] {key}): {e}")
            return fallback

    def get_float(self, section: str, key: str) -> float:
        if key in self._overrides:
            try:
                return float(self._overrides[key])
            except (ValueError, TypeError) as e:
                logger.debug(f"Ошибка парсинга override get_float({key}): {e}")
        fallback = float(DEFAULT_CONFIG.get(section, {}).get(key, 0.0))
        try:
            return self._parser.getfloat(section, key, fallback=fallback)
        except Exception as e:
            logger.debug(f"Ошибка get_float([{section}] {key}): {e}")
            return fallback

    def get_bool(self, section: str, key: str) -> bool:
        if key in self._overrides:
            return bool(self._overrides[key])
        fallback = bool(DEFAULT_CONFIG.get(section, {}).get(key, False))
        try:
            return self._parser.getboolean(section, key, fallback=fallback)
        except Exception as e:
            logger.debug(f"Ошибка get_bool([{section}] {key}): {e}")
            return fallback

    @property
    def proxy_host(self) -> str:
        return self.get_str("proxy", "host")

    @property
    def proxy_port(self) -> int:
        return self.get_int("proxy", "port")

    @property
    def auto_system_proxy(self) -> bool:
        return self.get_bool("proxy", "auto_system_proxy")

    @property
    def proxy_discord(self) -> bool:
        return self.get_bool("proxy", "proxy_discord")

    @property
    def discord_voice_udp(self) -> bool:
        return self.get_bool("proxy", "discord_voice_udp")

    @property
    def proxy_youtube(self) -> bool:
        return self.get_bool("proxy", "proxy_youtube")

    @property
    def buffer_size(self) -> int:
        return self.get_int("proxy", "buffer_size")

    @property
    def timeout(self) -> int:
        return self.get_int("proxy", "timeout")

    @property
    def ipv6_mode(self) -> str:
        return self.get_str("proxy", "ipv6_mode")

    @property
    def early_connect(self) -> bool:
        return self.get_bool("proxy", "early_connect")

    @property
    def tcp_split(self) -> bool:
        return self.get_bool("bypass", "tcp_split")

    @property
    def tls_record_frag(self) -> bool:
        return self.get_bool("bypass", "tls_record_frag")

    @property
    def oob_data(self) -> bool:
        return self.get_bool("bypass", "oob_data")

    @property
    def http_host_obfuscation(self) -> bool:
        return self.get_bool("bypass", "http_host_obfuscation")

    @property
    def strip_ech(self) -> bool:
        return self.get_bool("bypass", "strip_ech")

    @property
    def tls_padding(self) -> bool:
        return self.get_bool("bypass", "tls_padding")

    @property
    def fragment_size(self) -> int:
        return self.get_int("fragmentation", "fragment_size")

    @property
    def fragment_delay(self) -> float:
        return self.get_float("fragmentation", "fragment_delay")

    @property
    def tlsrec_split_at_sni(self) -> bool:
        return self.get_bool("fragmentation", "tlsrec_split_at_sni")

    @property
    def fix_ttl(self) -> bool:
        return self.get_bool("tethering", "fix_ttl")

    @property
    def default_ttl(self) -> int:
        return self.get_int("tethering", "default_ttl")

    @property
    def enable_timestamps(self) -> bool:
        return self.get_bool("tethering", "enable_timestamps")

    @property
    def mask_user_agent(self) -> bool:
        return self.get_bool("tethering", "mask_user_agent")

    @property
    def clamp_mss(self) -> bool:
        return self.get_bool("tethering", "clamp_mss")

    @property
    def target_mtu(self) -> int:
        return self.get_int("tethering", "target_mtu")

    @property
    def ncsi_spoof(self) -> bool:
        return self.get_bool("tethering", "ncsi_spoof")

    @property
    def block_quic(self) -> bool:
        return self.get_bool("quic", "block_quic")

    @property
    def dns_primary(self) -> str:
        return self.get_str("dns", "primary")

    @property
    def dns_secondary(self) -> str:
        return self.get_str("dns", "secondary")

    @property
    def enable_custom_dns(self) -> bool:
        return self.get_bool("dns", "enable_custom_dns")

    @property
    def dns_doh_url(self) -> str:
        return self.get_str("dns", "doh_url")

    @property
    def dns_server(self) -> str:
        return self.get_str("dns", "server")

    @property
    def server(self) -> str:
        return self.dns_server

    @property
    def dns_doh_name(self) -> str:
        return self.get_str("dns", "doh_name")

    @property
    def whitelist_auto_detect(self) -> bool:
        return self.get_bool("whitelist_bypass", "auto_detect")

    @property
    def whitelist_spoof_sni(self) -> bool:
        return self.get_bool("whitelist_bypass", "spoof_sni")

    @property
    def whitelist_whitelisted_sni(self) -> str:
        return self.get_str("whitelist_bypass", "whitelisted_sni")

    @property
    def whitelist_fake_sni_record(self) -> bool:
        return self.get_bool("whitelist_bypass", "fake_sni_record")

    @property
    def whitelist_file(self) -> str:
        return self.get_str("targets", "whitelist_file")

    @property
    def only_target_domains(self) -> bool:
        return self.get_bool("targets", "only_target_domains")

    @property
    def use_hosts_file(self) -> bool:
        return self.get_bool("targets", "use_hosts_file")

    @property
    def mode_kind(self) -> str:
        kind = self.get_str("mode", "kind").lower().strip()
        if kind in ("packet", "hybrid"):
            return kind
        return "proxy"

    @property
    def auto_strategy(self) -> bool:
        return self.get_bool("strategy", "auto_strategy")

    @property
    def default_strategy(self) -> str:
        return self.get_str("strategy", "default_strategy")

    @property
    def report_transport(self) -> str:
        return self.get_str("support", "report_transport")

    @property
    def report_gateway_url(self) -> str:
        return self.get_str("support", "report_gateway_url")

    @property
    def telegram_bot_token(self) -> str:
        return self.get_str("support", "telegram_bot_token")

    @property
    def telegram_chat_id(self) -> str:
        return self.get_str("support", "telegram_chat_id")

    @property
    def discord_webhook_url(self) -> str:
        return self.get_str("support", "discord_webhook_url")

    @property
    def packet_desync_enabled(self) -> bool:
        return self.get_bool("desync", "enabled")

    @property
    def packet_desync_fooling(self) -> str:
        return self.get_str("desync", "fooling")

    @property
    def packet_desync_autottl(self) -> bool:
        return self.get_bool("desync", "autottl")

    @property
    def packet_desync_autottl_delta(self) -> int:
        return self.get_int("desync", "autottl_delta")

    @property
    def packet_desync_ttl(self) -> int:
        return self.get_int("desync", "ttl")

    @property
    def packet_desync_repeats(self) -> int:
        return self.get_int("desync", "repeats")

    @property
    def packet_desync_tcp(self) -> bool:
        return self.get_bool("desync", "tcp_fake_desync")

    @property
    def packet_desync_fake_tls(self) -> str:
        return self.get_str("desync", "fake_tls_file")

    @property
    def packet_desync_split_seqovl(self) -> int:
        return self.get_int("desync", "split_seqovl")


def load_whitelist_domains(filepath: str = "whitelist.txt") -> Tuple[set, Optional[str]]:
    """Загружает список целевых доменов для обхода из текстового файла.
    
    Поддерживает точные имена, маски wildcard (*.domain.com) и комментарии (#).
    Возвращает (набор_доменов, фактический_путь_к_файлу).
    """
    domains = set()
    search_paths = [
        filepath,
        os.path.join(os.getcwd(), filepath),
        os.path.join(get_app_base_dir(), filepath),
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), filepath),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), filepath),
    ]
    actual_path = None
    for p in search_paths:
        if os.path.exists(p) and os.path.isfile(p):
            actual_path = p
            break

    if actual_path:
        try:
            with open(actual_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        domains.add(line.lower())
            logger.info(f"Whitelist загружен: {len(domains)} доменов из {actual_path}")
        except Exception as e:
            logger.error(f"Ошибка чтения списка доменов {actual_path}: {e}")
            print(f"[!] Ошибка чтения списка доменов {actual_path}: {e}")
    else:
        logger.warning(f"Файл whitelist '{filepath}' не найден")
    return domains, actual_path


def is_host_in_whitelist(host: str, whitelist: set) -> bool:
    """Проверяет, входит ли хост или SNI в список целевых доменов обхода."""
    if not host or not whitelist:
        return False
    h = host.lower().strip().strip(".")
    if h.startswith("["):
        bracket_end = h.find("]")
        if bracket_end != -1:
            h = h[1:bracket_end]
    elif ":" in h and h.count(":") == 1:
        h = h.split(":", 1)[0]
    h = h.strip(".")
    if not h:
        return False
    if h in whitelist:
        return True
    parts = h.split(".")
    for i in range(1, len(parts)):
        sub = ".".join(parts[i:])
        if sub in whitelist or f"*.{sub}" in whitelist:
            return True
    # Поддержка произвольных wildcard-шаблонов (например rotterdam*.discord.media или rr*.googlevideo.com)
    for pattern in whitelist:
        if ("*" in pattern or "?" in pattern) and fnmatch.fnmatch(h, pattern):
            return True
    return False
