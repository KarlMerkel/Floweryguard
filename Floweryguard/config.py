"""Модуль конфигурации Flowery (Glue).
Чтение и валидация настроек из config.ini с поддержкой динамических переопределений авто-детектором.
"""

import os
import configparser
from typing import Dict, Any

DEFAULT_CONFIG: Dict[str, Dict[str, Any]] = {
    "proxy": {
        "host": "127.0.0.1",
        "port": 8118,
        "auto_system_proxy": True,
        "proxy_discord": True,
        "proxy_youtube": False,
        "timeout": 15,
        "buffer_size": 16384,
    },
    "bypass": {
        "tcp_split": True,
        "tls_record_frag": True,
        "oob_data": True,
        "http_host_obfuscation": True,
    },
    "fragmentation": {
        "fragment_size": 3,
        "fragment_delay": 0.005,  # 5 мс задержка между сегментами
        "tlsrec_split_at_sni": True,
    },
    "tethering": {
        "fix_ttl": True,
        "default_ttl": 65,
        "enable_timestamps": True,
    },
    "quic": {
        "block_quic": False,
    },
    "dns": {
        "primary": "1.1.1.1",
        "secondary": "8.8.8.8",
        "enable_custom_dns": False,
    },
    "whitelist_bypass": {
        "auto_detect": True,
        "spoof_sni": False,
        "whitelisted_sni": "gosuslugi.ru",
        "fake_sni_record": False,
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
        if os.path.exists(self.config_path):
            try:
                self._parser.read(self.config_path, encoding="utf-8")
            except Exception as e:
                print(f"[!] Ошибка чтения config.ini ({e}), используются стандартные параметры.")

    def set_override(self, key: str, value: Any) -> None:
        """Устанавливает динамическое переопределение параметра во время работы."""
        self._overrides[key] = value

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
        except Exception:
            return fallback

    def get_int(self, section: str, key: str) -> int:
        if key in self._overrides:
            return int(self._overrides[key])
        fallback = int(DEFAULT_CONFIG.get(section, {}).get(key, 0))
        try:
            return self._parser.getint(section, key, fallback=fallback)
        except Exception:
            return fallback

    def get_float(self, section: str, key: str) -> float:
        if key in self._overrides:
            return float(self._overrides[key])
        fallback = float(DEFAULT_CONFIG.get(section, {}).get(key, 0.0))
        try:
            return self._parser.getfloat(section, key, fallback=fallback)
        except Exception:
            return fallback

    def get_bool(self, section: str, key: str) -> bool:
        if key in self._overrides:
            return bool(self._overrides[key])
        fallback = bool(DEFAULT_CONFIG.get(section, {}).get(key, False))
        try:
            return self._parser.getboolean(section, key, fallback=fallback)
        except Exception:
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
    def proxy_youtube(self) -> bool:
        return self.get_bool("proxy", "proxy_youtube")

    @property
    def buffer_size(self) -> int:
        return self.get_int("proxy", "buffer_size")

    @property
    def timeout(self) -> int:
        return self.get_int("proxy", "timeout")

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
