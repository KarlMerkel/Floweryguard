"""Модуль автоматического обнаружения сетевых ограничений (Auto-Detector).
Определяет ОБА типа сетевых ограничений:
1. Ограничение мобильного оператора при раздаче (тетеринг, TTL=128, Captive Portal, блокировка раздачи)
2. Белый список / Default-Deny (Leaky L7 Whitelist, Strict L3 Whitelist, Черный список РКН)
Строго стандартная библиотека Python, 100% автономно без внешних серверов и регистраций.
"""

import socket
import struct
import time
import urllib.request
import urllib.parse
from typing import Dict, Any, Tuple, Optional
from Floweryguard.tls_parser import is_tls_client_hello, parse_sni
from Floweryguard.ttl_fix import TTLManager

# Проверочные цели для белого списка
WHITELIST_SNI_CANDIDATES = ["gosuslugi.ru", "vk.com", "yandex.ru", "sberbank.ru"]
BLOCKED_TARGETS = [
    {"host": "www.youtube.com", "ip": "142.250.74.78", "port": 443},
    {"host": "discord.com", "ip": "162.159.137.232", "port": 443},
    {"host": "rutracker.org", "ip": "104.21.32.39", "port": 443},
]
PUBLIC_DNS = [("1.1.1.1", 53), ("8.8.8.8", 53), ("77.88.8.8", 53)]

# Операторские домены заглушек и перехватов тетеринга
OPERATOR_PORTAL_KEYWORDS = [
    "megafon", "mts.ru", "tele2", "t2.ru", "beeline", "yota.ru", "rt.ru",
    "tinkoff", "sbermobile", "tattelecom", "motiv", "kcell", "activ"
]
TETHERING_HTML_KEYWORDS = [
    "раздач", "тетеринг", "tether", "подключите опцию", "ограничение скорости",
    "закончился трафик", "пакет интернета", "пополните баланс", "платная раздача"
]


def check_port_open(ip: str, port: int, timeout: float = 2.0) -> bool:
    """Проверяет доступность TCP порта на удаленном IP (L3/L4 маршрутизация)."""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        return True
    except Exception:
        return False
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass


def check_dns_udp(dns_ip: str, port: int = 53, timeout: float = 2.0) -> bool:
    """Проверяет доступность внешнего UDP/53 (работает ли базовый DNS во внешний мир)."""
    sock = None
    try:
        # DNS-запрос типа A для cloudflare.com
        packet = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        for part in ["cloudflare", "com"]:
            packet += bytes([len(part)]) + part.encode("ascii")
        packet += b"\x00\x00\x01\x00\x01"

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (dns_ip, port))
        data, _ = sock.recvfrom(512)
        return len(data) > 12 and data[0:2] == b"\x12\x34"
    except Exception:
        return False
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def check_tethering_interception(timeout: float = 2.5) -> Tuple[bool, str]:
    """Проверяет перехват трафика мобильным оператором (Captive Portal / редирект тетеринга).
    
    Возвращает (is_tethering_blocked, description).
    """
    probe_urls = [
        ("http://msftconnecttest.com/connecttest.txt", "Microsoft Connect Test"),
        ("http://detectportal.firefox.com/canonical.html", "canonical"),
        ("http://cp.cloudflare.com/generate_204", ""),
    ]

    for url, expected_text in probe_urls:
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            )
            # Запрещаем авто-переходы, чтобы поймать HTTP 302 к оператору
            opener = urllib.request.build_opener(NoRedirectHandler)
            with opener.open(req, timeout=timeout) as resp:
                status = resp.status
                redirect_url = resp.headers.get("Location", "")
                
                # Если произошел редирект на операторский шлюз
                for kw in OPERATOR_PORTAL_KEYWORDS:
                    if kw in redirect_url.lower():
                        return True, f"Редирект на портал оператора: {redirect_url}"

                # Читаем тело ответа
                body = resp.read().decode("utf-8", errors="ignore").lower()
                for kw in TETHERING_HTML_KEYWORDS:
                    if kw in body:
                        return True, f"Страница оператора сообщает об ограничении раздачи: '{kw}'"

                # Если ожидали текст, но получили что-то чужое
                if expected_text and expected_text.lower() not in body:
                    # Потенциальный перехват
                    if any(op in body for op in OPERATOR_PORTAL_KEYWORDS):
                        return True, "Обнаружен перехват HTTP порталом оператора"

        except RedirectionException as re:
            loc = re.location.lower()
            for kw in OPERATOR_PORTAL_KEYWORDS:
                if kw in loc:
                    return True, f"Перехват тетеринга: редирект на {re.location}"
        except Exception:
            continue

    return False, "Перехват HTTP-трафика оператором не обнаружен"


class RedirectionException(Exception):
    def __init__(self, location: str):
        self.location = location


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if fp:
            try:
                fp.close()
            except Exception:
                pass
        raise RedirectionException(newurl)


def check_sni_behavior(target_ip: str, blocked_host: str, whitelisted_host: str) -> Tuple[bool, bool]:
    """Проверяет реакцию DPI на заблокированный SNI против разрешенного SNI на одном IP.
    
    Возвращает (blocked_sni_passes, whitelisted_sni_passes)
    """
    def send_probe(sni_domain: str) -> bool:
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.5)
            s.connect((target_ip, 443))

            host_b = sni_domain.encode("ascii")
            sni_ext = b"\x00\x00" + (len(host_b) + 5).to_bytes(2, "big")
            sni_ext += (len(host_b) + 3).to_bytes(2, "big") + b"\x00" + len(host_b).to_bytes(2, "big") + host_b
            exts = len(sni_ext).to_bytes(2, "big") + sni_ext

            ch_body = b"\x03\x03" + (b"\x42" * 32) + b"\x00" + b"\x00\x02\x00\x9c" + b"\x01\x00" + exts
            ch_msg = b"\x01" + (len(ch_body)).to_bytes(3, "big") + ch_body
            pkt = b"\x16\x03\x01" + (len(ch_msg)).to_bytes(2, "big") + ch_msg

            s.sendall(pkt)
            resp = s.recv(1024)
            # Если получен валидный ответ TLS (ServerHello 0x16 или Alert 0x15)
            return len(resp) > 0 and resp[0] in [0x15, 0x16]
        except Exception:
            return False
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass

    blocked_res = send_probe(blocked_host)
    white_res = send_probe(whitelisted_host)
    return blocked_res, white_res


class NetworkDetector:
    """Комплексный авто-диагност сетевых ограничений и подбор профиля обхода."""

    def __init__(self):
        self.results: Dict[str, Any] = {}
        self.ttl_mgr = TTLManager()

    def run_full_diagnosis(self) -> Dict[str, Any]:
        """Проводит комплексное сканирование обоих типов ограничений."""
        print("\033[96m[*] Запуск комплексного анализа сети (Тетеринг + Белые списки / DPI)...\033[0m")

        # -------------------------------------------------------------
        # АНАЛИЗ 1: Ограничения тетеринга (раздачи с мобильного)
        # -------------------------------------------------------------
        curr_ttl_v4, _ = self.ttl_mgr.get_current_ttl()
        ttl_vulnerable = (curr_ttl_v4 != 65)
        self.results["ttl_v4_current"] = curr_ttl_v4 or 128
        self.results["ttl_vulnerable"] = ttl_vulnerable

        tether_blocked, tether_details = check_tethering_interception()
        self.results["tethering_blocked"] = tether_blocked
        self.results["tethering_details"] = tether_details

        # -------------------------------------------------------------
        # АНАЛИЗ 2: Доступность белого списка
        # -------------------------------------------------------------
        whitelisted_ok = False
        active_whitelisted_sni = "gosuslugi.ru"
        for sni in WHITELIST_SNI_CANDIDATES:
            try:
                ip = socket.gethostbyname(sni)
                if check_port_open(ip, 443, timeout=1.5):
                    whitelisted_ok = True
                    active_whitelisted_sni = sni
                    break
            except Exception:
                continue
        self.results["whitelisted_accessible"] = whitelisted_ok
        self.results["active_whitelisted_sni"] = active_whitelisted_sni

        # -------------------------------------------------------------
        # АНАЛИЗ 3: Доступность внешнего интернета и L7 фильтрация
        # -------------------------------------------------------------
        dns_open = False
        for dns_ip, port in PUBLIC_DNS:
            if check_dns_udp(dns_ip, port):
                dns_open = True
                break
        self.results["dns_udp_53_open"] = dns_open

        ip_reachable_count = 0
        for t in BLOCKED_TARGETS:
            if check_port_open(t["ip"], t["port"]):
                ip_reachable_count += 1
        self.results["ip_routing_open"] = (ip_reachable_count > 0)
        self.results["reachable_ips_ratio"] = f"{ip_reachable_count}/{len(BLOCKED_TARGETS)}"

        # Проверка реакции L7 на YouTube IP
        sample = BLOCKED_TARGETS[0]
        blocked_ok, white_ok = check_sni_behavior(sample["ip"], sample["host"], active_whitelisted_sni)
        self.results["blocked_sni_passes"] = blocked_ok
        self.results["whitelisted_sni_passes"] = white_ok

        # -------------------------------------------------------------
        # КЛАССИФИКАЦИЯ И ВЫБОР РЕЖИМА
        # -------------------------------------------------------------
        mode = "UNKNOWN"
        summary = ""
        profile_overrides: Dict[str, Any] = {}

        is_strict_whitelist = (not self.results["ip_routing_open"] and self.results["whitelisted_accessible"])
        is_leaky_whitelist = (self.results["ip_routing_open"] and white_ok and not blocked_ok)

        # Выбираем режим
        if is_strict_whitelist:
            mode = "STRICT_WHITELIST"
            summary = "Глухой белый список (внешние IP заблокированы маршрутизатором, открыты только ресурсы РФ)"
            profile_overrides = {
                "fake_sni_record": False,
                "tls_record_frag": True,
                "tcp_split": True,
                "fix_ttl": True,
                "block_quic": False,
            }
        elif is_leaky_whitelist:
            mode = "LEAKY_L7_WHITELIST"
            summary = "Частичный белый список (IP открыт, DPI режет соединения с чужим SNI)"
            profile_overrides = {
                "fake_sni_record": False,
                "tls_record_frag": True,
                "tcp_split": True,
                "fix_ttl": True,
                "block_quic": False,
            }
        elif tether_blocked or ttl_vulnerable:
            mode = "TETHERING_RESTRICTION"
            summary = "Ограничение мобильного тетеринга оператором (TTL / перехват трафика) + Blacklist DPI"
            profile_overrides = {
                "fix_ttl": True,
                "default_ttl": 65,
                "enable_timestamps": True,
                "block_quic": False,
                "tls_record_frag": True,
                "tcp_split": True,
                "oob_data": True,
                "fake_sni_record": False,
            }
        elif not blocked_ok:
            mode = "BLACKLIST_DPI"
            summary = "Стандартный черный список DPI (РКН / блокировка отдельных доменов: Discord, YouTube)"
            profile_overrides = {
                "tls_record_frag": True,
                "tcp_split": True,
                "oob_data": True,
                "block_quic": False,
                "fix_ttl": True,
                "fake_sni_record": False,
            }
        else:
            mode = "CLEAN_INTERNET"
            summary = "Прямых ограничений на проверенных ресурсах не обнаружено"
            profile_overrides = {
                "fix_ttl": True,
                "block_quic": False,
                "tls_record_frag": True,
                "fake_sni_record": False,
            }

        self.results["detected_mode"] = mode
        self.results["summary"] = summary
        self.results["profile_overrides"] = profile_overrides
        return self.results

    def print_report(self) -> None:
        """Печатает детальный цветной отчёт для пользователя."""
        if not self.results:
            self.run_full_diagnosis()

        mode = self.results.get("detected_mode", "UNKNOWN")
        summary = self.results.get("summary", "")
        ttl_val = self.results.get("ttl_v4_current", 128)
        ttl_vuln = self.results.get("ttl_vulnerable", False)
        tether_blocked = self.results.get("tethering_blocked", False)
        tether_details = self.results.get("tethering_details", "")
        dns_open = self.results.get("dns_udp_53_open", False)
        ip_open = self.results.get("ip_routing_open", False)
        sni_chosen = self.results.get("active_whitelisted_sni", "gosuslugi.ru")

        ttl_status = "\033[91mУЯЗВИМ (128 - палится раздача)\033[0m" if ttl_vuln else "\033[92mЗАЩИЩЁН (65)\033[0m"
        tether_status = f"\033[91mОБНАРУЖЕН ({tether_details})\033[0m" if tether_blocked else "\033[92mНЕТ ПЕРЕХВАТА\033[0m"
        ip_status = "\033[92mОТКРЫТА\033[0m" if ip_open else "\033[91mЗАБЛОКИРОВАНА\033[0m"
        dns_status = "\033[92mОТКРЫТ\033[0m" if dns_open else "\033[91mЗАКРЫТ\033[0m"

        print("\n\033[1;97m" + "═" * 70 + "\033[0m")
        print("\033[1;96m [РЕЗУЛЬТАТЫ АВТО-ДИАГНОСТИКИ СЕТИ (100% АВТОНОМНО)]\033[0m")
        print("\033[1;97m" + "─" * 70 + "\033[0m")
        print(f"  [1] Тетеринг / Раздача:")
        print(f"      * Системный TTL Windows:   {ttl_status}")
        print(f"      * Перехват оператора:      {tether_status}")
        print(f"  [2] Белый список vs Доступ в мир:")
        print(f"      * Внешняя IP маршрутизация: {ip_status}")
        print(f"      * Внешний DNS (UDP 53):     {dns_status}")
        print(f"      * Активный белый SNI:       \033[92m{sni_chosen}\033[0m")
        print(f"  [3] Сетевой диагноз:           \033[1;93m{summary}\033[0m")

        print("\n\033[1;94m [АВТОМАТИЧЕСКИ АКТИВИРОВАННЫЙ ПРОФИЛЬ ОБХОДА]:\033[0m")
        if mode in ["LEAKY_L7_WHITELIST", "STRICT_WHITELIST"]:
            print(f"  \033[92m-> Профиль: 'L7 SNI/Host Spoofing + TLS Record Frag'\033[0m")
            print(f"     (Спуфинг SNI под {sni_chosen} + разделение TLS записей)")
        elif mode == "TETHERING_RESTRICTION":
            print("  \033[92m-> Профиль: 'Tethering Mask (TTL 65) + ByeDPI Stream Desync'\033[0m")
            print("     (Фиксация TTL=65, RFC 1323 Timestamps, TCP Split, TLS Frag, WebRTC unblocked)")
        elif mode == "BLACKLIST_DPI":
            print("  \033[92m-> Профиль: 'DPI Desync Hybrid (Split + Frag + OOB)'\033[0m")
            print("     (Обход замедлений YouTube, Discord и блокировок РКН)")
        else:
            print("  \033[92m-> Профиль: 'Full Spectrum Adaptive'\033[0m")
        print("\033[1;97m" + "═" * 70 + "\033[0m\n")
