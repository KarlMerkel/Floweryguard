"""Модуль тестирования доступности ресурсов и проверки обхода блокировок.
"""

import socket
import sys
import time
import urllib.request
from typing import List, Dict, Any

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

TEST_TARGETS = [
    {"name": "Discord Web", "host": "discord.com", "port": 443},
    {"name": "Discord Gateway", "host": "gateway.discord.gg", "port": 443},
    {"name": "Discord CDN", "host": "cdn.discordapp.com", "port": 443},
    {"name": "Discord Voice", "host": "discord.media", "port": 443},
    {"name": "Discord Voice RTC", "host": "c-hel01-dbd8efe7.discord.media", "port": 443},
    {"name": "Discord Status", "host": "status.discord.com", "port": 443},
    {"name": "YouTube", "host": "www.youtube.com", "port": 443},
    {"name": "Twitter / X", "host": "x.com", "port": 443},
    {"name": "Rutracker", "host": "rutracker.org", "port": 443},
    {"name": "Cloudflare DNS", "host": "one.one.one.one", "port": 443},
    {"name": "NTC Party", "host": "ntc.party", "port": 443},
]


def test_proxy_connection(proxy_host: str = "127.0.0.1", proxy_port: int = 8118) -> List[Dict[str, Any]]:
    """Проверяет доступность тестовых сайтов через локальный прокси."""
    results = []
    proxy_url = f"http://{proxy_host}:{proxy_port}"
    import ssl
    ssl_ctx = ssl._create_unverified_context()
    proxy_handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    https_handler = urllib.request.HTTPSHandler(context=ssl_ctx)
    opener = urllib.request.build_opener(proxy_handler, https_handler)

    print(f"\033[96m[*] Запуск проверки доступности ресурсов через {proxy_url}...\033[0m\n")

    for target in TEST_TARGETS:
        name = target["name"]
        host = target["host"]
        url = f"https://{host}"
        start_time = time.time()

        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            )
            with opener.open(req, timeout=7) as resp:
                elapsed = int((time.time() - start_time) * 1000)
                code = resp.getcode()
                status = "OK" if code in [200, 301, 302] else f"HTTP {code}"
                print(f"  [\033[92m+\033[0m] {name:<20} ({host:<22}) -> \033[92m{status}\033[0m ({elapsed} мс)")
                results.append({"name": name, "host": host, "status": True, "latency": elapsed, "code": code})
        except urllib.error.HTTPError as he:
            elapsed = int((time.time() - start_time) * 1000)
            code = he.code
            # Для WebSocket и CDN шлюзов Discord коды 401, 403, 404, 520 означают успешный TLS handshake
            if code in [401, 403, 404, 520]:
                print(f"  [\033[92m+\033[0m] {name:<20} ({host:<22}) -> \033[92mTLS OK (HTTP {code})\033[0m ({elapsed} мс)")
                results.append({"name": name, "host": host, "status": True, "latency": elapsed, "code": code})
            else:
                print(f"  [\033[91m-\033[0m] {name:<20} ({host:<22}) -> \033[91mHTTP {code}\033[0m ({elapsed} мс)")
                results.append({"name": name, "host": host, "status": False, "latency": elapsed, "code": code})
        except Exception as e:
            elapsed = int((time.time() - start_time) * 1000)
            err_msg = str(e)
            if "timed out" in err_msg.lower():
                err_display = "Таймаут"
            elif "refused" in err_msg.lower():
                err_display = "Отказ соединения"
            else:
                err_display = "Ошибка"
            print(f"  [\033[91m-\033[0m] {name:<20} ({host:<22}) -> \033[91m{err_display}\033[0m ({elapsed} мс)")
            results.append({"name": name, "host": host, "status": False, "latency": elapsed, "error": err_msg})

    # Проверка Discord Voice UDP WebRTC (IP Discovery / STUN)
    print("\033[96m[*] Проверка голосового транспорта Discord (UDP WebRTC)...\033[0m")
    import struct
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.settimeout(2.0)
    packet = struct.pack('>HHI64sH', 1, 70, 181451, b'', 0)
    test_rtc_ip = "35.217.11.71"
    test_rtc_port = 50007
    udp_ok = False
    try:
        udp_start = time.time()
        udp_sock.sendto(packet, (test_rtc_ip, test_rtc_port))
        resp, _ = udp_sock.recvfrom(1024)
        udp_elapsed = int((time.time() - udp_start) * 1000)
        if len(resp) >= 70:
            udp_ok = True
            print(f"  [\033[92m+\033[0m] {'Discord Voice UDP':<20} ({test_rtc_ip}:{test_rtc_port:<17}) -> \033[92mOK (WebRTC активен)\033[0m ({udp_elapsed} мс)")
            results.append({"name": "Discord Voice UDP", "host": test_rtc_ip, "status": True, "latency": udp_elapsed})
    except Exception:
        pass
    finally:
        udp_sock.close()

    if not udp_ok:
        print(f"  [\033[93m!\033[0m] {'Discord Voice UDP':<20} ({test_rtc_ip}:{test_rtc_port:<17}) -> \033[93mUDP блокируется провайдером\033[0m")
        print("      \033[90m-> Для войсов убедитесь, что start.bat запущен от имени Администратора\033[0m")
        results.append({"name": "Discord Voice UDP", "host": test_rtc_ip, "status": False, "error": "UDP blocked"})

    print()
    return results


if __name__ == "__main__":
    test_proxy_connection()
