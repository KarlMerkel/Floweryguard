import unittest
from unittest.mock import MagicMock, patch
import os

from flowguard.voice_helper import VoiceHelper, cleanup_orphaned_winws
from flowguard.config import load_whitelist_domains, is_host_in_whitelist
from flowguard.system_proxy import build_proxy_override
from flowguard.proxy import is_gaming_host, DPIBypassProxy
from flowguard.config import Config


class TestHelldiversGamingFixes(unittest.TestCase):
    """Тесты для проверки исправления конфликта с Helldivers 2 и игровыми сервисами."""

    def test_voice_helper_udp_range(self):
        """Проверка, что диапазон UDP сегментирован (19294-19344,50000-52811,52841-57607,57609-65535) и исключает порты Helldivers 2."""
        helper = VoiceHelper()
        args = helper.build_winws_args()
        
        expected_filter = "19294-19344,50000-52811,52841-57607,57609-65535"
        self.assertIn(f"--wf-udp={expected_filter}", args)
        self.assertIn(f"--filter-udp={expected_filter}", args)

        # Проверка, что порты Helldivers 2 (52812-52840 и 57608) исключены из фильтра
        helldivers_ports = list(range(52812, 52841)) + [57608]
        for port in helldivers_ports:
            in_filter = False
            for part in expected_filter.split(","):
                if "-" in part:
                    start, end = map(int, part.split("-"))
                    if start <= port <= end:
                        in_filter = True
                        break
                elif int(part) == port:
                    in_filter = True
                    break
            self.assertFalse(in_filter, f"Port {port} of Helldivers 2 should NOT be in UDP filter")

        # Проверка канонического чистого fake десинка для мобильного тетеринга (без badsum и autottl)
        self.assertIn("--dpi-desync=fake", args)
        self.assertIn("--dpi-desync-repeats=6", args)
        self.assertNotIn("--dpi-desync-fooling=badsum", args)
        self.assertFalse(any("--dpi-desync-autottl" in a for a in args))

        # Проверка изоляции: в режиме proxy при tcp_desync=True параметры badsum не утекают в UDP
        helper_proxy = VoiceHelper(mode="proxy", tcp_desync=True, fooling="badsum", autottl=True)
        args_proxy = helper_proxy.build_winws_args()
        self.assertNotIn("--dpi-desync-fooling=badsum", args_proxy)
        self.assertFalse(any("--dpi-desync-autottl" in a for a in args_proxy))

        # В режиме packet с tcp_desync=True badsum уходит строго в секцию после --new
        helper_packet = VoiceHelper(mode="packet", tcp_desync=True, fooling="none", tcp_fooling="badsum", tcp_autottl=True)
        args_packet = helper_packet.build_winws_args()
        self.assertIn("--new", args_packet)
        new_idx = args_packet.index("--new")
        udp_part = args_packet[:new_idx]
        tcp_part = args_packet[new_idx:]
        self.assertNotIn("--dpi-desync-fooling=badsum", udp_part)
        self.assertIn("--dpi-desync-fooling=badsum", tcp_part)

    def test_whitelist_steam_domains_removed(self):
        """Проверка, что домены Steam удалены из whitelist.txt."""
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        wl_path = os.path.join(base_dir, "whitelist.txt")
        domains = load_whitelist_domains(wl_path)
        
        steam_check_domains = [
            "steamserver.net",
            "cmp1-iad.steamserver.net",
            "steampowered.com",
            "store.steampowered.com",
            "steamcommunity.com",
            "steamcontent.com",
            "steamstatic.com",
        ]
        for domain in steam_check_domains:
            self.assertFalse(
                is_host_in_whitelist(domain, domains),
                f"Domain {domain} should NOT be in whitelist"
            )

    def test_proxy_override_contains_gaming_domains(self):
        """Проверка, что build_proxy_override() содержит все домены Helldivers 2, Steam, Sony, PlayFab, GameGuard."""
        override = build_proxy_override()
        
        expected_patterns = [
            "*.steampowered.com",
            "*.steamcommunity.com",
            "*.steamcontent.com",
            "*.steamstatic.com",
            "*.steamserver.net",
            "*.steam-chat.com",
            "*.playstation.com",
            "*.playstation.net",
            "*.sonyentertainmentnetwork.com",
            "*.playfabapi.com",
            "*.playfab.com",
            "*.arrowheadgs.com",
            "*.helldivers2.dev",
            "*.nprotect.net",
            "*.nprotect.com",
            "*.inca.co.kr",
        ]
        for pattern in expected_patterns:
            self.assertIn(
                pattern,
                override,
                f"Pattern {pattern} must be present in ProxyOverride"
            )

    def test_is_gaming_host(self):
        """Проверка распознавания игровых хостов."""
        gaming_hosts = [
            "steamserver.net",
            "cmp1-iad.steamserver.net",
            "steampowered.com",
            "store.steampowered.com",
            "steamcommunity.com",
            "steamcontent.com",
            "steamstatic.com",
            "steam-chat.com",
            "playstation.com",
            "auth.api.sonyentertainmentnetwork.com",
            "api.playfab.com",
            "title.playfabapi.com",
            "api.arrowheadgs.com",
            "arrowheadgs.com",
            "helldivers2.dev",
            "gameguard.nprotect.net",
            "update.nprotect.com",
            "patch.inca.co.kr",
        ]
        for host in gaming_hosts:
            self.assertTrue(is_gaming_host(host), f"Host {host} should be recognized as gaming host")

        non_gaming = [
            "discord.com",
            "youtube.com",
            "googlevideo.com",
            "rutracker.org",
            "google.com",
            "github.com",
            "example.com",
            None,
            "",
        ]
        for host in non_gaming:
            self.assertFalse(is_gaming_host(host), f"Host {host} should NOT be recognized as gaming host")

    def test_gaming_host_forces_direct_strategy_in_proxy(self):
        """Проверка, что для игровых хостов вызывается стратегия direct без десинка."""
        config = Config()
        proxy = DPIBypassProxy(config=config)
        mock_sock = MagicMock()
        
        # Симулируем TLS ClientHello пакет для steamserver.net
        # Минимальный ClientHello c SNI
        # 0x16, 0x03, 0x01 ...
        fake_hello = (
            b"\x16\x03\x01\x00\x30"
            b"\x01\x00\x00\x2c\x03\x03" + b"\x00" * 32 + b"\x00"
            b"\x00\x02\x00\xff\x01\x00\x00\x03\x00\x00\x00"
        )
        with patch("flowguard.proxy.parse_sni", return_value=("cmp1.steamserver.net", 443)):
            strat, effective_host = proxy._send_tls_client_hello_with_bypass(
                mock_sock, fake_hello, "cmp1.steamserver.net"
            )
            self.assertEqual(strat, "direct")
            mock_sock.sendall.assert_called_once_with(fake_hello)

    def test_gaming_host_bypasses_http_obfuscation_and_ua_masking(self):
        """Проверка, что для игровых хостов отключается модификация заголовков HTTP."""
        config = Config()
        config.set_override("http_host_obfuscation", True)
        config.set_override("mask_user_agent", True)
        proxy = DPIBypassProxy(config=config)
        
        raw_http = (
            b"GET /patch HTTP/1.1\r\n"
            b"Host: patch.inca.co.kr\r\n"
            b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n"
        )
        
        obfuscated = proxy._obfuscate_http_request(raw_http, host="patch.inca.co.kr")
        # Должен остаться исходный неизмененный HTTP запрос
        self.assertEqual(obfuscated, raw_http)
        self.assertIn(b"Windows NT 10.0; Win64; x64", obfuscated)
        self.assertIn(b"Host: patch.inca.co.kr", obfuscated)

    def test_cleanup_orphaned_winws(self):
        """Проверка вызова cleanup_orphaned_winws без исключений."""
        try:
            cleanup_orphaned_winws()
        except Exception as e:
            self.fail(f"cleanup_orphaned_winws raised exception: {e}")


if __name__ == "__main__":
    unittest.main()
