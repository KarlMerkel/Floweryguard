import unittest
import socket
from flowguard.proxy import DPIBypassProxy, is_gaming_host, parse_sni
from flowguard.config import Config
from flowguard.system_proxy import build_proxy_override
from flowguard.quic_block import get_installed_browsers
from flowguard.ttl_fix import MTUManager


class MockSocket:
    def __init__(self):
        self.sent_data = bytearray()
        self.closed = False

    def sendall(self, data):
        self.sent_data.extend(data)

    def close(self):
        self.closed = True


class TestGamingCompatibility(unittest.TestCase):
    def test_is_gaming_host_classification(self):
        gaming_hosts = [
            "store.steampowered.com",
            "steamcommunity.com",
            "steamserver.net",
            "cmp1-iad.steamserver.net",
            "valve.net",
            "valvesoftware.com",
            "playstation.com",
            "auth.api.playstation.com",
            "np.community.playstation.net",
            "sonyentertainmentnetwork.com",
            "playfabapi.com",
            "titleid.playfabapi.com",
            "party.playfab.com",
            "playfab.net",
            "trafficmanager.net",
            "arrowheadgs.com",
            "api.live.helldivers.arrowheadgs.com",
            "helldivers2.dev",
            "api.helldivers2.dev",
            "nprotect.net",
            "update.nprotect.net",
            "inca.co.kr",
            "gameguard.des",
            "gameguard.co.kr",
            "battleye.com",
            "easyanticheat.net",
        ]
        for host in gaming_hosts:
            self.assertTrue(is_gaming_host(host), f"Host {host} should be classified as gaming")
            self.assertTrue(is_gaming_host(host.upper()), f"Upper host {host} should be classified as gaming")

        non_gaming = [
            "www.youtube.com",
            "googlevideo.com",
            "discord.com",
            "gateway.discord.gg",
            "rutracker.org",
            "x.com",
            "google.com",
        ]
        for host in non_gaming:
            self.assertFalse(is_gaming_host(host), f"Host {host} should NOT be classified as gaming")

    def test_build_proxy_override_contains_gaming_domains(self):
        override = build_proxy_override(proxy_discord=True, proxy_youtube=True)
        self.assertIn("*.steampowered.com", override)
        self.assertIn("*.valve.net", override)
        self.assertIn("*.playstation.com", override)
        self.assertIn("*.playfabapi.com", override)
        self.assertIn("*.arrowheadgs.com", override)
        self.assertIn("*.helldivers2.dev", override)
        self.assertIn("*.nprotect.net", override)
        self.assertIn("<local>", override)

    def test_gaming_tls_handshake_immediate_direct(self):
        cfg = Config()
        proxy = DPIBypassProxy(cfg)
        mock_client = MockSocket()
        mock_target = MockSocket()

        # Dummy non-TLS data
        res_sock, strat, eff_host, resp = proxy._handshake_with_fast_fallback(
            mock_client, mock_target, "api.helldivers2.dev", 443, b"NON_TLS_GAME_PACKET"
        )
        self.assertEqual(strat, "direct")
        self.assertEqual(eff_host, "api.helldivers2.dev")
        self.assertEqual(mock_target.sent_data, bytearray(b"NON_TLS_GAME_PACKET"))

    def test_mtu_manager_skips_ethernet(self):
        mgr = MTUManager(target_mtu=1420)
        # Mock active interfaces containing Ethernet
        mgr.get_active_interfaces = lambda: [
            ("Ethernet 2", 1500),
            ("VirtualBox Host-Only Ethernet Adapter", 1500),
        ]
        # Should not mutate Ethernet MTUs
        applied = mgr.apply_mtu()
        self.assertFalse(applied)
        self.assertEqual(len(mgr.original_mtus), 0)


if __name__ == "__main__":
    unittest.main()
