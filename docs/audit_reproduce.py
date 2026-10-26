"""Автономные воспроизведения аудита: измеряет текущее поведение, не исправляет его.

Запуск: python docs/audit_reproduce.py
Работает во временной копии. Сеть и запуск внешних процессов в проверках запрещены.
Это наблюдения дефектов, а не регрессионные тесты правильного поведения.
"""

import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def worker():
    def deny_external(event, args):
        if event.startswith("socket.") and event in (
            "socket.connect", "socket.sendto", "socket.getaddrinfo",
            "socket.gethostbyname", "socket.gethostbyaddr",
        ):
            raise RuntimeError("Сеть запрещена при воспроизведении аудита")
        if event == "subprocess.Popen":
            raise RuntimeError("Внешние процессы запрещены при воспроизведении аудита")

    sys.addaudithook(deny_external)
    sys.path.insert(0, str(Path.cwd()))
    import socket
    import threading
    from types import SimpleNamespace
    from unittest.mock import Mock, MagicMock, patch
    from flowguard.config import Config
    from flowguard import proxy, doh_resolver, strategy, dns_config, ttl_fix
    from flowguard import profiles, main, power_watchdog, tls_transport, log_sender
    from flowguard.sni_spoofer import build_fake_client_hello
    from flowguard.tls_parser import create_tls_record_fragments

    results = {}
    cfg = Config("absent.ini")
    cfg.set_value("dns", "server", "resolver.example")
    cfg.set_value("dns", "doh_url", "https://resolver.example/query")
    cfg.set_value("dns", "primary", "192.0.2.10")
    mgr = proxy.get_dns_failover_manager(cfg, force_new=True)
    results["custom_dns"] = {"requested": "resolver.example", "selected": mgr.primary_provider.doh_host}

    selector = strategy.ThompsonStrategySelector(scores_file="audit-scores.json")
    selector.configure_allowed(False, False, False)
    results["disabled_strategies"] = {
        "allowed": sorted(selector._allowed_strategies),
        "youtube": selector.select_strategy("youtube.com"),
        "whitelist": selector.select_strategy("example.test", is_whitelisted=True),
        "discord_fallback": selector.get_fallback_strategy("cdn.discordapp.com", failed_strategy="combo_tlsrec_tcpsplit"),
    }

    p = object.__new__(proxy.DPIBypassProxy)
    p.config = Config("absent.ini")
    p.timeout = 15
    p.whitelist_domains = set()
    p._whitelist_lock = threading.Lock()
    p._check_reload_whitelist = Mock()
    p.doh_harvester = p.dns_failover = None
    p.strategy_engine = selector
    p.route_health = proxy.RouteHealth()
    p.flush_stale_caches()
    sock = MagicMock()
    with patch.object(proxy.socket, "getaddrinfo", return_value=[
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 443, 0, 0))
    ]), patch.object(proxy.socket, "socket", return_value=sock) as factory:
        p._connect_target("ipv6.example", 443)
    results["ipv6_disabled"] = {"setting": p.config.ipv6_mode, "used_ipv6_socket": factory.call_args.args[0] == socket.AF_INET6}

    body = b"data\r\nHost: payload\r\nend"
    req = b"POST / HTTP/1.1\r\nHost: 192.0.2.1\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    altered = p._obfuscate_http_request(req, "192.0.2.1")
    results["http_body"] = {"unchanged": altered.split(b"\r\n\r\n", 1)[1] == body}
    client = Mock()
    p._connect_target = Mock()
    p._handle_http_request(client, b"POST http://ordinary.example/upload HTTP/1.1\r\nHost: ordinary.example\r\n\r\ndata", "http://ordinary.example/upload")
    results["http_redirect"] = {"status": client.sendall.call_args.args[0].split(b"\r\n")[0].decode(), "upstream_called": p._connect_target.called}

    p._lock = threading.Lock()
    p._concurrency_sem = Mock()
    p.active_connections = 1
    p.buffer_size = 65536
    hello = build_fake_client_hello("ordinary.example")
    fragments = create_tls_record_fragments(hello)
    client, upstream = Mock(), Mock()
    client.recv.side_effect = [b"CONNECT ordinary.example:443 HTTP/1.1\r\n\r\n", fragments[0], fragments[1]]
    p._connect_target.return_value = upstream
    p._handshake_with_fast_fallback = Mock(return_value=(None, "direct", "ordinary.example", None))
    p._handle_client(client, ("127.0.0.1", 10000))
    forwarded = p._handshake_with_fast_fallback.call_args.args[-1]
    results["fragmented_clienthello"] = {"forwarded_bytes": len(forwarded), "complete_bytes": sum(map(len, fragments)), "client_recv_calls": client.recv.call_count}

    p.sni_spoofer = Mock()
    p.sni_spoofer.send_with_fake_sni_desync.return_value = False
    p._logged_whitelisted_lock = threading.Lock()
    p._logged_whitelisted = set()
    p.config.set_override("fake_sni_record", True)
    upstream = Mock()
    with patch.object(proxy, "is_winws_tcp_filtering_active", return_value=False):
        name, _ = p._send_tls_client_hello_with_bypass(upstream, hello, "ordinary.example")
    results["failed_fake_sni"] = {"reported_strategy": name, "real_hello_sent": upstream.sendall.called}

    dns = dns_config.DNSManager()
    dns._changed_adapters = ["Adapter"]
    dns._original_dns = {"Adapter": ["192.0.2.53"]}
    backup = Path("audit-dns-backup.json")
    backup.write_text("{}", encoding="utf-8")
    with patch.object(dns_config, "is_admin", return_value=True), patch.object(dns, "_get_backup_filepath", return_value=str(backup)), patch.object(dns_config.subprocess, "run", return_value=Mock(returncode=1)):
        ok = dns.restore_dns()
    results["dns_failed_restore"] = {"reported_success": ok, "saved_state": dict(dns._original_dns), "backup_exists": backup.exists()}

    mtu = ttl_fix.MTUManager()
    mtu._applied = True
    mtu.original_mtus = {"Adapter": 1500}
    mtu.original_mtus_v6 = {"Adapter": 1480}
    with patch.object(ttl_fix, "is_admin", return_value=True), patch.object(ttl_fix.subprocess, "run", return_value=Mock(returncode=1)):
        ok = mtu.restore_mtu()
    results["mtu_failed_restore"] = {"reported_success": ok, "saved_state": dict(mtu.original_mtus), "retry_enabled": mtu._applied}

    with patch.object(dns_config.subprocess, "run", return_value=Mock(stdout=b"Enabled Disconnected Dedicated Ethernet\r\n")):
        results["disconnected_adapter"] = dns.get_active_interfaces()

    cfg = Config("audit-config.ini")
    cfg.set_value("tethering", "fix_ttl", False)
    cfg.set_value("proxy", "proxy_discord", False)
    cfg.save()
    reloaded = Config("audit-config.ini")
    pm = profiles.ProfileManager("audit-profiles.json")
    pm.apply_profile("home_wifi", reloaded)
    results["saved_settings_after_profile"] = {"fix_ttl": reloaded.fix_ttl, "proxy_discord": reloaded.proxy_discord}

    harvester = doh_resolver.MultiDoHHarvester(Config("absent.ini"))
    joins = []

    class FakeThread:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def start(self):
            return None

        def join(self, timeout=None):
            joins.append(timeout)

    with patch.object(doh_resolver.threading, "Thread", FakeThread):
        harvester.harvest("ordinary.example")
    results["harvester_timeouts"] = {"socket_timeout": harvester.timeout, "sequential_join_limits": joins}

    selector._dirty = True
    with patch.object(strategy.os, "replace", side_effect=PermissionError("Синтетический отказ записи")):
        selector.save_scores(force=True)
    results["failed_score_save"] = {"dirty": selector._dirty, "file_exists": Path(selector.cache_file).exists()}

    app = object.__new__(main.FloweryApp)
    app._cleanup_lock = threading.Lock()
    app._cleaned_up = False
    app._is_active = True
    app._timer_period_active = False
    for name in ("proxy_mgr", "power_watchdog", "tray_icon", "profile_mgr", "proxy_server", "voice_helper", "quic_blocker", "ttl_mgr", "mtu_mgr", "dns_mgr", "config"):
        setattr(app, name, Mock())
    app.config.enable_custom_dns = False
    app.dns_mgr._changed_adapters = []
    app.proxy_mgr.disable.return_value = False
    with patch.object(main, "is_admin", return_value=False), patch.object(main, "release_single_instance_mutex"):
        app.cleanup(force=True)
        app.cleanup(force=True)
    results["cleanup_retry"] = {"disable_calls_after_two_cleanups": app.proxy_mgr.disable.call_count, "cleaned_up": app._cleaned_up}

    recovery_app = SimpleNamespace(_is_active=True, config=SimpleNamespace(auto_system_proxy=True), proxy_server=Mock(), proxy_mgr=Mock())

    def concurrent_stop():
        recovery_app._is_active = False
        return False

    recovery_app.proxy_server.revive_if_needed.side_effect = concurrent_stop
    watchdog = power_watchdog.PowerWatchdog(recovery_app)
    with patch.object(power_watchdog.time, "sleep"), patch.object(power_watchdog, "is_admin", return_value=False), patch.object(power_watchdog.threading, "Thread", FakeThread):
        watchdog._execute_recovery_sequence("аудит")
    results["recovery_after_stop"] = {"active": recovery_app._is_active, "proxy_reenabled": recovery_app.proxy_mgr.ensure_active.called}

    now = [0.0]
    client, upstream = Mock(), Mock()
    client.recv.return_value = b"request"
    upstream.recv.return_value = b"x" * 14000
    ticks = [0]

    def select_ready(*args):
        ticks[0] += 1
        if ticks[0] == 1:
            return [client], [], []
        if ticks[0] == 2:
            now[0] = 1.0
            return [upstream], [], []
        now[0] += args[-1]
        return [], [], []

    with patch.object(tls_transport.select, "select", side_effect=select_ready), patch.object(tls_transport.time, "monotonic", side_effect=lambda: now[0]):
        progress, reason = tls_transport.relay_tls(client, upstream, lambda: True, 15, 65536, Mock(), Mock())
    results["partial_tls_idle"] = {"idle_seconds": now[0] - 1, "reason": reason, "outcome": progress.finish(reason, now[0])}

    sanitized = log_sender.sanitize_text("SSID wifi:PersonalNetwork IPv6 2001:db8::42 C:\\Users\\First Last\\secret.log")
    results["log_redaction"] = {"ssid_remains": "PersonalNetwork" in sanitized, "ipv6_remains": "2001:db8::42" in sanitized, "surname_remains": "Last" in sanitized}

    return results


def main_entry():
    if "--worker" in sys.argv:
        with contextlib.redirect_stdout(io.StringIO()):
            results = worker()
        print(json.dumps(results, ensure_ascii=False, indent=2))
        return 0
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="flowery-audit-") as directory:
        target = Path(directory)
        for name in ("flowguard", "Floweryguard"):
            shutil.copytree(root / name, target / name, ignore=shutil.ignore_patterns("__pycache__"))
        script = target / "reproduce.py"
        shutil.copy2(__file__, script)
        env = dict(os.environ, FLOWERY_HOME=str(target / "user-data"), PYTHONIOENCODING="utf-8")
        run = subprocess.run([sys.executable, str(script), "--worker"], cwd=target, env=env, timeout=30)
        return run.returncode


if __name__ == "__main__":
    raise SystemExit(main_entry())
