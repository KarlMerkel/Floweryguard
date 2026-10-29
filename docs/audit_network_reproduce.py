"""Автономные воспроизведения аудита 29.10.2026; это проверки дефектов, не тесты исправления.

Запуск: python docs/audit_network_reproduce.py
Код импортируется из временной копии. Сеть и запись реестра запрещены.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def worker():
    import threading
    from unittest.mock import Mock, patch

    def guard(event, args):
        if event in ('socket.connect', 'socket.sendto', 'socket.getaddrinfo',
                     'socket.gethostbyname', 'subprocess.Popen') or event.startswith('winreg.'):
            raise RuntimeError('Запрещённая операция в воспроизведении: ' + event)

    sys.addaudithook(guard)
    sys.path.insert(0, str(Path.cwd()))
    from flowguard.proxy import DPIBypassProxy, ShadowProber
    from flowguard.route_health import RouteHealth, TransferProgress
    from flowguard.strategy import ThompsonStrategySelector
    from flowguard.profiles import ProfileManager, get_network_fingerprint

    findings = {}
    progress = TransferProgress()
    progress.sent(300, 0)
    progress.received(8000, 1)
    findings['complete_small_response_then_idle'] = progress.finish('idle_timeout', 16)
    assert findings['complete_small_response_then_idle'] == 'suspect'
    progress.received(65536, 2)
    findings['large_response_then_stall'] = progress.finish('idle_timeout', 302)
    assert findings['large_response_then_stall'] == 'progress'

    engine = ThompsonStrategySelector(scores_file=str(Path.cwd() / 'audit-scores.json'))
    engine.configure_allowed(tcp_split=False, tls_record_frag=False, oob_data=False)
    engine.save_scores = Mock()
    probe = object.__new__(ShadowProber)
    probe.strategy_engine = engine
    fake_socket = Mock()
    fake_socket.recv.return_value = b'\x16' + bytes(15)
    with patch('flowguard.proxy.socket.socket', return_value=fake_socket), \
            patch('flowguard.proxy.execute_strategy') as execute:
        probe._probe_host('audit.example', '192.0.2.1')
    findings['synthetic_probe'] = {
        'executed': execute.call_args.args[0],
        'allowed': sorted(engine._allowed_strategies),
        'successes': dict(engine._network_champion_wins),
    }
    assert execute.call_args.args[0] not in engine._allowed_strategies
    assert engine._network_champion_wins['combo_tlsrec_tcpsplit'] == 1

    host, first_ip, next_ip = 'rr1.googlevideo.com', '192.0.2.1', '192.0.2.2'
    proxy = object.__new__(DPIBypassProxy)
    proxy.route_health = RouteHealth()
    proxy.strategy_engine = Mock()
    proxy.strategy_engine._current_network = 'audit-network'
    proxy.strategy_engine.select_strategy.return_value = 'direct'
    proxy.strategy_engine.get_fallback_strategy.return_value = 'direct'
    proxy.strategy_engine.allowed_strategy.side_effect = lambda value: value
    proxy._fixed_strategy = Mock(return_value=None)
    proxy._strategy_after_stall = Mock(side_effect=lambda h, p, ip, s, excluded=(): s)
    proxy._send_tls_client_hello_with_bypass = Mock(return_value=('direct', host))
    proxy._safe_execute_strategy = Mock(return_value=True)
    proxy.whitelist_domains = set()
    proxy._whitelist_lock = threading.Lock()
    proxy.shadow_prober = None
    first, alternate = Mock(), Mock()
    proxy._connect_target = Mock(return_value=alternate)
    proxy._probe_socket_response = Mock(side_effect=[('silent_drop', None, 380),
                                                    ('success', b'\x16', 10)])

    def metadata(sock):
        return {'target_ip': first_ip if sock is first else next_ip, 'connect_rtt': 0.01}

    with patch('flowguard.proxy.is_tls_client_hello', return_value=True), \
            patch('flowguard.proxy._get_socket_meta', side_effect=metadata), \
            patch('flowguard.proxy._safe_close_socket'):
        result = proxy._handshake_with_fast_fallback(Mock(), first, host, 443, b'hello')
    assert result[0] is alternate
    findings['failed_first_route_after_successful_fallback'] = {
        'status': proxy.route_health.status('audit-network', host, 443, first_ip),
        'techniques': sorted(proxy.route_health.stalled_strategies('audit-network', host, 443, first_ip)),
        'first_timeout': proxy._probe_socket_response.call_args_list[0].kwargs['probe_timeout'],
        'penalty_is_tspu': proxy.strategy_engine.record_failure.call_args.kwargs['is_tspu'],
    }
    assert findings['failed_first_route_after_successful_fallback']['status'] == 'unknown'
    assert findings['failed_first_route_after_successful_fallback']['techniques'] == []

    manager = object.__new__(ProfileManager)
    manager._lock = threading.Lock()
    manager._monitor_running = False
    manager._last_fingerprint = 'wifi:old'
    manager.active_profile_id = 'home_wifi'
    manager.network_map = {'wifi:new': 'home_wifi'}
    callback = Mock()

    def changed_network():
        manager._monitor_running = False
        return 'wifi:new'

    def synchronous_thread(*args, **kwargs):
        thread = Mock()
        thread.start.side_effect = kwargs['target']
        return thread

    with patch('flowguard.profiles.threading.Thread', side_effect=synchronous_thread), \
            patch('flowguard.profiles.time.sleep'), \
            patch('flowguard.profiles.get_network_fingerprint', side_effect=changed_network):
        manager.start_network_monitor(Mock(), callback)
    findings['same_profile_network_switch'] = {
        'fingerprint': manager._last_fingerprint, 'callback_calls': callback.call_count}
    assert manager._last_fingerprint == 'wifi:new' and callback.call_count == 0

    with patch('flowguard.profiles.get_wifi_ssid', return_value=None), \
            patch('flowguard.profiles.get_default_gateway_ip', side_effect=['192.168.1.1', '192.168.1.254']):
        fingerprints = [get_network_fingerprint(), get_network_fingerprint()]
    findings['different_gateways_same_fingerprint'] = fingerprints
    assert fingerprints[0] == fingerprints[1]
    print(json.dumps(findings, ensure_ascii=False, indent=2))
    return 0


def main():
    if '--worker' in sys.argv:
        return worker()
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix='flowery-audit-') as folder:
        shutil.copytree(root / 'flowguard', Path(folder) / 'flowguard',
                        ignore=shutil.ignore_patterns('__pycache__'))
        env = dict(os.environ, FLOWERY_HOME=folder, PYTHONIOENCODING='utf-8')
        return subprocess.run([sys.executable, str(Path(__file__).resolve()), '--worker'],
                              cwd=folder, env=env, timeout=30).returncode


if __name__ == '__main__':
    raise SystemExit(main())
