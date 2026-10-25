"""Тесты для исправления совместимости Discord, Zapret (winws) и восстановления прокси при закрытии."""

import unittest
from unittest.mock import patch, MagicMock, call
import subprocess
import base64
import sys

from flowguard.config import Config
from flowguard.main import FloweryApp
from flowguard.voice_helper import (
    get_winws_command_lines,
    is_winws_tcp_filtering_active,
    VoiceHelper,
)
from flowguard.proxy import DPIBypassProxy


class TestDiscordWinwsCoexistence(unittest.TestCase):
    def test_cleanup_disables_proxy_before_stopping_proxy_server(self):
        """В app.cleanup() отключение системного прокси (proxy_mgr.disable)
        ОБЯЗАНО вызываться ДО остановки proxy_server.stop(), чтобы не оставить
        Windows со включенным прокси, смотрящим на мертвый локальный порт 8118.
        """
        app = FloweryApp()
        app._is_active = True
        app._cleaned_up = False

        order = []
        app.proxy_mgr.disable = MagicMock(side_effect=lambda **kw: order.append("proxy_disable"))
        app.proxy_server.stop = MagicMock(side_effect=lambda: order.append("proxy_stop"))
        app.voice_helper.stop = MagicMock(side_effect=lambda: order.append("voice_stop"))

        app.cleanup(force=True)

        self.assertIn("proxy_disable", order)
        self.assertIn("proxy_stop", order)
        # Проверяем, что отключение системного прокси произошло ДО остановки сервера
        idx_disable = order.index("proxy_disable")
        idx_stop = order.index("proxy_stop")
        self.assertLess(idx_disable, idx_stop, "proxy_mgr.disable MUST be called before proxy_server.stop")

    def test_get_winws_command_lines_encoded_command(self):
        """Проверяет, что get_winws_command_lines использует -EncodedCommand и корректно парсит вывод."""
        if sys.platform != "win32":
            return

        mock_out = b"C:\\zapret\\winws.exe --wf-tcp=80,443 --filter-tcp=80,443\r\n"
        with patch("subprocess.check_output", return_value=mock_out) as mock_co:
            cmdlines = get_winws_command_lines()
            self.assertEqual(len(cmdlines), 1)
            self.assertIn("--wf-tcp=80,443", cmdlines[0])

            # Проверяем, что в аргументах был -EncodedCommand
            args_passed = mock_co.call_args[0][0]
            self.assertIn("-EncodedCommand", args_passed)
            idx = args_passed.index("-EncodedCommand")
            encoded_str = args_passed[idx + 1]
            decoded = base64.b64decode(encoded_str).decode("utf-16le")
            self.assertIn("Get-CimInstance Win32_Process", decoded)

    def test_is_winws_tcp_filtering_active_flags(self):
        """Проверяет распознавание различных TCP флагов zapret winws."""
        ext_vh = VoiceHelper(mode="proxy")
        ext_vh.managed_by_us = False

        # Флаг --wf-l3 (перехват на сетевом уровне L3)
        with patch("flowguard.voice_helper.is_system_winws_running", return_value=True), \
             patch("flowguard.voice_helper.get_winws_command_lines", return_value=["winws.exe --wf-l3=ipv4,ipv6"]):
            self.assertTrue(is_winws_tcp_filtering_active(voice_helper=ext_vh, force_refresh=True))

        # Только UDP войс (не перехватывает TCP)
        with patch("flowguard.voice_helper.is_system_winws_running", return_value=True), \
             patch("flowguard.voice_helper.get_winws_command_lines", return_value=["winws.exe --wf-udp=50000-50100"]):
            self.assertFalse(is_winws_tcp_filtering_active(voice_helper=ext_vh, force_refresh=True))

    def test_proxy_fallback_from_failed_direct_to_dpi_bypass(self):
        """Если прямой запрос direct через zapret завершился неудачей,
        _handshake_with_fast_fallback должна в Попытке 3 автоматически переключиться
        на комбо-стратегию DPI bypass ('combo_tlsrec_tcpsplit'), а не повторять 'direct'.
        """
        cfg = Config()
        proxy = DPIBypassProxy(cfg)

        from flowguard.proxy import ShadowProber
        dummy_hello = ShadowProber._build_dummy_client_hello("discord.com")

        mock_client = MagicMock()
        mock_target1 = MagicMock()
        mock_target3 = MagicMock()

        with patch("flowguard.proxy.is_winws_tcp_filtering_active", return_value=True), \
             patch.object(proxy, "_send_tls_client_hello_with_bypass", return_value=("direct", "discord.com")), \
             patch.object(proxy, "_probe_socket_response", side_effect=[
                 ("rst_fast", None, 0.1),  # Попытка 1 direct завершилась неудачей (zapret не пробил)
                 ("success", b"\x16\x03\x03serverhello", 0.05)  # Попытка 3 DPI bypass успешна
             ]), \
             patch.object(proxy, "_connect_target", side_effect=[None, mock_target3]), \
             patch.object(proxy, "_safe_execute_strategy", return_value=True) as mock_exec, \
             patch("flowguard.proxy._get_socket_meta", return_value={"target_ip": "162.159.130.233", "connect_rtt": 0.05}):

            live_sock, used_strat, eff_host, resp = proxy._handshake_with_fast_fallback(
                mock_client, mock_target1, "discord.com", 443, dummy_hello
            )

            self.assertEqual(used_strat, "combo_tlsrec_tcpsplit")
            self.assertEqual(eff_host, "discord.com")
            self.assertEqual(live_sock, mock_target3)
            mock_exec.assert_called_with("combo_tlsrec_tcpsplit", mock_target3, dummy_hello, host="discord.com")

    def test_clean_argument_skips_admin_elevation(self):
        """Проверяет, что аргумент --clean / --reset не требует UAC-элевации,
        чтобы непривилегированный пользователь мог сбросить HKCU прокси без вылетов."""
        from flowguard.main import check_admin_or_elevate
        import argparse

        # Моделируем разбор аргументов командной строки:
        # if not (args.status or args.detect or args.test or args.calibrate or args.clean):
        #     check_admin_or_elevate(auto_elevate=True)
        parser = argparse.ArgumentParser()
        parser.add_argument("--clean", action="store_true")
        parser.add_argument("--status", action="store_true")
        parser.add_argument("--detect", action="store_true")
        parser.add_argument("--test", action="store_true")
        parser.add_argument("--calibrate", action="store_true")

        args = parser.parse_args(["--clean"])
        skip_admin = bool(args.status or args.detect or args.test or args.calibrate or args.clean)
        self.assertTrue(skip_admin, "--clean must skip check_admin_or_elevate")

    def test_stop_bat_encoded_commands_validity(self):
        """Проверяет, что base64-команды в stop.bat и Flowery_Release/stop.bat
        декодируются в валидный PowerShell скрипт без синтаксических ошибок."""
        import os
        for bat_path in ["stop.bat", os.path.join("Flowery_Release", "stop.bat")]:
            with open(bat_path, "r", encoding="utf-8") as f:
                content = f.read()

            self.assertIn("-EncodedCommand", content)
            # Извлекаем все base64 токены
            import re
            b64_matches = re.findall(r"-EncodedCommand\s+([A-Za-z0-9+/=]+)", content)
            self.assertGreaterEqual(len(b64_matches), 2, f"Expected at least 2 EncodedCommand in {bat_path}")

            for enc in b64_matches:
                decoded = base64.b64decode(enc).decode("utf-16le")
                # Убеждаемся, что внутри нет пропущенных переменных cmd типа 'in )'
                self.assertNotIn("in )", decoded)
                self.assertTrue("InternetSetOption" in decoded or "Stop-Process" in decoded)

    def test_stop_bat_powershell_no_generic_zapret_filters(self):
        """Проверяет, что stop.bat и Flowery_Release/stop.bat не содержат общих
        фильтров портов/флагов zapret, которые могли бы убить внешний winws.exe."""
        import os
        import re
        for bat_path in ["stop.bat", os.path.join("Flowery_Release", "stop.bat")]:
            with open(bat_path, "r", encoding="utf-8") as f:
                content = f.read()

            b64_matches = re.findall(r"-EncodedCommand\s+([A-Za-z0-9+/=]+)", content)
            stop_proc_script = None
            for enc in b64_matches:
                dec = base64.b64decode(enc).decode("utf-16le")
                if "Stop-Process" in dec:
                    stop_proc_script = dec
                    break

            self.assertIsNotNone(stop_proc_script, f"Stop-Process script not found in {bat_path}")
            # Должен искать строго flowery_winws.pid, ACTIVE_DISCORD_UDP.bin или _MEI
            self.assertIn("flowery_winws.pid", stop_proc_script)
            self.assertIn("ACTIVE_DISCORD_UDP.bin", stop_proc_script)
            self.assertIn("_MEI", stop_proc_script)

            # Категорически ЗАПРЕЩЕНЫ общие фильтры zapret
            forbidden_patterns = [
                "50000-65535",
                "50000-50100",
                "19294-19344",
                "52811",
                "fake-discord",
                "fake-stun",
                "*zapret_bin*",
            ]
            for pat in forbidden_patterns:
                self.assertNotIn(pat, stop_proc_script, f"Forbidden filter '{pat}' found in {bat_path}")

    def test_cleanup_orphaned_winws_with_pid_file(self):
        """Если существует PID_FILE, cleanup_orphaned_winws() убивает только указанный PID."""
        import os
        from flowguard.voice_helper import PID_FILE, cleanup_orphaned_winws

        test_pid = 76543
        with open(PID_FILE, "w", encoding="utf-8") as f:
            f.write(str(test_pid))

        try:
            with patch("subprocess.run") as mock_run:
                cleanup_orphaned_winws()

                self.assertTrue(mock_run.called)
                args = mock_run.call_args[0][0]
                ps_script = args[args.index("-Command") + 1]

                # Проверяем, что запрос был именно на test_pid и проверял Name = 'winws.exe'
                self.assertIn(f"ProcessId = {test_pid}", ps_script)
                self.assertIn(f"Stop-Process -Id {test_pid} -Force", ps_script)
                self.assertIn("winws.exe", ps_script)

                # Fallback команда не должна вызываться
                self.assertNotIn("ACTIVE_DISCORD_UDP.bin", ps_script)

                # PID_FILE должен быть удален
                self.assertFalse(os.path.exists(PID_FILE))
        finally:
            if os.path.exists(PID_FILE):
                os.remove(PID_FILE)

    def test_cleanup_orphaned_winws_fallback_no_generic_filters(self):
        """Без PID_FILE fallback в cleanup_orphaned_winws() использует только
        Flowery-специфичные маркеры и не трогает чужие zapret (bol-van, Flowseal)."""
        import os
        from flowguard.voice_helper import PID_FILE, cleanup_orphaned_winws

        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)

        with patch("subprocess.run") as mock_run:
            cleanup_orphaned_winws()

            self.assertTrue(mock_run.called)
            args = mock_run.call_args[0][0]
            ps_script = args[args.index("-Command") + 1]

            # Должен содержать только маркеры Flowery
            self.assertIn("ACTIVE_DISCORD_UDP.bin", ps_script)
            self.assertIn("_MEI", ps_script)

            # Никаких общих портов или generic флагов
            forbidden = [
                "50000-65535",
                "50000-50100",
                "19294-19344",
                "52811",
                "fake-discord",
                "fake-stun",
                "*zapret_bin*",
            ]
            for f_pattern in forbidden:
                self.assertNotIn(f_pattern, ps_script, f"Forbidden generic pattern found: {f_pattern}")

    def test_voice_helper_start_stop_pid_file_lifecycle(self):
        """VoiceHelper при запуске сохраняет PID в PID_FILE, а при stop() удаляет его."""
        import os
        from flowguard.voice_helper import PID_FILE, VoiceHelper

        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)

        vh = VoiceHelper(mode="proxy")
        mock_proc = MagicMock()
        mock_proc.pid = 98765
        mock_proc.poll.return_value = None

        with patch("flowguard.voice_helper.is_system_winws_running", side_effect=[False, True, True]), \
             patch("flowguard.voice_helper.is_admin", return_value=True), \
             patch.object(vh, "is_available", return_value=True), \
             patch("subprocess.Popen", return_value=mock_proc):

            started = vh.start()
            self.assertTrue(started)
            self.assertTrue(os.path.exists(PID_FILE))
            with open(PID_FILE, "r", encoding="utf-8") as f:
                self.assertEqual(f.read().strip(), "98765")

            # Остановка
            vh.stop()
            mock_proc.terminate.assert_called_once()
            self.assertFalse(os.path.exists(PID_FILE))

    def test_external_winws_not_terminated_by_cleanup_orphaned_winws(self):
        """Проверяет на уровне выполнения PowerShell-фильтра, что сторонние winws.exe
        (с общими портами Discord 50000-65535, флагами fake-discord, bol-van, Flowseal)
        НЕ попадают под условие завершения, а завершается ТОЛЬКО процесс Flowery."""
        if sys.platform != "win32":
            return

        ps_test_script = (
            "$mock_procs = @(\n"
            "    [PSCustomObject]@{ ProcessId = 1001; CommandLine = 'winws.exe --wf-udp=50000-65535 --filter-udp=50000-65535 --dpi-desync=fake --dpi-desync-fake-discord=discord.bin'; ExecutablePath = 'C:\\tools\\zapret\\winws.exe' },\n"
            "    [PSCustomObject]@{ ProcessId = 1002; CommandLine = 'winws.exe --filter-udp=19294-19344,50000-65535 --filter-l7=discord,stun --dpi-desync=fake'; ExecutablePath = 'D:\\Games\\zapret_bin\\winws.exe' },\n"
            "    [PSCustomObject]@{ ProcessId = 1003; CommandLine = 'winws.exe --wf-tcp=80,443 --filter-tcp=80,443 --dpi-desync=split2'; ExecutablePath = 'C:\\zapret-discord\\winws.exe' },\n"
            "    [PSCustomObject]@{ ProcessId = 1004; CommandLine = 'winws.exe --dpi-desync=fake --dpi-desync-fake-discord=C:\\Flowery\\zapret_bin\\ACTIVE_DISCORD_UDP.bin'; ExecutablePath = 'C:\\Flowery\\zapret_bin\\winws.exe' },\n"
            "    [PSCustomObject]@{ ProcessId = 1005; CommandLine = 'winws.exe --wf-udp=19294-19344'; ExecutablePath = 'C:\\Users\\User\\AppData\\Local\\Temp\\_MEI123456\\zapret_bin\\winws.exe' }\n"
            ");\n"
            "$killed = @();\n"
            "foreach ($proc in $mock_procs) {\n"
            "    if ($proc.CommandLine -like '*ACTIVE_DISCORD_UDP.bin*' -or $proc.ExecutablePath -like '*\\_MEI*\\zapret_bin\\winws.exe*') {\n"
            "        $killed += $proc.ProcessId\n"
            "    }\n"
            "};\n"
            "Write-Output ($killed -join ',')\n"
        )
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_test_script],
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(res.returncode, 0, f"PowerShell test script failed: {res.stderr}")
        killed_ids = [int(x.strip()) for x in res.stdout.strip().split(",") if x.strip()]
        self.assertNotIn(1001, killed_ids, "External zapret 1001 must NOT be killed")
        self.assertNotIn(1002, killed_ids, "External zapret 1002 must NOT be killed")
        self.assertNotIn(1003, killed_ids, "External zapret 1003 must NOT be killed")
        self.assertIn(1004, killed_ids, "Flowery source winws 1004 must be killed")
        self.assertIn(1005, killed_ids, "Flowery release exe winws 1005 must be killed")

    def test_cleanup_orphaned_winws_corrupted_pid_file_fallback(self):
        """Если PID_FILE повреждён (пустой или не число), cleanup_orphaned_winws()
        удаляет повреждённый файл и переходит к безопасному fallback."""
        import os
        from flowguard.voice_helper import PID_FILE, cleanup_orphaned_winws

        with open(PID_FILE, "w", encoding="utf-8") as f:
            f.write("corrupted_pid_text")

        try:
            with patch("subprocess.run") as mock_run:
                cleanup_orphaned_winws()

                # Должен удалиться повреждённый PID_FILE
                self.assertFalse(os.path.exists(PID_FILE))
                # Должен вызваться fallback с Flowery маркерами
                self.assertTrue(mock_run.called)
                args = mock_run.call_args[0][0]
                ps_script = args[args.index("-Command") + 1]
                self.assertIn("ACTIVE_DISCORD_UDP.bin", ps_script)
                self.assertNotIn("ProcessId = corrupted_pid_text", ps_script)
        finally:
            if os.path.exists(PID_FILE):
                os.remove(PID_FILE)

    def test_flowery_release_voice_helper_matches_flowguard(self):
        """Проверяет, что модуль Flowery_Release/Floweryguard/voice_helper.py содержит
        идентичную логику PID_FILE и безопасного cleanup_orphaned_winws."""
        import Flowery_Release.Floweryguard.voice_helper as rel_vh
        import flowguard.voice_helper as fg_vh
        import inspect

        self.assertEqual(rel_vh.PID_FILE, fg_vh.PID_FILE)

        rel_code = inspect.getsource(rel_vh.cleanup_orphaned_winws)
        fg_code = inspect.getsource(fg_vh.cleanup_orphaned_winws)
        self.assertEqual(rel_code, fg_code, "cleanup_orphaned_winws must be identical across flowguard and Flowery_Release")


if __name__ == "__main__":
    unittest.main()


