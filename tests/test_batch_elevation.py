"""Тесты валидации пакетных файлов (.bat) Flowery и их эквивалентов в Flowery_Release."""

import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


class TestBatchElevation(unittest.TestCase):
    CANONICAL_BATCHES = ["start.bat", "menu.bat", "stop.bat", "test.bat"]

    def test_batch_files_exist_in_root_and_release(self):
        for bat in self.CANONICAL_BATCHES:
            root_path = os.path.join(".", bat)
            rel_path = os.path.join("Flowery_Release", bat)
            self.assertTrue(os.path.isfile(root_path), f"{root_path} must exist")
            self.assertTrue(os.path.isfile(rel_path), f"{rel_path} must exist")

    def test_strict_parity_between_root_and_release(self):
        for bat in self.CANONICAL_BATCHES:
            root_path = os.path.join(".", bat)
            rel_path = os.path.join("Flowery_Release", bat)
            with open(root_path, "rb") as f1, open(rel_path, "rb") as f2:
                content1 = f1.read()
                content2 = f2.read()
            self.assertEqual(
                content1,
                content2,
                f"Byte mismatch between {root_path} and {rel_path}"
            )

    def test_crlf_line_endings_strictly_enforced(self):
        for bat in self.CANONICAL_BATCHES:
            for base_dir in [".", "Flowery_Release"]:
                path = os.path.join(base_dir, bat)
                with open(path, "rb") as f:
                    raw = f.read()
                self.assertIn(b"\r\n", raw, f"{path} must contain CRLF")
                isolated_lf = raw.replace(b"\r\n", b"").count(b"\n")
                isolated_cr = raw.replace(b"\r\n", b"").count(b"\r")
                self.assertEqual(isolated_lf, 0, f"{path} has isolated LF line endings")
                self.assertEqual(isolated_cr, 0, f"{path} has isolated CR line endings")

    def test_no_nx0_or_extension_collapse_in_elevation(self):
        """Проверяет, что ни в одном .bat файле в блоке UAC не используется %~nx0
        (сворачивается в '.bat'), и что UAC вызов использует полный экранированный путь через %~dp0."""
        elevated_batches = ["start.bat", "menu.bat", "stop.bat"]
        for bat in elevated_batches:
            for base_dir in [".", "Flowery_Release"]:
                path = os.path.join(base_dir, bat)
                with open(path, "r", encoding="utf-8") as f:
                    text = f.read()

                self.assertNotIn("%~nx0", text, f"{path} must not use %~nx0")
                expected_ps_arg = r"'\"\"%~dp0" + bat + r"\"\" %UAC_ARGS%'"
                self.assertIn(
                    expected_ps_arg,
                    text,
                    f"{path} must use quoted {expected_ps_arg} in Start-Process (not relative name)"
                )
                self.assertIn(
                    f'Chr^(34^) ^& "%~dp0{bat}" ^& Chr^(34^)',
                    text,
                    f"{path} must use absolute '%~dp0{bat}' in VBScript ShellExecute"
                )

    def test_no_parenthesis_syntax_bugs_in_compound_blocks(self):
        """Проверяет отсутствие синтаксических ошибок cmd.exe из-за скобок внутри блоков."""
        for bat in self.CANONICAL_BATCHES:
            for base_dir in [".", "Flowery_Release"]:
                path = os.path.join(base_dir, bat)
                with open(path, "r", encoding="utf-8") as f:
                    text = f.read()

                self.assertNotIn("(Glue)...", text, f"{path} contains unescaped '(Glue)...' which breaks cmd.exe blocks")
                self.assertNotIn("Chr(34)", text, f"{path} contains unescaped Chr(34) in parenthesized block")
                self.assertNotIn(
                    "for /d %%D in (%%U\\AppData",
                    text,
                    f"{path} must quote user profile path in for loop"
                )

    def test_cmd_execution_start_elevated_status(self):
        """Проверяет cmd.exe с подменой системных команд и точки входа приложения."""
        for bat_rel in ["start.bat", os.path.join("Flowery_Release", "start.bat")]:
            with tempfile.TemporaryDirectory(prefix="flowery batch ") as directory:
                root = Path(directory)
                stub_dir = root / "_test_tools"
                stub_dir.mkdir()
                commands = ("reg", "net", "fltmc", "fsutil", "taskkill", "netstat", "powershell", "cscript")
                for command in commands:
                    content = "@echo off\n"
                    if command == "reg":
                        content += 'if /i "%~1"=="query" echo ExecutablePath REG_SZ ' + sys.executable + "\n"
                    content += "exit /b 0\n"
                    (stub_dir / (command + ".cmd")).write_bytes(content.replace("\n", "\r\n").encode("utf-8"))
                text = Path(bat_rel).read_text(encoding="utf-8")
                # Сохраняем управляющие конструкции BAT, заменяем только внешние команды.
                for command in commands:
                    text = re.sub(r"\b" + command + r"(?= )", lambda m: 'call "%~dp0_test_tools\\' + command + '.cmd"', text)
                batch = root / "start.bat"
                batch.write_bytes(text.replace("\n", "\r\n").encode("utf-8"))
                package = root / "flowguard"
                package.mkdir()
                (package / "main.py").write_text(
                    "import sys\nprint('FLOWERY_TEST_ARGS=' + repr(sys.argv[1:]))\n", encoding="utf-8"
                )
                res = subprocess.run(
                    '"' + os.environ.get("COMSPEC", "cmd.exe") + f'" /d /s /c ""{batch}" elevated --status"',
                    cwd=directory,
                    input="",
                    capture_output=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=30,
                )
            self.assertEqual(
                res.returncode,
                0,
                f"{bat_rel} exited with code {res.returncode}. Stderr: {res.stderr}"
            )
            self.assertNotIn(
                "was unexpected at this time",
                res.stdout,
                f"{bat_rel} syntax crash in stdout: {res.stdout}"
            )
            self.assertNotIn(
                "was unexpected at this time",
                res.stderr,
                f"{bat_rel} syntax crash in stderr: {res.stderr}"
            )
            self.assertIn(
                "Flowery [Glue]",
                res.stdout,
                f"{bat_rel} did not reach expected Glue execution banner"
            )
            self.assertIn("FLOWERY_TEST_ARGS=['--status']", res.stdout)

    def test_emergency_stop_filter_excludes_client_connections(self):
        """Аварийный stop.bat не должен выбирать клиентские соединения браузера."""
        check_batches = ["stop.bat"]
        for bat in check_batches:
            for base_dir in [".", "Flowery_Release"]:
                path = os.path.join(base_dir, bat)
                with open(path, "r", encoding="utf-8") as f:
                    text = f.read()

                self.assertIn(
                    'findstr /i "LISTENING"',
                    text,
                    f"{path} must filter strictly for LISTENING sockets to prevent killing browser connections"
                )
                self.assertNotIn(
                    "'netstat -ano ^| findstr \":8118\"'",
                    text,
                    f"{path} has unsafe netstat filter without LISTENING check"
                )
                self.assertIn(
                    'for /f "tokens=5" %%P in (\'netstat -ano 2^>nul ^| findstr /i "LISTENING" ^| findstr ":8118"\') do (',
                    text,
                    f"{path} must contain safe LISTENING check pattern for port 8118"
                )

    def test_netstat_listening_filter_rejects_established_client_sockets(self):
        """Проверяет, что фильтр netstat 'findstr /i LISTENING' отсекает сокеты клиентов в состоянии ESTABLISHED."""
        import subprocess
        simulated_netstat = (
            "echo TCP 127.0.0.1:8118 0.0.0.0:0 LISTENING 4321 & "
            "echo TCP 127.0.0.1:50572 127.0.0.1:8118 ESTABLISHED 17256 & "
            "echo TCP 127.0.0.1:8118 127.0.0.1:50572 ESTABLISHED 4321 & "
            "echo TCP [::]:8118 [::]:0 LISTENING 4321"
        )
        cmd = f'({simulated_netstat}) | findstr /i "LISTENING" | findstr ":8118"'
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertNotIn("17256", res.stdout)
        self.assertNotIn("ESTABLISHED", res.stdout)
        self.assertIn("4321", res.stdout)


if __name__ == "__main__":
    unittest.main()


