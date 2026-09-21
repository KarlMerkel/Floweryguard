@echo off
title Flowery (Glue) - DPI Bypass for Mobile Tethering

REM Enable ANSI / Virtual Terminal Processing in Windows Console
reg add "HKCU\Console" /v VirtualTerminalLevel /t REG_DWORD /d 1 /f >nul 2>&1

REM Set wide console buffer and window (125 cols) so ASCII art never wraps
mode con: cols=125 lines=52 >nul 2>&1

cd /d "%~dp0"

REM Safety reset: ensure any stale proxy from an unclean shutdown is disabled before starting
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f >nul 2>&1

REM Check for administrator privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    if "%~1" neq "elevated" (
        echo [*] Requesting Administrator privileges...
        powershell -NoProfile -Command "Start-Process cmd.exe -ArgumentList '/k', 'cd /d \"%~dp0\" && start.bat elevated' -Verb RunAs" 2>nul
        if %errorlevel% equ 0 exit /b
        echo [!] Could not elevate automatically. Running in standard mode...
    )
)

REM Find Python executable
set "PY_CMD="
where python >nul 2>&1 && set "PY_CMD=python"
if not defined PY_CMD (
    where py >nul 2>&1 && set "PY_CMD=py"
)
if not defined PY_CMD (
    if exist "%LocalAppData%\Programs\Python\Python311\python.exe" (
        set "PY_CMD=%LocalAppData%\Programs\Python\Python311\python.exe"
    )
)

if not defined PY_CMD (
    echo [X] ERROR: Python was not found!
    echo Please install Python 3.8+ from https://python.org and check 'Add Python to PATH'.
    echo.
    pause
    exit /b 1
)

echo [*] Starting Flowery (Glue)...
echo.
"%PY_CMD%" Floweryguard\main.py --all

REM Safe exit: guarantee system proxy is turned off upon exit
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f >nul 2>&1

if %errorlevel% neq 0 (
    echo.
    echo [!] Flowery terminated with error code %errorlevel%
    pause
)
