@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul
title Flowery - DPI Bypass and Tethering Mask for Windows

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
        echo [*] Запрос прав Администратора Windows (UAC)...
        powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd.exe -ArgumentList '/c \"\"%~f0\" elevated %*\"' -Verb RunAs"
        exit /b
    )
    echo.
    echo ==============================================================================
    echo [X] ОШИБКА: Flowery требует обязательных прав Администратора!
    echo.
    echo Для работы Flowery необходимы системные привилегии:
    echo   1. Установка DefaultTTL в реестре HKLM (маскировка тетеринга под смартфон).
    echo   2. Запуск WinDivert драйвера для голосовых каналов Discord (UDP).
    echo   3. Блокировка QUIC в Windows Firewall для принуждения к TCP/TLS.
    echo.
    echo Запустите start.bat через "Запуск от имени администратора".
    echo ==============================================================================
    echo.
    pause
    exit /b 1
)

REM Filter out internal 'elevated' token from argument list
set "RUN_ARGS="
for %%A in (%*) do (
    if /i "%%~A" neq "elevated" (
        if defined RUN_ARGS (
            set "RUN_ARGS=!RUN_ARGS! %%A"
        ) else (
            set "RUN_ARGS=%%A"
        )
    )
)

REM Check for standalone Flowery.exe first
if exist "%~dp0Flowery.exe" (
    echo [*] Starting Flowery Standalone...
    echo.
    "%~dp0Flowery.exe" !RUN_ARGS!
    set "EXIT_CODE=!errorlevel!"
    goto :safe_exit
)

REM Find Python executable
set "PY_CMD="
where python >nul 2>&1 && set "PY_CMD=python"
if not defined PY_CMD (
    where py >nul 2>&1 && set "PY_CMD=py"
)
if not defined PY_CMD (
    for /d %%D in ("%LocalAppData%\Programs\Python\Python3*") do (
        if exist "%%D\python.exe" set "PY_CMD=%%D\python.exe"
    )
)

if not defined PY_CMD (
    echo [X] ERROR: Python or Flowery.exe was not found!
    echo Please install Python 3.8+ from https://python.org and check 'Add Python to PATH'.
    echo Or place Flowery.exe into this directory.
    echo.
    pause
    exit /b 1
)

echo [*] Starting Flowery...
echo.
"%PY_CMD%" Floweryguard\main.py !RUN_ARGS!
set "EXIT_CODE=!errorlevel!"

:safe_exit
REM Safe exit: guarantee system proxy is turned off upon exit
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f >nul 2>&1

if defined EXIT_CODE (
    if !EXIT_CODE! neq 0 (
        echo.
        echo [!] Flowery terminated with error code !EXIT_CODE!
        pause
    )
)
