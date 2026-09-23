@echo off
title Flowery (Glue) - Test Connection
cd /d "%~dp0"

REM Включение поддержки цветов ANSI в Windows
reg add "HKCU\Console" /v VirtualTerminalLevel /t REG_DWORD /d 1 /f >nul 2>&1
mode con: cols=125 lines=40 >nul 2>&1

REM Проверка автономного бинарника Flowery.exe
if exist "%~dp0Flowery.exe" (
    echo [*] Запуск экспресс-теста доступности ресурсов через Flowery.exe...
    echo.
    "%~dp0Flowery.exe" --test
    echo.
    pause
    exit /b 0
)

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
    echo [X] ОШИБКА: Python не найден в системе!
    echo Установите Python 3.8+ с сайта https://python.org и отметьте 'Add Python to PATH'.
    echo.
    pause
    exit /b 1
)

echo [*] Запуск экспресс-теста доступности ресурсов через Flowery...
echo.
"%PY_CMD%" Floweryguard\main.py --test
echo.
pause
