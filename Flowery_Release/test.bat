@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul
title Flowery — Проверка доступности сайтов
cd /d "%~dp0"

REM Включение поддержки цветов ANSI в Windows
reg add "HKCU\Console" /v VirtualTerminalLevel /t REG_DWORD /d 1 /f >nul 2>&1
mode con: cols=125 lines=40 >nul 2>&1

set "PY_CMD="
for /d %%D in ("%LocalAppData%\Programs\Python\Python3*") do (
    if exist "%%D\python.exe" set "PY_CMD=%%D\python.exe"
)
if not defined PY_CMD (
    for /d %%D in ("%ProgramFiles%\Python3*") do (
        if exist "%%D\python.exe" set "PY_CMD=%%D\python.exe"
    )
)
if not defined PY_CMD (
    py -0 >nul 2>&1 && set "PY_CMD=py"
)
if not defined PY_CMD (
    python -V >nul 2>&1 && set "PY_CMD=python"
)
if not defined PY_CMD (
    where python >nul 2>&1 && set "PY_CMD=python"
)

if defined PY_CMD (
    if exist "%~dp0Floweryguard\main.py" (
        echo [*] Запуск экспресс-теста доступности ресурсов через Flowery [Python]...
        echo.
        "%PY_CMD%" "%~dp0Floweryguard\main.py" --test
        echo.
        pause
        exit /b 0
    )
    if exist "%~dp0flowguard\main.py" (
        echo [*] Запуск экспресс-теста доступности ресурсов через Flowery [Python]...
        echo.
        "%PY_CMD%" "%~dp0flowguard\main.py" --test
        echo.
        pause
        exit /b 0
    )
)

REM Проверка автономного бинарника Flowery.exe
if exist "%~dp0Flowery.exe" (
    echo [*] Запуск экспресс-теста доступности ресурсов через Flowery.exe...
    echo.
    "%~dp0Flowery.exe" --test
    echo.
    pause
    exit /b 0
)

echo [X] ОШИБКА: Python или Flowery.exe не найдены в системе!
echo Установите Python 3.8+ с сайта https://python.org и отметьте 'Add Python to PATH'.
echo.
pause
exit /b 1
