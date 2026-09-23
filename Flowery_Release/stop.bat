@echo off
chcp 65001 >nul
title Flowery - Emergency Reset and Restore
cd /d "%~dp0"

echo [*] Сброс настроек и восстановление системы Windows...

REM Отключение системного прокси в реестре
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f >nul 2>&1

REM Удаление правила брандмауэра для QUIC
netsh advfirewall firewall delete rule name="Flowery_Block_QUIC" >nul 2>&1

REM Использование Flowery.exe если доступен
if exist "%~dp0Flowery.exe" (
    "%~dp0Flowery.exe" --clean >nul 2>&1
    goto :done
)

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

if defined PY_CMD (
    "%PY_CMD%" -c "import sys; sys.path.insert(0, '.'); from Floweryguard.system_proxy import SystemProxyManager, refresh_system_proxy_settings; SystemProxyManager().disable(force=True); refresh_system_proxy_settings()" >nul 2>&1
)

:done
echo [+] Системный прокси Windows выключен.
echo [+] Настройки сети и брандмауэра успешно сброшены в исходное состояние.
echo.
pause
