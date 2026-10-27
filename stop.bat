@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul
title Flowery — Экстренный сброс и восстановление системы
cd /d "%~dp0"

REM 0. Немедленное отключение системного прокси пользователя ДО любых проверок прав UAC и taskkill
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f >nul 2>&1
powershell -NoProfile -NonInteractive -EncodedCommand JABzAGkAZwAgAD0AIABAACcACgBbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgB3AGkAbgBpAG4AZQB0AC4AZABsAGwAIgApAF0ACgBwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABiAG8AbwBsACAASQBuAHQAZQByAG4AZQB0AFMAZQB0AE8AcAB0AGkAbwBuACgAaQBuAHQAIABoACwAIABpAG4AdAAgAG8ALAAgAGkAbgB0ACAAYgAsACAAaQBuAHQAIABsACkAOwAKACcAQAAKACQAdwAgAD0AIABBAGQAZAAtAFQAeQBwAGUAIAAtAE0AZQBtAGIAZQByAEQAZQBmAGkAbgBpAHQAaQBvAG4AIAAkAHMAaQBnACAALQBOAGEAbQBlACAAKAAnAFcAJwAgACsAIABbAGcAdQBpAGQAXQA6ADoATgBlAHcARwB1AGkAZAAoACkALgBUAG8AUwB0AHIAaQBuAGcAKAAnAE4AJwApACkAIAAtAFAAYQBzAHMAVABoAHIAdQAKAFsAdgBvAGkAZABdACQAdwA6ADoASQBuAHQAZQByAG4AZQB0AFMAZQB0AE8AcAB0AGkAbwBuACgAMAAsACAAMwA5ACwAIAAwACwAIAAwACkACgBbAHYAbwBpAGQAXQAkAHcAOgA6AEkAbgB0AGUAcgBuAGUAdABTAGUAdABPAHAAdABpAG8AbgAoADAALAAgADMANwAsACAAMAAsACAAMAApAAoA >nul 2>&1

REM Проверка прав Администратора (для завершения elevated Flowery.exe и winws.exe)
net session >nul 2>&1
if %errorlevel% equ 0 goto :admin_ok
fltmc >nul 2>&1
if %errorlevel% equ 0 goto :admin_ok
fsutil dirty query %systemdrive% >nul 2>&1
if %errorlevel% equ 0 goto :admin_ok

if "%~1"=="elevated" goto :admin_ok

echo [*] Запрос прав Администратора Windows (UAC)...
set "UAC_ARGS=elevated"
if not "%*"=="" set "UAC_ARGS=elevated %*"

REM Запуск от имени Администратора в текущей директории
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd.exe -WorkingDirectory '%~dp0.' -ArgumentList '/c', '\"\"%~dp0stop.bat\"\" %UAC_ARGS%' -Verb RunAs" >nul 2>&1
if %errorlevel% equ 0 exit /b 0

REM Резервный вызов через VBScript для систем с отключенным PowerShell
set "VBS_ELEVATE=%temp%\flowery_elevate_%random%.vbs"
(
    echo Set UAC = CreateObject^("Shell.Application"^)
    echo UAC.ShellExecute "cmd.exe", "/c " ^& Chr^(34^) ^& "%~dp0stop.bat" ^& Chr^(34^) ^& " %UAC_ARGS%", "%~dp0", "runas", 1
) > "!VBS_ELEVATE!" 2>nul
cscript //nologo "!VBS_ELEVATE!" >nul 2>&1
del "!VBS_ELEVATE!" >nul 2>&1
exit /b 0

:admin_ok

echo [*] Сброс настроек и восстановление системы Windows...

REM 1. Срочное отключение системного прокси ДО завершения процессов (защита от зависания программ на мертвом порту)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f >nul 2>&1
powershell -NoProfile -NonInteractive -EncodedCommand JABzAGkAZwAgAD0AIABAACcACgBbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgB3AGkAbgBpAG4AZQB0AC4AZABsAGwAIgApAF0ACgBwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABiAG8AbwBsACAASQBuAHQAZQByAG4AZQB0AFMAZQB0AE8AcAB0AGkAbwBuACgAaQBuAHQAIABoACwAIABpAG4AdAAgAG8ALAAgAGkAbgB0ACAAYgAsACAAaQBuAHQAIABsACkAOwAKACcAQAAKACQAdwAgAD0AIABBAGQAZAAtAFQAeQBwAGUAIAAtAE0AZQBtAGIAZQByAEQAZQBmAGkAbgBpAHQAaQBvAG4AIAAkAHMAaQBnACAALQBOAGEAbQBlACAAKAAnAFcAJwAgACsAIABbAGcAdQBpAGQAXQA6ADoATgBlAHcARwB1AGkAZAAoACkALgBUAG8AUwB0AHIAaQBuAGcAKAAnAE4AJwApACkAIAAtAFAAYQBzAHMAVABoAHIAdQAKAFsAdgBvAGkAZABdACQAdwA6ADoASQBuAHQAZQByAG4AZQB0AFMAZQB0AE8AcAB0AGkAbwBuACgAMAAsACAAMwA5ACwAIAAwACwAIAAwACkACgBbAHYAbwBpAGQAXQAkAHcAOgA6AEkAbgB0AGUAcgBuAGUAdABTAGUAdABPAHAAdABpAG8AbgAoADAALAAgADMANwAsACAAMAAsACAAMAApAAoA >nul 2>&1

REM 2. Завершение фонового процесса Flowery
taskkill /f /im Flowery.exe >nul 2>&1

REM 3. Освобождение порта 8118
for /f "tokens=5" %%P in ('netstat -ano 2^>nul ^| findstr /i "LISTENING" ^| findstr ":8118"') do (
    if "%%P" neq "0" taskkill /f /pid %%P >nul 2>&1
)

REM 4. Завершение winws.exe ТОЛЬКО если он запущен из папки Flowery (не трогая внешний zapret)
powershell -NoProfile -NonInteractive -EncodedCommand JABQAHIAbwBnAHIAZQBzAHMAUAByAGUAZgBlAHIAZQBuAGMAZQAgAD0AIAAnAFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1AGUAJwAKACQAcABpAGQARgBpAGwAZQAgAD0AIABKAG8AaQBuAC0AUABhAHQAaAAgACQAZQBuAHYAOgBUAEUATQBQACAAJwBmAGwAbwB3AGUAcgB5AF8AdwBpAG4AdwBzAC4AcABpAGQAJwAKACQAawBpAGwAbABlAGQAIAA9ACAAJABmAGEAbABzAGUACgBpAGYAIAAoAFQAZQBzAHQALQBQAGEAdABoACAAJABwAGkAZABGAGkAbABlACkAIAB7AAoAIAAgACAAIAB0AHIAeQAgAHsACgAgACAAIAAgACAAIAAgACAAJABzAGEAdgBlAGQAUABpAGQAIAA9ACAAKABHAGUAdAAtAEMAbwBuAHQAZQBuAHQAIAAkAHAAaQBkAEYAaQBsAGUAIAAtAFIAYQB3ACkALgBUAHIAaQBtACgAKQAKACAAIAAgACAAIAAgACAAIABpAGYAIAAoACQAcwBhAHYAZQBkAFAAaQBkACAALQBtAGEAdABjAGgAIAAnAF4AXABkACsAJAAnACkAIAB7AAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABwACAAPQAgAEcAZQB0AC0AQwBpAG0ASQBuAHMAdABhAG4AYwBlACAAVwBpAG4AMwAyAF8AUAByAG8AYwBlAHMAcwAgAC0ARgBpAGwAdABlAHIAIAAiAFAAcgBvAGMAZQBzAHMASQBkACAAPQAgACQAcwBhAHYAZQBkAFAAaQBkACIACgAgACAAIAAgACAAIAAgACAAIAAgACAAIABpAGYAIAAoACQAcAAgAC0AYQBuAGQAIAAkAHAALgBOAGEAbQBlACAALQBlAHEAIAAnAHcAaQBuAHcAcwAuAGUAeABlACcAKQAgAHsACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAFMAdABvAHAALQBQAHIAbwBjAGUAcwBzACAALQBJAGQAIAAkAHAALgBQAHIAbwBjAGUAcwBzAEkAZAAgAC0ARgBvAHIAYwBlAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAGsAaQBsAGwAZQBkACAAPQAgACQAdAByAHUAZQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgAH0ACgAgACAAIAAgACAAIAAgACAAfQAKACAAIAAgACAAfQAgAGMAYQB0AGMAaAAgAHsAfQAKACAAIAAgACAAUgBlAG0AbwB2AGUALQBJAHQAZQBtACAAJABwAGkAZABGAGkAbABlACAALQBGAG8AcgBjAGUAIAAtAEUAcgByAG8AcgBBAGMAdABpAG8AbgAgAFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1AGUACgB9AAoAaQBmACAAKAAtAG4AbwB0ACAAJABrAGkAbABsAGUAZAApACAAewAKACAAIAAgACAAJABwACAAPQAgAEcAZQB0AC0AQwBpAG0ASQBuAHMAdABhAG4AYwBlACAAVwBpAG4AMwAyAF8AUAByAG8AYwBlAHMAcwAgAC0ARgBpAGwAdABlAHIAIAAiAE4AYQBtAGUAIAA9ACAAJwB3AGkAbgB3AHMALgBlAHgAZQAnACIACgAgACAAIAAgAGYAbwByAGUAYQBjAGgAIAAoACQAcAByAG8AYwAgAGkAbgAgACQAcAApACAAewAKACAAIAAgACAAIAAgACAAIABpAGYAIAAoACQAcAByAG8AYwAuAEMAbwBtAG0AYQBuAGQATABpAG4AZQAgAC0AbABpAGsAZQAgACcAKgBBAEMAVABJAFYARQBfAEQASQBTAEMATwBSAEQAXwBVAEQAUAAuAGIAaQBuACoAJwAgAC0AbwByACAAJABwAHIAbwBjAC4ARQB4AGUAYwB1AHQAYQBiAGwAZQBQAGEAdABoACAALQBsAGkAawBlACAAJwAqAFwAXwBNAEUASQAqAFwAegBhAHAAcgBlAHQAXwBiAGkAbgBcAHcAaQBuAHcAcwAuAGUAeABlACoAJwApACAAewAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgAFMAdABvAHAALQBQAHIAbwBjAGUAcwBzACAALQBJAGQAIAAkAHAAcgBvAGMALgBQAHIAbwBjAGUAcwBzAEkAZAAgAC0ARgBvAHIAYwBlAAoAIAAgACAAIAAgACAAIAAgAH0ACgAgACAAIAAgAH0ACgB9AAoA >nul 2>&1

if exist "%~dp0Flowery.exe.old" (
    del /f /q "%~dp0Flowery.exe.old" >nul 2>&1
)

REM Гарантированное отключение системного прокси в реестре и оповещение WinINet
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f >nul 2>&1
powershell -NoProfile -NonInteractive -EncodedCommand JABzAGkAZwAgAD0AIABAACcACgBbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgB3AGkAbgBpAG4AZQB0AC4AZABsAGwAIgApAF0ACgBwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABiAG8AbwBsACAASQBuAHQAZQByAG4AZQB0AFMAZQB0AE8AcAB0AGkAbwBuACgAaQBuAHQAIABoACwAIABpAG4AdAAgAG8ALAAgAGkAbgB0ACAAYgAsACAAaQBuAHQAIABsACkAOwAKACcAQAAKACQAdwAgAD0AIABBAGQAZAAtAFQAeQBwAGUAIAAtAE0AZQBtAGIAZQByAEQAZQBmAGkAbgBpAHQAaQBvAG4AIAAkAHMAaQBnACAALQBOAGEAbQBlACAAKAAnAFcAJwAgACsAIABbAGcAdQBpAGQAXQA6ADoATgBlAHcARwB1AGkAZAAoACkALgBUAG8AUwB0AHIAaQBuAGcAKAAnAE4AJwApACkAIAAtAFAAYQBzAHMAVABoAHIAdQAKAFsAdgBvAGkAZABdACQAdwA6ADoASQBuAHQAZQByAG4AZQB0AFMAZQB0AE8AcAB0AGkAbwBuACgAMAAsACAAMwA5ACwAIAAwACwAIAAwACkACgBbAHYAbwBpAGQAXQAkAHcAOgA6AEkAbgB0AGUAcgBuAGUAdABTAGUAdABPAHAAdABpAG8AbgAoADAALAAgADMANwAsACAAMAAsACAAMAApAAoA >nul 2>&1

REM Удаление правила брандмауэра для QUIC
netsh advfirewall firewall delete rule name="Flowery_Block_QUIC" >nul 2>&1

REM Восстановление DNS всех адаптеров Windows к DHCP (защита от потери интернета)
for /f "tokens=3*" %%a in ('netsh interface show interface ^| findstr /i "Connected Подключен"') do (
    netsh interface ipv4 set dns name="%%b" dhcp >nul 2>&1
)
ipconfig /flushdns >nul 2>&1

REM Быстрый и надежный поиск интерпретатора Python
set "PY_CMD="

REM 1. Проверка в реестре Windows (HKCU и HKLM \Software\Python\PythonCore)
for /f "tokens=2*" %%A in ('reg query "HKCU\Software\Python\PythonCore" /s /v "ExecutablePath" 2^>nul ^| findstr /i "ExecutablePath"') do (
    if not defined PY_CMD if exist "%%~B" set "PY_CMD=%%~B"
)
for /f "tokens=2*" %%A in ('reg query "HKLM\Software\Python\PythonCore" /s /v "ExecutablePath" 2^>nul ^| findstr /i "ExecutablePath"') do (
    if not defined PY_CMD if exist "%%~B" set "PY_CMD=%%~B"
)

REM 2. Проверка стандартных каталогов AppData текущего пользователя
if not defined PY_CMD if exist "%LocalAppData%\Programs\Python\Python311\python.exe" set "PY_CMD=%LocalAppData%\Programs\Python\Python311\python.exe"
if not defined PY_CMD if exist "%LocalAppData%\Programs\Python\Python312\python.exe" set "PY_CMD=%LocalAppData%\Programs\Python\Python312\python.exe"
if not defined PY_CMD if exist "%LocalAppData%\Programs\Python\Python310\python.exe" set "PY_CMD=%LocalAppData%\Programs\Python\Python310\python.exe"
if not defined PY_CMD if exist "%LocalAppData%\Programs\Python\Python313\python.exe" set "PY_CMD=%LocalAppData%\Programs\Python\Python313\python.exe"
if not defined PY_CMD if exist "%LocalAppData%\Programs\Python\Python39\python.exe" set "PY_CMD=%LocalAppData%\Programs\Python\Python39\python.exe"
if not defined PY_CMD if exist "%LocalAppData%\Programs\Python\Python38\python.exe" set "PY_CMD=%LocalAppData%\Programs\Python\Python38\python.exe"

REM 3. Поиск во всех пользовательских профилях C:\Users\*
if not defined PY_CMD (
    for /d %%U in (%SystemDrive%\Users\*) do (
        if not defined PY_CMD (
            for /d %%D in ("%%U\AppData\Local\Programs\Python\Python3*") do (
                if exist "%%D\python.exe" set "PY_CMD=%%D\python.exe"
            )
        )
    )
)

REM 4. Проверка системных Program Files и корня диска C:
if not defined PY_CMD (
    for /d %%D in ("%ProgramFiles%\Python3*") do (
        if exist "%%D\python.exe" set "PY_CMD=%%D\python.exe"
    )
)
if not defined PY_CMD (
    for /d %%D in ("%ProgramFiles(x86)%\Python3*") do (
        if exist "%%D\python.exe" set "PY_CMD=%%D\python.exe"
    )
)
if not defined PY_CMD (
    for /d %%D in (%SystemDrive%\Python3*) do (
        if exist "%%D\python.exe" set "PY_CMD=%%D\python.exe"
    )
)

REM 5. Проверка командной строки (py launcher / python в PATH)
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
    "%PY_CMD%" -c "import ctypes; w=ctypes.windll.wininet; w.InternetSetOptionW(0,39,0,0); w.InternetSetOptionW(0,37,0,0)" >nul 2>&1
    if exist "%~dp0Floweryguard\main.py" (
        "%PY_CMD%" "%~dp0Floweryguard\main.py" --clean >nul 2>&1
    ) else if exist "%~dp0flowguard\main.py" (
        "%PY_CMD%" "%~dp0flowguard\main.py" --clean >nul 2>&1
    )
) else if exist "%~dp0Flowery.exe" (
    "%~dp0Flowery.exe" --clean >nul 2>&1
)

echo [+] Все фоновые процессы Flowery завершены.
echo [+] Системный прокси Windows выключен.
echo [+] Настройки сети и брандмауэра успешно сброшены в исходное состояние.
echo.
pause
