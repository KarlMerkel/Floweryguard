@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul
title Flowery — Меню управления (Glue)

REM Включение поддержки цветов ANSI в Windows
reg add "HKCU\Console" /v VirtualTerminalLevel /t REG_DWORD /d 1 /f >nul 2>&1

cd /d "%~dp0"

REM Безопасный сброс прокси перед стартом
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f >nul 2>&1

REM Проверка прав Администратора через несколько быстрых системных механизмов
net session >nul 2>&1
if %errorlevel% equ 0 goto :admin_ok
fltmc >nul 2>&1
if %errorlevel% equ 0 goto :admin_ok
fsutil dirty query %systemdrive% >nul 2>&1
if %errorlevel% equ 0 goto :admin_ok

:need_admin
if "%~1"=="elevated" goto :admin_ok

echo [*] Запрос прав Администратора Windows (UAC)...
set "UAC_ARGS=elevated"
if not "%*"=="" set "UAC_ARGS=elevated %*"

REM Запуск от имени Администратора в текущей директории
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd.exe -WorkingDirectory '%~dp0.' -ArgumentList '/k', '\"\"%~dp0menu.bat\"\" %UAC_ARGS%' -Verb RunAs" >nul 2>&1
if %errorlevel% equ 0 exit /b

REM Резервный вызов через VBScript для систем с отключенным PowerShell
set "VBS_ELEVATE=%temp%\flowery_elevate_%random%.vbs"
(
    echo Set UAC = CreateObject^("Shell.Application"^)
    echo UAC.ShellExecute "cmd.exe", "/k " ^& Chr^(34^) ^& "%~dp0menu.bat" ^& Chr^(34^) ^& " %UAC_ARGS%", "%~dp0", "runas", 1
) > "!VBS_ELEVATE!" 2>nul
cscript //nologo "!VBS_ELEVATE!" >nul 2>&1
del "!VBS_ELEVATE!" >nul 2>&1
goto :admin_failed

:admin_failed
echo.
echo ==============================================================================
echo [X] ОШИБКА: Flowery требует обязательных прав Администратора!
echo.
echo Для работы интерактивного меню и служб Flowery необходимы привилегии:
echo   1. Установка DefaultTTL в реестре HKLM [маскировка тетеринга].
echo   2. Запуск WinDivert для голосовых каналов Discord [UDP].
echo   3. Блокировка QUIC в Windows Firewall для принуждения к TCP/TLS.
echo.
echo Запустите menu.bat через "Запуск от имени администратора".
echo ==============================================================================
echo.
pause
exit /b 1

:admin_ok

REM Сброс прокси перед стартом и освобождение порта 8118
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f >nul 2>&1
taskkill /f /im Flowery.exe >nul 2>&1
for /f "tokens=5" %%P in ('netstat -ano 2^>nul ^| findstr /i "LISTENING" ^| findstr ":8118"') do (
    if "%%P" neq "0" taskkill /f /pid %%P >nul 2>&1
)

REM Фильтрация внутреннего служебного аргумента 'elevated'
set "EXTRA_ARGS="
for %%A in (%*) do (
    if /i "%%~A" neq "elevated" (
        if defined EXTRA_ARGS (
            set "EXTRA_ARGS=!EXTRA_ARGS! %%A"
        ) else (
            set "EXTRA_ARGS=%%A"
        )
    )
)

REM Быстрый и надежный поиск интерпретатора Python во всех профилях и реестре
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

REM Запуск через Python при наличии исходных кодов
if defined PY_CMD (
    if exist "%~dp0Floweryguard\main.py" (
        echo [*] Запуск меню Flowery через Python...
        echo.
        "%PY_CMD%" "%~dp0Floweryguard\main.py" --menu !EXTRA_ARGS!
        set "EXIT_CODE=!errorlevel!"
        goto :safe_exit
    )
    if exist "%~dp0flowguard\main.py" (
        echo [*] Запуск меню Flowery [Glue]...
        "%PY_CMD%" "%~dp0flowguard\main.py" --menu !EXTRA_ARGS!
        set "EXIT_CODE=!errorlevel!"
        goto :safe_exit
    )
)

REM Если исходные коды присутствуют, но Python не найден
if exist "%~dp0flowguard\main.py" (
    echo.
    echo ==============================================================================
    echo [X] ОШИБКА: Интерпретатор Python не найден в системе!
    echo.
    echo Для работы Flowery требуется Python 3.8+:
    echo   https://python.org
    echo Установите Python или отметьте галочку "Add python.exe to PATH".
    echo ==============================================================================
    echo.
    pause
    exit /b 1
)
if exist "%~dp0Floweryguard\main.py" (
    echo.
    echo ==============================================================================
    echo [X] ОШИБКА: Интерпретатор Python не найден в системе!
    echo.
    echo Для работы Flowery требуется Python 3.8+:
    echo   https://python.org
    echo Установите Python или отметьте галочку "Add python.exe to PATH".
    echo ==============================================================================
    echo.
    pause
    exit /b 1
)

REM Запуск автономного бинарника Flowery.exe при отсутствии исходников Python
if exist "%~dp0Flowery.exe" (
    echo [*] Запуск меню Flowery [Glue]...
    "%~dp0Flowery.exe" --menu !EXTRA_ARGS!
    set "EXIT_CODE=!errorlevel!"
    goto :safe_exit
)

echo.
echo ==============================================================================
echo [X] ОШИБКА: Компоненты запуска Flowery не найдены!
echo ==============================================================================
echo.
pause
exit /b 1

:safe_exit
REM Гарантированное отключение системного прокси при выходе
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f >nul 2>&1
powershell -NoProfile -NonInteractive -EncodedCommand JABzAGkAZwAgAD0AIABAACcACgBbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgB3AGkAbgBpAG4AZQB0AC4AZABsAGwAIgApAF0ACgBwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABiAG8AbwBsACAASQBuAHQAZQByAG4AZQB0AFMAZQB0AE8AcAB0AGkAbwBuACgAaQBuAHQAIABoACwAIABpAG4AdAAgAG8ALAAgAGkAbgB0ACAAYgAsACAAaQBuAHQAIABsACkAOwAKACcAQAAKACQAdwAgAD0AIABBAGQAZAAtAFQAeQBwAGUAIAAtAE0AZQBtAGIAZQByAEQAZQBmAGkAbgBpAHQAaQBvAG4AIAAkAHMAaQBnACAALQBOAGEAbQBlACAAKAAnAFcAJwAgACsAIABbAGcAdQBpAGQAXQA6ADoATgBlAHcARwB1AGkAZAAoACkALgBUAG8AUwB0AHIAaQBuAGcAKAAnAE4AJwApACkAIAAtAFAAYQBzAHMAVABoAHIAdQAKAFsAdgBvAGkAZABdACQAdwA6ADoASQBuAHQAZQByAG4AZQB0AFMAZQB0AE8AcAB0AGkAbwBuACgAMAAsACAAMwA5ACwAIAAwACwAIAAwACkACgBbAHYAbwBpAGQAXQAkAHcAOgA6AEkAbgB0AGUAcgBuAGUAdABTAGUAdABPAHAAdABpAG8AbgAoADAALAAgADMANwAsACAAMAAsACAAMAApAAoA >nul 2>&1

echo.
if defined EXIT_CODE (
    if !EXIT_CODE! neq 0 (
        echo [!] Меню Flowery завершило работу с кодом ошибки !EXIT_CODE!
    ) else (
        echo [*] Меню Flowery закрыто. Системные настройки восстановлены.
    )
) else (
    echo [*] Меню Flowery закрыто. Системные настройки восстановлены.
)
echo.
pause
exit /b 0
