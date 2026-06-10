@echo off
setlocal enabledelayedexpansion
title EmberArmor Proxy

REM ── Resolve install dir ───────────────────────────────────────────────────────
REM start.bat lives inside EmberArmor\ember_proxy\ — so parent is EmberArmor root
set PROXY_DIR=%~dp0
set EMBER_ARMOR_DIR=%~dp0..

REM Normalise trailing slash
if "%EMBER_ARMOR_DIR:~-1%"=="\" set EMBER_ARMOR_DIR=%EMBER_ARMOR_DIR:~0,-1%

REM ── Load .env if present ─────────────────────────────────────────────────────
set EMBER_API_KEY=ember-proxy-internal-key
set PROXY_PORT=8080
set STATUS_PORT=7070
set BLOCK_ON_UNSAFE=false

if exist "%PROXY_DIR%.env" (
    for /f "usebackq tokens=1,2 delims==" %%A in ("%PROXY_DIR%.env") do (
        if not "%%A"=="" if not "%%A:~0,1%"=="#" set %%A=%%B
    )
)

REM Allow .env to override the install dir
if defined EMBER_ARMOR_DIR_OVERRIDE set EMBER_ARMOR_DIR=%EMBER_ARMOR_DIR_OVERRIDE%

echo.
echo  ======================================================
echo   EMBERARMOR PROXY
echo  ======================================================
echo   Armor dir : %EMBER_ARMOR_DIR%
echo   Proxy port: %PROXY_PORT%
echo   Dashboard : http://localhost:%STATUS_PORT%
echo  ======================================================
echo.

REM ── Verify EmberArmor is present ─────────────────────────────────────────────
if not exist "%EMBER_ARMOR_DIR%\ember_armor\api\main.py" (
    echo [ERROR] EmberArmor not found at:
    echo         %EMBER_ARMOR_DIR%
    echo.
    echo  Run install_windows.bat first to download EmberArmor from GitHub.
    echo  Or set EMBER_ARMOR_DIR_OVERRIDE in ember_proxy\.env to your install path.
    pause
    exit /b 1
)

REM ── Pull latest from GitHub ───────────────────────────────────────────────────
echo [0/2] Checking for updates...
cd /d "%EMBER_ARMOR_DIR%"
git pull --quiet 2>nul && echo [OK] Up to date. || echo [WARN] Could not pull — continuing with local version.

REM ── Kill anything on our ports ───────────────────────────────────────────────
for %%P in (8000 %PROXY_PORT% %STATUS_PORT%) do (
    for /f "tokens=5" %%i in ('netstat -ano 2^>nul ^| findstr ":%%P "') do (
        taskkill /f /pid %%i >nul 2>&1
    )
)

REM ── Start EmberArmor API ──────────────────────────────────────────────────────
echo [1/2] Starting EmberArmor enforcement API on port 8000...
cd /d "%EMBER_ARMOR_DIR%"
start "EmberArmor API" /min cmd /c "python -m uvicorn ember_armor.api.main:app --host 127.0.0.1 --port 8000 --log-level warning"

REM Wait until the API responds
echo       Waiting for API...
:wait_api
timeout /t 1 /nobreak >nul
curl -s -o nul -w "%%{http_code}" http://localhost:8000/api/v1/health 2>nul | findstr "200" >nul
if errorlevel 1 goto wait_api
echo [OK] EmberArmor API is ready.

REM ── Enable system proxy ───────────────────────────────────────────────────────
echo [2/2] Setting Windows system proxy...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /t REG_SZ /d "127.0.0.1:%PROXY_PORT%" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyOverride /t REG_SZ /d "localhost;127.0.0.1;<local>" /f >nul
echo [OK] System proxy active.

REM ── Open dashboard ────────────────────────────────────────────────────────────
start "" "http://localhost:%STATUS_PORT%"

echo.
echo  ======================================================
echo   Running! Close this window to stop.
echo  ======================================================
echo.

REM ── Run mitmproxy (blocks until closed) ──────────────────────────────────────
cd /d "%PROXY_DIR%"
mitmdump --listen-port %PROXY_PORT% --mode regular --scripts "%PROXY_DIR%addon.py" --quiet

REM ── Cleanup on exit ───────────────────────────────────────────────────────────
echo.
echo [Cleanup] Restoring system proxy...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f >nul
taskkill /f /im python.exe /fi "WINDOWTITLE eq EmberArmor API" >nul 2>&1
echo [OK] EmberArmor proxy stopped.
pause
