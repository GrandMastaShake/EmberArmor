@echo off
setlocal enabledelayedexpansion
title EmberArmor Proxy

echo.
echo  ======================================================
echo   EMBERARMOR PROXY — Starting up...
echo  ======================================================
echo.

REM ── Paths — edit EMBER_ARMOR_DIR if your repo is elsewhere ──────────────────
set SCRIPT_DIR=%~dp0
set EMBER_ARMOR_DIR=%SCRIPT_DIR%..\EmberArmor
set PROXY_DIR=%SCRIPT_DIR%

REM ── Load .env ────────────────────────────────────────────────────────────────
set EMBER_API_KEY=ember-proxy-internal-key
set PROXY_PORT=8080
set STATUS_PORT=7070

if exist "%PROXY_DIR%.env" (
    for /f "usebackq tokens=1,2 delims==" %%A in ("%PROXY_DIR%.env") do (
        set %%A=%%B
    )
)

REM ── Check EmberArmor repo exists ─────────────────────────────────────────────
if not exist "%EMBER_ARMOR_DIR%\ember_armor\api\main.py" (
    echo [ERROR] EmberArmor not found at %EMBER_ARMOR_DIR%
    echo         Edit EMBER_ARMOR_DIR in this script to point to your repo.
    pause
    exit /b 1
)

REM ── Kill anything on our ports ───────────────────────────────────────────────
for %%P in (8000 %PROXY_PORT% %STATUS_PORT%) do (
    for /f "tokens=5" %%i in ('netstat -ano ^| findstr ":%%P " 2^>nul') do (
        taskkill /f /pid %%i >nul 2>&1
    )
)

REM ── Start EmberArmor API (background) ───────────────────────────────────────
echo [1/2] Starting EmberArmor enforcement API on port 8000...
start "EmberArmor API" /min cmd /c "cd /d %EMBER_ARMOR_DIR% && python -m uvicorn ember_armor.api.main:app --host 127.0.0.1 --port 8000 --log-level warning 2>&1"

REM Wait for it to be ready
echo       Waiting for API to be ready...
:wait_api
timeout /t 1 /nobreak >nul
curl -s -o nul http://localhost:8000/api/v1/health >nul 2>&1
if errorlevel 1 goto wait_api
echo [OK] EmberArmor API is up.

REM ── Set system proxy ─────────────────────────────────────────────────────────
echo [2/2] Setting Windows system proxy to localhost:%PROXY_PORT%...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /t REG_SZ /d "127.0.0.1:%PROXY_PORT%" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyOverride /t REG_SZ /d "localhost;127.0.0.1;<local>" /f >nul
echo [OK] System proxy set.

REM ── Launch mitmproxy with addon ───────────────────────────────────────────────
echo.
echo  ======================================================
echo   EmberArmor Proxy is running!
echo.
echo   Dashboard  →  http://localhost:%STATUS_PORT%
echo   API        →  http://localhost:8000
echo   Proxy      →  127.0.0.1:%PROXY_PORT%
echo.
echo   Close this window to stop the proxy.
echo   (System proxy will be restored automatically)
echo  ======================================================
echo.

REM Open dashboard in browser
start "" "http://localhost:%STATUS_PORT%"

REM Run mitmproxy — this blocks until closed
mitmdump --listen-port %PROXY_PORT% --mode regular --ssl-insecure --scripts "%PROXY_DIR%addon.py" --quiet

REM ── Cleanup on exit ──────────────────────────────────────────────────────────
echo.
echo [Cleanup] Restoring system proxy settings...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f >nul
echo [OK] Proxy disabled. EmberArmor stopped.
echo.
pause
