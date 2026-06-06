@echo off
setlocal enabledelayedexpansion
title EmberArmor Proxy — Windows Installer

echo.
echo  ======================================================
echo   EMBERARMOR PROXY — Windows Installer
echo  ======================================================
echo.

REM ── Check Python ────────────────────────────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.11+ from python.org and re-run.
    pause
    exit /b 1
)
echo [OK] Python found.

REM ── Install Python dependencies ─────────────────────────────────────────────
echo.
echo [1/4] Installing Python dependencies...
pip install mitmproxy httpx uvicorn fastapi 2>&1 | findstr /v "already satisfied"
if errorlevel 1 (
    echo [ERROR] pip install failed. Check your internet connection.
    pause
    exit /b 1
)
echo [OK] Dependencies installed.

REM ── Generate mitmproxy CA cert ──────────────────────────────────────────────
echo.
echo [2/4] Generating mitmproxy CA certificate...
REM Run mitmdump briefly to generate the cert, then kill it
start /b mitmdump --listen-port 18080 --quiet
timeout /t 3 /nobreak >nul
taskkill /f /im mitmdump.exe >nul 2>&1

REM Locate the generated cert
set CERT_PATH=%USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.cer
if not exist "%CERT_PATH%" (
    echo [ERROR] Could not find mitmproxy cert at %CERT_PATH%
    echo         Try running 'mitmdump' manually once, then re-run this installer.
    pause
    exit /b 1
)
echo [OK] Cert found at %CERT_PATH%

REM ── Trust the cert in Windows ────────────────────────────────────────────────
echo.
echo [3/4] Installing cert into Windows Trusted Root store...
echo       (You may see a UAC / security prompt — click Yes)
certutil -addstore -f "Root" "%CERT_PATH%" >nul 2>&1
if errorlevel 1 (
    echo [WARN] certutil failed — trying with elevated privileges...
    powershell -Command "Start-Process certutil -ArgumentList '-addstore -f Root \"%CERT_PATH%\"' -Verb RunAs -Wait"
)
echo [OK] Certificate trusted.

REM ── Create .env for EmberArmor ───────────────────────────────────────────────
echo.
echo [4/4] Writing EmberArmor proxy config...
set ENV_FILE=%~dp0..\ember_proxy\.env
(
    echo EMBER_API_KEY=ember-proxy-internal-key
    echo EMBER_PROXY_PORT=8080
    echo EMBER_STATUS_PORT=7070
    echo BLOCK_ON_UNSAFE=false
) > "%ENV_FILE%"
echo [OK] Config written to %ENV_FILE%

REM ── Done ────────────────────────────────────────────────────────────────────
echo.
echo  ======================================================
echo   Installation complete!
echo.
echo   Next steps:
echo     1. Double-click  start.bat  to launch EmberArmor
echo     2. Open http://localhost:7070 for the live dashboard
echo     3. Use your AI tools normally — everything is monitored
echo.
echo   To uninstall the proxy cert:
echo     certutil -delstore Root "mitmproxy"
echo  ======================================================
echo.
pause
