@echo off
setlocal enabledelayedexpansion
title EmberArmor Proxy — Windows Installer

echo.
echo  ======================================================
echo   EMBERARMOR PROXY — Windows Installer
echo  ======================================================
echo.

REM ── Install dir — everything goes here ──────────────────────────────────────
set INSTALL_DIR=%USERPROFILE%\EmberArmor
set REPO_URL=https://github.com/GrandMastaShake/EmberArmor.git

REM ── Check Python ─────────────────────────────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found.
    echo         Install Python 3.11+ from https://python.org and re-run.
    pause
    exit /b 1
)
echo [OK] Python found.

REM ── Check Git ────────────────────────────────────────────────────────────────
git --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Git not found.
    echo         Install Git from https://git-scm.com and re-run.
    pause
    exit /b 1
)
echo [OK] Git found.

REM ── Clone or update EmberArmor ───────────────────────────────────────────────
echo.
echo [1/5] Fetching EmberArmor from GitHub...
if exist "%INSTALL_DIR%\.git" (
    echo       Repo already exists — pulling latest...
    cd /d "%INSTALL_DIR%"
    git pull --quiet
) else (
    echo       Cloning to %INSTALL_DIR% ...
    git clone --quiet "%REPO_URL%" "%INSTALL_DIR%"
    if errorlevel 1 (
        echo.
        echo [ERROR] Clone failed.
        echo         The repo is private — you need to be logged in to GitHub.
        echo         Run:  gh auth login
        echo         Or set up a personal access token:
        echo         https://github.com/settings/tokens
        pause
        exit /b 1
    )
)
echo [OK] EmberArmor repo ready at %INSTALL_DIR%

REM ── Install Python dependencies ──────────────────────────────────────────────
echo.
echo [2/5] Installing Python dependencies...
cd /d "%INSTALL_DIR%"
pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo [WARN] requirements.txt install had issues — trying core deps directly...
    pip install fastapi uvicorn httpx mitmproxy --quiet
)
pip install mitmproxy httpx --quiet
echo [OK] Dependencies installed.

REM ── Generate mitmproxy CA cert ───────────────────────────────────────────────
echo.
echo [3/5] Generating mitmproxy CA certificate...
start /b mitmdump --listen-port 18081 --quiet
timeout /t 4 /nobreak >nul
taskkill /f /im mitmdump.exe >nul 2>&1

set CERT_PATH=%USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.cer
if not exist "%CERT_PATH%" (
    echo [ERROR] Could not generate mitmproxy cert.
    echo         Try running 'mitmdump' once manually in a terminal, then re-run this installer.
    pause
    exit /b 1
)
echo [OK] Certificate generated at %CERT_PATH%

REM ── Trust the cert in Windows ────────────────────────────────────────────────
echo.
echo [4/5] Installing cert into Windows Trusted Root store...
echo       (A UAC security prompt may appear — click Yes to trust the proxy cert)
certutil -addstore -f "Root" "%CERT_PATH%" >nul 2>&1
if errorlevel 1 (
    powershell -Command "Start-Process certutil -ArgumentList '-addstore -f Root \"%CERT_PATH%\"' -Verb RunAs -Wait"
)
echo [OK] Certificate trusted by Windows.

REM ── Write .env config ────────────────────────────────────────────────────────
echo.
echo [5/5] Writing config...
set ENV_FILE=%INSTALL_DIR%\ember_proxy\.env
if not exist "%ENV_FILE%" (
    (
        echo EMBER_ARMOR_DIR=%INSTALL_DIR%
        echo EMBER_API_KEY=ember-proxy-internal-key
        echo PROXY_PORT=8080
        echo STATUS_PORT=7070
        echo BLOCK_ON_UNSAFE=false
    ) > "%ENV_FILE%"
    echo [OK] Config written.
) else (
    echo [OK] Config already exists — not overwritten.
)

REM ── Write EMBER_API_KEY into EmberArmor .env if not present ─────────────────
set ARMOR_ENV=%INSTALL_DIR%\.env
if not exist "%ARMOR_ENV%" (
    (
        echo EMBER_API_KEY=ember-proxy-internal-key
        echo PERPLEXITY_API_KEY=
    ) > "%ARMOR_ENV%"
    echo [NOTE] Add your PERPLEXITY_API_KEY to %ARMOR_ENV%
)

REM ── Create desktop shortcut for start.bat ────────────────────────────────────
set SHORTCUT=%USERPROFILE%\Desktop\EmberArmor Proxy.lnk
powershell -Command ^
  "$s=(New-Object -COM WScript.Shell).CreateShortcut('%SHORTCUT%');^
   $s.TargetPath='%INSTALL_DIR%\ember_proxy\start.bat';^
   $s.WorkingDirectory='%INSTALL_DIR%\ember_proxy';^
   $s.IconLocation='%SystemRoot%\System32\shell32.dll,44';^
   $s.Description='Start EmberArmor Proxy';^
   $s.Save()" >nul 2>&1
echo [OK] Desktop shortcut created.

REM ── Done ────────────────────────────────────────────────────────────────────
echo.
echo  ======================================================
echo   Installation complete!
echo.
echo   Installed to: %INSTALL_DIR%
echo.
echo   Next steps:
echo     1. Add your PERPLEXITY_API_KEY to:
echo        %ARMOR_ENV%
echo     2. Double-click "EmberArmor Proxy" on your Desktop
echo        — or run: %INSTALL_DIR%\ember_proxy\start.bat
echo     3. Open http://localhost:7070 for the live dashboard
echo.
echo   To uninstall the proxy cert:
echo     certutil -delstore Root "mitmproxy"
echo  ======================================================
echo.
pause
