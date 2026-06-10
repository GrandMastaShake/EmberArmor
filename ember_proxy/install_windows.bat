@echo off
setlocal enabledelayedexpansion
title EmberArmor Proxy — Windows Installer

echo.
echo  ======================================================
echo   EMBERARMOR PROXY -- Windows Installer
echo  ======================================================
echo.

REM ── Install dir ──────────────────────────────────────────────────────────────
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
    echo       Repo already exists -- pulling latest...
    cd /d "%INSTALL_DIR%"
    git pull --quiet
) else (
    echo       Cloning to %INSTALL_DIR% ...
    git clone --quiet "%REPO_URL%" "%INSTALL_DIR%"
    if errorlevel 1 (
        echo.
        echo [ERROR] Clone failed. The repo is private.
        echo         Make sure you are logged in to GitHub via git credential manager,
        echo         or set up a personal access token at:
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

REM Install from pyproject.toml if pip supports it, otherwise install deps directly
pip install -e . --quiet --disable-pip-version-check >nul 2>&1
if errorlevel 1 (
    echo       Falling back to direct dependency install...
    pip install fastapi "uvicorn[standard]" pydantic pydantic-settings ^
        prometheus-client structlog httpx python-multipart ^
        "python-jose[cryptography]" --quiet --disable-pip-version-check
)
pip install mitmproxy --quiet --disable-pip-version-check
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
    echo         Try running 'mitmdump' once manually in a terminal, then re-run.
    pause
    exit /b 1
)
echo [OK] Certificate generated.

REM ── Trust the cert in Windows ────────────────────────────────────────────────
echo.
echo [4/5] Installing cert into Windows Trusted Root store...
echo       (A UAC prompt may appear -- click Yes)
certutil -addstore -f "Root" "%CERT_PATH%" >nul 2>&1
if errorlevel 1 (
    powershell -Command "Start-Process -FilePath certutil -ArgumentList @('-addstore', '-f', 'Root', '%CERT_PATH%') -Verb RunAs -Wait"
)
echo [OK] Certificate trusted by Windows.

REM ── Write proxy .env config ──────────────────────────────────────────────────
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
    echo [OK] Config already exists -- not overwritten.
)

REM ── Write EmberArmor .env if not present ─────────────────────────────────────
set ARMOR_ENV=%INSTALL_DIR%\.env

echo.
echo  -- API Key Setup --
echo.
echo  Your Perplexity API key powers the Sonar consensus agent in EmberArmor.
echo  Get one at: https://www.perplexity.ai/settings/api
echo.
set /p PPLX_KEY=  Paste your Perplexity API key and press Enter: 

REM Strip accidental quotes
set PPLX_KEY=%PPLX_KEY:"=%

REM Always write fresh .env so key is applied even on re-runs
(
    echo EMBER_API_KEY=ember-proxy-internal-key
    echo PERPLEXITY_API_KEY=%PPLX_KEY%
) > "%ARMOR_ENV%"

if not "%PPLX_KEY%"=="" (
    echo [OK] Perplexity API key saved to %ARMOR_ENV%
) else (
    echo [WARN] No key entered -- add PERPLEXITY_API_KEY manually to %ARMOR_ENV%
)

REM ── Create desktop shortcut via a temp VBScript (reliable on all Windows) ────
set SHORTCUT_PATH=%USERPROFILE%\Desktop\EmberArmor Proxy.lnk
set TARGET_PATH=%INSTALL_DIR%\ember_proxy\start.bat
set VBS_FILE=%TEMP%\make_shortcut.vbs

(
    echo Set oShell = CreateObject("WScript.Shell"^)
    echo Set oLink = oShell.CreateShortcut("%SHORTCUT_PATH%"^)
    echo oLink.TargetPath = "%TARGET_PATH%"
    echo oLink.WorkingDirectory = "%INSTALL_DIR%\ember_proxy"
    echo oLink.Description = "Start EmberArmor Proxy"
    echo oLink.IconLocation = "%SystemRoot%\System32\shell32.dll, 44"
    echo oLink.Save
) > "%VBS_FILE%"

cscript //nologo "%VBS_FILE%" >nul 2>&1
del "%VBS_FILE%" >nul 2>&1

if exist "%SHORTCUT_PATH%" (
    echo [OK] Desktop shortcut created.
) else (
    echo [WARN] Shortcut creation failed -- launch manually from:
    echo        %TARGET_PATH%
)

REM ── Done ────────────────────────────────────────────────────────────────────
echo.
echo  ======================================================
echo   Installation complete!
echo.
echo   Installed to: %INSTALL_DIR%
echo.
echo   Next steps:
echo     1. Double-click "EmberArmor Proxy" on your Desktop
echo        -- or run: %TARGET_PATH%
echo     2. Open http://localhost:7070 for the live dashboard
echo.
echo   (If you skipped the API key, add PERPLEXITY_API_KEY to %ARMOR_ENV%)
echo.
echo   To uninstall the proxy cert later:
echo     certutil -delstore Root "mitmproxy"
echo  ======================================================
echo.
pause
