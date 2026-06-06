@echo off
title EmberArmor Proxy — Stopping

echo Stopping EmberArmor Proxy...

REM Kill mitmproxy and API
taskkill /f /im mitmdump.exe >nul 2>&1
taskkill /f /im python.exe /fi "WINDOWTITLE eq EmberArmor API" >nul 2>&1

REM Disable system proxy
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f >nul

echo [OK] Proxy stopped and system proxy restored.
timeout /t 2 /nobreak >nul
