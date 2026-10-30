@echo off
title Western AppLock - 1-Click Any-Network Cloud Server
color 0B
cd /d "%~dp0"

echo ============================================================================
echo      WESTERN APPLOCK - 1-CLICK CLOUD RELAY SERVER (AUTO-SYNC)
echo ============================================================================
echo.
echo  [!] ZERO CONFIGURATION NEEDED:
echo      - Automatically creates free HTTPS Cloudflare tunnel
echo      - Automatically syncs link to all tablets worldwide
echo      - Opens Cloud Portal: https://is.gd/westernintapplock (Code: 7866)
echo.

where node >nul 2>nul
if %errorlevel% neq 0 (
    if exist "C:\Program Files\nodejs\node.exe" (
        set "PATH=C:\Program Files\nodejs;%PATH%"
    ) else (
        color 0C
        echo [ERROR] Node.js is not installed on this PC.
        echo Please install Node.js from https://nodejs.org/ and run again.
        pause
        exit /b 1
    )
)

if not exist "cloudflared.exe" (
    echo [*] Downloading Cloudflare Tunnel Engine...
    powershell -Command "Invoke-WebRequest -Uri 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe' -OutFile 'cloudflared.exe'"
)

echo [*] Opening Live Cloud Portal in your browser...
start "" "https://is.gd/westernintapplock"

echo [*] Starting Cloud Server... (Keep this window open or minimized)
node server.js
pause
