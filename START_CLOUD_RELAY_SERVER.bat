@echo off
title Western AppLock - 1-Click Any-Network Cloud Server (Auto-Sync Enabled)
color 0B
cd /d "%~dp0"

echo ============================================================================
echo    WESTERN APPLOCK - 1-CLICK ANY-NETWORK CLOUD SERVER (AUTO-SYNC)
echo ============================================================================
echo.
echo  [!] ZERO CONFIGURATION NEEDED:
echo      1. Even if your Laptop restarts or Tablet changes Wi-Fi/SIM card,
echo         this server automatically generates a free HTTPS link and sends it
echo         to all your tablets over the internet automatically!
echo      2. Your browser will open automatically to http://localhost:8080
echo         (Access Code: 7866)
echo.

where node >nul 2>nul
if %errorlevel% neq 0 (
    if exist "C:\Program Files\nodejs\node.exe" (
        set "PATH=C:\Program Files\nodejs;%PATH%"
    ) else (
        color 0C
        echo [ERROR] Node.js is not installed on this PC.
        echo Please install Node.js from https://nodejs.org/ and run this script again.
        pause
        exit /b 1
    )
)

if not exist "cloudflared.exe" (
    echo [*] Downloading Cloudflare Free HTTPS Tunnel Engine - One-Time Setup...
    powershell -Command "Invoke-WebRequest -Uri 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe' -OutFile 'cloudflared.exe'"
)

echo [*] Opening Web Control Dashboard in your browser...
start "" "http://localhost:8080"

echo [*] Starting Cloud Relay Server + Automatic Tablet Sync...
node server.js
pause
