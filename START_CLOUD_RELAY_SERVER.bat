@echo off
title Western AppLock - 1-Click Cloud Relay Server [LIVE]
color 0B
cd /d "%~dp0"

echo ============================================================================
echo      WESTERN APPLOCK - HIGH-SPEED ANY-NETWORK CLOUD RELAY SERVER
echo              Western International Group IT Team - KSA
echo ============================================================================
echo.

:: 1. LOCATE NODE.JS RUNTIME
set "NODE_EXE="
if exist "C:\Program Files\nodejs\node.exe" (
    set "NODE_EXE=C:\Program Files\nodejs\node.exe"
    set "PATH=C:\Program Files\nodejs;%PATH%"
) else if exist "C:\Users\ThinkPad\ittrack\node.exe" (
    set "NODE_EXE=C:\Users\ThinkPad\ittrack\node.exe"
    set "PATH=C:\Users\ThinkPad\ittrack;%PATH%"
) else if exist "%~dp0node.exe" (
    set "NODE_EXE=%~dp0node.exe"
) else (
    where node >nul 2>nul
    if %errorlevel% equ 0 set "NODE_EXE=node"
)

if "%NODE_EXE%"=="" (
    color 0C
    echo [ERROR] Node.js runtime not found!
    echo Please install Node.js from https://nodejs.org/
    pause
    exit /b 1
)

:: 2. VERIFY CLOUDFLARE ENGINE
if not exist "cloudflared.exe" (
    echo [*] Downloading Cloudflare Tunnel Engine...
    powershell -NoProfile -Command "Invoke-WebRequest -Uri 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe' -OutFile 'cloudflared.exe'"
)

:: 3. CLEAN UP ANY OLD ORPHANED PROCESSES LOCKING PORT 8080
echo [*] Checking network ports and clearing previous instances...
powershell -NoProfile -Command "$ports = @(8080, 8254); foreach ($p in $ports) { $procs = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique; foreach ($procId in $procs) { if ($procId -and $procId -ne $PID) { Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue } } }"

:: 4. OPEN LIVE CLOUD PORTAL ONCE TUNNEL INITIALIZES (AFTER 3 SECONDS)
start "" powershell -NoProfile -Command "Start-Sleep -Seconds 3; Start-Process 'https://is.gd/westernintapplock'"

echo.
echo ============================================================================
echo  [+] SERVER ACTIVE & RUNNING (AUTO-SYNC ENABLED)
echo  [+] OFFICIAL PORTAL : https://is.gd/westernintapplock
echo  [+] MASTER ADMIN PIN: 7866  (Super Pass: Wf@3125210946)
echo ============================================================================
echo  [!] Keep this window open or minimized.
echo.

:SERVER_LOOP
"%NODE_EXE%" server.js
echo.
echo [!] Server process exited. Restarting automatically in 2 seconds...
timeout /t 2 /nobreak >nul
goto SERVER_LOOP
