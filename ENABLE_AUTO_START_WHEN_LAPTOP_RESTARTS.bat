@echo off
title Enable Auto-Start on Laptop Boot
color 0A
cd /d "%~dp0"

set "STARTUP_DIR=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
set "SHORTCUT_BAT=%STARTUP_DIR%\Western_Cloud_Server_AutoStart.bat"

set "TARGET_DIR=%~dp0"
if "%TARGET_DIR:~-1%"=="\" set "TARGET_DIR=%TARGET_DIR:~0,-1%"

(
echo @echo off
echo cd /d "%TARGET_DIR%"
echo start "Western Cloud Server" /min node server.js
) > "%SHORTCUT_BAT%"

echo ============================================================================
echo  [SUCCESS] AUTO-START ON LAPTOP RESTART IS ENABLED!
echo ============================================================================
echo.
echo  Whenever this laptop restarts and logs into Windows:
echo  1. Western Cloud Server will start automatically in the background.
echo  2. It generates a live HTTPS tunnel and connects tablets automatically!
echo  3. Live Cloud Portal: https://is.gd/westernintapplock (PIN: 7866)
echo.
pause
