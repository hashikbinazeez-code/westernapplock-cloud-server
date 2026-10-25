@echo off
title Enable Auto-Start on Laptop Restart
color 0A
cd /d "%~dp0"

set "STARTUP_DIR=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
set "SHORTCUT_BAT=%STARTUP_DIR%\Western_Cloud_Server_AutoStart.bat"

(
echo @echo off
echo cd /d "%~dp0"
echo start /min "" cmd /c "node server.js"
) > "%SHORTCUT_BAT%"

echo ============================================================================
echo  [SUCCESS] AUTO-START ON LAPTOP RESTART IS NOW ENABLED!
echo ============================================================================
echo.
echo  Whenever your laptop restarts and logs into Windows:
echo  1. The Western Cloud Relay Server will start automatically in the background.
echo  2. It will generate a fresh HTTPS tunnel link and automatically send it to
echo     all your tablets over the internet within 5 seconds!
echo  3. Simply open http://localhost:3000 in your browser (PIN: 2580) anytime!
echo.
pause
