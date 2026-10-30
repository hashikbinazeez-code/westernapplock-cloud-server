@echo off
title Reset Western AppLock Fleet Devices
color 0C
cd /d "%~dp0"

echo ============================================================================
echo      RESET WESTERN APPLOCK FLEET DEVICES LIST
echo ============================================================================
echo.
echo  This tool removes all saved/offline/damaged tablets from the fleet list.
echo  Only tablets that are currently online and active will reconnect.
echo.
set /p confirm="Are you sure you want to clear the device fleet list? (Y/N): "
if /i "%confirm%" neq "Y" (
    echo [Canceled] No changes made.
    pause
    exit /b 0
)

echo [] > devices_state.json
echo.
echo [*] Devices list cleared! Restarting Cloud Server...
taskkill /F /IM cloudflared.exe 2>nul
taskkill /F /IM node.exe 2>nul
timeout /t 1 /nobreak >nul
start "" cmd /c "node server.js"
echo.
echo [DONE] Clean fleet list ready.
pause
