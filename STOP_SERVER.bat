@echo off
title Stop Western AppLock Server
color 0E
echo Stopping Western AppLock Server and Cloudflare Tunnel...
taskkill /F /IM cloudflared.exe 2>nul
taskkill /F /IM node.exe 2>nul
echo.
echo [DONE] Server and Tunnel stopped successfully.
pause
