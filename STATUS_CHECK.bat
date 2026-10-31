@echo off
title Western AppLock Server Status
color 0B
echo ==============================================================
echo       WESTERN APPLOCK CLOUD SERVER STATUS CHECK
echo ==============================================================
echo.
powershell -Command "$node = Get-Process node -ErrorAction SilentlyContinue; $cf = Get-Process cloudflared -ErrorAction SilentlyContinue; if ($node -and $cf) { Write-Host ' [OK] Server & Cloudflare Tunnel are RUNNING!' -ForegroundColor Green } elseif ($node) { Write-Host ' [!] Node server running, tunnel starting...' -ForegroundColor Yellow } else { Write-Host ' [OFFLINE] Server is NOT running. Double-click START_SERVER.bat' -ForegroundColor Red }"
echo.
if exist "CURRENT_PUBLIC_HTTPS_LINK.txt" (
  echo Current Live Public Cloud URL:
  type CURRENT_PUBLIC_HTTPS_LINK.txt
)
echo.
echo Live Cloud Portal: https://is.gd/westernintapplock
echo Access PIN: 7866
echo.
pause
