@echo off
title Push Western AppLock Server to GitHub
echo ==============================================================
echo  PUSHING WESTERN APPLOCK CLOUD SERVER TO GITHUB
echo ==============================================================
echo.
cd /d "D:\Last\3_Any_Network_Cloud_Server"
git branch -M main
git remote remove origin 2>nul
git remote add origin https://github.com/hashikbinazeez-code/westernapplock-cloud-server.git
echo Pushing to: https://github.com/hashikbinazeez-code/westernapplock-cloud-server.git
echo If a browser window opens, click 'Sign in with your browser' / 'Authorize'.
echo.
git push -u origin main
echo.
if %errorlevel% equ 0 (
    echo ==============================================================
    echo  [SUCCESS] Code successfully pushed to GitHub!
    echo ==============================================================
) else (
    echo [ERROR] Push failed. If authentication failed, please try again or drag-and-drop the files on github.com.
)
echo.
pause
