@echo off
title AI Intrusion Detection & Simulation System
cls
echo =======================================================
echo    Starting AI Intrusion Detection & Simulation Lab
echo =======================================================
echo.

echo [1/2] Launching Backend Flask AI Server (Port 5000)...
start "Flask AI Backend" cmd /k "cd /d "%~dp0files" && "..\.venv\Scripts\python.exe" app.py"

echo Waiting for backend initialization...
timeout /t 3 >nul

echo [2/2] Launching React UI Dashboard (Vite)...
start "React UI Frontend" cmd /k "cd /d "%~dp0files\CUsersg3295OneDriveDocumentsGraduation Simulataionreact-ui" && npm.cmd run dev"

echo.
echo =======================================================
echo  Servers are starting in separate windows!
echo   - Backend:  http://127.0.0.1:5000
echo   - Frontend: http://localhost:5173
echo =======================================================
echo.
echo You can keep this window open or close it.
pause
