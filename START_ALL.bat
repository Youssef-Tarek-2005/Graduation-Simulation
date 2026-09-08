@echo off
title AI Intrusion-Detection Simulation Dashboard
cd /d "%~dp0"
echo ========================================================
echo    AI Intrusion-Detection & Threat Simulation Lab
echo ========================================================
echo.
echo Starting dashboard and AI simulation server...
echo.
echo Access URL: http://127.0.0.1:5000
echo.
start http://127.0.0.1:5000
node run_dashboard.cjs
pause
