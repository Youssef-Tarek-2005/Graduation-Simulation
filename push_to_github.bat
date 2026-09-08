@echo off
title Push to GitHub
cd /d "%~dp0"
echo ========================================================
echo    Pushing Graduation Simulation to GitHub
echo ========================================================
echo.
echo Remote: https://github.com/Youssef-Tarek-2005/Graduation-Simulation.git
echo Branch: main
echo.
git push -u origin main
echo.
pause
