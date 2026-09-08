@echo off
title Flask AI Backend
cd /d "%~dp0files"
echo Starting Flask AI backend server on http://127.0.0.1:5000 ...
"..\.venv\Scripts\python.exe" app.py
pause
