@echo off
echo ========================================
echo Starting KAVACH Project
echo ========================================
echo.

echo [1/2] Starting Backend API Server...
start "KAVACH Backend" cmd /k "cd /d %~dp0 && python main.py"
timeout /t 5 /nobreak >nul

echo [2/2] Starting Frontend Dashboard...
start "KAVACH Frontend" cmd /k "cd /d %~dp0\dashboard && npm start"
timeout /t 3 /nobreak >nul

echo.
echo ========================================
echo KAVACH is starting!
echo ========================================
echo.
echo Backend API: http://localhost:5001
echo Frontend Dashboard: http://localhost:3000
echo.
echo Press any key to exit this window...
pause >nul

