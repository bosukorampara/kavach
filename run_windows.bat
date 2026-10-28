@echo off
setlocal enabledelayedexpansion

cd /d "%~dp0"

if not exist venv (
    echo [INFO] Creating virtual environment...
    python -m venv venv
)

echo [INFO] Activating virtual environment...
call venv\Scripts\activate.bat

echo [INFO] Installing dependencies...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

if exist ".env" (
    echo [INFO] Loading environment variables from .env
    for /f "usebackq tokens=* delims=" %%A in (".env") do (
        set "line=%%A"
        if not "!line!"=="" if not "!line:~0,1!"=="#" (
            set "line=!line:"=!"
            set "!line!"
        )
    )
) else (
    echo [WARN] .env file not found. Copy env.example to .env and adjust values.
)

echo [INFO] Starting KAVACH API...
python main.py

endlocal

