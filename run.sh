#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

if [ ! -d "venv" ]; then
  echo "[INFO] Creating virtual environment..."
  python -m venv venv
fi

echo "[INFO] Activating virtual environment..."
source venv/bin/activate

echo "[INFO] Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

if [ -f ".env" ]; then
  echo "[INFO] Loading environment variables from .env"
  set -a
  # shellcheck source=/dev/null
  source .env
  set +a
else
  echo "[WARN] .env file not found. Copy env.example to .env and adjust values."
fi

echo "[INFO] Starting KAVACH API..."
python main.py

