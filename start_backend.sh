#!/bin/bash
# Start KAVACH backend API server

cd "$(dirname "$0")"

# Activate virtual environment
if [ -d "venv" ]; then
    source venv/bin/activate
else
    echo "Error: Virtual environment not found. Run setup first."
    exit 1
fi

# Start the server
echo "Starting KAVACH API server on port 5001..."
python main.py

