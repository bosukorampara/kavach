## KAVACH Run Guide

### 1. Environment Setup
- Copy `env.example` to `.env` and adjust values (model paths, DBs, ports).
- Option A (macOS/Linux): `./run.sh`
- Option B (Windows): `run_windows.bat`
- Manual steps:
  1. `python -m venv venv`
  2. `source venv/bin/activate` (or `venv\Scripts\activate` on Windows)
  3. `pip install --upgrade pip && pip install -r requirements.txt`
  4. `python main.py`

### 2. Starting the API Server
```
python main.py
```
The server auto-loads cached models from `models/` or trains new ones on first boot. Default host/port: `0.0.0.0:5001`.

### 3. Key API Endpoints
- `GET /health`
- `POST /api/predict`
- `GET /api/alerts`
- `GET /api/honeytokens`
- `POST /api/honeytokens/plant`
- `GET /api/metrics`
- `GET /api/threat-trends`
- `GET /api/activity-timeline`
- `POST /api/chat`

Example prediction request:
```
curl -X POST http://localhost:5001/api/predict \
  -H "Content-Type: application/json" \
  -d '{
        "user_id": "user_42",
        "bytes_transferred": 120000,
        "request_count": 75,
        "activity_type": "api_call",
        "source_ip": "192.168.1.50",
        "destination_ip": "10.0.0.5",
        "user_role": "admin",
        "location": "US"
      }'
```

To trigger honeytoken alerts, include either `honeytoken_id` or `honeytoken_value` from `/api/honeytokens` in the payload.

### 4. Demo / Training Script
Run the feature showcase (re-trains models with fresh synthetic data):
```
python demo.py
```

### 5. Streaming Simulator / Kafka
- Real Kafka: set `KAFKA_ENABLED=True` in `.env`, update broker details, then use `core/streaming/kafka_stream.py`.
- Simulation: use `StreamingSimulator` in `core/streaming/streaming_simulator.py` to feed `StreamProcessor` without Kafka.

### 6. Dashboard (Optional UI)
```
cd dashboard
npm install
npm start
```
The React dashboard connects to the Flask API (configure host/port via `.env`).

### 7. Testing the API
After starting the server, you can test endpoints using the provided test script:
```bash
# Install requests for testing (optional)
pip install requests

# Run test suite
python test_api.py
```

This will test:
- Health check endpoint
- Prediction endpoint
- Honeytoken planting and retrieval
- Alerts endpoint
- Metrics endpoint

### 8. GPU / PyTorch
- The UEBA autoencoder uses PyTorch. Install `torch` with GPU support if available; otherwise CPU wheels work.
- If PyTorch is missing, the API automatically disables autoencoder features but all other components remain functional.

