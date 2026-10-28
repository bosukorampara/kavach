# KAVACH

AI-driven threat and anomaly detection: ML classifiers, UEBA, honeytokens, a Flask API, and a React dashboard.

This guide is enough to clone the repo and run the full stack on a new machine (macOS, Linux, or Windows).

---

## What you will run

| Piece | URL | Role |
|---|---|---|
| Flask API | http://localhost:5001 | Predictions, auth, alerts, dashboard data |
| React dashboard | http://localhost:3001 | Login, charts, honeytokens, AI assistant |

Keep **two terminals** open: one for the API, one for the dashboard.

---

## Prerequisites

Install these first.

1. **Python 3.10 or newer** (3.11/3.12 recommended)
   - Check: `python3 --version`
2. **Node.js 18 or newer** and npm
   - Check: `node --version` and `npm --version`
3. **Git**
4. About **2–4 GB** disk for Python packages (PyTorch is the large one)

Optional: a GPU is **not** required. The autoencoder uses CPU if no GPU is present.

---

## 1. Clone the repository

```bash
git clone https://github.com/bosukorampara/kavach.git
cd kavach
```

---

## 2. Configure environment files

Do **not** commit real secrets. Copy the examples:

```bash
cp env.example .env
cp dashboard/.env.example dashboard/.env
```

On Windows (Command Prompt):

```bat
copy env.example .env
copy dashboard\.env.example dashboard\.env
```

You can leave the default values. Important defaults:

- API port: **5001** (`FLASK_PORT`)
- Dashboard port: **3001** (`PORT` in `dashboard/.env`)
- API URL the UI calls: `http://localhost:5001`

On macOS, port **5000** is often taken by AirPlay Receiver. Do not switch the API back to 5000 unless you know that port is free.

---

## 3. Backend (Flask API)

From the **project root** (`kavach/`):

### Create and activate a virtual environment

**macOS / Linux:**

```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows (Command Prompt):**

```bat
python -m venv venv
venv\Scripts\activate
```

**Windows (PowerShell):**

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
```

If PowerShell blocks scripts, run:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

### Install Python packages

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

The first install can take several minutes because of `torch` and `scikit-learn`.

### Start the API

```bash
python main.py
```

Wait until you see that the server is listening. Then in a browser or another terminal:

```bash
curl http://localhost:5001/health
```

You should get JSON with `"status": "healthy"`. You can also open http://localhost:5001 in a browser.

Leave this terminal running.

**First boot:** if `models/` has no saved files yet, the API trains models on synthetic data. That can take a few minutes. Later starts load cached files from `models/` and are faster.

---

## 4. Seed sample data (so charts are not empty)

The dashboard reads SQLite files under `data/`. An empty database shows **“No data yet.”**

With the **same venv activated**, from the project root (API may already be running in the other terminal):

```bash
python -m utils.data_generator --seed-threats --days 7
```

This writes roughly two thousand synthetic events into `data/audit_trail.db`.

Optional extra load (bursts for UEBA-style patterns):

```bash
python -m utils.data_generator --simulate-bursts
```

You can also seed after the API is up:

```bash
curl -X POST "http://localhost:5001/api/testcases/seed?days=7"
```

---

## 5. Frontend (React dashboard)

Open a **second** terminal. Do not stop the API.

```bash
cd dashboard
cp .env.example .env
npm install
npm start
```

Windows if `cp` is missing:

```bat
cd dashboard
copy .env.example .env
npm install
npm start
```

If `npm install` fails on peer dependencies:

```bash
npm install --legacy-peer-deps
npm start
```

The app is set to **port 3001**. The browser should open http://localhost:3001. If it asks to use another port, choose a free one and keep `REACT_APP_API_URL=http://localhost:5001`.

---

## 6. Create an account and open the dashboard

1. Open http://localhost:3001
2. Use **Sign up** (username, email, password at least 6 characters)
3. You are logged in and sent to http://localhost:3001/dashboard
4. If charts are still empty, run the seed command in step 4, then refresh

---

## Daily workflow (after the first setup)

**Terminal 1 — API**

```bash
cd kavach
source venv/bin/activate    # Windows: venv\Scripts\activate
python main.py
```

**Terminal 2 — dashboard**

```bash
cd kavach/dashboard
npm start
```

You do **not** need to reinstall packages or re-seed unless you deleted `venv/`, `dashboard/node_modules/`, or `data/*.db`.

---

## Project layout (what matters)

```
kavach/
├── main.py                 # start the API
├── requirements.txt
├── env.example             # copy to .env
├── api/                    # Flask routes
├── core/                   # ML + honeytokens + streaming
├── ueba/                   # behavior analytics
├── chatbot/                # security assistant
├── utils/                  # data generator, DBs, catalog
├── models/                 # saved ML artifacts (created/updated on train)
├── data/                   # SQLite (created locally, not required in git)
├── dashboard/              # React UI
│   ├── package.json
│   └── .env.example
└── tests/
```

---

## Useful API checks

Health:

```bash
curl http://localhost:5001/health
```

Example prediction:

```bash
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

Main routes:

- `GET /health`
- `POST /api/auth/register` and `POST /api/auth/login`
- `POST /api/predict`
- `GET /api/alerts`
- `GET /api/honeytokens` and `POST /api/honeytokens/plant`
- `GET /api/metrics`
- `GET /api/threat-trends`
- `GET /api/activity-timeline`
- `POST /api/chat`
- `GET /api/dashboard/threat-trends` (and related dashboard endpoints)

---

## Troubleshooting

| Problem | What to do |
|---|---|
| `ModuleNotFoundError` | Activate `venv`, then `pip install -r requirements.txt` |
| `python` not found | Use `python3` |
| Port 5001 already in use | Stop the other process, or set `FLASK_PORT` in `.env` and `REACT_APP_API_URL` in `dashboard/.env` to the same host:port |
| Dashboard “API not available” / empty charts | API must be running on 5001. Confirm `/health`. Then seed data (step 4) and refresh |
| `npm` errors | Node 18+, then `npm install --legacy-peer-deps` |
| Login fails | API must be up. Sign up a new user. Clear site data for localhost:3001 if an old token is stuck |
| Charts still empty after seed | Seed writes `data/audit_trail.db` in the **project root**. Run the seed command from `kavach/`, not from `dashboard/` |
| macOS “operation not permitted” on `./run.sh` | Skip the script; use `source venv/bin/activate` and `python main.py` |
| First API start is slow | Normal while models train. Watch the terminal until “Starting KAVACH API server” |

---

## Optional extras

- **Demo / retrain:** `python demo.py`
- **Kafka:** set `KAFKA_ENABLED=True` in `.env` only if you have a broker. Default is off; a simulator exists under `core/streaming/`
- **Tests:** `python -m pytest tests/ -v` (install pytest if needed: `pip install pytest`)

---

## License

MIT
