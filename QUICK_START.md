# 🚀 KAVACH Quick Start Guide

## ✅ Project Status

**Backend API Server**: ✅ Running on http://localhost:5001
**Frontend Dashboard**: ✅ Running on http://localhost:3000

## 🌐 Access Points

### Frontend Dashboard
- **URL**: http://localhost:3000
- **Features**:
  - Login/Signup pages
  - Live threat analysis dashboard
  - All API endpoints integrated
  - Enhanced chatbot
  - Real-time updates

### Backend API
- **URL**: http://localhost:5001
- **Health Check**: http://localhost:5001/health
- **API Docs**: http://localhost:5001/ (HTML page)

## 📋 Quick Start Steps

### Option 1: Use the Startup Script
```bash
# Double-click or run:
start_project.bat
```

### Option 2: Manual Start

**Terminal 1 - Backend:**
```bash
cd C:\Users\abdul\Desktop\kavach
python main.py
```

**Terminal 2 - Frontend:**
```bash
cd C:\Users\abdul\Desktop\kavach\dashboard
npm start
```

## 🔐 First Time Login

1. Open http://localhost:3000
2. Click "Sign up" to create an account
3. Enter:
   - Username
   - Email
   - Password (min 6 characters)
4. You'll be automatically logged in after signup

## 🎯 Dashboard Features

### Overview Tab
- Live threat analysis charts
- Real-time statistics
- Recent high-severity alerts

### Threats Tab
- All security alerts
- Threat trends visualization
- Severity distribution charts

### Honeytokens Tab
- View all honeytokens
- Plant new honeytokens
- Monitor breach status

### Metrics Tab
- Model performance metrics
- Radar charts for ML models
- Accuracy, precision, recall stats

### Activity Tab
- User activity timeline
- Risk score visualization
- Event details

### AI Assistant
- Click "💬 AI Assistant" button
- Ask questions about:
  - Security alerts
  - Threat analysis
  - Incident response
  - Model performance

## 🔧 Troubleshooting

### Backend Not Starting
```bash
# Check if port 5001 is in use
netstat -ano | findstr :5001

# Install missing dependencies
pip install -r requirements.txt
```

### Frontend Not Starting
```bash
cd dashboard
npm install --legacy-peer-deps
npm start
```

### CORS Issues
- Make sure backend is running on port 5001
- Check that Flask-CORS is installed
- Verify API URL in dashboard (default: http://localhost:5001)

### Authentication Issues
- Clear browser localStorage
- Check browser console for errors
- Verify backend auth endpoints are working

## 📊 API Endpoints

All endpoints are integrated in the dashboard:

- `GET /health` - Health check
- `POST /api/auth/login` - Login
- `POST /api/auth/register` - Register
- `POST /api/auth/verify` - Verify token
- `GET /api/alerts` - Get alerts
- `GET /api/threat-trends` - Get threat trends
- `GET /api/activity-timeline` - Get activity
- `GET /api/honeytokens` - Get honeytokens
- `POST /api/honeytokens/plant` - Plant honeytoken
- `GET /api/metrics` - Get metrics
- `POST /api/chat` - Chatbot
- `POST /api/predict` - Predict threat

## 🎨 Features

✅ **Live Threat Analysis** - Real-time charts updating every 10 seconds
✅ **All APIs Integrated** - Clickable methods for all endpoints
✅ **Login/Signup** - Full authentication system
✅ **Animations** - Smooth UI transitions and effects
✅ **Enhanced Chatbot** - AI assistant with full interface
✅ **Responsive Design** - Works on all devices

## 📝 Notes

- Backend loads models from cache (fast startup)
- Frontend auto-refreshes data every 10 seconds
- Chatbot uses the security_bot module
- All data is stored in SQLite databases in `data/` folder

Enjoy using KAVACH! 🛡️

