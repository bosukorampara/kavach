# KAVACH Dashboard - Frontend Setup Guide

## Features Implemented

✅ **Authentication System**
- Login page with username/password
- Signup page with email validation
- JWT token-based authentication
- Protected routes

✅ **Live Threat Analysis Dashboard**
- Real-time threat trends chart (updates every 10 seconds)
- Multiple chart types: Line, Bar, Doughnut, Radar
- Live statistics cards
- Animated data visualization

✅ **All API Endpoints Integrated**
- Overview tab with live threat analysis
- Threats tab with all alerts and charts
- Honeytokens tab with management interface
- Metrics tab with model performance
- Activity tab with user timeline
- Clickable methods for all endpoints

✅ **Enhanced UI/UX**
- Smooth animations (fade-in, slide-in, pulse)
- Modern gradient design
- Responsive layout
- Interactive charts
- Real-time updates

✅ **AI Chatbot Assistant**
- Full-screen modal interface
- Chat history
- Real-time responses
- Context-aware assistance
- Welcome message with capabilities

## Setup Instructions

### 1. Install Dependencies

```bash
cd dashboard
npm install
```

### 2. Configure API URL

Create a `.env` file in the dashboard directory:

```env
REACT_APP_API_URL=http://localhost:5001
```

### 3. Start Development Server

```bash
npm start
```

The dashboard will open at `http://localhost:3000`

## Project Structure

```
dashboard/
├── src/
│   ├── App.tsx              # Main app with routing
│   ├── App.css              # Global styles
│   ├── index.tsx            # Entry point
│   └── components/
│       ├── LoginPage.tsx    # Login component
│       ├── SignupPage.tsx   # Signup component
│       ├── Dashboard.tsx    # Main dashboard
│       ├── Dashboard.css    # Dashboard styles
│       └── Auth.css         # Auth page styles
├── public/
│   └── index.html
├── package.json
└── tsconfig.json
```

## Available Routes

- `/login` - Login page
- `/signup` - Registration page
- `/dashboard` - Main dashboard (protected)
- `/` - Redirects to dashboard

## Dashboard Tabs

1. **Overview** - Live threat analysis, stats, recent alerts
2. **Threats** - All alerts, threat trends, severity distribution
3. **Honeytokens** - Honeytoken management and monitoring
4. **Metrics** - Model performance metrics and charts
5. **Activity** - User activity timeline
6. **AI Assistant** - Chatbot for security assistance

## API Integration

All endpoints are integrated:
- `GET /api/alerts` - Fetch alerts
- `GET /api/threat-trends` - Get threat trends
- `GET /api/activity-timeline` - Get activity timeline
- `GET /api/honeytokens` - Get honeytokens
- `POST /api/honeytokens/plant` - Plant honeytoken
- `GET /api/metrics` - Get model metrics
- `POST /api/chat` - Chatbot endpoint
- `POST /api/auth/login` - User login
- `POST /api/auth/register` - User registration
- `POST /api/auth/verify` - Verify token

## Features

### Animations
- Fade-in animations for content
- Slide-in animations for cards
- Pulse animation for live status
- Smooth transitions on hover

### Charts
- Line charts for threat trends
- Doughnut charts for severity distribution
- Radar charts for model performance
- Real-time data updates

### Responsive Design
- Mobile-friendly layout
- Adaptive grid system
- Touch-friendly interactions

## Troubleshooting

### CORS Issues
Make sure the Flask backend has CORS enabled and the API URL is correct.

### Authentication Issues
- Check that JWT tokens are being stored in localStorage
- Verify the backend auth endpoints are working
- Check browser console for errors

### Chart Not Displaying
- Ensure Chart.js dependencies are installed
- Check browser console for errors
- Verify data is being fetched correctly

## Production Build

```bash
npm run build
```

This creates an optimized production build in the `build/` directory.

