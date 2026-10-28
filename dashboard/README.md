# KAVACH Dashboard

React-based dashboard for KAVACH Threat Detection System.

## Setup

1. Install dependencies:
```bash
npm install
```

2. Start the development server:
```bash
npm start
```

The dashboard will be available at http://localhost:3000

## Features

- Real-time threat trends visualization
- User activity timeline
- Alert list with severity levels
- Risk scoring visualization
- AI Chatbot assistant integration

## Building for Production

```bash
npm run build
```

The `build` folder will contain the production-ready files.

## API Endpoints Used

- GET `/api/alerts` - Fetch all alerts
- GET `/api/threat-trends` - Fetch threat trends data
- GET `/api/activity-timeline` - Fetch activity timeline
- POST `/api/chat` - Chatbot interaction

## Configuration

Update `src/config.js` to point to your KAVACH API endpoint.


