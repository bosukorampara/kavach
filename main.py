"""
KAVACH - AI-Driven Threat and Anomaly Detection System
Main entry point
"""

import os
import sys
from dotenv import load_dotenv
from api.app import create_app

# Load environment variables
load_dotenv()

def main():
    """Run KAVACH system"""
    print("=" * 60)
    print("KAVACH - AI-Driven Threat and Anomaly Detection System")
    print("=" * 60)
    
    # Create Flask app
    app = create_app()
    
    # Get configuration
    host = os.getenv('FLASK_HOST', '0.0.0.0')
    port = int(os.getenv('FLASK_PORT', 5001))  # Changed to 5001 to avoid conflict with AirPlay
    # Override port 5000 if it's in use (common on macOS with AirPlay)
    if port == 5000:
        port = 5001
        print("Note: Port 5000 is in use, switching to port 5001")
    debug = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
    
    print(f"\nStarting KAVACH API server...")
    print(f"Host: {host}")
    print(f"Port: {port}")
    print(f"Debug: {debug}")
    print("\nAPI Endpoints:")
    print("  GET  /health              - Health check")
    print("  POST /api/predict         - Predict threat")
    print("  GET  /api/alerts          - Get alerts")
    print("  GET  /api/honeytokens     - Get honeytokens")
    print("  POST /api/honeytokens/plant - Plant honeytoken")
    print("  GET  /api/metrics         - Get model metrics")
    print("  GET  /api/threat-trends   - Get threat trends")
    print("  GET  /api/activity-timeline - Get activity timeline")
    print("\nPress Ctrl+C to stop")
    print("=" * 60)
    
    # Run app
    app.run(host=host, port=port, debug=debug)

if __name__ == '__main__':
    main()

