"""
Flask API for KAVACH Threat Detection System
"""

from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import os
import logging
from datetime import datetime, timedelta
from pathlib import Path
import traceback
import pandas as pd
import numpy as np
import sqlite3
import json

from core.models.breach_detector import BreachDetector
from core.models.anomaly_detector import AnomalyDetector
from core.deception.honeytoken_monitor import HoneytokenMonitor
from utils.data_generator import generate_sample_data
from utils.event_storage import event_storage
from ueba.behavior_analyzer import BehaviorAnalyzer
from api.auth import auth_manager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Try to import autoencoder (optional)
try:
    from ueba.autoencoder_ueba import AutoencoderUEBA
    HAS_AUTOENCODER = True
except ImportError:
    HAS_AUTOENCODER = False
    logger.warning("Autoencoder UEBA not available (PyTorch may not be installed)")

# Allow disabling autoencoder startup/training with env var to speed local dev
if os.getenv('DISABLE_AUTOENCODER', '').lower() in ('1', 'true', 'yes'):
    HAS_AUTOENCODER = False
    logger.info("Autoencoder UEBA disabled via DISABLE_AUTOENCODER environment variable")


def create_app():
    """Create and configure Flask app"""
    app = Flask(__name__)
    CORS(app)
    
    model_dir = Path(os.getenv('MODEL_DIR', 'models'))
    model_dir.mkdir(parents=True, exist_ok=True)
    
    breach_detector = BreachDetector()
    anomaly_detector = AnomalyDetector()
    honeytoken_monitor = HoneytokenMonitor()
    behavior_analyzer = BehaviorAnalyzer()
    
    autoencoder_ueba = None
    if HAS_AUTOENCODER:
        try:
            autoencoder_ueba = AutoencoderUEBA()
            logger.info("Autoencoder UEBA initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize autoencoder: {str(e)}")
            autoencoder_ueba = None
    
    numeric_cols = ['bytes_transferred', 'request_count', 'business_value_impact', 'known_vulnerabilities']
    sample_data = None
    model_status = {}
    
    def get_sample_data():
        nonlocal sample_data
        if sample_data is None:
            logger.info("Generating synthetic data for training...")
            sample_data = generate_sample_data(n_samples=10000)
        return sample_data
    
    def resolve_path(env_key: str, default_name: str) -> Path:
        env_value = os.getenv(env_key)
        path = Path(env_value) if env_value else model_dir / default_name
        path.parent.mkdir(parents=True, exist_ok=True)
        return path
    
    # Breach detector
    breach_model_path = resolve_path('BREACH_DETECTOR_MODEL', 'breach_detector.joblib')
    try:
        if breach_model_path.exists():
            breach_detector.load_model(str(breach_model_path))
            model_status['breach_detector'] = f"loaded:{breach_model_path}"
        else:
            raise FileNotFoundError
    except Exception:
        logger.info("Training breach detector...")
        data = get_sample_data()
        breach_detector.train(data, target_column='is_malicious')
        breach_detector.save_model(str(breach_model_path))
        model_status['breach_detector'] = f"trained:{breach_model_path}"

    # Ensure at least a few honeytokens exist on startup (helps detect attackers early)
    try:
        monitor = honeytoken_monitor
        existing = monitor.get_all_honeytokens(show_all=True)
        if len(existing) < 3:
            logger.info("Planting default honeytokens for initial deployment...")
            monitor.plant_honeytoken('credential', '/etc/passwd', severity='HIGH')
            monitor.plant_honeytoken('file', '/var/secrets/credentials.txt', severity='HIGH')
            monitor.plant_honeytoken('ip', '10.0.0.250', severity='MEDIUM')
            model_status['honeytokens'] = 'planted:3'
    except Exception as e:
        logger.warning(f"Failed to ensure default honeytokens: {str(e)}")
    
    # Anomaly detector
    anomaly_model_path = resolve_path('ANOMALY_DETECTOR_MODEL', 'anomaly_detector.joblib')
    try:
        if anomaly_model_path.exists():
            anomaly_detector.load_model(str(anomaly_model_path))
            model_status['anomaly_detector'] = f"loaded:{anomaly_model_path}"
        else:
            raise FileNotFoundError
    except Exception:
        logger.info("Training anomaly detector...")
        data = get_sample_data()
        anomaly_detector.train(data[numeric_cols])
        anomaly_detector.save_model(str(anomaly_model_path))
        model_status['anomaly_detector'] = f"trained:{anomaly_model_path}"
    
    # Behavior analyzer profiles
    behavior_model_path = resolve_path('BEHAVIOR_ANALYZER_MODEL', 'behavior_analyzer.joblib')
    try:
        if behavior_model_path.exists():
            behavior_analyzer.load_profiles(str(behavior_model_path))
            model_status['behavior_analyzer'] = f"loaded:{behavior_model_path}"
        else:
            raise FileNotFoundError
    except Exception:
        logger.info("Building behavioral profiles...")
        data = get_sample_data()
        behavior_analyzer.train(data)
        behavior_analyzer.save_profiles(str(behavior_model_path))
        model_status['behavior_analyzer'] = f"trained:{behavior_model_path}"
    
    # Autoencoder (optional)
    autoencoder_model_path = resolve_path('AUTOENCODER_MODEL', 'autoencoder_ueba.pkl')
    if autoencoder_ueba:
        try:
            if autoencoder_model_path.exists():
                logger.info(f"Loading autoencoder from {autoencoder_model_path}")
                autoencoder_ueba.load_model(str(autoencoder_model_path))
                model_status['autoencoder_ueba'] = f"loaded:{autoencoder_model_path}"
                logger.info("Autoencoder loaded successfully")
            else:
                raise FileNotFoundError(f"Model file not found: {autoencoder_model_path}")
        except Exception as e:
            logger.warning(f"Failed to load autoencoder: {str(e)}, retraining...")
            try:
                logger.info("Training autoencoder UEBA...")
                data = get_sample_data()
                autoencoder_ueba.train(data, validation_split=0.2)
                autoencoder_ueba.save_model(str(autoencoder_model_path))
                model_status['autoencoder_ueba'] = f"trained:{autoencoder_model_path}"
                logger.info("Autoencoder trained and saved successfully")
            except Exception as e2:
                logger.warning(f"Autoencoder unavailable: {str(e2)}")
                autoencoder_ueba = None
    
    # Store in app context
    app.config['breach_detector'] = breach_detector
    app.config['anomaly_detector'] = anomaly_detector
    app.config['honeytoken_monitor'] = honeytoken_monitor
    app.config['behavior_analyzer'] = behavior_analyzer
    app.config['autoencoder_ueba'] = autoencoder_ueba
    app.config['has_autoencoder'] = autoencoder_ueba is not None
    app.config['model_status'] = model_status
    
    @app.route('/', methods=['GET'])
    def index():
        """Root endpoint with API information"""
        # Check if client wants JSON (API client) or HTML (browser)
        if request.headers.get('Accept', '').startswith('application/json'):
            return jsonify({
                'service': 'KAVACH - AI-Driven Threat Detection System',
                'version': '1.0.0',
                'status': 'operational',
                'endpoints': {
                    'health': 'GET /health',
                    'predict': 'POST /api/predict',
                    'alerts': 'GET /api/alerts',
                    'honeytokens': 'GET /api/honeytokens',
                    'plant_honeytoken': 'POST /api/honeytokens/plant',
                    'metrics': 'GET /api/metrics',
                    'threat_trends': 'GET /api/threat-trends',
                    'activity_timeline': 'GET /api/activity-timeline',
                    'chat': 'POST /api/chat'
                },
                'models': app.config.get('model_status', {}),
                'documentation': 'Visit /health for health check or use the API endpoints listed above',
                'timestamp': datetime.now().isoformat()
            }), 200
        
        # Return HTML page for browsers
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>KAVACH - AI-Driven Threat Detection System</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: #333;
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }
                .container {
                    background: white;
                    border-radius: 20px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                    max-width: 900px;
                    width: 100%;
                    padding: 40px;
                }
                h1 {
                    color: #667eea;
                    margin-bottom: 10px;
                    font-size: 2.5em;
                }
                .subtitle {
                    color: #666;
                    margin-bottom: 30px;
                    font-size: 1.1em;
                }
                .status {
                    display: inline-block;
                    background: #10b981;
                    color: white;
                    padding: 8px 16px;
                    border-radius: 20px;
                    font-size: 0.9em;
                    margin-bottom: 30px;
                }
                .endpoints {
                    margin-top: 30px;
                }
                .endpoint {
                    background: #f7fafc;
                    border-left: 4px solid #667eea;
                    padding: 15px;
                    margin-bottom: 15px;
                    border-radius: 5px;
                    transition: transform 0.2s;
                }
                .endpoint:hover {
                    transform: translateX(5px);
                    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                }
                .method {
                    display: inline-block;
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-weight: bold;
                    font-size: 0.85em;
                    margin-right: 10px;
                }
                .get { background: #10b981; color: white; }
                .post { background: #3b82f6; color: white; }
                .path {
                    font-family: 'Monaco', 'Courier New', monospace;
                    color: #667eea;
                    font-weight: 600;
                }
                .description {
                    color: #666;
                    margin-top: 5px;
                    font-size: 0.9em;
                }
                .footer {
                    margin-top: 40px;
                    padding-top: 20px;
                    border-top: 1px solid #e5e7eb;
                    text-align: center;
                    color: #999;
                }
                .test-link {
                    display: inline-block;
                    margin-top: 20px;
                    padding: 12px 24px;
                    background: #667eea;
                    color: white;
                    text-decoration: none;
                    border-radius: 8px;
                    transition: background 0.3s;
                }
                .test-link:hover {
                    background: #5568d3;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🛡️ KAVACH</h1>
                <p class="subtitle">AI-Driven Threat and Anomaly Detection System</p>
                <span class="status">● Operational</span>
                
                <div class="endpoints">
                    <h2 style="margin-bottom: 20px; color: #333;">API Endpoints</h2>
                    
                    <div class="endpoint">
                        <span class="method get">GET</span>
                        <span class="path">/health</span>
                        <div class="description">Health check endpoint</div>
                    </div>
                    
                    <div class="endpoint">
                        <span class="method post">POST</span>
                        <span class="path">/api/predict</span>
                        <div class="description">Predict threat from security event</div>
                    </div>
                    
                    <div class="endpoint">
                        <span class="method get">GET</span>
                        <span class="path">/api/metrics</span>
                        <div class="description">Get model performance metrics</div>
                    </div>
                    
                    <div class="endpoint">
                        <span class="method get">GET</span>
                        <span class="path">/api/alerts</span>
                        <div class="description">Get all security alerts</div>
                    </div>
                    
                    <div class="endpoint">
                        <span class="method get">GET</span>
                        <span class="path">/api/honeytokens</span>
                        <div class="description">Get all honeytokens</div>
                    </div>
                    
                    <div class="endpoint">
                        <span class="method post">POST</span>
                        <span class="path">/api/honeytokens/plant</span>
                        <div class="description">Plant a new honeytoken</div>
                    </div>
                    
                    <div class="endpoint">
                        <span class="method get">GET</span>
                        <span class="path">/api/threat-trends</span>
                        <div class="description">Get threat trends (last 24 hours)</div>
                    </div>
                    
                    <div class="endpoint">
                        <span class="method get">GET</span>
                        <span class="path">/api/activity-timeline</span>
                        <div class="description">Get user activity timeline</div>
                    </div>
                    
                    <div class="endpoint">
                        <span class="method post">POST</span>
                        <span class="path">/api/chat</span>
                        <div class="description">AI chatbot assistant</div>
                    </div>
                </div>
                
                <div style="text-align: center;">
                    <a href="/health" class="test-link">Test Health Endpoint</a>
                </div>
                
                <div class="footer">
                    <p>Version 1.0.0 | API Server Running on Port 5001</p>
                    <p style="margin-top: 10px;">For API documentation, send requests with Accept: application/json header</p>
                </div>
            </div>
        </body>
        </html>
        """
        return html, 200
    
    @app.route('/health', methods=['GET'])
    def health_check():
        """Health check endpoint"""
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'service': 'KAVACH API'
        })
    
    @app.route('/api/predict', methods=['POST'])
    def predict():
        """Predict if event is malicious"""
        try:
            data = request.json
            
            # Get event data
            event = {
                'user_id': data.get('user_id'),
                'timestamp': data.get('timestamp', datetime.now().isoformat()),
                'bytes_transferred': data.get('bytes_transferred', 0),
                'request_count': data.get('request_count', 0),
                'activity_type': data.get('activity_type', 'normal'),
                'source_ip': data.get('source_ip'),
                'destination_ip': data.get('destination_ip'),
                'user_role': data.get('user_role', 'user'),
                'location': data.get('location', 'unknown'),
                'business_value_impact': data.get('business_value_impact', 0.5),
                'known_vulnerabilities': data.get('known_vulnerabilities', 0),
                'honeytoken_id': data.get('honeytoken_id'),
                'honeytoken_value': data.get('honeytoken_value')
            }
            
            # Make prediction
            detector = app.config['breach_detector']
            result = detector.predict_streaming(event)
            
            # Check for anomalies - use numeric features matching training
            anomaly_features = pd.DataFrame([{
                'bytes_transferred': event.get('bytes_transferred', 0),
                'request_count': event.get('request_count', 0),
                'business_value_impact': event.get('business_value_impact', 0.5),
                'known_vulnerabilities': event.get('known_vulnerabilities', 0)
            }])
            anomaly_result = app.config['anomaly_detector'].predict(anomaly_features)
            
            # Handle numpy array results
            is_anomaly_val = anomaly_result['is_anomaly']
            if isinstance(is_anomaly_val, np.ndarray):
                result['is_anomaly'] = bool(is_anomaly_val[0])
            else:
                result['is_anomaly'] = bool(is_anomaly_val)
            
            anomaly_score_val = anomaly_result['anomaly_score']
            if isinstance(anomaly_score_val, np.ndarray):
                result['anomaly_score'] = float(anomaly_score_val[0])
            else:
                result['anomaly_score'] = float(anomaly_score_val)
            
            # UEBA analysis
            ueba_result = None
            try:
                behavior_analyzer = app.config['behavior_analyzer']
                ueba_result = behavior_analyzer.detect_anomaly(event)
                result['ueba_anomaly'] = ueba_result.get('is_anomaly', False)
                result['ueba_risk_score'] = ueba_result.get('risk_score', 0.0)
            except Exception as e:
                logger.warning(f"UEBA analysis failed: {str(e)}")
                ueba_result = {'is_anomaly': False, 'risk_score': 0.0}
            
            # Autoencoder UEBA analysis (optional)
            autoencoder_result = None
            if app.config.get('has_autoencoder') and app.config['autoencoder_ueba']:
                try:
                    autoencoder_ueba = app.config['autoencoder_ueba']
                    event_df = pd.DataFrame([event])
                    autoencoder_result = autoencoder_ueba.predict_single(event)
                    result['autoencoder_anomaly'] = autoencoder_result.get('is_anomaly', False)
                    result['autoencoder_score'] = autoencoder_result.get('anomaly_score', 0.0)
                except Exception as e:
                    logger.warning(f"Autoencoder analysis failed: {str(e)}")
                    autoencoder_result = {'is_anomaly': False, 'anomaly_score': 0.0}
            
            # Check honeytoken interactions
            honeytoken_alert = app.config['honeytoken_monitor'].check_event_for_honeytoken(event)
            if honeytoken_alert:
                result['honeytoken_breach'] = True
            
            # Store event in database for dashboard
            try:
                event_storage.store_event(
                    event_data=event,
                    prediction_result=result,
                    anomaly_result=anomaly_result,
                    honeytoken_alert=honeytoken_alert,
                    ueba_result=ueba_result,
                    autoencoder_result=autoencoder_result
                )
            except Exception as e:
                logger.warning(f"Failed to store event: {str(e)}")
            
            # Generate response
            response = {
                'event': event,
                'prediction': result,
                'timestamp': datetime.now().isoformat()
            }
            
            if honeytoken_alert:
                response['honeytoken_alert'] = honeytoken_alert
            
            return jsonify(response), 200
            
        except Exception as e:
            logger.error(f"Prediction error: {str(e)}\n{traceback.format_exc()}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/alerts', methods=['GET'])
    def get_alerts():
        """Get all alerts"""
        try:
            monitor = app.config['honeytoken_monitor']
            alerts = monitor.get_alerts()
            
            return jsonify({
                'alerts': alerts,
                'count': len(alerts),
                'timestamp': datetime.now().isoformat()
            }), 200
            
        except Exception as e:
            logger.error(f"Error fetching alerts: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/honeytokens', methods=['GET'])
    def get_honeytokens():
        """Get all honeytokens"""
        try:
            monitor = app.config['honeytoken_monitor']
            tokens = monitor.get_all_honeytokens(show_all=True)
            stats = monitor.get_statistics()
            
            return jsonify({
                'honeytokens': tokens,
                'statistics': stats,
                'timestamp': datetime.now().isoformat()
            }), 200
            
        except Exception as e:
            logger.error(f"Error fetching honeytokens: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/honeytokens/plant', methods=['POST'])
    def plant_honeytoken():
        """Plant a new honeytoken with optional attack type targeting"""
        try:
            data = request.json
            
            monitor = app.config['honeytoken_monitor']
            token_id = monitor.plant_honeytoken(
                token_type=data.get('token_type', 'credential'),
                location=data.get('location', 'unknown'),
                metadata=data.get('metadata', {}),
                severity=data.get('severity', 'HIGH'),
                attack_type=data.get('attack_type')  # New parameter: SQLi, XSS, CommandInjection, etc.
            )
            
            attack_info = f" for {data.get('attack_type')} attacks" if data.get('attack_type') else ""
            return jsonify({
                'token_id': token_id,
                'message': f'Honeytoken planted successfully{attack_info}',
                'attack_type': data.get('attack_type'),
                'timestamp': datetime.now().isoformat()
            }), 201
            
        except Exception as e:
            logger.error(f"Error planting honeytoken: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/metrics', methods=['GET'])
    def get_metrics():
        """Get model metrics"""
        try:
            detector = app.config['breach_detector']
            report = detector.get_metrics_report()
            
            return jsonify({
                'metrics': report,
                'timestamp': datetime.now().isoformat()
            }), 200
            
        except Exception as e:
            logger.error(f"Error fetching metrics: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/threat-trends', methods=['GET'])
    def get_threat_trends():
        """Get threat trends for dashboard"""
        try:
            # Get hours parameter (default 24)
            hours = int(request.args.get('hours', 24))
            
            # Get real data from event storage
            trends = event_storage.get_threat_trends(hours=hours)
            
            # If no data, return empty trends (dashboard will show zeros)
            if not trends:
                from datetime import timedelta
                trends = []
                for i in range(hours):
                    hour_time = (datetime.now() - timedelta(hours=i)).strftime('%Y-%m-%d %H:00:00')
                    trends.append({
                        'timestamp': hour_time,
                        'total_events': 0,
                        'threats_detected': 0,
                        'false_positives': 0,
                        'honeytoken_breaches': 0
                    })
                trends = sorted(trends, key=lambda x: x['timestamp'])
            
            return jsonify({
                'trends': trends,
                'statistics': event_storage.get_statistics(hours=hours),
                'timestamp': datetime.now().isoformat()
            }), 200
            
        except Exception as e:
            logger.error(f"Error fetching trends: {str(e)}\n{traceback.format_exc()}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/activity-timeline', methods=['GET'])
    def get_activity_timeline():
        """Get user activity timeline with diverse threat-aware risk scores from events and alerts"""
        try:
            # Get limit parameter (default 50)
            limit = int(request.args.get('limit', 50))

            audit_db_path = os.getenv('AUDIT_DB_PATH', 'data/audit_trail.db')
            if not os.path.isabs(audit_db_path):
                from pathlib import Path
                project_root = Path(__file__).parent.parent
                audit_db_path = str(project_root / audit_db_path)

            conn = sqlite3.connect(audit_db_path)
            cursor = conn.cursor()

            # ------------------------------------------------------------------
            # 1) Pull global threat-trend context (counts per threat_type/severity)
            # ------------------------------------------------------------------
            cursor.execute('''
                SELECT 
                    threat_type,
                    severity,
                    COUNT(*) as cnt
                FROM events
                WHERE threat_type IS NOT NULL
                  AND ts >= datetime('now', '-7 days')
                GROUP BY threat_type, severity
            ''')
            trend_rows = cursor.fetchall()

            threat_stats = {}
            total_trend_count = 0
            for t_type, sev, cnt in trend_rows:
                if not t_type:
                    continue
                key = (t_type or '').lower()
                sev_key = (sev or 'MEDIUM').upper()
                threat_stats.setdefault(key, {'total': 0, 'by_severity': {}})
                threat_stats[key]['total'] += cnt
                threat_stats[key]['by_severity'][sev_key] = (
                    threat_stats[key]['by_severity'].get(sev_key, 0) + cnt
                )
                total_trend_count += cnt

            # Avoid divide-by-zero
            total_trend_count = max(total_trend_count, 1)

            # ------------------------------------------------------------------
            # 2) Base query: pull recent events + alerts with severity/threat context.
            #    Risk is initially severity-based; we refine it in Python to make it
            #    dynamic, threat-specific, and trend-aware.
            # ------------------------------------------------------------------
            cursor.execute('''
                SELECT 
                    ts as timestamp,
                    user_id,
                    threat_type as action,
                    severity,
                    source_ip,
                    activity_type,
                    payload,
                    CASE 
                        WHEN severity = 'CRITICAL' THEN 1.0
                        WHEN severity = 'HIGH' THEN 0.85
                        WHEN severity = 'MEDIUM' THEN 0.65
                        WHEN severity = 'LOW' THEN 0.35
                        ELSE 0.5
                    END as base_risk_score,
                    CASE 
                        WHEN label = 'malicious' OR severity IN ('HIGH', 'CRITICAL') THEN 1
                        ELSE 0
                    END as is_malicious,
                    CASE 
                        WHEN threat_type IS NOT NULL THEN 1
                        ELSE 0
                    END as is_anomaly
                FROM events
                WHERE threat_type IS NOT NULL
                
                UNION ALL
                
                SELECT 
                    ts as timestamp,
                    user_id,
                    threat_type as action,
                    severity,
                    source_ip,
                    'api_call' as activity_type,
                    '' as payload,
                    CASE 
                        WHEN severity = 'CRITICAL' THEN 1.0
                        WHEN severity = 'HIGH' THEN 0.85
                        WHEN severity = 'MEDIUM' THEN 0.65
                        WHEN severity = 'LOW' THEN 0.35
                        ELSE 0.5
                    END as base_risk_score,
                    1 as is_malicious,
                    1 as is_anomaly
                FROM alerts
                WHERE threat_type IS NOT NULL
                
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))

            rows = cursor.fetchall()
            conn.close()

            # Helper: compute a more nuanced, trend-aware risk score
            import hashlib

            def compute_dynamic_risk(timestamp, user_id, threat_type, severity, activity_type,
                                     base_risk, is_malicious):
                # Normalize inputs
                sev = (severity or 'MEDIUM').upper()
                tt = (threat_type or '').lower()
                act = (activity_type or '').lower()

                # --------------------------------------------------------------
                # Severity floor keeps ordering intuitive across levels
                # --------------------------------------------------------------
                severity_floor = {
                    'CRITICAL': 0.93,
                    'HIGH': 0.80,
                    'MEDIUM': 0.55,
                    'LOW': 0.22
                }.get(sev, 0.5)

                risk = max(base_risk, severity_floor)

                # --------------------------------------------------------------
                # Threat-type specific adjustments (impact-driven)
                # --------------------------------------------------------------
                if 'dataexfil' in tt or 'data_exfil' in tt or 'exfil' in tt:
                    risk = max(risk, 0.9)
                elif 'privilege' in tt:
                    risk = max(risk, 0.88)
                elif 'honeypot' in tt or 'honey' in tt:
                    risk = max(risk, 0.95)
                elif 'bruteforce' in tt or 'brute' in tt or 'credential' in tt:
                    risk = max(risk, 0.75)
                elif 'phishing' in tt:
                    risk = max(risk, 0.6)
                elif 'portscan' in tt or 'port_scan' in tt or 'dns_tunnel' in tt or 'dns' in tt:
                    risk = max(risk, 0.6)
                elif 'malware' in tt or 'rce' in tt or 'command' in tt:
                    risk = max(risk, 0.9)

                # --------------------------------------------------------------
                # Activity-type context (what the attacker is actually doing)
                # --------------------------------------------------------------
                if 'login' in act:
                    risk += 0.05
                if 'file_download' in act or 'download' in act or 'upload' in act:
                    risk += 0.08
                if 'dns' in act:
                    risk += 0.04

                # --------------------------------------------------------------
                # Trend-aware adjustment:
                # - If a threat type is spiking in the last 7 days, push it higher.
                # - Rare but critical threats also get a bump.
                # --------------------------------------------------------------
                t_stats = threat_stats.get(tt, None)
                if t_stats:
                    freq = t_stats['total'] / float(total_trend_count)
                    # Map frequency into a small bump [0 .. 0.12]
                    trend_bump = min(0.12, freq * 0.8)

                    # Heavier bump if most recent occurrences are CRITICAL/HIGH
                    sev_counts = t_stats.get('by_severity', {})
                    high_like = sev_counts.get('CRITICAL', 0) + sev_counts.get('HIGH', 0)
                    total_for_type = max(t_stats['total'], 1)
                    severe_ratio = high_like / float(total_for_type)
                    severity_trend_bump = severe_ratio * 0.10  # up to +0.10

                    risk += trend_bump + severity_trend_bump

                # --------------------------------------------------------------
                # Benign / lower confidence events should not look like high risk
                # --------------------------------------------------------------
                if not is_malicious:
                    risk = min(risk, 0.42)

                # --------------------------------------------------------------
                # Deterministic jitter based on event identity:
                # gives a spread while staying stable per event.
                # --------------------------------------------------------------
                key = f"{timestamp}-{user_id}-{threat_type}-{activity_type}"
                h = hashlib.md5(key.encode('utf-8')).hexdigest()
                jitter_raw = int(h[:8], 16) / 0xFFFFFFFF  # 0..1
                jitter = (jitter_raw - 0.5) * 0.16       # ~[-0.08, +0.08]
                risk += jitter

                # Final clamp to approximately [0.052, 0.999] to show 5.2–99.9%
                risk = max(0.052, min(0.999, risk))
                return risk

            timeline = []
            for row in rows:
                threat_type = row[2] or 'Unknown Threat'
                severity = row[3] or 'MEDIUM'
                activity_type = row[5]
                base_risk = float(row[7]) if row[7] is not None else 0.5
                is_malicious = bool(row[8])

                # Compute refined risk
                dynamic_risk = compute_dynamic_risk(
                    timestamp=row[0],
                    user_id=row[1] or 'unknown',
                    threat_type=threat_type,
                    severity=severity,
                    activity_type=activity_type,
                    base_risk=base_risk,
                    is_malicious=is_malicious,
                )

                # Format action to be more descriptive
                action = f"{threat_type} detected"
                if activity_type:
                    action = f"{threat_type} via {activity_type}"

                timeline.append({
                    'timestamp': row[0],
                    'user_id': row[1] or 'unknown',
                    'action': action,
                    'threat_type': threat_type,
                    'risk_score': dynamic_risk,
                    'is_malicious': is_malicious,
                    'is_anomaly': bool(row[9]),
                    'source_ip': row[4],
                    'severity': severity
                })

            # Sort by timestamp descending and limit
            timeline.sort(key=lambda x: x['timestamp'], reverse=True)
            timeline = timeline[:limit]

            # If no data, try to get from event_storage as fallback
            if not timeline:
                try:
                    timeline = event_storage.get_activity_timeline(limit=limit)
                except:
                    pass

            return jsonify({
                'timeline': timeline,
                'count': len(timeline),
                'timestamp': datetime.now().isoformat()
            }), 200

        except Exception as e:
            logger.error(f"Error fetching timeline: {str(e)}\n{traceback.format_exc()}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/chat', methods=['POST'])
    def chat():
        """AI Chatbot endpoint"""
        try:
            from chatbot.security_bot import SecurityBot
            
            bot = SecurityBot()
            data = request.json
            message = data.get('message', '')
            context = data.get('context', {})
            
            # Enhance context with real system data if needed
            enhanced_context = context.copy()
            lower_msg = message.lower()
            
            # If querying alerts, fetch real alerts and latest alert type
            try:
                monitor = app.config['honeytoken_monitor']
                alerts = monitor.get_alerts()
                enhanced_context.setdefault('alerts', alerts)
                if 'alert' in lower_msg and 'alert_type' not in context and alerts:
                    latest_alert = alerts[-1]
                    enhanced_context['alert_type'] = latest_alert.get('type', 'MALICIOUS_ACTIVITY')
                    
                # Honeytoken statistics for deception-layer questions
                try:
                    enhanced_context.setdefault('honeytoken_stats', monitor.get_statistics())
                except Exception:
                    pass
            except Exception:
                pass
            
            # If querying metrics/confidence, fetch real metrics
            if any(word in lower_msg for word in ['metric', 'performance', 'model', 'accuracy']):
                try:
                    detector = app.config['breach_detector']
                    if hasattr(detector, 'evaluation_results'):
                        enhanced_context['model_metrics'] = detector.evaluation_results
                except Exception:
                    pass
            
            # If querying statistics or trends, fetch real stats and threat trends
            if ('statistic' in lower_msg or 'summary' in lower_msg or 'trend' in lower_msg):
                try:
                    stats = event_storage.get_statistics(hours=24)
                    enhanced_context['statistics'] = stats
                except Exception:
                    pass
                try:
                    trends = event_storage.get_threat_trends(hours=24)
                    enhanced_context['threat_trends'] = trends
                except Exception:
                    pass
            
            # If asking about recent activity, include activity timeline snapshot
            if any(word in lower_msg for word in ['recent', 'latest', 'activity', 'events', 'timeline']):
                try:
                    timeline = event_storage.get_activity_timeline(limit=50)
                    enhanced_context['timeline'] = timeline
                except Exception:
                    pass
            
            response = bot.process_message(message, enhanced_context)
            
            return jsonify(response), 200
            
        except Exception as e:
            logger.error(f"Chat error: {str(e)}\n{traceback.format_exc()}")
            return jsonify({'error': str(e)}), 500
    
    # Authentication endpoints
    @app.route('/api/auth/register', methods=['POST'])
    def register():
        """Register a new user"""
        try:
            data = request.json
            username = data.get('username', '').strip()
            email = data.get('email', '').strip()
            password = data.get('password', '')
            
            if not username or not email or not password:
                return jsonify({'success': False, 'message': 'All fields are required'}), 400
            
            if len(password) < 6:
                return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400
            
            result = auth_manager.register_user(
                username=username,
                email=email,
                password=password,
                role=data.get('role', 'user')
            )
            
            if result['success']:
                # Generate token for immediate login
                user = auth_manager.authenticate_user(username, password)
                if user:
                    token = auth_manager.generate_token(user)
                    return jsonify({
                        'success': True,
                        'message': result['message'],
                        'token': token,
                        'user': user
                    }), 201
            
            return jsonify(result), 400
            
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            return jsonify({'success': False, 'message': str(e)}), 500
    
    @app.route('/api/auth/login', methods=['POST'])
    def login():
        """Login user"""
        try:
            data = request.json
            username = data.get('username', '').strip()
            password = data.get('password', '')
            
            if not username or not password:
                return jsonify({'success': False, 'message': 'Username and password are required'}), 400
            
            user = auth_manager.authenticate_user(username, password)
            if not user:
                return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
            
            token = auth_manager.generate_token(user)
            
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'token': token,
                'user': user
            }), 200
            
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            return jsonify({'success': False, 'message': str(e)}), 500
    
    @app.route('/api/auth/verify', methods=['POST'])
    def verify_token():
        """Verify JWT token"""
        try:
            data = request.json
            token = data.get('token', '')
            
            if not token:
                return jsonify({'success': False, 'message': 'Token required'}), 400
            
            user_info = auth_manager.verify_token(token)
            if not user_info:
                return jsonify({'success': False, 'message': 'Invalid or expired token'}), 401
            
            user = auth_manager.get_user(user_info['user_id'])
            if not user:
                return jsonify({'success': False, 'message': 'User not found'}), 404
            
            return jsonify({
                'success': True,
                'user': user
            }), 200
            
        except Exception as e:
            logger.error(f"Token verification error: {str(e)}")
            return jsonify({'success': False, 'message': str(e)}), 500
    
    # Initialize audit trail schema on startup
    try:
        from utils.db_schema import init_audit_trail_schema
        audit_db_path = os.getenv('AUDIT_DB_PATH', 'data/audit_trail.db')
        init_audit_trail_schema(audit_db_path)
    except Exception as e:
        logger.warning(f"Failed to initialize audit schema: {str(e)}")
    
    # New dashboard endpoints
    @app.route('/api/dashboard/threat-trends', methods=['GET'])
    def get_threat_trends_dashboard():
        """Get threat trends by day and threat_type"""
        try:
            window = request.args.get('window', '7d')
            days = int(window.replace('d', '')) if 'd' in window else 7
            
            audit_db_path = os.getenv('AUDIT_DB_PATH', 'data/audit_trail.db')
            if not os.path.isabs(audit_db_path):
                from pathlib import Path
                project_root = Path(__file__).parent.parent
                audit_db_path = str(project_root / audit_db_path)
            
            conn = sqlite3.connect(audit_db_path)
            cursor = conn.cursor()
            
            cutoff = (datetime.now() - timedelta(days=days)).isoformat()
            # Query both alerts table (real-time detected threats) and events table (with threat_type)
            cursor.execute('''
                SELECT 
                    DATE(ts) as day,
                    threat_type,
                    COUNT(*) as count
                FROM alerts
                WHERE ts >= ? AND threat_type IS NOT NULL
                GROUP BY day, threat_type
                
                UNION ALL
                
                SELECT 
                    DATE(ts) as day,
                    threat_type,
                    COUNT(*) as count
                FROM events
                WHERE ts >= ? AND threat_type IS NOT NULL AND label = 'malicious'
                GROUP BY day, threat_type
                
                ORDER BY day DESC, count DESC
            ''', (cutoff, cutoff))
            
            rows = cursor.fetchall()
            conn.close()
            
            # Aggregate by day and threat_type
            trends_dict = {}
            for row in rows:
                key = (row[0], row[1])
                if key not in trends_dict:
                    trends_dict[key] = 0
                trends_dict[key] += row[2]
            
            trends = [{'day': day, 'threat_type': threat_type, 'count': count} 
                     for (day, threat_type), count in trends_dict.items()]
            
            # If no data, return seeded data from events table only
            if not trends:
                cursor.execute('''
                    SELECT 
                        DATE(ts) as day,
                        threat_type,
                        COUNT(*) as count
                    FROM events
                    WHERE ts >= ? AND threat_type IS NOT NULL
                    GROUP BY day, threat_type
                    ORDER BY day DESC, count DESC
                    LIMIT 50
                ''', (cutoff,))
                rows = cursor.fetchall()
                trends = [{'day': row[0], 'threat_type': row[1], 'count': row[2]} for row in rows]
            
            return jsonify(trends), 200
            
        except Exception as e:
            logger.error(f"Error fetching threat trends: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/dashboard/severity-dist', methods=['GET'])
    def get_severity_distribution():
        """Get severity distribution"""
        try:
            window = request.args.get('window', '7d')
            days = int(window.replace('d', '')) if 'd' in window else 7
            
            audit_db_path = os.getenv('AUDIT_DB_PATH', 'data/audit_trail.db')
            if not os.path.isabs(audit_db_path):
                from pathlib import Path
                project_root = Path(__file__).parent.parent
                audit_db_path = str(project_root / audit_db_path)
            
            conn = sqlite3.connect(audit_db_path)
            cursor = conn.cursor()
            
            cutoff = (datetime.now() - timedelta(days=days)).isoformat()
            # Query both alerts and events for severity distribution
            cursor.execute('''
                SELECT severity, COUNT(*) as count
                FROM alerts
                WHERE ts >= ? AND severity IS NOT NULL
                GROUP BY severity
                
                UNION ALL
                
                SELECT severity, COUNT(*) as count
                FROM events
                WHERE ts >= ? AND severity IS NOT NULL AND label = 'malicious'
                GROUP BY severity
            ''', (cutoff, cutoff))
            
            rows = cursor.fetchall()
            conn.close()
            
            # Aggregate by severity
            severity_dict = {}
            for row in rows:
                severity = row[0]
                if severity not in severity_dict:
                    severity_dict[severity] = 0
                severity_dict[severity] += row[1]
            
            # If no data, get from events table
            if not severity_dict:
                cursor.execute('''
                    SELECT severity, COUNT(*) as count
                    FROM events
                    WHERE ts >= ? AND severity IS NOT NULL
                    GROUP BY severity
                ''', (cutoff,))
                rows = cursor.fetchall()
                for row in rows:
                    severity_dict[row[0]] = row[1]
            
            severity_order = {'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 3, 'LOW': 4}
            dist = [{'severity': s, 'count': severity_dict[s]} 
                   for s in sorted(severity_dict.keys(), key=lambda x: severity_order.get(x, 5))]
            
            return jsonify(dist), 200
            
        except Exception as e:
            logger.error(f"Error fetching severity distribution: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/dashboard/top-attack-types', methods=['GET'])
    def get_top_attack_types():
        """Get top attack types"""
        try:
            limit = int(request.args.get('limit', 10))
            window = request.args.get('window', '7d')
            days = int(window.replace('d', '')) if 'd' in window else 7
            
            audit_db_path = os.getenv('AUDIT_DB_PATH', 'data/audit_trail.db')
            if not os.path.isabs(audit_db_path):
                from pathlib import Path
                project_root = Path(__file__).parent.parent
                audit_db_path = str(project_root / audit_db_path)
            
            conn = sqlite3.connect(audit_db_path)
            cursor = conn.cursor()
            
            cutoff = (datetime.now() - timedelta(days=days)).isoformat()
            # Query both alerts and events for top attack types
            cursor.execute('''
                SELECT threat_type, COUNT(*) as count
                FROM alerts
                WHERE ts >= ? AND threat_type IS NOT NULL
                GROUP BY threat_type
                
                UNION ALL
                
                SELECT threat_type, COUNT(*) as count
                FROM events
                WHERE ts >= ? AND threat_type IS NOT NULL AND label = 'malicious'
                GROUP BY threat_type
            ''', (cutoff, cutoff))
            
            rows = cursor.fetchall()
            conn.close()
            
            # Aggregate by threat_type
            attack_dict = {}
            for row in rows:
                threat_type = row[0]
                if threat_type not in attack_dict:
                    attack_dict[threat_type] = 0
                attack_dict[threat_type] += row[1]
            
            # If no data, get from events table
            if not attack_dict:
                cursor.execute('''
                    SELECT threat_type, COUNT(*) as count
                    FROM events
                    WHERE ts >= ? AND threat_type IS NOT NULL
                    GROUP BY threat_type
                    ORDER BY count DESC
                    LIMIT ?
                ''', (cutoff, limit))
                rows = cursor.fetchall()
                attack_dict = {row[0]: row[1] for row in rows}
            
            top_attacks = [{'threat_type': threat_type, 'count': count} 
                          for threat_type, count in sorted(attack_dict.items(), key=lambda x: x[1], reverse=True)[:limit]]
            
            return jsonify(top_attacks), 200
            
        except Exception as e:
            logger.error(f"Error fetching top attack types: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/dashboard/top-source-ips', methods=['GET'])
    def get_top_source_ips():
        """Get top source IPs by event count"""
        try:
            limit = int(request.args.get('limit', 20))
            window = request.args.get('window', '7d')
            days = int(window.replace('d', '')) if 'd' in window else 7
            
            audit_db_path = os.getenv('AUDIT_DB_PATH', 'data/audit_trail.db')
            if not os.path.isabs(audit_db_path):
                from pathlib import Path
                project_root = Path(__file__).parent.parent
                audit_db_path = str(project_root / audit_db_path)
            
            conn = sqlite3.connect(audit_db_path)
            cursor = conn.cursor()
            
            cutoff = (datetime.now() - timedelta(days=days)).isoformat()
            cursor.execute('''
                SELECT source_ip, COUNT(*) as events
                FROM events
                WHERE ts >= ? AND source_ip IS NOT NULL
                GROUP BY source_ip
                ORDER BY events DESC
                LIMIT ?
            ''', (cutoff, limit))
            
            rows = cursor.fetchall()
            conn.close()
            
            top_ips = [{'source_ip': row[0], 'events': row[1]} for row in rows]
            
            return jsonify(top_ips), 200
            
        except Exception as e:
            logger.error(f"Error fetching top source IPs: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/dashboard/ueba-user-risk', methods=['GET'])
    def get_ueba_user_risk():
        """Get UEBA user risk (aggregate anomalies)"""
        try:
            top = int(request.args.get('top', 10))
            window = request.args.get('window', '7d')
            days = int(window.replace('d', '')) if 'd' in window else 7
            
            audit_db_path = os.getenv('AUDIT_DB_PATH', 'data/audit_trail.db')
            if not os.path.isabs(audit_db_path):
                from pathlib import Path
                project_root = Path(__file__).parent.parent
                audit_db_path = str(project_root / audit_db_path)
            
            conn = sqlite3.connect(audit_db_path)
            cursor = conn.cursor()
            
            cutoff = (datetime.now() - timedelta(days=days)).isoformat()
            cursor.execute('''
                SELECT 
                    user_id,
                    DATE(ts) as day,
                    COUNT(*) as anomalies
                FROM events
                WHERE ts >= ? 
                    AND user_id IS NOT NULL
                    AND (threat_type LIKE '%anomaly%' OR severity IN ('HIGH', 'CRITICAL'))
                GROUP BY user_id, day
                ORDER BY anomalies DESC
                LIMIT ?
            ''', (cutoff, top))
            
            rows = cursor.fetchall()
            
            # If no data, get any users with high severity events
            if not rows:
                cursor.execute('''
                    SELECT 
                        user_id,
                        DATE(ts) as day,
                        COUNT(*) as anomalies
                    FROM events
                    WHERE ts >= ? 
                        AND user_id IS NOT NULL
                        AND severity IN ('HIGH', 'CRITICAL')
                    GROUP BY user_id, day
                    ORDER BY anomalies DESC
                    LIMIT ?
                ''', (cutoff, top))
                rows = cursor.fetchall()
            
            conn.close()
            
            user_risks = [{'user_id': row[0], 'day': row[1], 'anomalies': row[2]} for row in rows]
            
            return jsonify(user_risks), 200
            
        except Exception as e:
            logger.error(f"Error fetching UEBA user risk: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/dashboard/honeytoken-heatmap', methods=['GET'])
    def get_honeytoken_heatmap():
        """Get honeytoken hits by hour and target"""
        try:
            window = request.args.get('window', '7d')
            days = int(window.replace('d', '')) if 'd' in window else 7
            
            audit_db_path = os.getenv('AUDIT_DB_PATH', 'data/audit_trail.db')
            if not os.path.isabs(audit_db_path):
                from pathlib import Path
                project_root = Path(__file__).parent.parent
                audit_db_path = str(project_root / audit_db_path)
            
            conn = sqlite3.connect(audit_db_path)
            cursor = conn.cursor()
            
            cutoff = (datetime.now() - timedelta(days=days)).isoformat()
            # Query honeytoken events with all attack types
            cursor.execute('''
                SELECT 
                    target,
                    CAST(strftime('%H', ts) AS INTEGER) as hour,
                    COUNT(*) as count
                FROM events
                WHERE ts >= ? 
                    AND (threat_type = 'Honeypot' 
                         OR threat_type LIKE '%Honeytoken%' 
                         OR threat_type LIKE '%Honeypot%'
                         OR activity_type = 'honeytoken_access'
                         OR target LIKE '%honeytoken%'
                         OR target LIKE '%decoy%')
                    AND target IS NOT NULL
                GROUP BY target, hour
                
                UNION ALL
                
                SELECT 
                    location as target,
                    CAST(strftime('%H', ts) AS INTEGER) as hour,
                    COUNT(*) as count
                FROM alerts
                WHERE ts >= ? 
                    AND (type = 'HONEYTOKEN_BREACH' OR threat_type LIKE '%Honeypot%')
                    AND location IS NOT NULL
                GROUP BY location, hour
                
                ORDER BY target, hour
            ''', (cutoff, cutoff))
            
            rows = cursor.fetchall()
            conn.close()
            
            # Aggregate by target and hour
            heatmap_dict = {}
            for row in rows:
                key = (row[0], int(row[1]))
                if key not in heatmap_dict:
                    heatmap_dict[key] = 0
                heatmap_dict[key] += row[2]
            
            heatmap = [{'target': target, 'hour': hour, 'count': count} 
                      for (target, hour), count in sorted(heatmap_dict.items())]
            
            # If no data, return empty array (charts will show empty state)
            # But ensure we have at least some structure
            if not heatmap:
                # Try to get any honeytoken-related events
                cursor.execute('''
                    SELECT 
                        target,
                        CAST(strftime('%H', ts) AS INTEGER) as hour,
                        COUNT(*) as count
                    FROM events
                    WHERE ts >= ? 
                        AND (threat_type = 'Honeypot' OR activity_type LIKE '%honeytoken%')
                        AND target IS NOT NULL
                    GROUP BY target, hour
                    LIMIT 100
                ''', (cutoff,))
                rows = cursor.fetchall()
                heatmap = [{'target': row[0], 'hour': int(row[1]), 'count': row[2]} for row in rows]
            
            return jsonify(heatmap), 200
            
        except Exception as e:
            logger.error(f"Error fetching honeytoken heatmap: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/dashboard/feature-importance', methods=['GET'])
    def get_feature_importance():
        """Get feature importance for a model"""
        try:
            model = request.args.get('model', 'Ensemble')
            
            audit_db_path = os.getenv('AUDIT_DB_PATH', 'data/audit_trail.db')
            if not os.path.isabs(audit_db_path):
                from pathlib import Path
                project_root = Path(__file__).parent.parent
                audit_db_path = str(project_root / audit_db_path)
            
            conn = sqlite3.connect(audit_db_path)
            cursor = conn.cursor()
            
            # Get most recent feature importance for the model
            cursor.execute('''
                SELECT feature, importance
                FROM feature_importance
                WHERE model_name = ?
                ORDER BY ts DESC, importance DESC
                LIMIT 20
            ''', (model,))
            
            rows = cursor.fetchall()
            conn.close()
            
            if not rows:
                # Return mock data if no data exists
                features = [
                    {'feature': 'bytes_transferred', 'importance': 0.25},
                    {'feature': 'request_count', 'importance': 0.20},
                    {'feature': 'activity_type', 'importance': 0.15},
                    {'feature': 'user_role', 'importance': 0.12},
                    {'feature': 'location', 'importance': 0.10}
                ]
            else:
                features = [{'feature': row[0], 'importance': row[1]} for row in rows]
            
            return jsonify({'features': features, 'model': model}), 200
            
        except Exception as e:
            logger.error(f"Error fetching feature importance: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/dashboard/model-metrics', methods=['GET'])
    def get_model_metrics_dashboard():
        """Get model performance metrics"""
        try:
            model = request.args.get('model', 'Ensemble')
            
            audit_db_path = os.getenv('AUDIT_DB_PATH', 'data/audit_trail.db')
            if not os.path.isabs(audit_db_path):
                from pathlib import Path
                project_root = Path(__file__).parent.parent
                audit_db_path = str(project_root / audit_db_path)
            
            conn = sqlite3.connect(audit_db_path)
            cursor = conn.cursor()
            
            # Get most recent metrics for the model
            cursor.execute('''
                SELECT accuracy, precision, recall, f1, roc_auc, cm
                FROM model_metrics
                WHERE model_name = ?
                ORDER BY ts DESC
                LIMIT 1
            ''', (model,))
            
            row = cursor.fetchall()
            conn.close()
            
            if row:
                metrics = {
                    'accuracy': row[0][0],
                    'precision': row[0][1],
                    'recall': row[0][2],
                    'f1': row[0][3],
                    'roc_auc': row[0][4],
                    'cm': json.loads(row[0][5]) if row[0][5] else None
                }
            else:
                # Fallback to breach detector metrics if available
                detector = app.config.get('breach_detector')
                if detector and hasattr(detector, 'evaluation_results'):
                    rf_metrics = detector.evaluation_results.get('RandomForest', {})
                    gb_metrics = detector.evaluation_results.get('GradientBoosting', {})
                    
                    # Average metrics for ensemble
                    metrics = {
                        'accuracy': (rf_metrics.get('accuracy', 0) + gb_metrics.get('accuracy', 0)) / 2,
                        'precision': (rf_metrics.get('precision', 0) + gb_metrics.get('precision', 0)) / 2,
                        'recall': (rf_metrics.get('recall', 0) + gb_metrics.get('recall', 0)) / 2,
                        'f1': (rf_metrics.get('f1_score', 0) + gb_metrics.get('f1_score', 0)) / 2,
                        'roc_auc': (rf_metrics.get('roc_auc', 0) + gb_metrics.get('roc_auc', 0)) / 2,
                        'cm': None
                    }
                else:
                    metrics = {
                        'accuracy': 0.0,
                        'precision': 0.0,
                        'recall': 0.0,
                        'f1': 0.0,
                        'roc_auc': 0.0,
                        'cm': None
                    }
            
            return jsonify({'metrics': metrics, 'model': model}), 200
            
        except Exception as e:
            logger.error(f"Error fetching model metrics: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/testcases/seed', methods=['POST'])
    def seed_testcases():
        """Seed threat testcases into events table"""
        try:
            from utils.data_generator import seed_threat_testcases
            
            db_path = os.getenv('AUDIT_DB_PATH', 'data/audit_trail.db')
            catalog_path = os.getenv('THREAT_CATALOG_PATH', 'utils/threats_catalog.json')
            days = int(request.args.get('days', 7))
            
            count = seed_threat_testcases(db_path, catalog_path, days=days)
            
            return jsonify({
                'success': True,
                'message': f'Seeded {count} threat testcases',
                'count': count
            }), 200
            
        except Exception as e:
            logger.error(f"Error seeding testcases: {str(e)}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    return app


if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5000, debug=True)

