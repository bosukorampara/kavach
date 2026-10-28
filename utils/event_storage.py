"""
Event Storage System for KAVACH
Stores all security events for dashboard visualization and analytics
"""

import sqlite3
import json
import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import pandas as pd

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EventStorage:
    """
    Stores and retrieves security events for dashboard and analytics
    """
    
    def __init__(self, db_path='data/events.db'):
        db_path = os.getenv('EVENT_STORAGE_DB', db_path)
        # Ensure directory exists
        db_dir = os.path.dirname(db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
        
        # Convert to absolute path if relative
        if not os.path.isabs(db_path):
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            db_path = os.path.join(project_root, db_path)
        
        self.db_path = db_path
        self._init_db()
        logger.info(f"EventStorage initialized with DB: {self.db_path}")
    
    def _init_db(self):
        """Initialize SQLite database for event storage"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Main events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                user_id TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                activity_type TEXT,
                bytes_transferred INTEGER,
                request_count INTEGER,
                user_role TEXT,
                location TEXT,
                is_malicious BOOLEAN,
                confidence REAL,
                is_anomaly BOOLEAN,
                anomaly_score REAL,
                risk_score REAL,
                prediction_details TEXT,
                honeytoken_alert TEXT,
                ueba_result TEXT,
                autoencoder_result TEXT,
                created_at TEXT NOT NULL
            )
        ''')
        
        # Create indexes for faster queries
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON security_events(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_id ON security_events(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_is_malicious ON security_events(is_malicious)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_is_anomaly ON security_events(is_anomaly)')
        
        conn.commit()
        conn.close()
    
    def store_event(self, event_data: Dict, prediction_result: Dict = None, 
                   anomaly_result: Dict = None, honeytoken_alert: Dict = None,
                   ueba_result: Dict = None, autoencoder_result: Dict = None) -> str:
        """
        Store a security event with all analysis results
        Returns: event_id
        """
        import hashlib
        import secrets
        
        # Generate unique event ID
        event_id = hashlib.sha256(
            f"{event_data.get('user_id', '')}{event_data.get('timestamp', '')}{secrets.token_hex(8)}".encode()
        ).hexdigest()[:16]
        
        # Extract prediction details
        is_malicious = False
        confidence = 0.0
        risk_score = 0.0
        
        if prediction_result:
            is_malicious = prediction_result.get('is_malicious', False)
            confidence = prediction_result.get('confidence', 0.0)
            risk_score = max(confidence, prediction_result.get('rf_confidence', 0.0), 
                           prediction_result.get('gb_confidence', 0.0))
        
        # Extract anomaly details
        is_anomaly = False
        anomaly_score = 0.0
        if anomaly_result:
            if isinstance(anomaly_result.get('is_anomaly'), (list, pd.Series)):
                is_anomaly = bool(anomaly_result['is_anomaly'][0] if len(anomaly_result['is_anomaly']) > 0 else False)
            else:
                is_anomaly = bool(anomaly_result.get('is_anomaly', False))
            
            if isinstance(anomaly_result.get('anomaly_score'), (list, pd.Series)):
                anomaly_score = float(anomaly_result['anomaly_score'][0] if len(anomaly_result['anomaly_score']) > 0 else 0.0)
            else:
                anomaly_score = float(anomaly_result.get('anomaly_score', 0.0))
        
        # Store in database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO security_events 
            (event_id, timestamp, user_id, source_ip, destination_ip, activity_type,
             bytes_transferred, request_count, user_role, location,
             is_malicious, confidence, is_anomaly, anomaly_score, risk_score,
             prediction_details, honeytoken_alert, ueba_result, autoencoder_result, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event_id,
            event_data.get('timestamp', datetime.now().isoformat()),
            event_data.get('user_id'),
            event_data.get('source_ip'),
            event_data.get('destination_ip'),
            event_data.get('activity_type'),
            event_data.get('bytes_transferred', 0),
            event_data.get('request_count', 0),
            event_data.get('user_role'),
            event_data.get('location'),
            is_malicious,
            confidence,
            is_anomaly,
            anomaly_score,
            risk_score,
            json.dumps(prediction_result) if prediction_result else None,
            json.dumps(honeytoken_alert) if honeytoken_alert else None,
            json.dumps(ueba_result) if ueba_result else None,
            json.dumps(autoencoder_result) if autoencoder_result else None,
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
        
        logger.debug(f"Stored event {event_id}")
        return event_id
    
    def get_threat_trends(self, hours=24) -> List[Dict]:
        """
        Get threat trends for the last N hours
        Returns aggregated data by hour
        """
        cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Query events grouped by hour
        cursor.execute('''
            SELECT 
                strftime('%Y-%m-%d %H:00:00', timestamp) as hour,
                COUNT(*) as total_events,
                SUM(CASE WHEN is_malicious = 1 THEN 1 ELSE 0 END) as threats_detected,
                SUM(CASE WHEN is_malicious = 1 AND confidence < 0.5 THEN 1 ELSE 0 END) as false_positives,
                SUM(CASE WHEN honeytoken_alert IS NOT NULL THEN 1 ELSE 0 END) as honeytoken_breaches
            FROM security_events
            WHERE timestamp >= ?
            GROUP BY hour
            ORDER BY hour DESC
            LIMIT ?
        ''', (cutoff_time, hours))
        
        rows = cursor.fetchall()
        conn.close()
        
        trends = []
        for row in rows:
            trends.append({
                'timestamp': row[0],
                'total_events': row[1],
                'threats_detected': row[2],
                'false_positives': row[3],
                'honeytoken_breaches': row[4]
            })
        
        # Fill in missing hours with zeros
        result = []
        for i in range(hours):
            hour_time = (datetime.now() - timedelta(hours=i)).strftime('%Y-%m-%d %H:00:00')
            existing = next((t for t in trends if t['timestamp'] == hour_time), None)
            if existing:
                result.append(existing)
            else:
                result.append({
                    'timestamp': hour_time,
                    'total_events': 0,
                    'threats_detected': 0,
                    'false_positives': 0,
                    'honeytoken_breaches': 0
                })
        
        return sorted(result, key=lambda x: x['timestamp'])
    
    def get_activity_timeline(self, limit=50) -> List[Dict]:
        """
        Get recent activity timeline
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                timestamp,
                user_id,
                activity_type as action,
                risk_score,
                is_malicious,
                is_anomaly,
                source_ip
            FROM security_events
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        timeline = []
        for row in rows:
            timeline.append({
                'timestamp': row[0],
                'user_id': row[1] or 'unknown',
                'action': row[2] or 'unknown',
                'risk_score': float(row[3]) if row[3] else 0.0,
                'is_malicious': bool(row[4]),
                'is_anomaly': bool(row[5]),
                'source_ip': row[6]
            })
        
        return timeline
    
    def get_statistics(self, hours=24) -> Dict:
        """Get overall statistics"""
        cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                COUNT(*) as total_events,
                SUM(CASE WHEN is_malicious = 1 THEN 1 ELSE 0 END) as threats,
                SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies,
                SUM(CASE WHEN honeytoken_alert IS NOT NULL THEN 1 ELSE 0 END) as honeytoken_breaches,
                AVG(risk_score) as avg_risk_score
            FROM security_events
            WHERE timestamp >= ?
        ''', (cutoff_time,))
        
        row = cursor.fetchone()
        conn.close()
        
        return {
            'total_events': row[0] or 0,
            'threats_detected': row[1] or 0,
            'anomalies_detected': row[2] or 0,
            'honeytoken_breaches': row[3] or 0,
            'avg_risk_score': float(row[4]) if row[4] else 0.0,
            'period_hours': hours
        }
    
    def cleanup_old_events(self, days_to_keep=30):
        """Delete events older than specified days"""
        cutoff_time = (datetime.now() - timedelta(days=days_to_keep)).isoformat()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM security_events WHERE timestamp < ?', (cutoff_time,))
        deleted_count = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        logger.info(f"Cleaned up {deleted_count} old events")
        return deleted_count


# Global event storage instance
event_storage = EventStorage()

