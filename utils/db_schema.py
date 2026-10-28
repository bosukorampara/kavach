"""
Database Schema Migration for KAVACH Audit Trail
Creates and migrates audit_trail.db tables
"""

import sqlite3
import os
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def init_audit_trail_schema(db_path='data/audit_trail.db'):
    """
    Initialize or migrate audit_trail.db with required tables:
    - events
    - alerts
    - model_metrics
    - feature_importance
    """
    # Ensure directory exists
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
    
    # Convert to absolute path if relative
    if not os.path.isabs(db_path):
        project_root = Path(__file__).parent.parent
        db_path = str(project_root / db_path)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create events table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            user_id TEXT,
            source_ip TEXT,
            activity_type TEXT,
            target TEXT,
            threat_type TEXT,
            payload TEXT,
            severity TEXT,
            label TEXT,
            meta TEXT
        )
    ''')
    
    # Create alerts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            user_id TEXT,
            source_ip TEXT,
            threat_type TEXT,
            severity TEXT,
            model_score REAL,
            model_name TEXT,
            explanation TEXT
        )
    ''')
    
    # Create model_metrics table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS model_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            model_name TEXT,
            split TEXT,
            accuracy REAL,
            precision REAL,
            recall REAL,
            f1 REAL,
            roc_auc REAL,
            cm TEXT
        )
    ''')
    
    # Create feature_importance table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS feature_importance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            model_name TEXT,
            feature TEXT,
            importance REAL
        )
    ''')
    
    # Create indexes for performanceeee
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_threat_type ON events(threat_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_user_id ON events(user_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip)')
    
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_threat_type ON alerts(threat_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)')
    
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_model_metrics_ts ON model_metrics(ts)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_model_metrics_model_name ON model_metrics(model_name)')
    
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_feature_importance_ts ON feature_importance(ts)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_feature_importance_model_name ON feature_importance(model_name)')
    
    conn.commit()
    conn.close()
    
    logger.info(f"Audit trail schema initialized: {db_path}")


if __name__ == '__main__':
    init_audit_trail_schema()

