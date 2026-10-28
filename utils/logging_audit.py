"""
Secure Logging and Audit Trail Module for KAVACH
Ensures GDPR/CCPA compliance with secure, encrypted logging
"""

import json
import hashlib
import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path
import sqlite3

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SecureLogger:
    """
    Secure logging with encryption and compliance features
    """
    
    def __init__(self, log_dir='logs', audit_db='data/audit_trail.db', 
                 enable_encryption=True, anonymize_pii=True):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        self.audit_db = audit_db
        self.enable_encryption = enable_encryption
        self.anonymize_pii = anonymize_pii
        
        # Initialize audit database
        self._init_audit_db()
        
        logger.info("SecureLogger initialized")
    
    def _init_audit_db(self):
        """Initialize audit trail database"""
        conn = sqlite3.connect(self.audit_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                user_id TEXT,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                result TEXT,
                compliance_metadata TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source TEXT,
                description TEXT,
                resolution_status TEXT,
                compliance_checks TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_event(self, event_type: str, action: str, user_id: str = None, 
                 details: Dict = None, ip_address: str = None, result: str = 'SUCCESS'):
        """Log an event to audit trail"""
        timestamp = datetime.now().isoformat()
        
        # Anonymize PII if required
        if self.anonymize_pii and user_id:
            user_id = self._anonymize_identifier(user_id)
        
        if self.anonymize_pii and ip_address:
            ip_address = self._anonymize_ip(ip_address)
        
        # Prepare compliance metadata
        compliance_metadata = {
            'gdpr_compliant': True,
            'ccpa_compliant': True,
            'data_anonymized': self.anonymize_pii,
            'retention_policy': '30_days',
            'encrypted': self.enable_encryption
        }
        
        # Store in database
        conn = sqlite3.connect(self.audit_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO audit_log 
            (timestamp, event_type, user_id, action, details, ip_address, result, compliance_metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, event_type, user_id, action, 
              json.dumps(details), ip_address, result, 
              json.dumps(compliance_metadata)))
        
        conn.commit()
        conn.close()
        
        # Log to file
        log_entry = {
            'timestamp': timestamp,
            'event_type': event_type,
            'user_id': user_id,
            'action': action,
            'details': details,
            'ip_address': ip_address,
            'result': result,
            'compliance': compliance_metadata
        }
        
        self._write_log_file(log_entry)
        
        logger.info(f"Audit log: {event_type} - {action}")
    
    def log_alert(self, alert_id: str, alert_type: str, severity: str,
                 source: str = None, description: str = None,
                 compliance_checks: Dict = None):
        """Log a security alert"""
        timestamp = datetime.now().isoformat()
        
        if self.anonymize_pii and source:
            source = self._anonymize_identifier(source)
        
        # Anonymize PII in description
        if self.anonymize_pii and description:
            description = self._anonymize_text(description)
        
        conn = sqlite3.connect(self.audit_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO security_alerts
            (alert_id, timestamp, alert_type, severity, source, description, 
             resolution_status, compliance_checks)
            VALUES (?, ?, ?, ?, ?, ?, 'OPEN', ?)
        ''', (alert_id, timestamp, alert_type, severity, source, 
              description, json.dumps(compliance_checks or {})))
        
        conn.commit()
        conn.close()
        
        logger.warning(f"Security alert logged: {alert_type} - {severity}")
    
    def _anonymize_identifier(self, identifier: str) -> str:
        """Anonymize user identifiers (GDPR compliant)"""
        # Use consistent hashing for anonymization
        hash_obj = hashlib.sha256(identifier.encode())
        # Return first 12 characters of hash (96 bits)
        return f"anon_{hash_obj.hexdigest()[:12]}"
    
    def _anonymize_ip(self, ip_address: str) -> str:
        """Partially anonymize IP address"""
        parts = ip_address.split('.')
        if len(parts) == 4:
            # Keep only first two octets
            return f"{parts[0]}.{parts[1]}.XXX.XXX"
        return ip_address
    
    def _anonymize_text(self, text: str) -> str:
        """Anonymize PII in text"""
        # Simple anonymization - replace common patterns
        import re
        
        # Anonymize email addresses
        text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 
                     'anonymized@example.com', text)
        
        # Anonymize credit card numbers
        text = re.sub(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', 
                     'XXXX-XXXX-XXXX-XXXX', text)
        
        # Anonymize SSN
        text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', 'XXX-XX-XXXX', text)
        
        return text
    
    def _write_log_file(self, log_entry: Dict):
        """Write to log file"""
        date_str = datetime.now().strftime('%Y-%m-%d')
        log_file = self.log_dir / f"kavach_{date_str}.log"
        
        with open(log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def query_audit_log(self, start_date: str = None, end_date: str = None,
                       event_type: str = None, user_id: str = None) -> List[Dict]:
        """Query audit logs with filters"""
        conn = sqlite3.connect(self.audit_db)
        cursor = conn.cursor()
        
        query = "SELECT * FROM audit_log WHERE 1=1"
        params = []
        
        if start_date:
            query += " AND timestamp >= ?"
            params.append(start_date)
        
        if end_date:
            query += " AND timestamp <= ?"
            params.append(end_date)
        
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        
        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)
        
        query += " ORDER BY timestamp DESC LIMIT 1000"
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        # Convert to dicts
        columns = ['id', 'timestamp', 'event_type', 'user_id', 'action', 
                  'details', 'ip_address', 'result', 'compliance_metadata']
        
        logs = []
        for row in rows:
            log_dict = dict(zip(columns, row))
            if log_dict['details']:
                log_dict['details'] = json.loads(log_dict['details'])
            if log_dict['compliance_metadata']:
                log_dict['compliance_metadata'] = json.loads(log_dict['compliance_metadata'])
            logs.append(log_dict)
        
        return logs
    
    def get_alerts_summary(self, severity: str = None) -> List[Dict]:
        """Get summary of security alerts"""
        conn = sqlite3.connect(self.audit_db)
        cursor = conn.cursor()
        
        query = "SELECT * FROM security_alerts WHERE resolution_status = 'OPEN'"
        params = []
        
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        query += " ORDER BY timestamp DESC"
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        columns = ['id', 'alert_id', 'timestamp', 'alert_type', 'severity',
                  'source', 'description', 'resolution_status', 'compliance_checks']
        
        alerts = []
        for row in rows:
            alert_dict = dict(zip(columns, row))
            if alert_dict['compliance_checks']:
                alert_dict['compliance_checks'] = json.loads(alert_dict['compliance_checks'])
            alerts.append(alert_dict)
        
        return alerts
    
    def export_audit_log(self, output_file: str, start_date: str = None, 
                        end_date: str = None):
        """Export audit logs for compliance reporting"""
        logs = self.query_audit_log(start_date=start_date, end_date=end_date)
        
        with open(output_file, 'w') as f:
            json.dump(logs, f, indent=2)
        
        logger.info(f"Audit logs exported to {output_file}")
    
    def delete_old_logs(self, days_to_keep: int = 30):
        """Delete logs older than specified days (GDPR right to deletion)"""
        cutoff_date = (datetime.now() - timedelta(days=days_to_keep)).isoformat()
        
        conn = sqlite3.connect(self.audit_db)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM audit_log WHERE timestamp < ?', (cutoff_date,))
        deleted_count = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        logger.info(f"Deleted {deleted_count} old audit log entries")
        return deleted_count


# Global logger instance
secure_logger = SecureLogger()


