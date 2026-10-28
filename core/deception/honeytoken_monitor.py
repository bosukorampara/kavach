"""
Deception Module - Honeytoken Monitoring and Alerting
Plants and monitors decoy credentials, files, IPs
"""

import sqlite3
import json
import logging
import os
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict
import hashlib
import secrets

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class Honeytoken:
    """Represents a honeytoken (decoy credential, file, or IP)"""
    id: str
    token_type: str  # 'credential', 'file', 'ip', 'url'
    token_value: str
    location: str
    planted_at: str
    accessed: bool = False
    accessed_at: Optional[str] = None
    accessed_by: Optional[str] = None
    severity: str = 'HIGH'
    metadata: Dict = None


class HoneytokenMonitor:
    """
    Monitors and manages honeytokens (fake credentials, decoy files, unused IPs)
    """
    
    def __init__(self, db_path=None):
        # Get database path from environment or use default
        if db_path is None:
            db_path = os.getenv('HONEYTOKEN_DB_PATH', 'data/honeytokens.db')
        
        # Ensure directory exists
        db_dir = os.path.dirname(db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
        
        # Convert to absolute path if relative
        if not os.path.isabs(db_path):
            # Get project root (assuming this file is in core/deception/)
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            db_path = os.path.join(project_root, db_path)
        
        self.db_path = db_path
        self._init_db()
        self.alerts = []
        logger.info(f"HoneytokenMonitor initialized with DB: {self.db_path}")
    
    def _init_db(self):
        """Initialize SQLite database for honeytoken storage"""
        # Ensure directory exists
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS honeytokens (
                id TEXT PRIMARY KEY,
                token_type TEXT NOT NULL,
                token_value TEXT NOT NULL,
                location TEXT NOT NULL,
                planted_at TEXT NOT NULL,
                accessed BOOLEAN DEFAULT FALSE,
                accessed_at TEXT,
                accessed_by TEXT,
                severity TEXT NOT NULL,
                metadata TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS honeytoken_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                event_timestamp TEXT NOT NULL,
                source_ip TEXT,
                user_id TEXT,
                event_data TEXT,
                FOREIGN KEY (token_id) REFERENCES honeytokens(id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def plant_honeytoken(self, token_type: str, location: str, 
                        metadata: Dict = None, severity: str = 'HIGH', 
                        attack_type: str = None) -> str:
        """
        Plant a honeytoken at specified location with optional attack type targeting
        Returns: honeytoken ID
        """
        # Generate unique token
        token_id = hashlib.sha256(
            f"{token_type}{location}{datetime.now().isoformat()}{secrets.token_hex(8)}".encode()
        ).hexdigest()
        
        # Generate appropriate token value based on attack type
        if attack_type:
            # Generate attack-specific honeytoken values
            if attack_type == 'SQLi':
                if token_type == 'credential':
                    token_value = f"admin' OR '1'='1' --"
                elif token_type == 'file':
                    token_value = f"db_credentials.sql"
                else:
                    token_value = f"sql_injection_target_{secrets.token_hex(8)}"
            elif attack_type == 'XSS':
                if token_type == 'file':
                    token_value = f"user_comment.html"
                elif token_type == 'url':
                    token_value = f"/comment?payload=<script>alert(1)</script>"
                else:
                    token_value = f"xss_target_{secrets.token_hex(8)}"
            elif attack_type == 'CommandInjection':
                if token_type == 'file':
                    token_value = f"exec_script.sh"
                else:
                    token_value = f"cmd_injection_target_{secrets.token_hex(8)}"
            elif attack_type == 'SSRF':
                if token_type == 'url':
                    token_value = f"http://169.254.169.254/latest/meta-data"
                else:
                    token_value = f"ssrf_target_{secrets.token_hex(8)}"
            elif attack_type == 'DirTraversal':
                if token_type == 'file':
                    token_value = f"../../../etc/passwd"
                else:
                    token_value = f"traversal_target_{secrets.token_hex(8)}"
            else:
                # Generic attack type
                token_value = f"{attack_type.lower()}_target_{secrets.token_hex(8)}"
        else:
            # Default token generation
            if token_type == 'credential':
                token_value = self._generate_fake_credential()
            elif token_type == 'file':
                token_value = self._generate_fake_filename()
            elif token_type == 'ip':
                token_value = self._generate_unused_ip()
            elif token_type == 'url':
                token_value = self._generate_fake_url()
            else:
                token_value = secrets.token_hex(16)
        
        # Store attack_type in metadata
        if metadata is None:
            metadata = {}
        if attack_type:
            metadata['attack_type'] = attack_type
            metadata['target_attack'] = attack_type
        
        # Store in database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO honeytokens 
            (id, token_type, token_value, location, planted_at, severity, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (token_id, token_type, token_value, location, 
              datetime.now().isoformat(), severity, json.dumps(metadata)))
        
        conn.commit()
        conn.close()
        
        attack_info = f" for {attack_type} attacks" if attack_type else ""
        logger.info(f"Planted honeytoken {token_id} of type {token_type} at {location}{attack_info}")
        
        return token_id
    
    def _record_access(self, token_id: str, source_ip: Optional[str], user_id: Optional[str], event_data: Dict = None):
        """Mark a honeytoken as accessed and write an event log."""
        timestamp = datetime.now().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''
                UPDATE honeytokens 
                SET accessed = TRUE, accessed_at = ?, accessed_by = ?
                WHERE id = ?
                ''',
                (timestamp, user_id or source_ip, token_id)
            )
            cursor.execute(
                '''
                INSERT INTO honeytoken_events 
                (token_id, event_type, event_timestamp, source_ip, user_id, event_data)
                VALUES (?, ?, ?, ?, ?, ?)
                ''',
                (token_id, 'access', timestamp, source_ip, user_id, json.dumps(event_data or {}))
            )
            conn.commit()
    
    def _create_alert(self, row, source_user: Optional[str], source_ip: Optional[str] = None) -> Dict:
        """Build alert payload and cache it."""
        token_id = row[0]
        token_type = row[1]
        location = row[3]
        planted_at = row[4]
        severity = row[8]
        
        alert = {
            'id': token_id,
            'type': 'HONEYTOKEN_BREACH',
            'severity': severity,
            'timestamp': datetime.now().isoformat(),
            'token_type': token_type,
            'location': location,
            'source_user': source_user,
            'source_ip': source_ip,
            'planted_at': planted_at,
            'message': f'Honeytoken breach detected! Type: {token_type}, Location: {location}'
        }
        self.alerts.append(alert)
        logger.warning("⚠️ HONEYTOKEN BREACH: %s", alert['message'])
        return alert
    
    def _fetch_token_by_value(self, token_value: str):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM honeytokens WHERE token_value = ?', (token_value,))
            return cursor.fetchone()
    
    def _fetch_token_by_id(self, token_id: str):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM honeytokens WHERE id = ?', (token_id,))
            return cursor.fetchone()
    
    def check_event_for_honeytoken(self, event: Dict) -> Optional[Dict]:
        """
        Inspect an event payload for honeytoken interactions.
        Supports direct token IDs/values and auto-checks decoy IPs.
        Also detects attack patterns in payloads when honeytokens are accessed.
        """
        from core.threat_detection.pattern_detector import ThreatPatternDetector
        
        token_id = event.get('honeytoken_id')
        token_value = event.get('honeytoken_value')
        actor = event.get('user_id')
        source_ip = event.get('source_ip')
        candidate_values = []
        
        if token_value:
            candidate_values.append(token_value)
        if event.get('source_ip'):
            candidate_values.append(event['source_ip'])
        if event.get('destination_ip'):
            candidate_values.append(event['destination_ip'])
        
        honeytoken_alert = None
        detected_row = None
        
        # Direct lookup by ID
        if token_id:
            row = self._fetch_token_by_id(token_id)
            if row:
                detected_row = row
                honeytoken_alert = self._handle_token_row(row, actor, source_ip)
        
        # Lookup by provided value or IP matches (only for IP honeytokens)
        if not detected_row:
            for value in candidate_values:
                if not value:
                    continue
                row = self._fetch_token_by_value(value)
                if row:
                    token_type = row[1]
                    if token_type == 'ip' or value == token_value:
                        detected_row = row
                        honeytoken_alert = self._handle_token_row(row, actor, source_ip if token_type == 'ip' else None)
                        break
        
        # If honeytoken was accessed, analyze payload for attack patterns
        if honeytoken_alert:
            pattern_detector = ThreatPatternDetector()
            threat_result = pattern_detector.analyze_event(event)
            
            if threat_result:
                # Enhance alert with detected attack type
                honeytoken_alert['attack_type'] = threat_result['threat_type']
                honeytoken_alert['attack_severity'] = threat_result['severity']
                honeytoken_alert['message'] = f"Honeytoken breach with {threat_result['threat_type']} attack detected! Type: {detected_row[1]}, Location: {detected_row[3]}"
                logger.warning("⚠️ HONEYTOKEN BREACH WITH ATTACK: %s - %s", threat_result['threat_type'], honeytoken_alert['message'])
        
        return honeytoken_alert
    
    def _handle_token_row(self, row, actor: Optional[str], source_ip: Optional[str]) -> Optional[Dict]:
        """Helper to mark a token access and emit alert."""
        if not row:
            return None
        already_accessed = bool(row[5])
        token_id = row[0]
        token_value = row[2]
        
        if already_accessed:
            return None
        
        self._record_access(token_id, source_ip, actor, {'token_value': token_value})
        return self._create_alert(row, actor, source_ip)
    
    def check_interaction(self, token_identifier: str, source: str = None) -> Optional[Dict]:
        """
        Backwards-compatible API to check a direct honeytoken value.
        """
        event_payload = {
            'honeytoken_value': token_identifier,
            'user_id': source,
            'source_ip': source
        }
        return self.check_event_for_honeytoken(event_payload)
    
    def get_all_honeytokens(self, show_all: bool = True) -> List[Dict]:
        """Get all honeytokens"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = 'SELECT * FROM honeytokens' if show_all else 'SELECT * FROM honeytokens WHERE accessed = FALSE'
        cursor.execute(query)
        
        results = cursor.fetchall()
        conn.close()
        
        honeytokens = []
        for row in results:
            honeytokens.append({
                'id': row[0],
                'type': row[1],
                'value': row[2],
                'location': row[3],
                'planted_at': row[4],
                'accessed': bool(row[5]),
                'accessed_at': row[6],
                'accessed_by': row[7],
                'severity': row[8],
                'metadata': json.loads(row[9]) if row[9] else {}
            })
        
        return honeytokens
    
    def get_alerts(self) -> List[Dict]:
        """Get all triggered alerts"""
        return self.alerts.copy()
    
    def get_statistics(self) -> Dict:
        """Get honeytoken statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM honeytokens')
        total = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM honeytokens WHERE accessed = TRUE')
        accessed = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM honeytoken_events WHERE event_type = "access"')
        breach_events = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_tokens': total,
            'tokens_accessed': accessed,
            'tokens_active': total - accessed,
            'breach_events': breach_events,
            'breach_rate': (accessed / total * 100) if total > 0 else 0
        }
    
    def _generate_fake_credential(self) -> str:
        """Generate fake credential"""
        username = f"service_{secrets.token_hex(4)}"
        password = secrets.token_urlsafe(16)
        return f"{username}:{password}"
    
    def _generate_fake_filename(self) -> str:
        """Generate fake filename"""
        fake_names = ['credentials.txt', 'passwords.xlsx', 'secret_data.db', 
                     'private_keys.key', 'backup_2024.zip']
        return secrets.choice(fake_names)
    
    def _generate_unused_ip(self) -> str:
        """Generate unused IP address"""
        # Example: 10.x.x.x (private range)
        return f"10.{secrets.randbelow(255)}.{secrets.randbelow(255)}.{secrets.randbelow(255)}"
    
    def _generate_fake_url(self) -> str:
        """Generate fake URL"""
        domains = ['admin', 'secure', 'internal', 'private']
        return f"https://{secrets.choice(domains)}-{secrets.token_hex(4)}.internal.com"
    
    def log_event(self, token_id: str, event_type: str, 
                  source_ip: str = None, user_id: str = None, event_data: Dict = None):
        """Log a honeytoken event"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO honeytoken_events 
            (token_id, event_type, event_timestamp, source_ip, user_id, event_data)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (token_id, event_type, datetime.now().isoformat(), 
              source_ip, user_id, json.dumps(event_data or {})))
        
        conn.commit()
        conn.close()
        logger.info(f"Logged event: {event_type} for token {token_id}")

