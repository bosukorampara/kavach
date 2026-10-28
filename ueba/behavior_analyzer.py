"""
User and Entity Behavior Analytics (UEBA)
Builds behavioral profiles and detects insider threats
"""

import os
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from collections import defaultdict
from datetime import datetime, timedelta
import json
import logging
import joblib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BehaviorProfile:
    """Represents behavioral profile for a user or entity"""
    
    def __init__(self, entity_id: str, entity_type: str = 'user'):
        self.entity_id = entity_id
        self.entity_type = entity_type
        self.login_times = []
        self.access_patterns = defaultdict(int)
        self.access_frequency = defaultdict(int)
        self.data_volume_stats = []
        self.locations = []
        self.devices = []
        self.activity_types = defaultdict(int)
        self.first_seen = datetime.now()
        self.last_seen = datetime.now()
        
        # Computed baseline
        self.baseline_login_time = None
        self.baseline_access_frequency = None
        self.baseline_data_volume = None
    
    def update(self, activity_data: dict):
        """Update profile with new activity"""
        if 'timestamp' in activity_data:
            try:
                timestamp = pd.to_datetime(activity_data['timestamp'])
            except:
                timestamp = datetime.now()
            
            hour = timestamp.hour
            self.login_times.append(hour)
            
            if 'location' in activity_data:
                self.locations.append(activity_data['location'])
            
            if 'device' in activity_data:
                self.devices.append(activity_data['device'])
        
        if 'activity_type' in activity_data:
            self.activity_types[activity_data['activity_type']] += 1
            self.access_patterns[activity_data['activity_type']] += 1
        
        if 'bytes_transferred' in activity_data:
            self.data_volume_stats.append(activity_data['bytes_transferred'])
        
        self.last_seen = datetime.now()
    
    def compute_baseline(self):
        """Compute baseline behavioral statistics"""
        if len(self.login_times) > 0:
            self.baseline_login_time = np.mean(self.login_times)
            self.baseline_access_frequency = sum(self.access_frequency.values())
        
        if len(self.data_volume_stats) > 0:
            self.baseline_data_volume = np.mean(self.data_volume_stats)
    
    def to_dict(self):
        """Convert profile to dictionary"""
        return {
            'entity_id': self.entity_id,
            'entity_type': self.entity_type,
            'baseline_login_time': self.baseline_login_time,
            'baseline_access_frequency': self.baseline_access_frequency,
            'baseline_data_volume': self.baseline_data_volume,
            'total_sessions': len(self.login_times),
            'unique_locations': len(set(self.locations)),
            'unique_devices': len(set(self.devices)),
            'activity_types': dict(self.activity_types),
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat()
        }


class BehaviorAnalyzer:
    """
    UEBA system - analyzes behavior patterns to detect insider threats
    """
    
    def __init__(self, deviation_threshold=2.0):
        self.profiles = {}  # entity_id -> BehaviorProfile
        self.deviation_threshold = deviation_threshold
        self.scaler = StandardScaler()
        self.is_trained = False
        
        logger.info("BehaviorAnalyzer initialized")
    
    def train(self, activity_data: pd.DataFrame):
        """
        Train the UEBA system by building behavioral profiles
        """
        logger.info("Building behavioral profiles...")
        
        for _, row in activity_data.iterrows():
            entity_id = row.get('user_id', 'unknown')
            
            # Get or create profile
            if entity_id not in self.profiles:
                self.profiles[entity_id] = BehaviorProfile(entity_id, 'user')
            
            # Update profile
            self.profiles[entity_id].update(row.to_dict())
        
        # Compute baselines
        for entity_id, profile in self.profiles.items():
            profile.compute_baseline()
        
        self.is_trained = True
        logger.info(f"Trained {len(self.profiles)} behavioral profiles")
    
    def detect_anomaly(self, activity_data: dict) -> dict:
        """
        Detect behavioral anomalies for a given activity
        Returns: anomaly detection result
        """
        if not self.is_trained:
            return {
                'is_anomaly': False,
                'reason': 'Model not trained',
                'risk_score': 0.0,
                'anomalies': []
            }
        
        entity_id = activity_data.get('user_id', 'unknown')
        
        if entity_id not in self.profiles:
            # New entity - flag as potentially suspicious
            return {
                'is_anomaly': True,
                'reason': 'Unknown entity - not in behavioral baseline',
                'risk_score': 0.5,
                'anomalies': []
            }
        
        profile = self.profiles[entity_id]
        anomaly_score = 0.0
        anomalies = []
        
        # Check login time anomaly
        if 'timestamp' in activity_data:
            try:
                timestamp = pd.to_datetime(activity_data['timestamp'])
                current_hour = timestamp.hour
                
                if profile.baseline_login_time is not None:
                    deviation = abs(current_hour - profile.baseline_login_time) / 24.0
                    if deviation > 0.5:  # Different time of day
                        anomaly_score += 0.3
                        anomalies.append('unusual_login_time')
            except:
                pass
        
        # Check data volume anomaly
        if 'bytes_transferred' in activity_data and profile.baseline_data_volume is not None:
            data_vol = activity_data['bytes_transferred']
            if data_vol > 0 and profile.baseline_data_volume > 0:
                ratio = data_vol / profile.baseline_data_volume
                if ratio > 5.0:  # 5x normal volume
                    anomaly_score += 0.4
                    anomalies.append('excessive_data_transfer')
        
        # Check location anomaly
        if 'location' in activity_data:
            location = activity_data['location']
            if location not in profile.locations:
                anomaly_score += 0.2
                anomalies.append('unusual_location')
        
        # Check activity type anomaly
        if 'activity_type' in activity_data:
            activity_type = activity_data['activity_type']
            baseline_freq = profile.activity_types.get(activity_type, 0)
            total_activities = sum(profile.activity_types.values())
            
            if total_activities > 0 and baseline_freq == 0:
                anomaly_score += 0.3
                anomalies.append('unusual_activity_type')
        
        # Normalize risk score
        risk_score = min(anomaly_score, 1.0)
        
        return {
            'is_anomaly': risk_score > 0.4 or len(anomalies) >= 2,
            'anomalies': anomalies,
            'risk_score': risk_score,
            'entity_id': entity_id
        }
    
    def get_profile(self, entity_id: str) -> BehaviorProfile:
        """Get behavioral profile for an entity"""
        return self.profiles.get(entity_id, None)
    
    def get_all_profiles(self) -> list:
        """Get all behavioral profiles"""
        return [profile.to_dict() for profile in self.profiles.values()]
    
    def update_profile(self, entity_id: str, activity_data: dict):
        """Update a profile with new activity"""
        if entity_id not in self.profiles:
            self.profiles[entity_id] = BehaviorProfile(entity_id)
        
        self.profiles[entity_id].update(activity_data)
        self.profiles[entity_id].compute_baseline()
    
    def save_profiles(self, filepath: str):
        """Persist behavioral profiles to disk."""
        target = os.path.abspath(filepath)
        directory = os.path.dirname(target)
        if directory:
            os.makedirs(directory, exist_ok=True)
        joblib.dump({
            'profiles': self.profiles,
            'deviation_threshold': self.deviation_threshold
        }, target)
        self.is_trained = True
        logger.info("Behavior profiles saved to %s", target)
    
    def load_profiles(self, filepath: str):
        """Load behavioral profiles from disk."""
        target = os.path.abspath(filepath)
        data = joblib.load(target)
        self.profiles = data.get('profiles', {})
        self.deviation_threshold = data.get('deviation_threshold', self.deviation_threshold)
        self.is_trained = len(self.profiles) > 0
        logger.info("Loaded %d behavioral profiles from %s", len(self.profiles), target)


class InsiderThreatDetector:
    """
    Specialized detector for insider threats
    Detects: privilege escalation, data exfiltration, unusual access patterns
    """
    
    def __init__(self, behavior_analyzer: BehaviorAnalyzer):
        self.analyzer = behavior_analyzer
        
    def detect_threat(self, activity_data: dict) -> dict:
        """Detect insider threat indicators"""
        entity_id = activity_data.get('user_id', 'unknown')
        profile = self.analyzer.get_profile(entity_id)
        
        if not profile:
            return {'threat_detected': False, 'reason': 'No profile'}
        
        threats = []
        
        # Check for privilege escalation
        if 'user_role' in activity_data:
            if activity_data['user_role'] == 'admin' and profile.entity_type == 'user':
                threats.append('potential_privilege_escalation')
        
        # Check for data exfiltration
        if 'bytes_transferred' in activity_data:
            data_vol = activity_data['bytes_transferred']
            if data_vol > 10000000:  # > 10MB
                threats.append('potential_data_exfiltration')
        
        # Check for unusual access patterns
        anomaly = self.analyzer.detect_anomaly(activity_data)
        if anomaly['is_anomaly']:
            threats.append('behavioral_anomaly')
        
        return {
            'threat_detected': len(threats) > 0,
            'threats': threats,
            'entity_id': entity_id,
            'risk_score': anomaly.get('risk_score', 0.0)
        }

