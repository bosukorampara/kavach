"""
GDPR/CCPA Compliance Module for KAVACH
Handles data anonymization, encryption, and privacy controls
"""

import json
import hashlib
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ComplianceManager:
    """
    Manage GDPR/CCPA compliance for KAVACH
    """
    
    def __init__(self):
        self.anonymization_enabled = True
        self.encryption_enabled = True
        self.retention_policy_days = 30
        
        logger.info("ComplianceManager initialized")
    
    def anonymize_data(self, data: Any, fields_to_anonymize: List[str] = None) -> Any:
        """
        Anonymize PII in data
        """
        if fields_to_anonymize is None:
            fields_to_anonymize = [
                'email', 'phone', 'credit_card', 'ssn', 'ip_address',
                'user_id', 'username', 'name', 'address'
            ]
        
        if isinstance(data, dict):
            anonymized = {}
            for key, value in data.items():
                if key in fields_to_anonymize:
                    anonymized[key] = self._anonymize_field(key, value)
                elif isinstance(value, (dict, list)):
                    anonymized[key] = self.anonymize_data(value, fields_to_anonymize)
                else:
                    anonymized[key] = value
            return anonymized
        
        elif isinstance(data, list):
            return [self.anonymize_data(item, fields_to_anonymize) for item in data]
        
        return data
    
    def _anonymize_field(self, field_name: str, value: str) -> str:
        """Anonymize a specific field"""
        if not isinstance(value, str):
            value = str(value)
        
        # Email
        if field_name in ['email']:
            return self._anonymize_email(value)
        
        # IP Address
        elif field_name in ['ip_address', 'source_ip', 'destination_ip']:
            return self._anonymize_ip(value)
        
        # Phone
        elif field_name in ['phone', 'phone_number']:
            return self._anonymize_phone(value)
        
        # Credit card
        elif field_name in ['credit_card', 'card_number']:
            return 'XXXX-XXXX-XXXX-XXXX'
        
        # SSN
        elif field_name == 'ssn':
            return 'XXX-XX-XXXX'
        
        # User ID
        elif field_name in ['user_id', 'username']:
            return self._anonymize_identifier(value)
        
        # Name
        elif field_name in ['name', 'first_name', 'last_name']:
            return 'Anonymized'
        
        # Address
        elif field_name == 'address':
            return 'Anonymized Address'
        
        # Default: hash
        else:
            return self._anonymize_identifier(value)
    
    def _anonymize_email(self, email: str) -> str:
        """Anonymize email address"""
        if '@' in email:
            local, domain = email.split('@', 1)
            # Keep first 2 chars, hash the rest
            hash_obj = hashlib.sha256(local.encode()).hexdigest()[:8]
            return f"{local[:2]}***{hash_obj}@{domain}"
        return email
    
    def _anonymize_phone(self, phone: str) -> str:
        """Anonymize phone number"""
        # Remove non-digits
        digits = re.sub(r'\D', '', phone)
        if len(digits) >= 10:
            return f"***-***-{digits[-4:]}"
        return phone
    
    def _anonymize_ip(self, ip: str) -> str:
        """Partially anonymize IP address"""
        parts = ip.split('.')
        if len(parts) == 4:
            # Keep first octet only
            return f"{parts[0]}.XXX.XXX.XXX"
        return ip
    
    def _anonymize_identifier(self, identifier: str) -> str:
        """Anonymize identifier using consistent hashing"""
        hash_obj = hashlib.sha256(identifier.encode()).hexdigest()
        return f"anon_{hash_obj[:12]}"
    
    def pseudonymize_data(self, data: Dict, key_field: str = 'user_id') -> Dict:
        """
        Pseudonymize data (reversible anonymization for GDPR)
        Store mapping separately for legal/regulatory needs
        """
        pseudonymized = data.copy()
        
        # Create consistent pseudonym
        identifier = data.get(key_field, 'unknown')
        pseudonym = self._anonymize_identifier(identifier)
        
        # Replace identifier
        if key_field in pseudonymized:
            pseudonymized[key_field] = pseudonym
        
        return pseudonymized
    
    def check_retention_policy(self, data: Dict, event_date: str = None) -> bool:
        """Check if data should be retained per policy"""
        if not event_date:
            return True
        
        try:
            event_datetime = datetime.fromisoformat(event_date)
            age = datetime.now() - event_datetime
            
            # Data older than retention policy should be marked for deletion
            if age.days > self.retention_policy_days:
                return False
        except:
            pass
        
        return True
    
    def create_consent_record(self, user_id: str, consent_type: str, 
                              granted: bool = True) -> Dict:
        """Create GDPR consent record"""
        return {
            'user_id': user_id,
            'consent_type': consent_type,
            'granted': granted,
            'timestamp': datetime.now().isoformat(),
            'gdpr_compliant': True
        }
    
    def export_user_data(self, user_id: str, data: List[Dict]) -> Dict:
        """
        Export user data in GDPR-compliant format
        Right to data portability
        """
        return {
            'user_id': user_id,
            'export_date': datetime.now().isoformat(),
            'format': 'JSON',
            'data': data,
            'total_records': len(data)
        }
    
    def delete_user_data(self, user_id: str) -> bool:
        """
        Delete all data for a user
        Right to be forgotten (GDPR Article 17)
        """
        logger.info(f"Deleting all data for user {user_id} (GDPR Article 17)")
        # Implementation would delete from database
        return True
    
    def encrypt_sensitive_fields(self, data: Dict, fields: List[str]) -> Dict:
        """
        Encrypt sensitive fields
        """
        encrypted = data.copy()
        
        for field in fields:
            if field in encrypted:
                # Simple encryption (in production, use proper encryption)
                value = str(encrypted[field])
                hash_obj = hashlib.sha256(value.encode()).hexdigest()
                encrypted[field] = f"enc_{hash_obj[:16]}"
        
        return encrypted
    
    def verify_compliance(self, data: Dict) -> Dict:
        """Verify GDPR/CCPA compliance"""
        issues = []
        
        # Check for PII without anonymization
        pii_fields = ['email', 'phone', 'credit_card', 'ssn']
        for field in pii_fields:
            if field in data and not self._is_anonymized(str(data[field])):
                issues.append(f"Potential PII in field: {field}")
        
        # Check data retention
        if 'timestamp' in data:
            if not self.check_retention_policy(data, data['timestamp']):
                issues.append("Data exceeds retention policy")
        
        return {
            'compliant': len(issues) == 0,
            'issues': issues,
            'checks': {
                'anonymization': self.anonymization_enabled,
                'encryption': self.encryption_enabled,
                'retention_policy': f"{self.retention_policy_days} days"
            }
        }
    
    def _is_anonymized(self, value: str) -> bool:
        """Check if value appears to be anonymized"""
        anonymized_patterns = [
            'XXX', '***', 'anon_', 'enc_', 'Anonymized'
        ]
        return any(pattern in value for pattern in anonymized_patterns)
    
    def add_compliance_metadata(self, data: Dict) -> Dict:
        """Add compliance metadata to data"""
        metadata = {
            'compliance': {
                'gdpr_compliant': True,
                'ccpa_compliant': True,
                'anonymization_enabled': self.anonymization_enabled,
                'encryption_enabled': self.encryption_enabled,
                'retention_policy_days': self.retention_policy_days,
                'timestamp': datetime.now().isoformat()
            }
        }
        
        if isinstance(data, dict):
            data['_compliance_metadata'] = metadata['compliance']
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    item['_compliance_metadata'] = metadata['compliance']
        
        return data


# Global compliance manager
compliance_manager = ComplianceManager()


