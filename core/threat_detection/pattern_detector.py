"""
Real-time threat pattern detection
Detects SQL injection, XSS, Command Injection, and other attack patterns in payloads
"""

import re
import logging
from typing import Dict, Optional, List, Tuple

logger = logging.getLogger(__name__)


class ThreatPatternDetector:
    """Detects various attack patterns in event payloads"""
    
    def __init__(self):
        # SQL Injection patterns
        self.sqli_patterns = [
            r"(['\"])\s*(OR|AND)\s*\1\s*\d+\s*=\s*\d+",  # ' OR 1=1
            r"(['\"])\s*(OR|AND)\s*\1\s*['\"]\s*=\s*['\"]",  # ' OR ''='
            r"UNION\s+SELECT",  # UNION SELECT
            r"UNION\s+ALL\s+SELECT",  # UNION ALL SELECT
            r"'\s*OR\s*'1'\s*=\s*'1",  # ' OR '1'='1
            r"'\s*OR\s*1\s*=\s*1",  # ' OR 1=1
            r"--\s*$",  # SQL comment
            r";\s*--",  # SQL comment
            r"/\*.*\*/",  # SQL comment block
            r"WAITFOR\s+DELAY",  # Time-based SQLi
            r"SLEEP\s*\(",  # Time-based SQLi
            r"BENCHMARK\s*\(",  # Time-based SQLi
            r"EXEC\s*\(",  # SQL execution
            r"EXECUTE\s*\(",  # SQL execution
            r"xp_cmdshell",  # SQL Server command execution
            r"sp_executesql",  # SQL Server stored procedure
        ]
        
        # XSS patterns
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",  # <script> tags
            r"<img[^>]*onerror\s*=",  # <img onerror=
            r"<svg[^>]*onload\s*=",  # <svg onload=
            r"onclick\s*=\s*['\"]",  # onclick=
            r"onerror\s*=\s*['\"]",  # onerror=
            r"onload\s*=\s*['\"]",  # onload=
            r"javascript:",  # javascript: protocol
            r"<iframe[^>]*>",  # <iframe>
            r"<object[^>]*>",  # <object>
            r"<embed[^>]*>",  # <embed>
            r"eval\s*\(",  # eval()
            r"alert\s*\(",  # alert()
            r"document\.cookie",  # document.cookie
            r"document\.write",  # document.write
        ]
        
        # Command Injection patterns
        self.command_injection_patterns = [
            r";\s*(cat|ls|pwd|whoami|id|uname)",  # ; cat /etc/passwd
            r"\|\s*(cat|ls|pwd|whoami|id|uname)",  # | cat /etc/passwd
            r"`[^`]*`",  # Backticks
            r"\$\s*\([^)]+\)",  # $() command substitution
            r"&&\s*(cat|ls|pwd|whoami|id|uname)",  # && cat
            r"\|\|\s*(cat|ls|pwd|whoami|id|uname)",  # || cat
            r"/etc/passwd",  # /etc/passwd access
            r"/etc/shadow",  # /etc/shadow access
            r"\.\./\.\./",  # Path traversal
            r"cmd\s*=\s*",  # cmd= parameter
        ]
        
        # SSRF patterns
        self.ssrf_patterns = [
            r"169\.254\.169\.254",  # AWS metadata
            r"127\.0\.0\.1",  # Localhost
            r"localhost",  # Localhost
            r"0\.0\.0\.0",  # All interfaces
            r"file:///",  # File protocol
            r"gopher://",  # Gopher protocol
            r"dict://",  # Dict protocol
        ]
        
        # Path Traversal patterns
        self.path_traversal_patterns = [
            r"\.\./\.\./",  # ../../
            r"\.\.\\\.\.\\",  # ..\..\ (Windows)
            r"/etc/passwd",  # /etc/passwd
            r"/etc/shadow",  # /etc/shadow
            r"/proc/self/environ",  # /proc/self/environ
            r"\.\.%2F",  # URL encoded ../
            r"\.\.%5C",  # URL encoded ..\
        ]
        
        # LDAP Injection patterns
        self.ldap_injection_patterns = [
            r"\)\s*\(|",  # )(| LDAP injection
            r"\*\s*\)",  # *) wildcard
            r"\(&",  # (& LDAP filter
            r"\(|",  # (| LDAP filter
        ]
        
        # NoSQL Injection patterns
        self.nosql_injection_patterns = [
            r"\$\s*ne\s*",  # $ne MongoDB
            r"\$\s*gt\s*",  # $gt MongoDB
            r"\$\s*lt\s*",  # $lt MongoDB
            r"\$\s*in\s*",  # $in MongoDB
            r"\$\s*nin\s*",  # $nin MongoDB
            r"\$\s*regex\s*",  # $regex MongoDB
            r"\{\s*\"\s*\$",  # {$ MongoDB operators
        ]
        
        # XXE patterns
        self.xxe_patterns = [
            r"<!DOCTYPE\s+[^>]*ENTITY",  # DOCTYPE ENTITY
            r"<!ENTITY\s+[^>]*SYSTEM",  # ENTITY SYSTEM
            r"file:///",  # file:// protocol
            r"&[a-zA-Z_][a-zA-Z0-9_]*;",  # Entity reference
        ]
        
        # JWT manipulation patterns
        self.jwt_patterns = [
            r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",  # JWT token
            r"alg\s*:\s*['\"]none['\"]",  # none algorithm
            r"alg\s*:\s*['\"]HS256['\"]",  # HS256 (weak if secret is weak)
        ]
    
    def detect_threats(self, payload: str, target: str = None, activity_type: str = None) -> List[Tuple[str, str]]:
        """
        Detect threats in a payload string
        Returns list of (threat_type, severity) tuples
        """
        if not payload:
            return []
        
        payload_lower = payload.lower()
        detected_threats = []
        
        # SQL Injection
        if any(re.search(pattern, payload, re.IGNORECASE) for pattern in self.sqli_patterns):
            detected_threats.append(("SQLi", "CRITICAL"))
        
        # XSS
        if any(re.search(pattern, payload, re.IGNORECASE) for pattern in self.xss_patterns):
            detected_threats.append(("XSS", "HIGH"))
        
        # Command Injection
        if any(re.search(pattern, payload, re.IGNORECASE) for pattern in self.command_injection_patterns):
            detected_threats.append(("CommandInjection", "CRITICAL"))
        
        # SSRF
        if any(re.search(pattern, payload, re.IGNORECASE) for pattern in self.ssrf_patterns):
            if target and any(ip in target for ip in ["169.254.169.254", "127.0.0.1", "localhost"]):
                detected_threats.append(("SSRF", "HIGH"))
        
        # Path Traversal
        if any(re.search(pattern, payload, re.IGNORECASE) for pattern in self.path_traversal_patterns):
            detected_threats.append(("DirTraversal", "HIGH"))
        
        # LDAP Injection
        if any(re.search(pattern, payload, re.IGNORECASE) for pattern in self.ldap_injection_patterns):
            detected_threats.append(("LDAPInjection", "HIGH"))
        
        # NoSQL Injection
        if any(re.search(pattern, payload, re.IGNORECASE) for pattern in self.nosql_injection_patterns):
            detected_threats.append(("NoSQLInjection", "HIGH"))
        
        # XXE
        if any(re.search(pattern, payload, re.IGNORECASE) for pattern in self.xxe_patterns):
            detected_threats.append(("XXE", "CRITICAL"))
        
        # JWT Manipulation
        if any(re.search(pattern, payload, re.IGNORECASE) for pattern in self.jwt_patterns):
            if "none" in payload_lower or "alg" in payload_lower:
                detected_threats.append(("JWTManipulation", "HIGH"))
        
        return detected_threats
    
    def analyze_event(self, event: Dict) -> Optional[Dict]:
        """
        Analyze an event for threat patterns
        Returns threat detection result or None
        """
        payload = event.get('payload', '') or event.get('request_body', '') or event.get('query_string', '')
        target = event.get('target', '') or event.get('endpoint', '')
        activity_type = event.get('activity_type', '')
        
        if not payload:
            return None
        
        threats = self.detect_threats(payload, target, activity_type)
        
        if not threats:
            return None
        
        # Return the highest severity threat
        threat_type, severity = max(threats, key=lambda x: ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(x[1]))
        
        return {
            'threat_type': threat_type,
            'severity': severity,
            'detected_patterns': threats,
            'payload': payload[:200],  # Truncate for storage
            'target': target
        }

