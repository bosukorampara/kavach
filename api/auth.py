"""
Authentication module for KAVACH
Handles user registration, login, and session management
"""

import sqlite3
import hashlib
import secrets
import os
import jwt
from datetime import datetime, timedelta
from typing import Optional, Dict
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Secret key for JWT (in production, use environment variable)
SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'kavach-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_HOURS = 24

# Database path
AUTH_DB_PATH = os.getenv('AUTH_DB_PATH', 'data/auth.db')


class AuthManager:
    """Manages user authentication and authorization"""
    
    def __init__(self, db_path: str = AUTH_DB_PATH):
        self.db_path = db_path
        self._init_db()
        logger.info(f"AuthManager initialized with DB: {self.db_path}")
    
    def _init_db(self):
        """Initialize authentication database"""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                created_at TEXT NOT NULL,
                last_login TEXT,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        
        # Sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _hash_password(self, password: str, salt: str = None) -> tuple:
        """Hash password with salt"""
        if salt is None:
            salt = secrets.token_hex(16)
        
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # Number of iterations
        ).hex()
        
        return password_hash, salt
    
    def register_user(self, username: str, email: str, password: str, role: str = 'user') -> Dict:
        """Register a new user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Check if username or email already exists
            cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
            if cursor.fetchone():
                return {'success': False, 'message': 'Username or email already exists'}
            
            # Hash password
            password_hash, salt = self._hash_password(password)
            
            # Insert user
            created_at = datetime.now().isoformat()
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, salt, role, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, email, password_hash, salt, role, created_at))
            
            user_id = cursor.lastrowid
            conn.commit()
            
            logger.info(f"User registered: {username}")
            return {
                'success': True,
                'message': 'User registered successfully',
                'user_id': user_id
            }
        
        except Exception as e:
            conn.rollback()
            logger.error(f"Registration error: {str(e)}")
            return {'success': False, 'message': f'Registration failed: {str(e)}'}
        
        finally:
            conn.close()
    
    def authenticate_user(self, username: str, password: str) -> Optional[Dict]:
        """Authenticate user and return user info"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Get user
            cursor.execute('''
                SELECT id, username, email, password_hash, salt, role, is_active
                FROM users WHERE username = ? OR email = ?
            ''', (username, username))
            
            user = cursor.fetchone()
            if not user:
                return None
            
            user_id, db_username, email, db_password_hash, salt, role, is_active = user
            
            if not is_active:
                return None
            
            # Verify password
            password_hash, _ = self._hash_password(password, salt)
            if password_hash != db_password_hash:
                return None
            
            # Update last login
            cursor.execute('''
                UPDATE users SET last_login = ? WHERE id = ?
            ''', (datetime.now().isoformat(), user_id))
            conn.commit()
            
            logger.info(f"User authenticated: {username}")
            return {
                'id': user_id,
                'username': db_username,
                'email': email,
                'role': role
            }
        
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return None
        
        finally:
            conn.close()
    
    def generate_token(self, user: Dict) -> str:
        """Generate JWT token for user"""
        payload = {
            'user_id': user['id'],
            'username': user['username'],
            'role': user['role'],
            'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),
            'iat': datetime.utcnow()
        }
        
        token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)
        return token
    
    def verify_token(self, token: str) -> Optional[Dict]:
        """Verify JWT token and return user info"""
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
            return {
                'user_id': payload['user_id'],
                'username': payload['username'],
                'role': payload['role']
            }
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except jwt.InvalidTokenError:
            logger.warning("Invalid token")
            return None
    
    def get_user(self, user_id: int) -> Optional[Dict]:
        """Get user by ID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT id, username, email, role, created_at, last_login
                FROM users WHERE id = ? AND is_active = 1
            ''', (user_id,))
            
            user = cursor.fetchone()
            if not user:
                return None
            
            return {
                'id': user[0],
                'username': user[1],
                'email': user[2],
                'role': user[3],
                'created_at': user[4],
                'last_login': user[5]
            }
        
        except Exception as e:
            logger.error(f"Error getting user: {str(e)}")
            return None
        
        finally:
            conn.close()


# Global auth manager instance
auth_manager = AuthManager()

