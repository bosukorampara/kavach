"""
API Module for KAVACH
Provides RESTful endpoints for predictions, alerts, and monitoring
"""

from .app import create_app

__all__ = ['create_app']

