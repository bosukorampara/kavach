"""
Anomaly Detection using Isolation Forest and Autoencoders
"""

import os
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AnomalyDetector:
    """
    Anomaly Detection for identifying unusual patterns in user behavior
    """
    
    def __init__(self, contamination=0.05, random_state=42):
        self.model = IsolationForest(contamination=contamination, random_state=random_state)
        self.scaler = StandardScaler()
        self.is_trained = False
        
        logger.info("AnomalyDetector initialized")
    
    def train(self, data: pd.DataFrame):
        """
        Train the anomaly detection model
        """
        logger.info("Training anomaly detection model...")
        
        # Scale features
        scaled_data = self.scaler.fit_transform(data)
        
        # Train model
        self.model.fit(scaled_data)
        self.is_trained = True
        
        logger.info("Anomaly detection model trained successfully")
        
        return self
    
    def predict(self, data: pd.DataFrame):
        """
        Detect anomalies in data
        Returns: -1 for anomaly, 1 for normal
        """
        if not self.is_trained:
            raise ValueError("Model not trained. Call train() first.")
        
        scaled_data = self.scaler.transform(data)
        predictions = self.model.predict(scaled_data)
        anomaly_scores = self.model.score_samples(scaled_data)
        
        return {
            'is_anomaly': predictions == -1,
            'anomaly_score': -anomaly_scores  # Higher score = more anomalous
        }
    
    def save_model(self, filepath='models/anomaly_detector.joblib'):
        """Save the model"""
        model_path = os.path.abspath(filepath)
        directory = os.path.dirname(model_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler
        }, model_path)
        logger.info(f"Model saved to {model_path}")
    
    def load_model(self, filepath='models/anomaly_detector.joblib'):
        """Load the model"""
        model_path = os.path.abspath(filepath)
        data = joblib.load(model_path)
        self.model = data['model']
        self.scaler = data['scaler']
        self.is_trained = True
        logger.info(f"Model loaded from {model_path}")

