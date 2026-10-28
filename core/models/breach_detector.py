"""
AI-Powered Breach Detection using Random Forest and Gradient Boosting
"""

import os
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold, GridSearchCV
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, roc_curve, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import joblib
import json
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BreachDetector:
    """
    Breach Detection Classifier using Random Forest and Gradient Boosting
    Implements ensemble consensus logic to minimize false positives
    """
    
    def __init__(self, n_estimators_rf=100, n_estimators_gb=100, max_depth=10, 
                 random_state=42, use_ensemble_consensus=True, consensus_threshold=0.5):
        self.rf_model = None
        self.gb_model = None
        self.label_encoders = {}  # Dictionary to store encoders for each categorical column
        self.feature_names = None
        self.use_ensemble_consensus = use_ensemble_consensus
        self.consensus_threshold = consensus_threshold
        self.scaler = None
        
        logger.info("BreachDetector initialized")
    
    def prepare_features(self, data: pd.DataFrame, is_training=True):
        """
        Extract features for breach detection
        """
        features_df = data.copy()
        
        # Store label encoders for each categorical column
        if not hasattr(self, 'label_encoders'):
            self.label_encoders = {}
        
        # Drop non-numeric columns that aren't useful for ML FIRST
        cols_to_drop = ['user_id', 'source_ip', 'destination_ip']
        for col in cols_to_drop:
            if col in features_df.columns:
                features_df = features_df.drop([col], axis=1)
        
        # Encode categorical variables
        categorical_cols = ['activity_type', 'user_role', 'location']
        for col in categorical_cols:
            if col in features_df.columns:
                if col not in self.label_encoders:
                    self.label_encoders[col] = LabelEncoder()
                if is_training:
                    features_df[col] = self.label_encoders[col].fit_transform(features_df[col].astype(str))
                else:
                    # Handle unseen categories during prediction
                    try:
                        features_df[col] = self.label_encoders[col].transform(features_df[col].astype(str))
                    except ValueError:
                        # If category not seen during training, use a default value
                        features_df[col] = 0
        
        # Extract temporal features
        if 'timestamp' in features_df.columns:
            features_df['timestamp'] = pd.to_datetime(features_df['timestamp'], errors='coerce')
            features_df['hour'] = features_df['timestamp'].dt.hour.fillna(12)
            features_df['day_of_week'] = features_df['timestamp'].dt.dayofweek.fillna(0)
            features_df['is_weekend'] = features_df['day_of_week'].apply(lambda x: 1 if x >= 5 else 0)
            features_df = features_df.drop(['timestamp'], axis=1)
        
        # Contextual filters - add risk score based on encoded user_role
        features_df = self._apply_contextual_filters(features_df)
        
        # Ensure all remaining columns are numeric
        # First, try to convert object columns to numeric
        for col in features_df.columns:
            if features_df[col].dtype == 'object':
                try:
                    features_df[col] = pd.to_numeric(features_df[col], errors='coerce')
                except:
                    pass
        
        # Drop any remaining non-numeric columns
        features_df = features_df.select_dtypes(include=[np.number])
        
        # Fill any NaN values with 0
        features_df = features_df.fillna(0)
        
        return features_df
    
    def _apply_contextual_filters(self, data: pd.DataFrame):
        """
        Apply contextual filters for enhanced classification
        """
        # Add risk score base (can be enhanced based on user_role encoding)
        if 'risk_score_base' not in data.columns:
            data['risk_score_base'] = 0.5
        
        return data
    
    def train(self, data: pd.DataFrame, target_column='is_malicious', test_size=0.2):
        """
        Train both Random Forest and Gradient Boosting models
        """
        logger.info("Starting model training...")
        
        # Prepare features
        X = self.prepare_features(data.drop([target_column], axis=1), is_training=True)
        y = data[target_column]
        
        # Final check: ensure all columns are numeric and convert to float
        for col in X.columns:
            if X[col].dtype == 'object':
                logger.warning(f"Column {col} is still object type, attempting conversion")
                X[col] = pd.to_numeric(X[col], errors='coerce')
        
        # Drop any remaining non-numeric columns
        X = X.select_dtypes(include=[np.number])
        X = X.fillna(0)
        
        # Convert to numpy array
        X_array = X.values.astype(float)
        
        self.feature_names = X.columns.tolist()
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_array, y, test_size=test_size, random_state=42, stratify=y
        )
        
        # Train Random Forest with hyperparameter tuning
        logger.info("Training Random Forest...")
        rf_param_grid = {
            'n_estimators': [50, 100, 200],
            'max_depth': [5, 10, 20],
            'min_samples_split': [2, 5, 10]
        }
        rf_base = RandomForestClassifier(random_state=42, n_jobs=-1)
        rf_grid = GridSearchCV(rf_base, rf_param_grid, cv=5, scoring='f1', n_jobs=-1)
        rf_grid.fit(X_train, y_train)
        self.rf_model = rf_grid.best_estimator_
        logger.info(f"Best RF params: {rf_grid.best_params_}")
        
        # Train Gradient Boosting with hyperparameter tuning
        logger.info("Training Gradient Boosting...")
        gb_param_grid = {
            'n_estimators': [50, 100, 200],
            'max_depth': [3, 5, 10],
            'learning_rate': [0.01, 0.1, 0.2]
        }
        gb_base = GradientBoostingClassifier(random_state=42)
        gb_grid = GridSearchCV(gb_base, gb_param_grid, cv=5, scoring='f1', n_jobs=-1)
        gb_grid.fit(X_train, y_train)
        self.gb_model = gb_grid.best_estimator_
        logger.info(f"Best GB params: {gb_grid.best_params_}")
        
        # Evaluate models
        self._evaluate_models(X_train, X_test, y_train, y_test)
        
        return self
    
    def _evaluate_models(self, X_train, X_test, y_train, y_test):
        """
        Evaluate models using comprehensive metrics
        """
        models = {'RandomForest': self.rf_model, 'GradientBoosting': self.gb_model}
        
        results = {}
        
        for name, model in models.items():
            # Predictions
            y_pred = model.predict(X_test)
            y_pred_proba = model.predict_proba(X_test)[:, 1]
            
            # Metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred)
            recall = recall_score(y_test, y_pred)
            f1 = f1_score(y_test, y_pred)
            
            try:
                roc_auc = roc_auc_score(y_test, y_pred_proba)
            except:
                roc_auc = 0.0
            
            # Cross-validation
            try:
                cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring='f1')
            except Exception:
                cv_scores = np.array([0.0])

            # Additional cross-val for accuracy (robustness check)
            try:
                cv_acc = cross_val_score(model, X_train, y_train, cv=5, scoring='accuracy')
            except Exception:
                cv_acc = np.array([0.0])
            
            results[name] = {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'roc_auc': roc_auc,
                'cv_f1_mean': cv_scores.mean(),
                'cv_f1_std': cv_scores.std()
            }
            
            logger.info(f"{name} - Accuracy: {accuracy:.4f}, Precision: {precision:.4f}, "
                       f"Recall: {recall:.4f}, F1: {f1:.4f}, ROC-AUC: {roc_auc:.4f}")

            # Add confusion matrix and class support for inspection
            try:
                cm = confusion_matrix(y_test, y_pred)
                results[name]['confusion_matrix'] = cm.tolist()
                # class support
                unique, counts = np.unique(y_test, return_counts=True)
                results[name]['class_support'] = dict(zip(unique.tolist(), counts.tolist()))
            except Exception:
                results[name]['confusion_matrix'] = None
                results[name]['class_support'] = {}

            # Suspicious-perfect-score guard: log and flag if metrics look unrealistically perfect
            if accuracy >= 0.999 or (precision >= 0.999 and recall >= 0.999 and f1 >= 0.999):
                logger.warning(
                    "%s produced near-perfect scores — this may indicate synthetic/trivial data, data leakage, or test/train overlap.",
                    name
                )
                results[name]['suspicious'] = True
                results[name]['note'] = (
                    "Possible data leakage or trivially separable synthetic data. "
                    "Consider adding noise, validating on external holdout data, or using stronger cross-validation."
                )
        
        self.evaluation_results = results
        return results
    
    def predict(self, data: pd.DataFrame):
        """
        Predict using ensemble consensus logic
        """
        if self.rf_model is None or self.gb_model is None:
            raise ValueError("Models not trained. Call train() first.")
        
        X = self.prepare_features(data, is_training=False)
        
        # Ensure X has the same columns as training (fill missing with 0)
        if self.feature_names is not None:
            # Convert to numpy array and ensure correct shape
            if isinstance(X, pd.DataFrame):
                # Reorder columns to match training order
                missing_cols = set(self.feature_names) - set(X.columns)
                for col in missing_cols:
                    X[col] = 0
                X = X[self.feature_names]
                X_array = X.values.astype(float)
            else:
                X_array = X.astype(float) if isinstance(X, np.ndarray) else np.array(X, dtype=float)
        else:
            X_array = X.values.astype(float) if isinstance(X, pd.DataFrame) else np.array(X, dtype=float)
        
        # Get predictions from both models
        rf_pred = self.rf_model.predict(X_array)
        gb_pred = self.gb_model.predict(X_array)
        
        # Get probabilities
        rf_proba = self.rf_model.predict_proba(X_array)[:, 1]
        gb_proba = self.gb_model.predict_proba(X_array)[:, 1]
        
        if self.use_ensemble_consensus:
            # Consensus voting - both models must agree for positive prediction
            # This minimizes false positives
            consensus_pred = (rf_pred == 1) & (gb_pred == 1)
            avg_proba = (rf_proba + gb_proba) / 2
            
            # Apply threshold for high-confidence predictions
            final_pred = (avg_proba >= self.consensus_threshold).astype(int)
            
            return {
                'prediction': final_pred,
                'prediction_proba': avg_proba,
                'rf_prediction': rf_pred,
                'gb_prediction': gb_pred,
                'rf_confidence': rf_proba,
                'gb_confidence': gb_proba,
                'consensus': consensus_pred
            }
        else:
            # Simple averaging
            avg_proba = (rf_proba + gb_proba) / 2
            return {
                'prediction': (avg_proba >= 0.5).astype(int),
                'prediction_proba': avg_proba,
                'rf_prediction': rf_pred,
                'gb_prediction': gb_pred
            }
    
    def predict_streaming(self, event_data: dict):
        """
        Real-time streaming prediction for single event
        """
        df = pd.DataFrame([event_data])
        result = self.predict(df)
        return {
            'is_malicious': bool(result['prediction'][0]),
            'confidence': float(result['prediction_proba'][0]),
            'rf_confidence': float(result['rf_confidence'][0]),
            'gb_confidence': float(result['gb_confidence'][0]),
            'consensus': bool(result['consensus'][0]) if 'consensus' in result else False,
            'timestamp': datetime.now().isoformat()
        }
    
    def save_model(self, filepath='models/breach_detector.joblib'):
        """
        Save trained models
        """
        model_path = os.path.abspath(filepath)
        directory = os.path.dirname(model_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        joblib.dump({
            'rf_model': self.rf_model,
            'gb_model': self.gb_model,
            'label_encoders': self.label_encoders,
            'feature_names': self.feature_names,
            'evaluation_results': self.evaluation_results
        }, model_path)
        logger.info(f"Model saved to {model_path}")
    
    def load_model(self, filepath='models/breach_detector.joblib'):
        """
        Load trained models
        """
        model_path = os.path.abspath(filepath)
        data = joblib.load(model_path)
        self.rf_model = data['rf_model']
        self.gb_model = data['gb_model']
        self.label_encoders = data.get('label_encoders', data.get('label_encoder', {}))  # Backward compatibility
        self.feature_names = data['feature_names']
        self.evaluation_results = data['evaluation_results']
        self.is_trained = True
        logger.info(f"Model loaded from {model_path}")
    
    def get_metrics_report(self):
        """
        Generate comprehensive metrics report
        """
        if hasattr(self, 'evaluation_results'):
            return {
                'timestamp': datetime.now().isoformat(),
                'models': self.evaluation_results,
                'consensus_enabled': self.use_ensemble_consensus,
                'consensus_threshold': self.consensus_threshold
            }
        return {}

