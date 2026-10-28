"""
Autoencoder-based UEBA for Advanced Anomaly Detection
Implements deep learning approach for behavioral anomaly detection
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.model_selection import train_test_split
import logging
import joblib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False
    logger.warning("PyTorch not available. Autoencoder functionality will be limited.")


class Autoencoder(nn.Module):
    """Deep Autoencoder for anomaly detection"""
    
    def __init__(self, input_dim, encoding_dim=10, hidden_dims=[128, 64, 32]):
        super(Autoencoder, self).__init__()
        
        # Encoder
        encoder_layers = []
        prev_dim = input_dim
        for hidden_dim in hidden_dims:
            encoder_layers.extend([
                nn.Linear(prev_dim, hidden_dim),
                nn.ReLU(),
                nn.Dropout(0.2)
            ])
            prev_dim = hidden_dim
        
        encoder_layers.append(nn.Linear(prev_dim, encoding_dim))
        
        # Decoder (reverse of encoder)
        decoder_layers = []
        prev_dim = encoding_dim
        for hidden_dim in reversed(hidden_dims):
            decoder_layers.extend([
                nn.Linear(prev_dim, hidden_dim),
                nn.ReLU(),
                nn.Dropout(0.2)
            ])
            prev_dim = hidden_dim
        
        decoder_layers.append(nn.Linear(prev_dim, input_dim))
        decoder_layers.append(nn.Sigmoid())
        
        self.encoder = nn.Sequential(*encoder_layers)
        self.decoder = nn.Sequential(*decoder_layers)
    
    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded
    
    def encode(self, x):
        """Get encoded representation"""
        return self.encoder(x)
    
    def reconstruct(self, x):
        """Get reconstructed output"""
        return self.forward(x)


class AutoencoderUEBA:
    """
    Autoencoder-based UEBA for deep behavioral analysis
    """
    
    def __init__(self, encoding_dim=10, hidden_dims=[128, 64, 32], 
                 epochs=100, batch_size=32, device='cpu'):
        self.encoding_dim = encoding_dim
        self.hidden_dims = hidden_dims
        self.epochs = epochs
        self.batch_size = batch_size
        self.device = device
        
        self.model = None
        self.scaler = StandardScaler()
        self.input_dim = None
        self.is_trained = False
        
        logger.info("AutoencoderUEBA initialized")
    
    def prepare_features(self, data: pd.DataFrame) -> pd.DataFrame:
        """Prepare features for training"""
        features_df = data.copy()
        
        # Temporal features
        if 'timestamp' in features_df.columns:
            features_df['timestamp'] = pd.to_datetime(features_df['timestamp'])
            features_df['hour'] = features_df['timestamp'].dt.hour
            features_df['day_of_week'] = features_df['timestamp'].dt.dayofweek
            features_df['is_weekend'] = features_df['day_of_week'].apply(lambda x: 1 if x >= 5 else 0)
            features_df = features_df.drop(['timestamp'], axis=1)
        
        # Select numerical features
        numerical_cols = features_df.select_dtypes(include=[np.number]).columns
        features_df = features_df[numerical_cols]
        
        # Fill NaN
        features_df = features_df.fillna(0)
        
        return features_df
    
    def train(self, data: pd.DataFrame, validation_split=0.2):
        """Train the autoencoder"""
        if not HAS_TORCH:
            logger.error("PyTorch not available. Cannot train autoencoder.")
            return self
        
        logger.info("Training autoencoder...")
        
        # Prepare data
        X = self.prepare_features(data)
        
        # Remove target column if present
        if 'is_malicious' in X.columns:
            X = X.drop('is_malicious', axis=1)
        
        # Scale data
        X_scaled = self.scaler.fit_transform(X)
        
        # Split data
        X_train, X_val = train_test_split(X_scaled, test_size=validation_split, random_state=42)
        
        # Convert to tensors
        train_data = torch.FloatTensor(X_train).to(self.device)
        val_data = torch.FloatTensor(X_val).to(self.device)
        
        train_loader = DataLoader(train_data, batch_size=self.batch_size, shuffle=True)
        
        # Initialize model
        self.input_dim = X_scaled.shape[1]
        self.model = Autoencoder(
            input_dim=self.input_dim,
            encoding_dim=self.encoding_dim,
            hidden_dims=self.hidden_dims
        ).to(self.device)
        
        # Optimizer and loss
        optimizer = optim.Adam(self.model.parameters(), lr=0.001)
        criterion = nn.MSELoss()
        
        # Training loop
        best_loss = float('inf')
        patience = 10
        patience_counter = 0
        
        for epoch in range(self.epochs):
            self.model.train()
            train_loss = 0
            
            for batch in train_loader:
                # Forward pass
                reconstructed = self.model(batch)
                loss = criterion(reconstructed, batch)
                
                # Backward pass
                optimizer.zero_grad()
                loss.backward()
                optimizer.step()
                
                train_loss += loss.item()
            
            avg_train_loss = train_loss / len(train_loader)
            
            # Validation
            self.model.eval()
            with torch.no_grad():
                val_reconstructed = self.model(val_data)
                val_loss = criterion(val_reconstructed, val_data).item()
            
            if (epoch + 1) % 10 == 0:
                logger.info(f"Epoch {epoch+1}/{self.epochs}, Train Loss: {avg_train_loss:.4f}, Val Loss: {val_loss:.4f}")
            
            # Early stopping
            if val_loss < best_loss:
                best_loss = val_loss
                patience_counter = 0
            else:
                patience_counter += 1
                if patience_counter >= patience:
                    logger.info(f"Early stopping at epoch {epoch+1}")
                    break
        
        self.is_trained = True
        logger.info("Autoencoder training complete")
        
        return self
    
    def detect_anomaly(self, data: pd.DataFrame, threshold_percentile=95) -> dict:
        """Detect anomalies using reconstruction error"""
        if not self.is_trained:
            logger.error("Model not trained. Call train() first.")
            return {}
        
        # Prepare data
        X = self.prepare_features(data)
        
        # Remove target column if present
        if 'is_malicious' in X.columns:
            X = X.drop('is_malicious', axis=1)
        
        # Scale data
        X_scaled = self.scaler.transform(X)
        
        # Convert to tensor
        X_tensor = torch.FloatTensor(X_scaled).to(self.device)
        
        # Reconstruct
        self.model.eval()
        with torch.no_grad():
            X_reconstructed = self.model(X_tensor)
        
        # Calculate reconstruction error
        reconstruction_error = torch.mean((X_tensor - X_reconstructed) ** 2, dim=1).cpu().numpy()
        
        # Determine threshold
        threshold = np.percentile(reconstruction_error, threshold_percentile)
        
        # Identify anomalies
        is_anomaly = reconstruction_error > threshold
        
        return {
            'is_anomaly': is_anomaly,
            'reconstruction_error': reconstruction_error,
            'anomaly_score': (reconstruction_error / np.max(reconstruction_error)).tolist(),
            'threshold': float(threshold)
        }
    
    def predict_single(self, event_data: dict) -> dict:
        """Predict anomaly for a single event"""
        # Convert to dataframe
        df = pd.DataFrame([event_data])
        result = self.detect_anomaly(df)
        
        if len(result) == 0:
            return {'is_anomaly': False, 'anomaly_score': 0.0}
        
        return {
            'is_anomaly': bool(result['is_anomaly'][0]),
            'anomaly_score': float(result['anomaly_score'][0]),
            'reconstruction_error': float(result['reconstruction_error'][0])
        }
    
    def save_model(self, filepath='models/autoencoder_ueba.pkl'):
        """Save the model"""
        if self.model is None:
            logger.error("No model to save")
            return
        
        try:
            import os
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
        except:
            pass
        
        torch.save({
            'model_state': self.model.state_dict(),
            'input_dim': self.input_dim,
            'encoding_dim': self.encoding_dim,
            'hidden_dims': self.hidden_dims,
            'scaler': self.scaler
        }, filepath)
        logger.info(f"Model saved to {filepath}")
    
    def load_model(self, filepath='models/autoencoder_ueba.pkl'):
        """Load the model"""
        checkpoint = torch.load(filepath, map_location=self.device)
        
        self.input_dim = checkpoint['input_dim']
        self.encoding_dim = checkpoint['encoding_dim']
        self.hidden_dims = checkpoint['hidden_dims']
        self.scaler = checkpoint['scaler']
        
        # Initialize model
        self.model = Autoencoder(
            input_dim=self.input_dim,
            encoding_dim=self.encoding_dim,
            hidden_dims=self.hidden_dims
        )
        
        self.model.load_state_dict(checkpoint['model_state'])
        self.model.to(self.device)
        self.is_trained = True
        
        logger.info(f"Model loaded from {filepath}")


def train_and_evaluate_autoencoder(data: pd.DataFrame, test_size=0.2):
    """Train and evaluate autoencoder model"""
    # Prepare data
    ueba = AutoencoderUEBA()
    
    # Train
    ueba.train(data, validation_split=test_size)
    
    # Evaluate
    X_test = ueba.prepare_features(data)
    if 'is_malicious' in X_test.columns:
        y_true = X_test['is_malicious']
        X_test = X_test.drop('is_malicious', axis=1)
    else:
        y_true = np.zeros(len(X_test))
    
    result = ueba.detect_anomaly(X_test)
    
    # Calculate metrics
    anomaly_mask = result['is_anomaly']
    accuracy = np.mean((anomaly_mask == y_true).astype(float)) if len(y_true) > 0 else 0
    
    logger.info(f"Autoencoder Accuracy: {accuracy:.4f}")
    logger.info(f"Anomalies detected: {np.sum(anomaly_mask)}")
    
    return ueba, result

