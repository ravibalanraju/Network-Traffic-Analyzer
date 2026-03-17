import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import joblib
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class AnomalyDetector:
    def __init__(self, model_type='isolation_forest'):
        """
        Initialize anomaly detector
        
        Args:
            model_type: 'isolation_forest' or 'dbscan'
        """
        self.model_type = model_type
        self.scaler = StandardScaler()
        self.model = None
        self.feature_names = None
        
    def train(self, X, contamination=0.1):
        """
        Train the anomaly detection model
        
        Args:
            X: Feature matrix
            contamination: Expected proportion of outliers
        """
        logger.info(f"Training {self.model_type} model...")
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        if self.model_type == 'isolation_forest':
            self.model = IsolationForest(
                contamination=contamination,
                random_state=42,
                n_estimators=100
            )
            self.model.fit(X_scaled)
        elif self.model_type == 'dbscan':
            self.model = DBSCAN(eps=0.5, min_samples=5)
            self.model.fit(X_scaled)
        
        logger.info("Model training completed")
        
    def predict(self, X):
        """
        Predict anomalies
        
        Args:
            X: Feature matrix
            
        Returns:
            Array of predictions (-1 for anomaly, 1 for normal)
        """
        if self.model is None:
            raise ValueError("Model not trained. Call train() first.")
        
        X_scaled = self.scaler.transform(X)
        
        if self.model_type == 'isolation_forest':
            predictions = self.model.predict(X_scaled)
        elif self.model_type == 'dbscan':
            labels = self.model.fit_predict(X_scaled)
            predictions = np.where(labels == -1, -1, 1)
        
        return predictions
    
    def get_anomaly_scores(self, X):
        """Get anomaly scores for each sample"""
        if self.model_type != 'isolation_forest':
            raise ValueError("Anomaly scores only available for Isolation Forest")
        
        X_scaled = self.scaler.transform(X)
        scores = self.model.score_samples(X_scaled)
        return scores
    
    def save_model(self, path='models/trained_models/anomaly_detector.pkl'):
        """Save trained model"""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'model_type': self.model_type,
            'feature_names': self.feature_names
        }
        
        joblib.dump(model_data, path)
        logger.info(f"Model saved to {path}")
    
    def load_model(self, path='models/trained_models/anomaly_detector.pkl'):
        """Load trained model"""
        model_data = joblib.load(path)
        
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.model_type = model_data['model_type']
        self.feature_names = model_data.get('feature_names')
        
        logger.info(f"Model loaded from {path}")

# Example usage
if __name__ == "__main__":
    from data_processor import DataProcessor
    
    # Load and process data
    df = pd.read_csv('data/raw/captured_packets.csv')
    processor = DataProcessor(df)
    df_processed = processor.extract_features()
    
    # Prepare ML features
    X, feature_names = processor.prepare_ml_features()
    
    # Train model
    detector = AnomalyDetector(model_type='isolation_forest')
    detector.feature_names = feature_names
    detector.train(X, contamination=0.05)
    
    # Predict anomalies
    predictions = detector.predict(X)
    
    # Add predictions to dataframe
    df_processed['is_anomaly'] = predictions
    df_processed['anomaly_score'] = detector.get_anomaly_scores(X)
    
    # Show anomalies
    anomalies = df_processed[df_processed['is_anomaly'] == -1]
    print(f"\nDetected {len(anomalies)} anomalies out of {len(df_processed)} packets")
    print("\nTop anomalies:")
    print(anomalies.nsmallest(10, 'anomaly_score')[['timestamp', 'src_ip', 'dst_ip', 'protocol_name', 'anomaly_score']])
    
    # Save model
    detector.save_model()
