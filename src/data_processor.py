import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class DataProcessor:
    def __init__(self, df):
        """
        Initialize data processor
        
        Args:
            df: DataFrame containing packet data
        """
        self.df = df.copy()
        
    def extract_features(self):
        """Extract features for machine learning"""
        
        # Time-based features
        if 'timestamp' in self.df.columns:
            self.df['timestamp'] = pd.to_datetime(self.df['timestamp'])
            self.df['hour'] = self.df['timestamp'].dt.hour
            self.df['day_of_week'] = self.df['timestamp'].dt.dayofweek
            
            # Calculate time differences
            self.df = self.df.sort_values('timestamp')
            self.df['time_diff'] = self.df['timestamp'].diff().dt.total_seconds().fillna(0)
        
        # Flow-based features (packets between same src and dst)
        flow_key = self.df['src_ip'] + '_' + self.df['dst_ip']
        self.df['flow_id'] = flow_key
        
        # Aggregate statistics per flow
        flow_stats = self.df.groupby('flow_id').agg({
            'length': ['count', 'sum', 'mean', 'std', 'min', 'max'],
            'time_diff': ['mean', 'std']
        }).reset_index()
        
        flow_stats.columns = ['flow_id', 'packet_count', 'total_bytes', 
                              'avg_packet_size', 'std_packet_size', 
                              'min_packet_size', 'max_packet_size',
                              'avg_time_diff', 'std_time_diff']
        
        # Merge back to original dataframe
        self.df = self.df.merge(flow_stats, on='flow_id', how='left')
        
        # Protocol encoding
        protocol_mapping = {'TCP': 0, 'UDP': 1, 'ICMP': 2, 'Other': 3}
        self.df['protocol_encoded'] = self.df['protocol_name'].map(protocol_mapping)
        
        # Port-based features
        self.df['is_well_known_port_src'] = (self.df['src_port'] < 1024).astype(int)
        self.df['is_well_known_port_dst'] = (self.df['dst_port'] < 1024).astype(int)
        
        logger.info(f"Extracted features. DataFrame shape: {self.df.shape}")
        return self.df
    
    def get_statistics(self):
        """Get statistical summary of traffic"""
        stats = {
            'total_packets': len(self.df),
            'unique_src_ips': self.df['src_ip'].nunique(),
            'unique_dst_ips': self.df['dst_ip'].nunique(),
            'protocol_distribution': self.df['protocol_name'].value_counts().to_dict(),
            'avg_packet_size': self.df['length'].mean(),
            'total_bytes': self.df['length'].sum(),
            'time_range': (self.df['timestamp'].min(), self.df['timestamp'].max()) if 'timestamp' in self.df.columns else None
        }
        return stats
    
    def detect_port_scan(self, threshold=20):
        """Simple port scan detection"""
        port_scans = []
        
        # Group by source IP and count unique destination ports
        port_counts = self.df.groupby('src_ip')['dst_port'].nunique()
        
        suspicious_ips = port_counts[port_counts > threshold]
        
        for ip in suspicious_ips.index:
            port_scans.append({
                'src_ip': ip,
                'unique_ports_accessed': port_counts[ip],
                'severity': 'high' if port_counts[ip] > 50 else 'medium'
            })
        
        return port_scans
    
    def prepare_ml_features(self):
        """Prepare features for ML model"""
        feature_columns = [
            'length', 'ttl', 'protocol_encoded',
            'packet_count', 'total_bytes', 'avg_packet_size',
            'std_packet_size', 'avg_time_diff', 'std_time_diff',
            'is_well_known_port_src', 'is_well_known_port_dst'
        ]
        
        # Filter valid features
        available_features = [col for col in feature_columns if col in self.df.columns]
        
        X = self.df[available_features].fillna(0)
        
        # Handle infinite values
        X = X.replace([np.inf, -np.inf], 0)
        
        return X, available_features

# Example usage
if __name__ == "__main__":
    # Load sample data
    df = pd.read_csv('data/raw/captured_packets.csv')
    
    processor = DataProcessor(df)
    df_processed = processor.extract_features()
    
    print("Statistics:")
    print(processor.get_statistics())
    
    print("\nPort Scan Detection:")
    scans = processor.detect_port_scan()
    for scan in scans:
        print(scan)
