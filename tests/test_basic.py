import unittest
import pandas as pd
from src.packet_capture import PacketCapture
from src.data_processor import DataProcessor
from src.anomaly_detector import AnomalyDetector

class TestBasicFunctionality(unittest.TestCase):
    
    def test_data_processor(self):
        """Test data processor with sample data"""
        # Create sample data
        data = {
            'timestamp': pd.date_range('2024-01-01', periods=100, freq='1S'),
            'src_ip': ['192.168.1.1'] * 50 + ['192.168.1.2'] * 50,
            'dst_ip': ['10.0.0.1'] * 100,
            'protocol': [6] * 100,
            'protocol_name': ['TCP'] * 100,
            'length': [64] * 100,
            'ttl': [64] * 100,
            'src_port': [443] * 100,
            'dst_port': [80] * 100,
            'flags': ['S'] * 100
        }
        
        df = pd.DataFrame(data)
        
        processor = DataProcessor(df)
        df_processed = processor.extract_features()
        
        self.assertGreater(len(df_processed.columns), len(df.columns))
        self.assertIn('flow_id', df_processed.columns)
    
    def test_anomaly_detector(self):
        """Test anomaly detector training and prediction"""
        # Create sample features
        import numpy as np
        X = np.random.randn(100, 5)
        
        detector = AnomalyDetector(model_type='isolation_forest')
        detector.train(X, contamination=0.1)
        
        predictions = detector.predict(X)
        
        self.assertEqual(len(predictions), 100)
        self.assertIn(-1, predictions)  # Should detect some anomalies

if __name__ == '__main__':
    unittest.main()
