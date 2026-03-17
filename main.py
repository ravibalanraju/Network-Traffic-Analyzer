#!/usr/bin/env python3
"""
Network Traffic Analyzer & Anomaly Detector
Main application entry point
"""

import argparse
import logging
from pathlib import Path
import yaml
from scapy.all import get_if_list

from src.packet_capture import PacketCapture
from src.data_processor import DataProcessor
from src.anomaly_detector import AnomalyDetector
from src.alert_system import AlertSystem
from src.dashboard import NetworkDashboard

# Setup logging
def setup_logging(config):
    log_file = Path(config['logging']['file'])
    log_file.parent.mkdir(parents=True, exist_ok=True)
    
    logging.basicConfig(
        level=getattr(logging, config['logging']['level']),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )

def load_config(config_path='config/config.yaml'):
    """Load configuration from YAML file"""
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

def run_capture_mode(config):
    """Run in packet capture mode (no dashboard)"""
    logger = logging.getLogger(__name__)
    logger.info("Starting in capture mode")
    
    interface = config['capture']['interface']
    packet_count = config['capture']['packet_count']
    
    # Initialize components
    capturer = PacketCapture(interface=interface, packet_count=packet_count)
    alert_system = AlertSystem()
    
    # Load or create anomaly detector
    detector = AnomalyDetector()
    try:
        detector.load_model()
        logger.info("Loaded existing anomaly detection model")
    except:
        logger.warning("No trained model found. Will train on first batch.")
    
    # Capture packets
    logger.info(f"Capturing packets from {interface}...")
    capturer.start_capture()
    
    # Process captured data
    df = capturer.get_dataframe()
    logger.info(f"Captured {len(df)} packets")
    
    # Save raw data
    capturer.save_to_csv('data/raw/captured_packets.csv')
    
    # Process and analyze
    processor = DataProcessor(df)
    df_processed = processor.extract_features()
    
    # Detect port scans
    port_scans = processor.detect_port_scan(threshold=config['alerts']['thresholds']['port_scan_ports'])
    for scan in port_scans:
        logger.warning(f"Port scan detected: {scan}")
        alert_system.create_port_scan_alert(scan)
    
    # Train or use model for anomaly detection
    X, feature_names = processor.prepare_ml_features()
    
    if detector.model is None and len(df) >= 100:
        logger.info("Training new anomaly detection model...")
        detector.feature_names = feature_names
        detector.train(X, contamination=config['anomaly_detection']['contamination'])
        detector.save_model()
    
    # Detect anomalies
    if detector.model:
        predictions = detector.predict(X)
        scores = detector.get_anomaly_scores(X)
        df_processed['is_anomaly'] = predictions
        df_processed['anomaly_score'] = scores
        
        # Alert on anomalies
        anomalies = df_processed[df_processed['is_anomaly'] == -1]
        logger.info(f"Detected {len(anomalies)} anomalies")
        
        for idx, anomaly in anomalies.iterrows():
            if anomaly['anomaly_score'] < config['alerts']['thresholds']['anomaly_score']:
                alert_system.create_anomaly_alert(anomaly.to_dict())
        
        # Save processed data
        df_processed.to_csv('data/processed/analyzed_packets.csv', index=False)

def run_dashboard_mode(config):
    """Run in dashboard mode with real-time monitoring"""
    logger = logging.getLogger(__name__)
    logger.info("Starting in dashboard mode")
    
    interface = config['capture']['interface']
    dashboard = NetworkDashboard(interface=interface)
    
    dashboard.run(
        debug=config['dashboard']['debug'],
        port=config['dashboard']['port']
    )

def main():
    parser = argparse.ArgumentParser(
        description='Network Traffic Analyzer & Anomaly Detector'
    )
    parser.add_argument(
        '--mode',
        choices=['dashboard', 'capture', 'list-interfaces'],
        default='dashboard',
        help='Operation mode'
    )
    parser.add_argument(
        '--config',
        default='config/config.yaml',
        help='Path to configuration file'
    )
    parser.add_argument(
        '--interface',
        help='Network interface to monitor (overrides config)'
    )
    
    args = parser.parse_args()
    
    # List interfaces mode
    if args.mode == 'list-interfaces':
        print("Available network interfaces:")
        for i, iface in enumerate(get_if_list()):
            print(f"  {i}: {iface}")
        return
    
    # Load configuration
    config = load_config(args.config)
    setup_logging(config)
    
    # Override interface if specified
    if args.interface:
        config['capture']['interface'] = args.interface
    
    # Run appropriate mode
    if args.mode == 'dashboard':
        run_dashboard_mode(config)
    elif args.mode == 'capture':
        run_capture_mode(config)

if __name__ == '__main__':
    main()
