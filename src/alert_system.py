import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from datetime import datetime, timedelta
import json
from pathlib import Path

logger = logging.getLogger(__name__)

class AlertSystem:
    def __init__(self, config_path='config/alert_config.json'):
        """Initialize alert system"""
        self.config_path = config_path
        self.config = self.load_config()
        self.alert_history = []
        self.cooldown_period = timedelta(minutes=5)  # Don't spam alerts
        self.last_alert_time = {}
        
    def load_config(self):
        """Load alert configuration"""
        if Path(self.config_path).exists():
            with open(self.config_path, 'r') as f:
                return json.load(f)
        else:
            # Default configuration
            default_config = {
                'email': {
                    'enabled': False,
                    'smtp_server': 'smtp.gmail.com',
                    'smtp_port': 587,
                    'sender_email': 'your-email@gmail.com',
                    'sender_password': 'your-app-password',
                    'recipient_emails': ['recipient@example.com']
                },
                'thresholds': {
                    'anomaly_score': -0.5,
                    'port_scan_threshold': 20,
                    'high_traffic_threshold': 1000  # packets per minute
                },
                'alert_levels': {
                    'critical': ['port_scan', 'ddos_detected'],
                    'warning': ['anomaly_detected', 'high_traffic'],
                    'info': ['model_trained', 'capture_started']
                }
            }
            
            # Save default config
            Path(self.config_path).parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_path, 'w') as f:
                json.dump(default_config, f, indent=2)
            
            return default_config
    
    def should_send_alert(self, alert_type):
        """Check if enough time has passed since last alert of this type"""
        if alert_type not in self.last_alert_time:
            return True
        
        time_since_last = datetime.now() - self.last_alert_time[alert_type]
        return time_since_last > self.cooldown_period
    
    def send_email_alert(self, subject, body):
        """Send email alert"""
        if not self.config['email']['enabled']:
            logger.info("Email alerts disabled in config")
            return False
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.config['email']['sender_email']
            msg['To'] = ', '.join(self.config['email']['recipient_emails'])
            msg['Subject'] = f"[Network Alert] {subject}"
            
            msg.attach(MIMEText(body, 'html'))
            
            server = smtplib.SMTP(
                self.config['email']['smtp_server'],
                self.config['email']['smtp_port']
            )
            server.starttls()
            server.login(
                self.config['email']['sender_email'],
                self.config['email']['sender_password']
            )
            
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Email alert sent: {subject}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            return False
    
    def create_anomaly_alert(self, anomaly_data):
        """Create alert for detected anomaly"""
        alert_type = 'anomaly_detected'
        
        if not self.should_send_alert(alert_type):
            return
        
        subject = f"Anomaly Detected - {anomaly_data['src_ip']}"
        
        body = f"""
        <html>
        <body>
            <h2>Network Anomaly Detected</h2>
            <p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Source IP:</strong> {anomaly_data['src_ip']}</p>
            <p><strong>Destination IP:</strong> {anomaly_data['dst_ip']}</p>
            <p><strong>Protocol:</strong> {anomaly_data['protocol_name']}</p>
            <p><strong>Packet Size:</strong> {anomaly_data['length']} bytes</p>
            <p><strong>Anomaly Score:</strong> {anomaly_data.get('anomaly_score', 'N/A')}</p>
            
            <h3>Recommended Actions:</h3>
            <ul>
                <li>Investigate the source IP address</li>
                <li>Check firewall rules</li>
                <li>Review recent network logs</li>
            </ul>
        </body>
        </html>
        """
        
        # Log to file
        self.log_alert(alert_type, subject, anomaly_data)
        
        # Send email if configured
        if self.config['email']['enabled']:
            self.send_email_alert(subject, body)
        
        self.last_alert_time[alert_type] = datetime.now()
    
    def create_port_scan_alert(self, scan_data):
        """Create alert for port scan detection"""
        alert_type = 'port_scan'
        
        if not self.should_send_alert(alert_type):
            return
        
        subject = f"Port Scan Detected - {scan_data['src_ip']}"
        
        body = f"""
        <html>
        <body>
            <h2 style="color: #e74c3c;">Port Scan Detected!</h2>
            <p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Source IP:</strong> {scan_data['src_ip']}</p>
            <p><strong>Unique Ports Accessed:</strong> {scan_data['unique_ports_accessed']}</p>
            <p><strong>Severity:</strong> {scan_data['severity'].upper()}</p>
            
            <h3>Immediate Actions Required:</h3>
            <ul>
                <li>Block the source IP immediately</li>
                <li>Review firewall logs for this IP</li>
                <li>Check for any successful connections</li>
                <li>Investigate potential data breach</li>
            </ul>
        </body>
        </html>
        """
        
        self.log_alert(alert_type, subject, scan_data)
        
        if self.config['email']['enabled']:
            self.send_email_alert(subject, body)
        
        self.last_alert_time[alert_type] = datetime.now()
    
    def create_high_traffic_alert(self, traffic_data):
        """Create alert for high traffic volume"""
        alert_type = 'high_traffic'
        
        if not self.should_send_alert(alert_type):
            return
        
        subject = "High Traffic Volume Detected"
        
        body = f"""
        <html>
        <body>
            <h2 style="color: #f39c12;">High Traffic Volume Alert</h2>
            <p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Packets per Minute:</strong> {traffic_data['packets_per_minute']}</p>
            <p><strong>Traffic Rate:</strong> {traffic_data['traffic_rate']}</p>
            <p><strong>Top Source IPs:</strong></p>
            <ul>
                {''.join([f"<li>{ip}: {count} packets</li>" for ip, count in traffic_data.get('top_sources', [])[:5]])}
            </ul>
            
            <h3>Potential Issues:</h3>
            <ul>
                <li>DDoS attack in progress</li>
                <li>Network congestion</li>
                <li>Misconfigured application</li>
            </ul>
        </body>
        </html>
        """
        
        self.log_alert(alert_type, subject, traffic_data)
        
        if self.config['email']['enabled']:
            self.send_email_alert(subject, body)
        
        self.last_alert_time[alert_type] = datetime.now()
    
    def log_alert(self, alert_type, subject, data):
        """Log alert to file"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'subject': subject,
            'data': data
        }
        
        self.alert_history.append(log_entry)
        
        # Save to file
        log_file = Path('logs/alerts.json')
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        existing_logs = []
        if log_file.exists():
            with open(log_file, 'r') as f:
                try:
                    existing_logs = json.load(f)
                except:
                    existing_logs = []
        
        existing_logs.append(log_entry)
        
        # Keep only last 1000 alerts
        existing_logs = existing_logs[-1000:]
        
        with open(log_file, 'w') as f:
            json.dump(existing_logs, f, indent=2)
        
        logger.info(f"Alert logged: {alert_type} - {subject}")
    
    def get_alert_summary(self, hours=24):
        """Get summary of recent alerts"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        recent_alerts = [
            alert for alert in self.alert_history
            if datetime.fromisoformat(alert['timestamp']) > cutoff_time
        ]
        
        summary = {
            'total_alerts': len(recent_alerts),
            'by_type': {},
            'recent_alerts': recent_alerts[-10:]  # Last 10 alerts
        }
        
        for alert in recent_alerts:
            alert_type = alert['type']
            summary['by_type'][alert_type] = summary['by_type'].get(alert_type, 0) + 1
        
        return summary

# Example usage
if __name__ == "__main__":
    alert_system = AlertSystem()
    
    # Test anomaly alert
    anomaly = {
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.1',
        'protocol_name': 'TCP',
        'length': 1500,
        'anomaly_score': -0.85
    }
    
    alert_system.create_anomaly_alert(anomaly)
    
    # Test port scan alert
    port_scan = {
        'src_ip': '192.168.1.200',
        'unique_ports_accessed': 150,
        'severity': 'high'
    }
    
    alert_system.create_port_scan_alert(port_scan)
    
    # Get summary
    summary = alert_system.get_alert_summary()
    print("\nAlert Summary:")
    print(json.dumps(summary, indent=2))
