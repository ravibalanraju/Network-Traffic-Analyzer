# Network Traffic Analyzer & Anomaly Detector

A real-time network traffic monitoring and analysis tool with machine learning-based anomaly detection.

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)

## Features

- **Real-time Packet Capture**: Monitor network traffic on any interface
- **Protocol Analysis**: Deep inspection of TCP, UDP, ICMP, and other protocols
- **Anomaly Detection**: Machine learning-based detection using Isolation Forest
- **Port Scan Detection**: Identify potential port scanning activities
- **Interactive Dashboard**: Real-time visualization with Plotly Dash
- **Alert System**: Email notifications for critical security events
- **Traffic Statistics**: Comprehensive analysis of network patterns

## Screenshots

[Add screenshots of your dashboard here]

## Installation

### Prerequisites

- Python 3.8 or higher
- Root/Administrator privileges (required for packet capture)
- libpcap (Linux/Mac) or WinPcap/Npcap (Windows)

### Linux/Mac
```bash
# Clone the repository
git clone https://github.com/yourusername/network-traffic-analyzer.git
cd network-traffic-analyzer

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install libpcap (if not already installed)
# Ubuntu/Debian:
sudo apt-get install libpcap-dev

# macOS:
brew install libpcap
```

### Windows
```bash
# Install Npcap from https://npcap.com/

# Clone and setup
git clone https://github.com/yourusername/network-traffic-analyzer.git
cd network-traffic-analyzer

python -m venv venv
venv\Scripts\activate

pip install -r requirements.txt
```

## Usage

### List Available Network Interfaces
```bash
sudo python main.py --mode list-interfaces
```

### Run Dashboard Mode (Recommended)
```bash
sudo python main.py --mode dashboard --interface eth0
```

Then open your browser to `http://localhost:8050`

### Run Capture Mode (CLI only)
```bash
sudo python main.py --mode capture --interface eth0
```

### Configuration

Edit `config/config.yaml` to customize:

- Network interface
- Anomaly detection parameters
- Alert thresholds
- Dashboard settings

## Project Structure
```
network-traffic-analyzer/
├── README.md
├── requirements.txt
├── main.py
├── config/
│   ├── config.yaml
│   └── alert_config.json
├── src/
│   ├── packet_capture.py      # Packet capture logic
│   ├── data_processor.py      # Data processing and feature extraction
│   ├── anomaly_detector.py    # ML-based anomaly detection
│   ├── alert_system.py        # Alert and notification system
│   └── dashboard.py           # Web dashboard
├── models/
│   └── trained_models/        # Saved ML models
├── data/
│   ├── raw/                   # Raw captured packets
│   └── processed/             # Processed data
├── logs/                      # Application logs
└── tests/                     # Unit tests
```

## How It Works

1. **Packet Capture**: Uses Scapy to capture network packets in real-time
2. **Feature Extraction**: Extracts relevant features (packet size, protocol, timing, etc.)
3. **Anomaly Detection**: Isolation Forest algorithm identifies unusual traffic patterns
4. **Visualization**: Dash dashboard displays real-time statistics and alerts
5. **Alerting**: Email notifications for critical security events

## Email Alert Setup

To enable email alerts:

1. Edit `config/alert_config.json`
2. Set `enabled: true`
3. Configure SMTP settings (Gmail example):
```json
   {
     "email": {
       "enabled": true,
       "smtp_server": "smtp.gmail.com",
       "smtp_port": 587,
       "sender_email": "your-email@gmail.com",
       "sender_password": "your-app-password",
       "recipient_emails": ["recipient@example.com"]
     }
   }
```

**Note**: For Gmail, use an [App Password](https://support.google.com/accounts/answer/185833)

## Security Considerations

- **Run with appropriate privileges**: Packet capture requires root/admin access
- **Use in controlled environments**: Only monitor networks you own or have permission to monitor
- **Protect credentials**: Never commit real passwords to version control
- **Review alerts carefully**: Machine learning models may have false positives

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## Future Enhancements

- [ ] Deep learning models (LSTM, CNN)
- [ ] Integration with threat intelligence feeds
- [ ] Automatic blocking of malicious IPs
- [ ] Mobile app for alerts
- [ ] Support for more protocols
- [ ] Docker containerization

## Acknowledgments

- Scapy for packet manipulation
- Scikit-learn for machine learning
- Plotly Dash for visualization

## Contact

Name - Ravibalan R

Project Link: [https://github.com/ravibalanraju/network-traffic-analyzer](https://github.com/ravibalanraju/network-traffic-analyzer)





After Running you may see the page like this
<img width="1920" height="1200" alt="image" src="https://github.com/user-attachments/assets/47a089a0-96e4-4b56-aba9-a50d7e7b5bc9" />

