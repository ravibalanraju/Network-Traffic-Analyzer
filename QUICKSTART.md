# Quick Start Guide

## 1. First Time Setup
```bash
# Install dependencies
sudo apt-get install libpcap-dev  # Linux
pip install -r requirements.txt

# Create necessary directories
mkdir -p data/raw data/processed models/trained_models logs
touch data/raw/.gitkeep data/processed/.gitkeep models/trained_models/.gitkeep logs/.gitkeep
```

## 2. Find Your Network Interface
```bash
sudo python main.py --mode list-interfaces
```

Output example:
```
Available network interfaces:
  0: lo
  1: eth0
  2: wlan0
```

## 3. Start the Dashboard
```bash
sudo python main.py --mode dashboard --interface eth0
```

Open browser: `http://localhost:8050`

## 4. Using the Dashboard

1. **Start Capture**: Click "Start Capture" button
2. **Wait for Data**: Let it collect 100+ packets
3. **Train Model**: Click "Train Model" button
4. **Monitor**: Watch real-time statistics and anomalies

## 5. Configure Email Alerts (Optional)

Edit `config/alert_config.json`:
```json
{
  "email": {
    "enabled": true,
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "sender_email": "your-email@gmail.com",
    "sender_password": "your-app-password",
    "recipient_emails": ["your-email@gmail.com"]
  }
}
```

## 6. Troubleshooting

**Permission Denied**: Run with `sudo`

**Interface not found**: Use `--mode list-interfaces` to find correct name

**Port already in use**: Change port in `config/config.yaml`

**No packets captured**: Check if interface is active and has traffic
