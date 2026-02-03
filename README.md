# Bluetooth Attack Detection System
## Blue Team Defense Framework

A comprehensive security monitoring tool designed to detect and alert on various Bluetooth attacks including KNOB, BIAS, BrakTooth, BlueBorne, and others.

## 🎯 Purpose

This tool is designed for **defensive security (Blue Team)** purposes:
- Monitor Bluetooth environments for attacks
- Detect vulnerable devices
- Alert on suspicious activity
- Generate security reports
- Support incident response

## 🚀 Features

### Attack Detection Capabilities

1. **KNOB Attack Detection**
   - Monitors encryption key negotiation
   - Alerts on downgraded key lengths
   - Detects forced weak encryption

2. **BIAS Attack Detection**
   - Tracks reconnection patterns
   - Identifies authentication bypasses
   - Monitors role switches

3. **BrakTooth Detection**
   - Identifies malformed LMP packets
   - Detects firmware exploitation attempts
   - Monitors for DoS patterns

4. **GATT Overflow Detection**
   - Monitors attribute write sizes
   - Detects buffer overflow attempts
   - Tracks unusual GATT operations

5. **Pairing Flood Detection**
   - Counts pairing requests
   - Identifies flooding attempts
   - Alerts on suspicious pairing patterns

6. **RSSI Anomaly Detection**
   - Tracks signal strength changes
   - Detects potential relay attacks
   - Identifies spoofing attempts

### Monitoring Features

- **Real-time Device Discovery**: Continuously scans for nearby Bluetooth devices
- **Device Profiling**: Builds profiles of discovered devices including manufacturer, vulnerabilities
- **Connection Monitoring**: Tracks connection patterns and anomalies
- **Packet Analysis**: Deep inspection of Bluetooth packets for attack signatures
- **Automated Reporting**: Generates comprehensive security reports

## 📋 Requirements

### System Requirements
- Linux system with Bluetooth hardware
- Python 3.8+
- Root/sudo access for packet capture

### Python Dependencies
```bash
pip install pybluez scapy
```

### System Tools
```bash
# Debian/Ubuntu
sudo apt-get install bluez bluez-tools libbluetooth-dev

# Fedora/RHEL
sudo dnf install bluez bluez-tools bluez-libs-devel
```

## 🔧 Installation

1. **Clone or download the tools**:
```bash
chmod +x bluetooth_attack_detector.py
chmod +x bluetooth_packet_analyzer.py
```

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

3. **Verify Bluetooth interface**:
```bash
hciconfig
```

## 📖 Usage

### Basic Monitoring

Start basic monitoring with default settings:
```bash
sudo python3 bluetooth_attack_detector.py
```

### Advanced Options

Monitor specific interface:
```bash
sudo python3 bluetooth_attack_detector.py -i hci0
```

Enable verbose logging:
```bash
sudo python3 bluetooth_attack_detector.py -v
```

Set custom alert threshold:
```bash
sudo python3 bluetooth_attack_detector.py -t 5
```

### Packet Analysis

For deep packet inspection:
```bash
sudo python3 bluetooth_packet_analyzer.py
```

## 📊 Output and Reports

### Real-time Alerts

The tool provides real-time alerts when threats are detected:
```
2026-02-03 10:15:23 - WARNING - THREAT DETECTED: KNOB [CRITICAL] 
from 00:1A:7D:DA:71:13 (Confidence: 95%) - {'key_length': 1}
```

### Security Reports

After monitoring, a comprehensive JSON report is generated:
```json
{
  "scan_summary": {
    "start_time": "2026-02-03T10:00:00",
    "end_time": "2026-02-03T11:00:00",
    "devices_detected": 15,
    "threats_found": 3
  },
  "devices": [...],
  "threats": [...],
  "recommendations": [...]
}
```

### Log Files

All activity is logged to:
- `bluetooth_detector.log` - Main detection log
- `bluetooth_security_report_YYYYMMDD_HHMMSS.json` - Security report

## 🛡️ Detection Rules

### Configurable Thresholds

The tool includes configurable detection rules:

```python
detection_rules = {
    'knob_detection': {
        'min_key_length': 7  # Alert if key < 7 bytes
    },
    'bias_detection': {
        'max_reconnect_time': 5  # Alert if reconnect < 5 seconds
    },
    'pairing_flood': {
        'max_pairing_requests': 10,
        'time_window': 60  # 10 requests in 60 seconds
    },
    'rssi_anomaly': {
        'rssi_jump_threshold': 30  # Alert on 30dBm changes
    }
}
```

## 🔍 Attack Signatures

### KNOB (Key Negotiation of Bluetooth)
- **Detection**: Monitors encryption key size negotiation
- **Indicator**: Key length < 7 bytes
- **Severity**: CRITICAL

### BIAS (Bluetooth Impersonation AttackS)
- **Detection**: Tracks reconnection timing and authentication
- **Indicator**: Rapid reconnection without authentication
- **Severity**: CRITICAL

### BrakTooth
- **Detection**: Identifies malformed LMP packets
- **Indicator**: Unusual packet structures, invalid opcodes
- **Severity**: HIGH

### BlueBorne
- **Detection**: Monitors L2CAP/SDP for exploits
- **Indicator**: Oversized SDP/BNEP packets
- **Severity**: CRITICAL

### GATT Overflow
- **Detection**: Checks attribute write sizes
- **Indicator**: Attributes > 512 bytes
- **Severity**: HIGH

## 📈 Use Cases

### 1. Security Auditing
```bash
# Run 1-hour security audit
sudo python3 bluetooth_attack_detector.py -v -t 3
# Review generated report
cat bluetooth_security_report_*.json
```

### 2. Continuous Monitoring
```bash
# Run as background service
sudo nohup python3 bluetooth_attack_detector.py > /dev/null 2>&1 &
# Monitor logs
tail -f bluetooth_detector.log
```

### 3. Incident Response
```bash
# Enable verbose mode for detailed forensics
sudo python3 bluetooth_attack_detector.py -v
# Analyze specific timeframe in logs
grep "THREAT DETECTED" bluetooth_detector.log
```

### 4. Vulnerability Assessment
```bash
# Scan for vulnerable devices
sudo python3 bluetooth_attack_detector.py
# Review device vulnerabilities in report
jq '.devices[] | select(.known_vulnerabilities != [])' report.json
```

## 🔐 Security Best Practices

### For Defenders

1. **Regular Monitoring**: Run periodic scans of your environment
2. **Update Firmware**: Keep all Bluetooth devices updated
3. **Disable When Not Needed**: Turn off Bluetooth when not in use
4. **Use Strong Pairing**: Implement secure pairing methods
5. **Limit Discoverability**: Only enable discoverable mode when pairing

### Recommendations from Reports

The tool automatically generates recommendations based on findings:
- Firmware update suggestions for vulnerable devices
- Configuration changes to mitigate detected attacks
- Best practices for specific threat scenarios

## 🧪 Testing

### Test Detection Rules

The tool includes test functionality:

```python
# Test KNOB detection
detector.detect_knob_attack(
    encryption_key_length=1,
    device_mac="00:11:22:33:44:55"
)

# Test GATT overflow detection
detector.detect_gatt_overflow(
    attribute_length=1024,
    device_mac="00:11:22:33:44:55"
)
```

## 📚 Technical Details

### Architecture

```
bluetooth_attack_detector.py
├── BluetoothAttackDetector (Main detection engine)
│   ├── Device Monitoring Thread
│   ├── Connection Analysis Thread
│   ├── Pairing Monitoring Thread
│   └── Detection Rules Engine
│
bluetooth_packet_analyzer.py
├── BluetoothPacketAnalyzer (Packet inspection)
│   ├── ACL Packet Analysis
│   ├── Event Packet Analysis
│   ├── Command Packet Analysis
│   └── Attack Signature Detection
```

### Threat Scoring

Threats are scored on multiple factors:
- **Threat Level**: LOW, MEDIUM, HIGH, CRITICAL
- **Confidence**: 0.0 to 1.0 based on signature match quality
- **Device Context**: Known vulnerabilities, manufacturer, behavior history

## 🚨 Limitations

1. **Requires Root Access**: Packet capture needs elevated privileges
2. **Linux Only**: Currently optimized for Linux systems
3. **Hardware Dependent**: Requires compatible Bluetooth adapter
4. **False Positives**: Some legitimate traffic may trigger alerts
5. **Passive Detection**: Cannot prevent attacks, only detect them

## 🤝 Contributing

This is a blue team defense tool. Contributions should focus on:
- Improving detection accuracy
- Adding new attack signatures
- Reducing false positives
- Better reporting capabilities
- Performance optimizations

## ⚖️ Legal Notice

**FOR DEFENSIVE SECURITY USE ONLY**

This tool is designed for:
- ✅ Monitoring your own network
- ✅ Security auditing with permission
- ✅ Educational purposes in controlled environments
- ✅ Incident response and forensics

Do NOT use for:
- ❌ Unauthorized monitoring of others' devices
- ❌ Attacking or exploiting systems
- ❌ Any illegal or unethical purposes

**Users are responsible for ensuring compliance with all applicable laws and regulations.**

## 📞 Support

For issues, questions, or contributions:
- Check logs in `bluetooth_detector.log`
- Review generated security reports
- Ensure all dependencies are installed
- Verify Bluetooth hardware compatibility

## 🔄 Version History

### v1.0 (Current)
- Initial release
- Support for KNOB, BIAS, BrakTooth, BlueBorne detection
- Real-time monitoring and reporting
- Comprehensive packet analysis
- Automated security recommendations

## 📄 License

This tool is provided for educational and defensive security purposes.
Use responsibly and ethically.

---

**Remember**: This is a DETECTION tool, not an ATTACK tool. 
Use it to protect systems, not to compromise them.
