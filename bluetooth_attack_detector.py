#!/usr/bin/env python3
"""
Bluetooth Attack Detection System (Blue Team)
Detects and monitors for various Bluetooth attacks including KNOB, BIAS, BrakTooth, etc.
For defensive security purposes only.
"""

import argparse
import json
import logging
import time
import threading
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict, deque
import socket
import struct

try:
    import bluetooth
    from bluetooth import BluetoothSocket, L2CAP, RFCOMM
except ImportError:
    print("Warning: PyBluez not installed. Some features may be limited.")
    bluetooth = None

try:
    from scapy.all import *
    from scapy.layers.bluetooth import *
except ImportError:
    print("Warning: Scapy not installed. Packet analysis features disabled.")

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bluetooth_detector.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackType(Enum):
    """Known Bluetooth attack types"""
    KNOB = "knob"  # Key Negotiation of Bluetooth
    BIAS = "bias"  # Bluetooth Impersonation AttackS
    BRAKTOOTH = "braktooth"  # Firmware exploits
    BLUEBORNE = "blueborne"  # Remote code execution
    BLUEPRINTING = "blueprinting"  # Device fingerprinting
    BLUESNARFING = "bluesnarfing"  # Data theft
    BLUEJACKING = "bluejacking"  # Spam messages
    BTLEJACKING = "btlejacking"  # BLE hijacking
    FAST_PAIR_EXPLOIT = "fast_pair_exploit"
    WHISPERPAIR_EXPLOIT = "whisperpair_exploit"
    GATT_OVERFLOW = "gatt_overflow"
    PAIRING_FLOOD = "pairing_flood"
    UNKNOWN = "unknown"


@dataclass
class ThreatIndicator:
    """Represents a detected threat"""
    timestamp: datetime
    attack_type: AttackType
    threat_level: ThreatLevel
    source_device: str
    target_device: Optional[str]
    details: Dict
    confidence: float  # 0.0 to 1.0
    

@dataclass
class DeviceProfile:
    """Profile of a detected Bluetooth device"""
    mac_address: str
    name: Optional[str]
    first_seen: datetime
    last_seen: datetime
    device_class: Optional[int]
    manufacturer: Optional[str]
    rssi_history: List[int]
    connection_attempts: int
    pairing_requests: int
    suspicious_behavior_count: int
    known_vulnerabilities: List[str]


class BluetoothAttackDetector:
    """Main detection engine for Bluetooth attacks"""
    
    def __init__(self, interface: str = "hci0", alert_threshold: int = 3):
        self.interface = interface
        self.alert_threshold = alert_threshold
        self.running = False
        
        # Detection state
        self.known_devices: Dict[str, DeviceProfile] = {}
        self.threats: List[ThreatIndicator] = []
        self.connection_timeline: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.pairing_timeline: Dict[str, deque] = defaultdict(lambda: deque(maxlen=50))
        
        # Detection rules
        self.detection_rules = self._initialize_detection_rules()
        
        # Statistics
        self.stats = {
            'devices_seen': 0,
            'threats_detected': 0,
            'packets_analyzed': 0,
            'connections_monitored': 0
        }
        
    def _initialize_detection_rules(self) -> Dict:
        """Initialize detection rules for various attacks"""
        return {
            'knob_detection': {
                'enabled': True,
                'min_key_length': 7,  # KNOB attack reduces to 1 byte
                'description': 'Detects Key Negotiation of Bluetooth attacks'
            },
            'bias_detection': {
                'enabled': True,
                'max_reconnect_time': 5,  # seconds
                'description': 'Detects Bluetooth Impersonation AttackS'
            },
            'braktooth_detection': {
                'enabled': True,
                'malformed_packet_threshold': 5,
                'description': 'Detects BrakTooth firmware exploits'
            },
            'pairing_flood': {
                'enabled': True,
                'max_pairing_requests': 10,
                'time_window': 60,  # seconds
                'description': 'Detects pairing request flooding'
            },
            'rssi_anomaly': {
                'enabled': True,
                'rssi_jump_threshold': 30,  # dBm
                'description': 'Detects sudden RSSI changes (potential relay attack)'
            },
            'gatt_overflow': {
                'enabled': True,
                'max_attribute_length': 512,
                'description': 'Detects GATT buffer overflow attempts'
            }
        }
    
    def start_monitoring(self):
        """Start the detection system"""
        logger.info(f"Starting Bluetooth attack detection on {self.interface}")
        self.running = True
        
        # Start monitoring threads
        threads = [
            threading.Thread(target=self._monitor_devices, daemon=True),
            threading.Thread(target=self._analyze_connections, daemon=True),
            threading.Thread(target=self._monitor_pairing, daemon=True),
        ]
        
        for thread in threads:
            thread.start()
        
        logger.info("All monitoring threads started")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Stopping monitoring...")
            self.stop_monitoring()
    
    def stop_monitoring(self):
        """Stop the detection system"""
        self.running = False
        logger.info("Detection system stopped")
        self._generate_report()
    
    def _monitor_devices(self):
        """Continuously scan for nearby Bluetooth devices"""
        logger.info("Device monitoring thread started")
        
        while self.running:
            try:
                if bluetooth:
                    nearby_devices = bluetooth.discover_devices(
                        duration=8,
                        lookup_names=True,
                        flush_cache=True,
                        lookup_class=True
                    )
                    
                    for addr, name, dev_class in nearby_devices:
                        self._process_discovered_device(addr, name, dev_class)
                        self.stats['devices_seen'] += 1
                else:
                    logger.warning("Bluetooth module not available")
                    time.sleep(30)
                    
            except Exception as e:
                logger.error(f"Error in device monitoring: {e}")
                time.sleep(10)
    
    def _process_discovered_device(self, mac: str, name: Optional[str], dev_class: Optional[int]):
        """Process a discovered device and update profile"""
        now = datetime.now()
        
        if mac not in self.known_devices:
            # New device
            profile = DeviceProfile(
                mac_address=mac,
                name=name,
                first_seen=now,
                last_seen=now,
                device_class=dev_class,
                manufacturer=self._get_manufacturer(mac),
                rssi_history=[],
                connection_attempts=0,
                pairing_requests=0,
                suspicious_behavior_count=0,
                known_vulnerabilities=self._check_vulnerabilities(mac, dev_class)
            )
            self.known_devices[mac] = profile
            logger.info(f"New device detected: {mac} ({name})")
            
            # Check for known vulnerable devices
            if profile.known_vulnerabilities:
                self._create_threat(
                    attack_type=AttackType.UNKNOWN,
                    threat_level=ThreatLevel.MEDIUM,
                    source_device=mac,
                    details={'vulnerabilities': profile.known_vulnerabilities},
                    confidence=0.7
                )
        else:
            # Update existing device
            self.known_devices[mac].last_seen = now
            if name and not self.known_devices[mac].name:
                self.known_devices[mac].name = name
    
    def _get_manufacturer(self, mac: str) -> Optional[str]:
        """Get manufacturer from MAC OUI"""
        oui_database = {
            '00:1A:7D': 'Qualcomm',
            '00:25:00': 'Apple',
            '00:E0:4C': 'Realtek',
            '08:EB:ED': 'Qualcomm',
            '20:68:9D': 'Espressif',
            '4C:75:25': 'Apple',
            '94:E6:F7': 'Espressif',
            'AC:DE:48': 'Apple',
            'DC:2C:26': 'Apple',
        }
        
        oui = mac[:8].upper()
        return oui_database.get(oui, 'Unknown')
    
    def _check_vulnerabilities(self, mac: str, dev_class: Optional[int]) -> List[str]:
        """Check for known vulnerabilities based on device characteristics"""
        vulnerabilities = []
        manufacturer = self._get_manufacturer(mac)
        
        # Example vulnerability checks
        vuln_db = {
            'Qualcomm': ['CVE-2020-12351', 'Potential BrakTooth'],
            'Realtek': ['CVE-2021-28139', 'Potential buffer overflow'],
        }
        
        if manufacturer in vuln_db:
            vulnerabilities.extend(vuln_db[manufacturer])
        
        return vulnerabilities
    
    def _monitor_pairing(self):
        """Monitor for pairing-related attacks"""
        logger.info("Pairing monitoring thread started")
        
        while self.running:
            try:
                # Monitor pairing requests
                for mac, requests in self.pairing_timeline.items():
                    if len(requests) > self.detection_rules['pairing_flood']['max_pairing_requests']:
                        recent_requests = [r for r in requests if 
                                         (datetime.now() - r).seconds < 
                                         self.detection_rules['pairing_flood']['time_window']]
                        
                        if len(recent_requests) > self.detection_rules['pairing_flood']['max_pairing_requests']:
                            self._create_threat(
                                attack_type=AttackType.PAIRING_FLOOD,
                                threat_level=ThreatLevel.HIGH,
                                source_device=mac,
                                details={
                                    'pairing_attempts': len(recent_requests),
                                    'time_window': self.detection_rules['pairing_flood']['time_window']
                                },
                                confidence=0.9
                            )
                
                time.sleep(5)
            except Exception as e:
                logger.error(f"Error in pairing monitoring: {e}")
                time.sleep(10)
    
    def _analyze_connections(self):
        """Analyze connection patterns for anomalies"""
        logger.info("Connection analysis thread started")
        
        while self.running:
            try:
                for mac, connections in self.connection_timeline.items():
                    if len(connections) >= 2:
                        # Check for BIAS attack pattern (rapid reconnection)
                        time_diff = (connections[-1] - connections[-2]).total_seconds()
                        
                        if time_diff < self.detection_rules['bias_detection']['max_reconnect_time']:
                            self._create_threat(
                                attack_type=AttackType.BIAS,
                                threat_level=ThreatLevel.CRITICAL,
                                source_device=mac,
                                details={
                                    'reconnect_time': time_diff,
                                    'description': 'Suspiciously fast reconnection detected'
                                },
                                confidence=0.85
                            )
                
                time.sleep(5)
            except Exception as e:
                logger.error(f"Error in connection analysis: {e}")
                time.sleep(10)
    
    def detect_knob_attack(self, encryption_key_length: int, device_mac: str) -> bool:
        """Detect KNOB attack based on encryption key length"""
        if encryption_key_length < self.detection_rules['knob_detection']['min_key_length']:
            self._create_threat(
                attack_type=AttackType.KNOB,
                threat_level=ThreatLevel.CRITICAL,
                source_device=device_mac,
                details={
                    'key_length': encryption_key_length,
                    'expected_min': self.detection_rules['knob_detection']['min_key_length'],
                    'description': 'Encryption key negotiation downgrade detected'
                },
                confidence=0.95
            )
            return True
        return False
    
    def detect_gatt_overflow(self, attribute_length: int, device_mac: str) -> bool:
        """Detect GATT buffer overflow attempts"""
        if attribute_length > self.detection_rules['gatt_overflow']['max_attribute_length']:
            self._create_threat(
                attack_type=AttackType.GATT_OVERFLOW,
                threat_level=ThreatLevel.HIGH,
                source_device=device_mac,
                details={
                    'attribute_length': attribute_length,
                    'max_expected': self.detection_rules['gatt_overflow']['max_attribute_length'],
                    'description': 'GATT attribute overflow attempt detected'
                },
                confidence=0.8
            )
            return True
        return False
    
    def detect_rssi_anomaly(self, device_mac: str, current_rssi: int) -> bool:
        """Detect RSSI anomalies that might indicate relay attacks"""
        if device_mac in self.known_devices:
            profile = self.known_devices[device_mac]
            
            if profile.rssi_history:
                avg_rssi = sum(profile.rssi_history) / len(profile.rssi_history)
                rssi_diff = abs(current_rssi - avg_rssi)
                
                if rssi_diff > self.detection_rules['rssi_anomaly']['rssi_jump_threshold']:
                    self._create_threat(
                        attack_type=AttackType.UNKNOWN,
                        threat_level=ThreatLevel.MEDIUM,
                        source_device=device_mac,
                        details={
                            'current_rssi': current_rssi,
                            'average_rssi': avg_rssi,
                            'difference': rssi_diff,
                            'description': 'Unusual RSSI change (potential relay attack)'
                        },
                        confidence=0.6
                    )
                    return True
            
            # Update RSSI history
            profile.rssi_history.append(current_rssi)
            if len(profile.rssi_history) > 20:
                profile.rssi_history.pop(0)
        
        return False
    
    def _create_threat(self, attack_type: AttackType, threat_level: ThreatLevel,
                       source_device: str, details: Dict, confidence: float,
                       target_device: Optional[str] = None):
        """Create a threat indicator"""
        threat = ThreatIndicator(
            timestamp=datetime.now(),
            attack_type=attack_type,
            threat_level=threat_level,
            source_device=source_device,
            target_device=target_device,
            details=details,
            confidence=confidence
        )
        
        self.threats.append(threat)
        self.stats['threats_detected'] += 1
        
        # Log the threat
        logger.warning(
            f"THREAT DETECTED: {attack_type.value.upper()} "
            f"[{threat_level.value.upper()}] from {source_device} "
            f"(Confidence: {confidence*100:.0f}%) - {details}"
        )
        
        # Update device suspicious behavior count
        if source_device in self.known_devices:
            self.known_devices[source_device].suspicious_behavior_count += 1
    
    def _generate_report(self):
        """Generate detection report"""
        report = {
            'scan_summary': {
                'start_time': min(
                    [d.first_seen for d in self.known_devices.values()],
                    default=datetime.now()
                ).isoformat(),
                'end_time': datetime.now().isoformat(),
                'devices_detected': len(self.known_devices),
                'threats_found': len(self.threats),
                'statistics': self.stats
            },
            'devices': [],
            'threats': [],
            'recommendations': []
        }
        
        # Add device information
        for device in self.known_devices.values():
            device_dict = asdict(device)
            device_dict['first_seen'] = device.first_seen.isoformat()
            device_dict['last_seen'] = device.last_seen.isoformat()
            report['devices'].append(device_dict)
        
        # Add threat information
        for threat in self.threats:
            threat_dict = asdict(threat)
            threat_dict['timestamp'] = threat.timestamp.isoformat()
            threat_dict['attack_type'] = threat.attack_type.value
            threat_dict['threat_level'] = threat.threat_level.value
            report['threats'].append(threat_dict)
        
        # Generate recommendations
        report['recommendations'] = self._generate_recommendations()
        
        # Save report
        report_file = f"bluetooth_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Security report saved to {report_file}")
        
        # Print summary
        print("\n" + "="*70)
        print("BLUETOOTH SECURITY SCAN SUMMARY")
        print("="*70)
        print(f"Devices Detected: {len(self.known_devices)}")
        print(f"Threats Found: {len(self.threats)}")
        print(f"Packets Analyzed: {self.stats['packets_analyzed']}")
        print("="*70)
        
        if self.threats:
            print("\nTHREATS DETECTED:")
            for threat in sorted(self.threats, key=lambda x: x.threat_level.value, reverse=True):
                print(f"  [{threat.threat_level.value.upper()}] {threat.attack_type.value} from {threat.source_device}")
        
        print(f"\nFull report: {report_file}\n")
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        if any(t.attack_type == AttackType.KNOB for t in self.threats):
            recommendations.append(
                "KNOB attack detected: Ensure all devices use Bluetooth 5.0+ with secure connections"
            )
        
        if any(t.attack_type == AttackType.BIAS for t in self.threats):
            recommendations.append(
                "BIAS attack detected: Disable automatic reconnection and require re-pairing"
            )
        
        if any(t.attack_type == AttackType.PAIRING_FLOOD for t in self.threats):
            recommendations.append(
                "Pairing flood detected: Disable discoverable mode when not needed"
            )
        
        if any(d.known_vulnerabilities for d in self.known_devices.values()):
            recommendations.append(
                "Vulnerable devices detected: Update firmware on all Bluetooth devices"
            )
        
        recommendations.append("Enable Bluetooth only when needed")
        recommendations.append("Use strong PIN codes for pairing")
        recommendations.append("Regularly review paired devices and remove unused ones")
        
        return recommendations


def main():
    parser = argparse.ArgumentParser(
        description="Bluetooth Attack Detection System (Blue Team Defense)"
    )
    parser.add_argument(
        "-i", "--interface",
        default="hci0",
        help="Bluetooth interface to monitor (default: hci0)"
    )
    parser.add_argument(
        "-t", "--threshold",
        type=int,
        default=3,
        help="Alert threshold for suspicious activity (default: 3)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Output file for results (default: auto-generated)"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║         Bluetooth Attack Detection System v1.0              ║
    ║                    Blue Team Defense                        ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    detector = BluetoothAttackDetector(
        interface=args.interface,
        alert_threshold=args.threshold
    )
    
    try:
        detector.start_monitoring()
    except KeyboardInterrupt:
        print("\n\nShutting down gracefully...")
        detector.stop_monitoring()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
