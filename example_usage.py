#!/usr/bin/env python3
"""
Example Usage: Bluetooth Attack Detection System

This script demonstrates how to use the detection system
for various security monitoring scenarios.
"""

import sys
import time
import json
from datetime import datetime
from bluetooth_attack_detector import BluetoothAttackDetector, ThreatLevel, AttackType

# Scenario 1: Basic Security Monitoring
def scenario_basic_monitoring():
    """
    Basic monitoring scenario - detect all threats
    """
    print("\n=== Scenario 1: Basic Security Monitoring ===\n")
    
    detector = BluetoothAttackDetector(interface="hci0", alert_threshold=3)
    
    print("Starting basic monitoring...")
    print("Press Ctrl+C to stop\n")
    
    try:
        detector.start_monitoring()
    except KeyboardInterrupt:
        print("\nStopping monitoring...")
        detector.stop_monitoring()


# Scenario 2: Targeted Attack Detection
def scenario_targeted_detection():
    """
    Monitor for specific attack types only
    """
    print("\n=== Scenario 2: Targeted Attack Detection ===\n")
    
    detector = BluetoothAttackDetector(interface="hci0")
    
    # Disable all rules except KNOB and BIAS
    detector.detection_rules['braktooth_detection']['enabled'] = False
    detector.detection_rules['pairing_flood']['enabled'] = False
    detector.detection_rules['gatt_overflow']['enabled'] = False
    
    print("Monitoring for KNOB and BIAS attacks only...")
    print("Press Ctrl+C to stop\n")
    
    try:
        detector.start_monitoring()
    except KeyboardInterrupt:
        detector.stop_monitoring()


# Scenario 3: High-Security Environment
def scenario_high_security():
    """
    Maximum sensitivity for critical environments
    """
    print("\n=== Scenario 3: High-Security Environment ===\n")
    
    detector = BluetoothAttackDetector(interface="hci0", alert_threshold=1)
    
    # Increase sensitivity
    detector.detection_rules['knob_detection']['min_key_length'] = 10
    detector.detection_rules['bias_detection']['max_reconnect_time'] = 10
    detector.detection_rules['pairing_flood']['max_pairing_requests'] = 5
    
    print("High-security monitoring active (maximum sensitivity)...")
    print("Press Ctrl+C to stop\n")
    
    try:
        detector.start_monitoring()
    except KeyboardInterrupt:
        detector.stop_monitoring()


# Scenario 4: Periodic Scanning
def scenario_periodic_scan():
    """
    Perform periodic 5-minute scans
    """
    print("\n=== Scenario 4: Periodic Security Scans ===\n")
    
    scan_duration = 300  # 5 minutes
    scan_interval = 1800  # 30 minutes between scans
    
    scan_number = 1
    
    while True:
        print(f"\n--- Scan #{scan_number} at {datetime.now()} ---")
        
        detector = BluetoothAttackDetector(interface="hci0")
        
        print(f"Starting {scan_duration}s scan...")
        
        # Start monitoring in a thread
        import threading
        monitor_thread = threading.Thread(target=detector.start_monitoring)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Wait for scan duration
        time.sleep(scan_duration)
        
        # Stop monitoring
        detector.stop_monitoring()
        
        print(f"\nScan complete. Threats found: {len(detector.threats)}")
        
        # Wait until next scan
        print(f"Next scan in {scan_interval}s...")
        time.sleep(scan_interval)
        
        scan_number += 1


# Scenario 5: Custom Threat Response
def scenario_custom_response():
    """
    Implement custom responses to detected threats
    """
    print("\n=== Scenario 5: Custom Threat Response ===\n")
    
    detector = BluetoothAttackDetector(interface="hci0")
    
    # Override the threat creation to add custom handling
    original_create_threat = detector._create_threat
    
    def custom_threat_handler(attack_type, threat_level, source_device, 
                            details, confidence, target_device=None):
        # Call original handler
        original_create_threat(attack_type, threat_level, source_device, 
                             details, confidence, target_device)
        
        # Custom response based on threat level
        if threat_level == ThreatLevel.CRITICAL:
            print(f"\n🚨 CRITICAL ALERT: {attack_type.value} from {source_device}")
            print(f"   Action: Blocking device {source_device}")
            # In real scenario: execute blocking command
            # os.system(f"hciconfig hci0 block {source_device}")
            
        elif threat_level == ThreatLevel.HIGH:
            print(f"\n⚠️  HIGH ALERT: {attack_type.value} from {source_device}")
            print(f"   Action: Logging for review")
            
        # Could send email, webhook, SMS, etc.
    
    detector._create_threat = custom_threat_handler
    
    print("Custom threat response enabled...")
    print("Press Ctrl+C to stop\n")
    
    try:
        detector.start_monitoring()
    except KeyboardInterrupt:
        detector.stop_monitoring()


# Scenario 6: Forensics Mode
def scenario_forensics():
    """
    Detailed logging for forensic analysis
    """
    print("\n=== Scenario 6: Forensics Mode ===\n")
    
    import logging
    
    # Enable debug logging
    logging.getLogger().setLevel(logging.DEBUG)
    
    detector = BluetoothAttackDetector(interface="hci0")
    
    print("Forensics mode: All activity logged to bluetooth_detector.log")
    print("Press Ctrl+C to stop\n")
    
    try:
        detector.start_monitoring()
    except KeyboardInterrupt:
        detector.stop_monitoring()
        
        # Generate detailed report
        print("\nGenerating forensic report...")
        
        forensic_data = {
            'scan_metadata': {
                'start_time': min([d.first_seen for d in detector.known_devices.values()]).isoformat(),
                'end_time': datetime.now().isoformat(),
                'duration_seconds': (datetime.now() - min([d.first_seen for d in detector.known_devices.values()])).seconds
            },
            'devices': [],
            'threats': [],
            'connection_timeline': {},
            'pairing_timeline': {}
        }
        
        # Add detailed device info
        for device in detector.known_devices.values():
            forensic_data['devices'].append({
                'mac': device.mac_address,
                'name': device.name,
                'manufacturer': device.manufacturer,
                'first_seen': device.first_seen.isoformat(),
                'last_seen': device.last_seen.isoformat(),
                'connection_attempts': device.connection_attempts,
                'pairing_requests': device.pairing_requests,
                'suspicious_behaviors': device.suspicious_behavior_count,
                'rssi_history': device.rssi_history,
                'vulnerabilities': device.known_vulnerabilities
            })
        
        # Add threat details
        for threat in detector.threats:
            forensic_data['threats'].append({
                'timestamp': threat.timestamp.isoformat(),
                'type': threat.attack_type.value,
                'level': threat.threat_level.value,
                'source': threat.source_device,
                'target': threat.target_device,
                'confidence': threat.confidence,
                'details': threat.details
            })
        
        # Save forensic report
        filename = f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(forensic_data, f, indent=2)
        
        print(f"Forensic report saved: {filename}")


# Scenario 7: Test Detection Rules
def scenario_test_detection():
    """
    Test detection rules with simulated data
    """
    print("\n=== Scenario 7: Test Detection Rules ===\n")
    
    detector = BluetoothAttackDetector(interface="hci0")
    
    print("Testing detection rules...\n")
    
    # Test KNOB detection
    print("1. Testing KNOB attack detection...")
    result = detector.detect_knob_attack(
        encryption_key_length=1,
        device_mac="00:11:22:33:44:55"
    )
    print(f"   Result: {'DETECTED' if result else 'NOT DETECTED'}")
    
    # Test GATT overflow
    print("\n2. Testing GATT overflow detection...")
    result = detector.detect_gatt_overflow(
        attribute_length=1024,
        device_mac="00:11:22:33:44:66"
    )
    print(f"   Result: {'DETECTED' if result else 'NOT DETECTED'}")
    
    # Test RSSI anomaly
    print("\n3. Testing RSSI anomaly detection...")
    
    # Create a device with normal RSSI
    from bluetooth_attack_detector import DeviceProfile
    test_device = DeviceProfile(
        mac_address="00:11:22:33:44:77",
        name="Test Device",
        first_seen=datetime.now(),
        last_seen=datetime.now(),
        device_class=None,
        manufacturer="Test",
        rssi_history=[-50, -52, -51, -49, -50],
        connection_attempts=0,
        pairing_requests=0,
        suspicious_behavior_count=0,
        known_vulnerabilities=[]
    )
    detector.known_devices["00:11:22:33:44:77"] = test_device
    
    # Test with anomalous RSSI
    result = detector.detect_rssi_anomaly(
        device_mac="00:11:22:33:44:77",
        current_rssi=-10  # Sudden jump
    )
    print(f"   Result: {'DETECTED' if result else 'NOT DETECTED'}")
    
    print(f"\n\nTotal threats detected: {len(detector.threats)}")
    print("\nThreat Summary:")
    for threat in detector.threats:
        print(f"  - {threat.attack_type.value}: {threat.threat_level.value} "
              f"(confidence: {threat.confidence*100:.0f}%)")


def main():
    """
    Main menu for example scenarios
    """
    print("""
╔══════════════════════════════════════════════════════════════╗
║    Bluetooth Attack Detection System - Example Usage        ║
╚══════════════════════════════════════════════════════════════╝

Select a scenario:

1. Basic Security Monitoring
2. Targeted Attack Detection (KNOB/BIAS only)
3. High-Security Environment (maximum sensitivity)
4. Periodic Scanning (every 30 minutes)
5. Custom Threat Response
6. Forensics Mode (detailed logging)
7. Test Detection Rules
8. Exit

    """)
    
    choice = input("Enter choice (1-8): ").strip()
    
    scenarios = {
        '1': scenario_basic_monitoring,
        '2': scenario_targeted_detection,
        '3': scenario_high_security,
        '4': scenario_periodic_scan,
        '5': scenario_custom_response,
        '6': scenario_forensics,
        '7': scenario_test_detection,
    }
    
    if choice in scenarios:
        scenarios[choice]()
    elif choice == '8':
        print("Exiting...")
        sys.exit(0)
    else:
        print("Invalid choice!")


if __name__ == "__main__":
    main()
