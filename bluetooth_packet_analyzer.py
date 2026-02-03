#!/usr/bin/env python3
"""
Bluetooth Packet Analyzer
Deep packet inspection for Bluetooth attack detection
"""

import logging
import struct
from datetime import datetime
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class PacketType(Enum):
    """HCI packet types"""
    COMMAND = 0x01
    ACL_DATA = 0x02
    SCO_DATA = 0x03
    EVENT = 0x04
    ISO_DATA = 0x05


class LMPOpcode(Enum):
    """Link Manager Protocol opcodes"""
    NAME_REQ = 1
    NAME_RES = 2
    ACCEPTED = 3
    NOT_ACCEPTED = 4
    ENCRYPTION_MODE_REQ = 23
    ENCRYPTION_KEY_SIZE_REQ = 16
    START_ENCRYPTION_REQ = 17


@dataclass
class PacketAnalysis:
    """Results of packet analysis"""
    timestamp: datetime
    packet_type: str
    source: Optional[str]
    destination: Optional[str]
    suspicious: bool
    indicators: list
    raw_data: bytes
    analysis: Dict


class BluetoothPacketAnalyzer:
    """Analyzes Bluetooth packets for attack signatures"""
    
    def __init__(self):
        self.packet_count = 0
        self.suspicious_packets = []
        
        # Attack signatures
        self.attack_signatures = {
            'knob': self._analyze_knob_signature,
            'bias': self._analyze_bias_signature,
            'braktooth': self._analyze_braktooth_signature,
            'blueborne': self._analyze_blueborne_signature,
            'gatt_overflow': self._analyze_gatt_overflow,
        }
    
    def analyze_packet(self, packet_data: bytes) -> PacketAnalysis:
        """Analyze a Bluetooth packet"""
        self.packet_count += 1
        
        analysis = PacketAnalysis(
            timestamp=datetime.now(),
            packet_type='unknown',
            source=None,
            destination=None,
            suspicious=False,
            indicators=[],
            raw_data=packet_data,
            analysis={}
        )
        
        try:
            # Parse HCI packet type
            if len(packet_data) < 1:
                return analysis
            
            packet_type = packet_data[0]
            
            if packet_type == PacketType.ACL_DATA.value:
                analysis.packet_type = 'ACL_DATA'
                self._analyze_acl_packet(packet_data[1:], analysis)
            
            elif packet_type == PacketType.EVENT.value:
                analysis.packet_type = 'EVENT'
                self._analyze_event_packet(packet_data[1:], analysis)
            
            elif packet_type == PacketType.COMMAND.value:
                analysis.packet_type = 'COMMAND'
                self._analyze_command_packet(packet_data[1:], analysis)
            
            # Run attack signature detection
            for attack_name, detector in self.attack_signatures.items():
                indicators = detector(packet_data, analysis)
                if indicators:
                    analysis.suspicious = True
                    analysis.indicators.extend(indicators)
            
            if analysis.suspicious:
                self.suspicious_packets.append(analysis)
                logger.warning(
                    f"Suspicious packet detected: {analysis.packet_type} - "
                    f"Indicators: {', '.join(analysis.indicators)}"
                )
        
        except Exception as e:
            logger.error(f"Error analyzing packet: {e}")
        
        return analysis
    
    def _analyze_acl_packet(self, data: bytes, analysis: PacketAnalysis):
        """Analyze ACL data packet"""
        if len(data) < 4:
            return
        
        # Parse ACL header
        handle_flags = struct.unpack('<H', data[0:2])[0]
        connection_handle = handle_flags & 0x0FFF
        pb_flag = (handle_flags >> 12) & 0x03
        bc_flag = (handle_flags >> 14) & 0x03
        data_length = struct.unpack('<H', data[2:4])[0]
        
        analysis.analysis['connection_handle'] = connection_handle
        analysis.analysis['data_length'] = data_length
        
        # Check for L2CAP layer
        if len(data) >= 8:
            l2cap_length = struct.unpack('<H', data[4:6])[0]
            l2cap_cid = struct.unpack('<H', data[6:8])[0]
            
            analysis.analysis['l2cap_cid'] = l2cap_cid
            
            # Check for GATT operations
            if l2cap_cid == 0x0004:  # ATT/GATT CID
                self._analyze_gatt_packet(data[8:], analysis)
    
    def _analyze_gatt_packet(self, data: bytes, analysis: PacketAnalysis):
        """Analyze GATT/ATT packet"""
        if len(data) < 1:
            return
        
        opcode = data[0]
        analysis.analysis['gatt_opcode'] = hex(opcode)
        
        # Check for write operations with unusual lengths
        if opcode in [0x12, 0x52]:  # Write Request/Command
            if len(data) > 512:
                analysis.indicators.append('gatt_oversized_write')
    
    def _analyze_event_packet(self, data: bytes, analysis: PacketAnalysis):
        """Analyze HCI event packet"""
        if len(data) < 2:
            return
        
        event_code = data[0]
        param_length = data[1]
        
        analysis.analysis['event_code'] = hex(event_code)
        analysis.analysis['param_length'] = param_length
        
        # Encryption Change event
        if event_code == 0x08:
            if len(data) >= 4:
                status = data[2]
                encryption_enabled = data[3]
                analysis.analysis['encryption_enabled'] = encryption_enabled
    
    def _analyze_command_packet(self, data: bytes, analysis: PacketAnalysis):
        """Analyze HCI command packet"""
        if len(data) < 3:
            return
        
        opcode = struct.unpack('<H', data[0:2])[0]
        param_length = data[2]
        
        analysis.analysis['command_opcode'] = hex(opcode)
        analysis.analysis['param_length'] = param_length
    
    def _analyze_knob_signature(self, packet: bytes, analysis: PacketAnalysis) -> list:
        """Detect KNOB attack signatures"""
        indicators = []
        
        # Check for encryption key size negotiation
        if 'encryption_key_size' in analysis.analysis:
            key_size = analysis.analysis['encryption_key_size']
            if key_size < 7:
                indicators.append(f'knob_weak_key_size_{key_size}')
        
        # Check for LMP encryption key size mask
        if len(packet) > 10:
            # Look for LMP_encryption_key_size_mask_req
            if b'\x10' in packet:  # Simplified check
                indicators.append('knob_key_negotiation_detected')
        
        return indicators
    
    def _analyze_bias_signature(self, packet: bytes, analysis: PacketAnalysis) -> list:
        """Detect BIAS attack signatures"""
        indicators = []
        
        # BIAS involves role switches and reconnections without authentication
        if analysis.packet_type == 'EVENT':
            event_code = analysis.analysis.get('event_code')
            
            # Role Change event without subsequent authentication
            if event_code == '0x12':
                indicators.append('bias_role_change_detected')
            
            # Connection Complete without authentication
            if event_code == '0x03':
                if 'encryption_enabled' in analysis.analysis:
                    if not analysis.analysis['encryption_enabled']:
                        indicators.append('bias_unencrypted_connection')
        
        return indicators
    
    def _analyze_braktooth_signature(self, packet: bytes, analysis: PacketAnalysis) -> list:
        """Detect BrakTooth attack signatures"""
        indicators = []
        
        # BrakTooth involves malformed LMP packets
        if len(packet) > 4:
            # Check for malformed packet structures
            if analysis.packet_type == 'ACL_DATA':
                data_length = analysis.analysis.get('data_length', 0)
                
                # Unusually large or small packets
                if data_length > 1021 or data_length == 0:
                    indicators.append('braktooth_malformed_length')
                
                # Look for specific LMP opcodes associated with BrakTooth
                if b'\x33\x00' in packet or b'\x44\x00' in packet:
                    indicators.append('braktooth_suspicious_lmp')
        
        return indicators
    
    def _analyze_blueborne_signature(self, packet: bytes, analysis: PacketAnalysis) -> list:
        """Detect BlueBorne attack signatures"""
        indicators = []
        
        # BlueBorne involves L2CAP/SDP exploitation
        if 'l2cap_cid' in analysis.analysis:
            cid = analysis.analysis['l2cap_cid']
            
            # SDP channel with oversized packets
            if cid == 0x0001 and len(packet) > 500:
                indicators.append('blueborne_sdp_overflow')
            
            # BNEP with unusual size
            if cid == 0x000F and len(packet) > 1000:
                indicators.append('blueborne_bnep_overflow')
        
        return indicators
    
    def _analyze_gatt_overflow(self, packet: bytes, analysis: PacketAnalysis) -> list:
        """Detect GATT buffer overflow attempts"""
        indicators = []
        
        if 'gatt_opcode' in analysis.analysis:
            # Check for oversized attribute writes
            if analysis.indicators and 'gatt_oversized_write' in analysis.indicators:
                indicators.append('gatt_buffer_overflow_attempt')
            
            # Check for rapid sequential writes (potential heap spray)
            # This would require tracking packet sequences
        
        return indicators
    
    def get_statistics(self) -> Dict:
        """Get analysis statistics"""
        return {
            'total_packets': self.packet_count,
            'suspicious_packets': len(self.suspicious_packets),
            'attack_indicators': self._count_indicators()
        }
    
    def _count_indicators(self) -> Dict[str, int]:
        """Count occurrences of each indicator"""
        indicator_counts = {}
        for packet in self.suspicious_packets:
            for indicator in packet.indicators:
                indicator_counts[indicator] = indicator_counts.get(indicator, 0) + 1
        return indicator_counts


class HCIDump:
    """Capture and analyze HCI packets"""
    
    def __init__(self, interface: str = "hci0"):
        self.interface = interface
        self.analyzer = BluetoothPacketAnalyzer()
        self.capture_active = False
    
    def start_capture(self, duration: Optional[int] = None):
        """Start capturing HCI packets"""
        import subprocess
        import signal
        
        logger.info(f"Starting HCI capture on {self.interface}")
        
        try:
            # Use btmon or hcidump
            cmd = ['btmon']
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            self.capture_active = True
            
            def signal_handler(sig, frame):
                self.capture_active = False
                process.terminate()
            
            signal.signal(signal.SIGINT, signal_handler)
            
            # Process output
            while self.capture_active:
                line = process.stdout.readline()
                if not line:
                    break
                
                # Parse and analyze packets
                # This is a simplified version - real implementation
                # would need proper btmon output parsing
                
            logger.info("HCI capture stopped")
            
        except FileNotFoundError:
            logger.error("btmon not found. Install bluez-tools package.")
        except Exception as e:
            logger.error(f"Error during capture: {e}")


if __name__ == "__main__":
    # Test the analyzer
    logging.basicConfig(level=logging.INFO)
    
    analyzer = BluetoothPacketAnalyzer()
    
    # Example: analyze a test packet
    test_packet = b'\x02\x00\x01\x00\x08\x00\x04\x00\x12\x01\x00' + b'A' * 600
    result = analyzer.analyze_packet(test_packet)
    
    print(f"Analysis result: {result}")
    print(f"Statistics: {analyzer.get_statistics()}")
