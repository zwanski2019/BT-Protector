"""
Bluetooth Attack Detection System - Web Interface
A comprehensive Streamlit dashboard for Bluetooth security monitoring
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json
import time
from collections import defaultdict
import random

# Page configuration
st.set_page_config(
    page_title="Bluetooth Security Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better UI
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        padding: 1rem 0;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 10px;
        color: white;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    
    .threat-critical {
        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #dc3545;
        margin: 0.5rem 0;
    }
    
    .threat-high {
        background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #fd7e14;
        margin: 0.5rem 0;
    }
    
    .threat-medium {
        background: linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%);
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #ffc107;
        margin: 0.5rem 0;
    }
    
    .threat-low {
        background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%);
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #17a2b8;
        margin: 0.5rem 0;
    }
    
    .device-card {
        background: white;
        padding: 1rem;
        border-radius: 8px;
        border: 1px solid #e0e0e0;
        margin: 0.5rem 0;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
    }
    
    .stButton>button {
        width: 100%;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        padding: 0.5rem 1rem;
        border-radius: 5px;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'monitoring_active' not in st.session_state:
    st.session_state.monitoring_active = False
if 'devices' not in st.session_state:
    st.session_state.devices = []
if 'threats' not in st.session_state:
    st.session_state.threats = []
if 'detection_rules' not in st.session_state:
    st.session_state.detection_rules = {
        'knob': True,
        'bias': True,
        'braktooth': True,
        'gatt': True,
        'pairing_flood': True,
        'rssi_anomaly': True
    }

def generate_demo_data():
    """Generate demo data for demonstration"""
    devices = [
        {'mac': '00:1A:7D:DA:71:13', 'name': 'Sony WH-1000XM4', 'manufacturer': 'Sony', 'rssi': -45,
         'first_seen': datetime.now() - timedelta(minutes=30), 'last_seen': datetime.now(),
         'vulnerabilities': ['CVE-2023-12345'], 'threat_level': 'medium'},
        {'mac': '4C:75:25:A1:B2:C3', 'name': 'AirPods Pro', 'manufacturer': 'Apple', 'rssi': -38,
         'first_seen': datetime.now() - timedelta(minutes=15), 'last_seen': datetime.now(),
         'vulnerabilities': [], 'threat_level': 'low'},
        {'mac': '00:E0:4C:D4:E5:F6', 'name': 'Unknown Device', 'manufacturer': 'Realtek', 'rssi': -52,
         'first_seen': datetime.now() - timedelta(minutes=5), 'last_seen': datetime.now(),
         'vulnerabilities': ['CVE-2021-28139', 'Potential BrakTooth'], 'threat_level': 'high'},
    ]
    
    threats = [
        {'timestamp': datetime.now() - timedelta(minutes=10), 'type': 'KNOB', 'level': 'critical',
         'source': '00:E0:4C:D4:E5:F6', 'confidence': 0.95,
         'description': 'Encryption key negotiation downgrade detected'},
        {'timestamp': datetime.now() - timedelta(minutes=25), 'type': 'Pairing Flood', 'level': 'high',
         'source': '00:1A:7D:DA:71:13', 'confidence': 0.82,
         'description': 'Multiple pairing requests in short time window'},
    ]
    
    return devices, threats

def main():
    st.markdown('<h1 class="main-header">🛡️ Bluetooth Security Monitor</h1>', unsafe_allow_html=True)
    st.markdown("### Educational Demo - Blue Team Defense Tool")
    st.markdown("---")
    
    with st.sidebar:
        st.title("Control Panel")
        st.subheader("📡 Monitoring")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("▶️ Start Demo"):
                st.session_state.monitoring_active = True
                st.session_state.devices, st.session_state.threats = generate_demo_data()
                st.success("Demo started!")
        
        with col2:
            if st.button("🔄 Reset"):
                st.session_state.devices = []
                st.session_state.threats = []
                st.session_state.monitoring_active = False
                st.success("Reset!")
        
        st.markdown("---")
        st.subheader("⚙️ Detection Rules")
        
        for rule in st.session_state.detection_rules:
            st.session_state.detection_rules[rule] = st.checkbox(
                rule.replace('_', ' ').title(),
                value=st.session_state.detection_rules[rule]
            )
        
        st.markdown("---")
        st.caption("v1.0 | Educational Tool")
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("🔍 Devices", len(st.session_state.devices))
    with col2:
        st.metric("⚠️ Threats", len(st.session_state.threats))
    with col3:
        critical = len([t for t in st.session_state.threats if t.get('level') == 'critical'])
        st.metric("🚨 Critical", critical)
    with col4:
        vuln = len([d for d in st.session_state.devices if d.get('vulnerabilities')])
        st.metric("🔓 Vulnerable", vuln)
    
    st.markdown("---")
    
    tab1, tab2, tab3 = st.tabs(["📊 Dashboard", "🔍 Devices", "⚠️ Threats"])
    
    with tab1:
        if st.session_state.monitoring_active:
            st.subheader("Recent Activity")
            for threat in st.session_state.threats:
                st.markdown(f"""
                <div class="threat-{threat['level']}">
                    <strong>{threat['type']}</strong> - {threat['level'].upper()}<br>
                    <small>{threat['description']}</small>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("Click 'Start Demo' to begin")
    
    with tab2:
        if st.session_state.devices:
            for device in st.session_state.devices:
                with st.expander(f"{device['name']} ({device['mac']})"):
                    st.write(f"**Manufacturer:** {device['manufacturer']}")
                    st.write(f"**RSSI:** {device['rssi']} dBm")
                    if device['vulnerabilities']:
                        st.warning(f"**Vulnerabilities:** {', '.join(device['vulnerabilities'])}")
        else:
            st.info("No devices detected")
    
    with tab3:
        if st.session_state.threats:
            for threat in st.session_state.threats:
                with st.expander(f"{threat['type']} - {threat['level'].upper()}"):
                    st.write(f"**Source:** {threat['source']}")
                    st.write(f"**Confidence:** {threat['confidence']*100:.0f}%")
                    st.write(f"**Description:** {threat['description']}")
        else:
            st.success("No threats detected")

if __name__ == "__main__":
    main()
