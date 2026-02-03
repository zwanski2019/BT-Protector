"""
Bluetooth Attack Detection System - Web Interface
A comprehensive Streamlit dashboard for Bluetooth security monitoring

Features:
- Real-time Bluetooth security monitoring dashboard
- Snowflake integration for data persistence
- Device profiling and threat detection visualization

Requirements:
    pip install streamlit plotly pandas snowflake-connector-python snowflake-sqlalchemy

Usage:
    streamlit run app.py
"""

import sys
import os
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Optional, Any
import json

# Try to import optional dependencies with graceful fallbacks
STREAMLIT_AVAILABLE = False
PANDAS_AVAILABLE = False
PLOTLY_AVAILABLE = False
SNOWFLAKE_AVAILABLE = False
SQLALCHEMY_AVAILABLE = False

try:
    import streamlit as st
    STREAMLIT_AVAILABLE = True
except ImportError:
    pass

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    pass

try:
    import plotly.express as px
    import plotly.graph_objects as go
    PLOTLY_AVAILABLE = True
except ImportError:
    pass

try:
    import snowflake.connector
    from snowflake.connector import errors as sf_errors
    SNOWFLAKE_AVAILABLE = True
except ImportError:
    pass

try:
    from sqlalchemy import create_engine, text
    from sqlalchemy.exc import SQLAlchemyError
    SQLALCHEMY_AVAILABLE = True
except ImportError:
    pass


class SnowflakeClient:
    """Client for Snowflake database operations"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.connection = None
        self.engine = None
        
    def connect(self) -> bool:
        """Establish connection to Snowflake"""
        if not SNOWFLAKE_AVAILABLE or not SQLALCHEMY_AVAILABLE:
            return False
            
        try:
            # Using SQLAlchemy for better compatibility
            conn_str = (
                f"snowflake://{self.config.get('user')}:{self.config.get('password')}"
                f"@{self.config.get('account')}/{self.config.get('database')}"
                f"/{self.config.get('schema', 'PUBLIC')}"
            )
            self.engine = create_engine(conn_str)
            self.connection = self.engine.connect()
            return True
        except Exception as e:
            print(f"Snowflake connection failed: {e}")
            return False
            
    def disconnect(self):
        """Close Snowflake connection"""
        if self.connection:
            self.connection.close()
        if self.engine:
            self.engine.dispose()
    
    def save_device(self, device_data: Dict[str, Any]) -> bool:
        """Save device information to Snowflake"""
        if not self.connection:
            return False
            
        try:
            query = text("""
                INSERT INTO BT_PROTECTOR_DEVICES 
                (mac_address, name, manufacturer, rssi, first_seen, last_seen, 
                 vulnerabilities, threat_level, created_at)
                VALUES (:mac, :name, :manufacturer, :rssi, :first_seen, :last_seen,
                        :vulnerabilities, :threat_level, :created_at)
            """)
            self.connection.execute(query, {
                'mac': device_data.get('mac'),
                'name': device_data.get('name'),
                'manufacturer': device_data.get('manufacturer'),
                'rssi': device_data.get('rssi'),
                'first_seen': device_data.get('first_seen'),
                'last_seen': device_data.get('last_seen'),
                'vulnerabilities': json.dumps(device_data.get('vulnerabilities', [])),
                'threat_level': device_data.get('threat_level'),
                'created_at': datetime.now()
            })
            self.connection.commit()
            return True
        except Exception as e:
            print(f"Error saving device: {e}")
            return False
    
    def save_threat(self, threat_data: Dict[str, Any]) -> bool:
        """Save threat information to Snowflake"""
        if not self.connection:
            return False
            
        try:
            query = text("""
                INSERT INTO BT_PROTECTOR_THREATS
                (timestamp, attack_type, threat_level, source_device, 
                 target_device, confidence, description, details, created_at)
                VALUES (:timestamp, :attack_type, :threat_level, :source_device,
                        :target_device, :confidence, :description, :details, :created_at)
            """)
            self.connection.execute(query, {
                'timestamp': threat_data.get('timestamp'),
                'attack_type': threat_data.get('type'),
                'threat_level': threat_data.get('level'),
                'source_device': threat_data.get('source'),
                'target_device': threat_data.get('target'),
                'confidence': threat_data.get('confidence'),
                'description': threat_data.get('description'),
                'details': json.dumps(threat_data.get('details', {})),
                'created_at': datetime.now()
            })
            self.connection.commit()
            return True
        except Exception as e:
            print(f"Error saving threat: {e}")
            return False
    
    def get_devices(self) -> List[Dict]:
        """Retrieve devices from Snowflake"""
        if not self.connection:
            return []
            
        try:
            query = text("SELECT * FROM BT_PROTECTOR_DEVICES ORDER BY last_seen DESC")
            result = self.connection.execute(query)
            devices = []
            for row in result:
                devices.append({
                    'mac': row[0],
                    'name': row[1],
                    'manufacturer': row[2],
                    'rssi': row[3],
                    'first_seen': row[4],
                    'last_seen': row[5],
                    'vulnerabilities': json.loads(row[6]) if row[6] else [],
                    'threat_level': row[7]
                })
            return devices
        except Exception as e:
            print(f"Error retrieving devices: {e}")
            return []
    
    def get_threats(self) -> List[Dict]:
        """Retrieve threats from Snowflake"""
        if not self.connection:
            return []
            
        try:
            query = text("SELECT * FROM BT_PROTECTOR_THREATS ORDER BY timestamp DESC")
            result = self.connection.execute(query)
            threats = []
            for row in result:
                threats.append({
                    'timestamp': row[0],
                    'type': row[1],
                    'level': row[2],
                    'source': row[3],
                    'target': row[4],
                    'confidence': row[5],
                    'description': row[6],
                    'details': json.loads(row[7]) if row[7] else {}
                })
            return threats
        except Exception as e:
            print(f"Error retrieving threats: {e}")
            return []
    
    def get_statistics(self) -> Dict:
        """Get statistics from Snowflake"""
        if not self.connection:
            return {}
            
        try:
            stats = {}
            
            # Device count
            query = text("SELECT COUNT(*) FROM BT_PROTECTOR_DEVICES")
            result = self.connection.execute(query)
            stats['total_devices'] = result.fetchone()[0]
            
            # Threat count
            query = text("SELECT COUNT(*) FROM BT_PROTECTOR_THREATS")
            result = self.connection.execute(query)
            stats['total_threats'] = result.fetchone()[0]
            
            # Critical threats
            query = text("SELECT COUNT(*) FROM BT_PROTECTOR_THREATS WHERE threat_level = 'critical'")
            result = self.connection.execute(query)
            stats['critical_threats'] = result.fetchone()[0]
            
            return stats
        except Exception as e:
            print(f"Error getting statistics: {e}")
            return {}


def load_config() -> Dict[str, Any]:
    """Load configuration from config.toml"""
    config = {
        'snowflake': {
            'account': os.environ.get('SNOWFLAKE_ACCOUNT', ''),
            'user': os.environ.get('SNOWFLAKE_USER', ''),
            'password': os.environ.get('SNOWFLAKE_PASSWORD', ''),
            'database': os.environ.get('SNOWFLAKE_DATABASE', 'BT_PROTECTOR'),
            'schema': os.environ.get('SNOWFLAKE_SCHEMA', 'PUBLIC'),
            'warehouse': os.environ.get('SNOWFLAKE_WAREHOUSE', 'COMPUTE_WH')
        }
    }
    
    # Try to read from config.toml if available
    config_path = os.path.join(os.path.dirname(__file__), 'config.toml')
    if os.path.exists(config_path):
        try:
            import toml
            with open(config_path, 'r') as f:
                toml_config = toml.load(f)
                if 'snowflake' in toml_config:
                    config['snowflake'].update(toml_config['snowflake'])
        except Exception as e:
            print(f"Warning: Could not load config.toml: {e}")
    
    return config


def check_dependencies() -> bool:
    """Check if all required dependencies are installed"""
    if not STREAMLIT_AVAILABLE:
        print("ERROR: streamlit is not installed.")
        print("Please install required packages:")
        print("  pip install streamlit plotly pandas")
        print("  pip install snowflake-connector-python snowflake-sqlalchemy")
        return False
    return True


def generate_demo_data():
    """Generate demo data for demonstration"""
    now = datetime.now()
    devices = [
        {
            'mac': '00:1A:7D:DA:71:13', 
            'name': 'Sony WH-1000XM4', 
            'manufacturer': 'Sony', 
            'rssi': -45,
            'first_seen': now - timedelta(minutes=30), 
            'last_seen': now,
            'vulnerabilities': ['CVE-2023-12345'], 
            'threat_level': 'medium'
        },
        {
            'mac': '4C:75:25:A1:B2:C3', 
            'name': 'AirPods Pro', 
            'manufacturer': 'Apple', 
            'rssi': -38,
            'first_seen': now - timedelta(minutes=15), 
            'last_seen': now,
            'vulnerabilities': [], 
            'threat_level': 'low'
        },
        {
            'mac': '00:E0:4C:D4:E5:F6', 
            'name': 'Unknown Device', 
            'manufacturer': 'Realtek', 
            'rssi': -52,
            'first_seen': now - timedelta(minutes=5), 
            'last_seen': now,
            'vulnerabilities': ['CVE-2021-28139', 'Potential BrakTooth'], 
            'threat_level': 'high'
        },
    ]
    
    threats = [
        {
            'timestamp': now - timedelta(minutes=10), 
            'type': 'KNOB', 
            'level': 'critical',
            'source': '00:E0:4C:D4:E5:F6', 
            'confidence': 0.95,
            'description': 'Encryption key negotiation downgrade detected'
        },
        {
            'timestamp': now - timedelta(minutes=25), 
            'type': 'Pairing Flood', 
            'level': 'high',
            'source': '00:1A:7D:DA:71:13', 
            'confidence': 0.82,
            'description': 'Multiple pairing requests in short time window'
        },
    ]
    
    return devices, threats


def run_demo_mode():
    """Run a simple demo without Streamlit UI"""
    print("=" * 60)
    print("🛡️ Bluetooth Security Monitor - Demo Mode")
    print("=" * 60)
    print("\nThis is a demo of the Bluetooth Attack Detection System.")
    print("For the full web interface, install dependencies and run:")
    print("  pip install streamlit plotly pandas snowflake-connector-python")
    print("  streamlit run app.py")
    print("\n" + "-" * 60)
    print("Demo Data:")
    print("-" * 60)
    
    devices, threats = generate_demo_data()
    
    print(f"\n📊 Devices Detected: {len(devices)}")
    for device in devices:
        print(f"  - {device['name']} ({device['mac']}) - {device['manufacturer']}")
    
    print(f"\n⚠️ Threats Found: {len(threats)}")
    for threat in threats:
        print(f"  - [{threat['level'].upper()}] {threat['type']}: {threat['description']}")
    
    print("\n" + "=" * 60)
    print("Demo completed. Install streamlit for the full dashboard!")
    print("=" * 60)


def main():
    """Main Streamlit application"""
    if not STREAMLIT_AVAILABLE:
        run_demo_mode()
        return
    
    # Check if we're in demo mode (no browser)
    config = load_config()
    
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
    if 'snowflake_client' not in st.session_state:
        st.session_state.snowflake_client = None
    if 'snowflake_connected' not in st.session_state:
        st.session_state.snowflake_connected = False

    def start_monitoring():
        st.session_state.monitoring_active = True
        st.session_state.devices, st.session_state.threats = generate_demo_data()
        
        # Try to connect to Snowflake
        if SNOWFLAKE_AVAILABLE and SQLALCHEMY_AVAILABLE:
            sf_config = config.get('snowflake', {})
            if sf_config.get('account') and sf_config.get('user'):
                client = SnowflakeClient(sf_config)
                if client.connect():
                    st.session_state.snowflake_client = client
                    st.session_state.snowflake_connected = True
                    # Save demo data to Snowflake
                    for device in st.session_state.devices:
                        client.save_device(device)
                    for threat in st.session_state.threats:
                        client.save_threat(threat)
        
        st.success("Demo started! " + 
                  ("✅ Snowflake connected" if st.session_state.snowflake_connected else "❌ Snowflake not configured"))

    def reset_monitoring():
        st.session_state.devices = []
        st.session_state.threats = []
        st.session_state.monitoring_active = False
        if st.session_state.snowflake_client:
            st.session_state.snowflake_client.disconnect()
        st.session_state.snowflake_client = None
        st.session_state.snowflake_connected = False
        st.success("Reset!")

    st.markdown('<h1 class="main-header">🛡️ Bluetooth Security Monitor</h1>', unsafe_allow_html=True)
    st.markdown("### Educational Demo - Blue Team Defense Tool")
    st.markdown("---")
    
    with st.sidebar:
        st.title("Control Panel")
        st.subheader("📡 Monitoring")
        
        col1, col2 = st.columns(2)
        with col1:
            st.button("▶️ Start Demo", on_click=start_monitoring, use_container_width=True)
        
        with col2:
            st.button("🔄 Reset", on_click=reset_monitoring, use_container_width=True)
        
        st.markdown("---")
        st.subheader("⚙️ Detection Rules")
        
        for rule in st.session_state.detection_rules:
            st.session_state.detection_rules[rule] = st.checkbox(
                rule.replace('_', ' ').title(),
                value=st.session_state.detection_rules[rule]
            )
        
        st.markdown("---")
        st.subheader("☁️ Snowflake Integration")
        
        if SNOWFLAKE_AVAILABLE and SQLALCHEMY_AVAILABLE:
            if st.session_state.snowflake_connected:
                st.success("✅ Connected to Snowflake")
            else:
                st.info("Configure Snowflake via environment variables:")
                st.code("""
export SNOWFLAKE_ACCOUNT=your_account
export SNOWFLAKE_USER=your_user
export SNOWFLAKE_PASSWORD=your_password
export SNOWFLAKE_DATABASE=BT_PROTECTOR
                """)
        else:
            st.warning("Snowflake packages not installed")
            st.code("pip install snowflake-connector-python snowflake-sqlalchemy")
        
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
                
            # Add charts if plotly is available
            if PLOTLY_AVAILABLE and PANDAS_AVAILABLE:
                st.markdown("### Threat Distribution")
                threat_df = pd.DataFrame(st.session_state.threats)
                if not threat_df.empty:
                    fig = px.pie(threat_df, names='level', title='Threats by Level')
                    st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Click 'Start Demo' to begin monitoring")
            st.markdown("""
            ### Getting Started
            
            This Bluetooth Security Monitor helps you:
            
            1. **Detect Threats** - Monitor for KNOB, BIAS, BrakTooth, and other Bluetooth attacks
            2. **Profile Devices** - Track discovered Bluetooth devices
            3. **Visualize Data** - See threat patterns and device distributions
            4. **Store in Snowflake** - Persist data for analysis
            
            Click **Start Demo** to see it in action!
            """)
    
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

