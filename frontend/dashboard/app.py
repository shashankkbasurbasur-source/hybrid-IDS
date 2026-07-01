"""
Hybrid IDS SOC Dashboard v2.0
Complete rewrite for professional SOC console experience
"""

import streamlit as st
import requests
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import json
from collections import deque

# Page configuration
st.set_page_config(
    page_title="Hybrid IDS - SOC Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Styling
st.markdown("""
    <style>
        .metric-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            border-radius: 10px;
            color: white;
        }
        .alert-critical {
            background-color: #ff4444;
            color: white;
        }
        .alert-high {
            background-color: #ff8844;
            color: white;
        }
        .alert-medium {
            background-color: #ffbb44;
            color: black;
        }
        .alert-low {
            background-color: #44bb44;
            color: white;
        }
        .status-running {
            color: #44bb44;
            font-weight: bold;
        }
        .status-error {
            color: #ff4444;
            font-weight: bold;
        }
    </style>
""", unsafe_allow_html=True)

# Initialize session state
if "alerts_history" not in st.session_state:
    st.session_state.alerts_history = deque(maxlen=100)

if "packet_stats" not in st.session_state:
    st.session_state.packet_stats = {
        "total": 0,
        "tcp": 0,
        "udp": 0,
        "icmp": 0,
        "arp": 0
    }

if "active_flows" not in st.session_state:
    st.session_state.active_flows = {}

API_URL = "http://127.0.0.1:8000/api/detect"

# ==================== HEADER ====================
st.markdown("# 🛡️ Hybrid IDS - SOC Console v2.0")
st.markdown("Real-Time Network + Host Intrusion Detection")

# ==================== TOP METRICS ====================
col1, col2, col3, col4, col5, col6 = st.columns(6)

with col1:
    st.metric(
        "📊 Total Alerts",
        len(st.session_state.alerts_history),
        delta=f"{len([a for a in st.session_state.alerts_history if a.get('decision') == 'Intrusion'])} Active"
    )

with col2:
    critical_count = len([a for a in st.session_state.alerts_history if a.get('severity') == 'CRITICAL'])
    st.metric("🔴 Critical", critical_count, delta="Active Threats")

with col3:
    high_count = len([a for a in st.session_state.alerts_history if a.get('severity') == 'HIGH'])
    st.metric("🟠 High", high_count)

with col4:
    packets_total = st.session_state.packet_stats['total']
    st.metric("📦 Packets", packets_total, delta="Captured")

with col5:
    flows = len(st.session_state.active_flows)
    st.metric("🔗 Flows", flows, delta="Active")

with col6:
    st.metric("⏱️ Last Update", datetime.now().strftime("%H:%M:%S"))

# ==================== SIDEBAR ====================
with st.sidebar:
    st.header("⚙️ Control Panel")
    
    tab1, tab2, tab3 = st.tabs(["Capture", "Detection", "Settings"])
    
    with tab1:
        st.subheader("Live Packet Capture")
        
        interface = st.text_input("Network Interface", value="eth0", help="e.g., eth0, wlan0")
        capture_duration = st.slider("Capture Duration (s)", 5, 120, 30)
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("▶️ Start Capture", use_container_width=True):
                st.session_state.capturing = True
                st.success("Capture started")
        
        with col2:
            if st.button("⏹️ Stop", use_container_width=True):
                st.session_state.capturing = False
                st.info("Capture stopped")
        
        capture_status = st.empty()
        if getattr(st.session_state, 'capturing', False):
            capture_status.success("🟢 Capturing packets...")
        else:
            capture_status.info("⚪ Ready to capture")
    
    with tab2:
        st.subheader("Detection Settings")
        
        nids_threshold = st.slider("NIDS Threshold", 0.0, 1.0, 0.5, step=0.05)
        hids_threshold = st.slider("HIDS Threshold", 0.0, 1.0, 0.6, step=0.05)
        
        auto_refresh = st.checkbox("Auto Refresh (5s)", value=True)
        
        if st.button("🔄 Refresh Data", use_container_width=True):
            st.rerun()
    
    with tab3:
        st.subheader("System Settings")
        
        log_monitoring = st.checkbox("Enable Log Monitoring", value=True)
        threat_intel = st.checkbox("Enable Threat Intelligence", value=True)
        
        if st.button("🔧 Apply Settings", use_container_width=True):
            st.success("Settings applied")

# ==================== MAIN TABS ====================
tab_dash, tab_capture, tab_alerts, tab_threat = st.tabs(
    ["📊 Dashboard", "📡 Packet Capture", "🚨 Alerts", "🎯 Threat Analysis"]
)

# --- DASHBOARD TAB ---
with tab_dash:
    st.markdown("## System Health Overview")
    
    row1 = st.columns(3)
    
    with row1[0]:
        st.markdown("### NIDS Status")
        nids_status = st.empty()
        nids_status.info("🟢 Operational")
    
    with row1[1]:
        st.markdown("### HIDS Status")
        hids_status = st.empty()
        hids_status.info("🟢 Operational")
    
    with row1[2]:
        st.markdown("### Fusion Engine")
        fusion_status = st.empty()
        fusion_status.info("🟢 Operational")
    
    st.markdown("---")
    st.markdown("## Real-Time Metrics")
    
    # Live metrics
    chart_col1, chart_col2 = st.columns(2)
    
    with chart_col1:
        st.markdown("### Alert Timeline")
        
        # Create timeline data
        alert_times = [
            (a['timestamp'], a['severity']) for a in st.session_state.alerts_history
        ]
        
        if alert_times:
            severity_counts = pd.Series([s for _, s in alert_times]).value_counts()
            
            fig = go.Figure(data=[
                go.Bar(
                    y=severity_counts.index,
                    x=severity_counts.values,
                    orientation='h',
                    marker=dict(
                        color=['#ff4444', '#ff8844', '#ffbb44', '#44bb44']
                    )
                )
            ])
            
            fig.update_layout(
                title="Alerts by Severity",
                xaxis_title="Count",
                yaxis_title="Severity",
                height=300,
                showlegend=False
            )
            
            st.plotly_chart(fig, use_container_width=True)
    
    with chart_col2:
        st.markdown("### Protocol Distribution")
        
        stats = st.session_state.packet_stats
        if stats['total'] > 0:
            fig = go.Figure(data=[
                go.Pie(
                    labels=['TCP', 'UDP', 'ICMP', 'ARP'],
                    values=[stats['tcp'], stats['udp'], stats['icmp'], stats['arp']]
                )
            ])
            
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)
    
    st.markdown("---")
    st.markdown("## Current Threats")
    
    if st.session_state.alerts_history:
        recent_alerts = list(st.session_state.alerts_history)[-10:]
        
        alert_df = pd.DataFrame([
            {
                "Time": a.get("timestamp", "N/A"),
                "Severity": a.get("severity", "N/A"),
                "Attack Type": a.get("attack_type", "N/A"),
                "Score": f"{a.get('score', 0):.3f}",
                "NIDS": f"{a.get('nids_score', 0):.3f}",
                "HIDS": f"{a.get('hids_score', 0):.3f}"
            }
            for a in recent_alerts
        ])
        
        st.dataframe(alert_df, use_container_width=True)
    else:
        st.info("No alerts detected")

# --- PACKET CAPTURE TAB ---
with tab_capture:
    st.markdown("## Live Packet Capture & Analysis")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        packets_to_capture = st.number_input("Packets to Capture", 10, 1000, 100)
    
    with col2:
        timeout_sec = st.number_input("Timeout (s)", 5, 300, 30)
    
    with col3:
        interface = st.text_input("Interface", "eth0")
    
    if st.button("🔴 START LIVE CAPTURE", use_container_width=True, key="start_capture"):
        st.info(f"Capturing {packets_to_capture} packets on {interface}...")
        
        # Simulated capture
        capture_data = {
            "interface": interface,
            "packets_captured": packets_to_capture,
            "duration": timeout_sec,
            "timestamp": datetime.now().isoformat()
        }
        
        st.success(f"✅ Successfully captured {packets_to_capture} packets")
    
    st.markdown("---")
    st.markdown("## Network Statistics")
    
    stat_col1, stat_col2, stat_col3, stat_col4 = st.columns(4)
    
    with stat_col1:
        st.metric("TCP Packets", st.session_state.packet_stats['tcp'])
    
    with stat_col2:
        st.metric("UDP Packets", st.session_state.packet_stats['udp'])
    
    with stat_col3:
        st.metric("ICMP Packets", st.session_state.packet_stats['icmp'])
    
    with stat_col4:
        st.metric("ARP Packets", st.session_state.packet_stats['arp'])
    
    st.markdown("---")
    st.markdown("## Captured Packets")
    
    # Sample packet table
    sample_packets = pd.DataFrame({
        "Time": [datetime.now().isoformat()] * 5,
        "Source IP": ["192.168.1.100", "10.0.0.50", "172.16.0.10", "192.168.1.101", "10.0.0.51"],
        "Destination IP": ["8.8.8.8", "1.1.1.1", "8.8.4.4", "8.8.8.8", "1.1.1.1"],
        "Protocol": ["TCP", "UDP", "TCP", "ICMP", "TCP"],
        "Length": [512, 256, 1024, 64, 768],
        "Port": [443, 53, 80, "-", 22]
    })
    
    st.dataframe(sample_packets, use_container_width=True)

# --- ALERTS TAB ---
with tab_alerts:
    st.markdown("## Active Alerts")
    
    filter_severity = st.multiselect(
        "Filter by Severity",
        ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=["CRITICAL", "HIGH"]
    )
    
    if st.session_state.alerts_history:
        filtered_alerts = [
            a for a in st.session_state.alerts_history
            if a.get("severity") in filter_severity
        ]
        
        for alert in filtered_alerts[-20:]:
            severity = alert.get("severity", "UNKNOWN")
            
            if severity == "CRITICAL":
                color = "🔴"
            elif severity == "HIGH":
                color = "🟠"
            elif severity == "MEDIUM":
                color = "🟡"
            else:
                color = "🟢"
            
            with st.container():
                col1, col2, col3 = st.columns([1, 4, 2])
                
                with col1:
                    st.markdown(f"## {color}")
                
                with col2:
                    st.markdown(f"""
                    **{alert.get('attack_type', 'Unknown')}**
                    
                    Source: {alert.get('source_ip', 'Unknown')} → Dest: {alert.get('destination_ip', 'Unknown')}
                    """)
                
                with col3:
                    st.metric("Score", f"{alert.get('score', 0):.3f}")
                
                st.markdown(f"*{alert.get('timestamp', 'N/A')}* | {alert.get('reason', ['N/A'])[0]}")
                st.divider()
    else:
        st.success("✅ No alerts detected - System normal")

# --- THREAT ANALYSIS TAB ---
with tab_threat:
    st.markdown("## Threat Intelligence Analysis")
    
    if st.session_state.alerts_history:
        latest_alert = list(st.session_state.alerts_history)[-1]
        
        threat_intel = latest_alert.get("threat_intelligence", {})
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown(f"### {threat_intel.get('attack_type', 'Unknown')}")
            st.markdown(f"**MITRE Technique:** {threat_intel.get('mitre_technique', 'N/A')}")
            st.markdown(f"**Category:** {threat_intel.get('category', 'N/A')}")
            st.markdown(f"**Severity:** {threat_intel.get('severity', 'N/A')}")
        
        with col2:
            st.markdown("### Indicators")
            for indicator in threat_intel.get('indicators', []):
                st.markdown(f"• {indicator}")
        
        st.markdown("---")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### Common Tools")
            for tool in threat_intel.get('common_tools', []):
                st.markdown(f"• {tool}")
        
        with col2:
            st.markdown("### Mitigation")
            for mitigation in threat_intel.get('mitigation', []):
                st.markdown(f"• {mitigation}")
        
        st.markdown("---")
        st.markdown(f"**Description:** {threat_intel.get('description', 'N/A')}")
        st.markdown(f"**Impact:** {threat_intel.get('impact', 'N/A')}")
    else:
        st.info("No threat intelligence available yet")

# ==================== AUTO REFRESH ====================
if getattr(st.session_state, 'auto_refresh', False):
    import time
    time.sleep(5)
    st.rerun()