"""
Hybrid IDS Dashboard
Professional SOC-style interface
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import requests
import json
from pathlib import Path
import sys

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from backend.dashboard.data_service import dashboard_data_service
from backend.dashboard.cache_manager import cache_manager

# ==================== PAGE CONFIGURATION ====================

st.set_page_config(
    page_title="Hybrid IDS - SOC Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==================== STYLING ====================

st.markdown("""
    <style>
        .metric-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }
        
        .alert-critical {
            background-color: #fee;
            border-left: 4px solid #f44;
            padding: 10px;
            border-radius: 5px;
        }
        
        .alert-high {
            background-color: #fef3cd;
            border-left: 4px solid #ff9800;
            padding: 10px;
            border-radius: 5px;
        }
        
        .status-operational {
            color: #4caf50;
            font-weight: bold;
        }
        
        .status-offline {
            color: #f44336;
            font-weight: bold;
        }
        
        .flow-diagram {
            text-align: center;
            font-family: monospace;
            background: #f5f5f5;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }
    </style>
""", unsafe_allow_html=True)

# ==================== SESSION STATE ====================

if "selected_incident" not in st.session_state:
    st.session_state.selected_incident = None

if "auto_refresh" not in st.session_state:
    st.session_state.auto_refresh = True

# ==================== SIDEBAR ====================

with st.sidebar:
    st.title("🛡️ Hybrid IDS")
    st.markdown("---")
    
    # Navigation
    page = st.radio(
        "Navigation",
        [
            "System Overview",
            "NIDS Monitor",
            "HIDS Monitor",
            "Fusion Analysis",
            "Alert Center",
            "Threat Intelligence",
            "Investigation",
            "History & Reports"
        ],
        key="page_selection"
    )
    
    st.markdown("---")
    
    # Settings
    st.subheader("⚙️ Settings")
    
    col1, col2 = st.columns(2)
    with col1:
        auto_refresh = st.checkbox("Auto Refresh", value=True)
    with col2:
        refresh_interval = st.select_slider(
            "Refresh (sec)",
            options=[1, 2, 5, 10],
            value=5
        )
    
    st.markdown("---")
    
    # Quick Stats
    st.subheader("📊 Quick Stats")
    
    stats = cache_manager.get("dashboard_stats")
    if not stats:
        stats = dashboard_data_service.get_dashboard_statistics()
        cache_manager.set("dashboard_stats", stats, ttl_seconds=10)
    
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Packets", f"{stats.get('packets_captured', 0):,}")
    with col2:
        alerts_data = stats.get('alerts_total', {})
        st.metric("Total Alerts", f"{alerts_data.get('total_alerts', 0)}")

# ==================== PAGE ROUTING ====================

if page == "System Overview":
    from pages import system_overview
    system_overview.show()

elif page == "NIDS Monitor":
    from pages import nids_monitor
    nids_monitor.show()

elif page == "HIDS Monitor":
    from pages import hids_monitor
    hids_monitor.show()

elif page == "Fusion Analysis":
    from pages import fusion_analysis
    fusion_analysis.show()

elif page == "Alert Center":
    from pages import alert_center
    alert_center.show()

elif page == "Threat Intelligence":
    from pages import threat_intelligence
    threat_intelligence.show()

elif page == "Investigation":
    from pages import investigation
    investigation.show()

elif page == "History & Reports":
    from pages import history_reports
    history_reports.show()

# ==================== AUTO REFRESH ====================

if auto_refresh:
    import time
    time.sleep(refresh_interval)
    st.rerun()