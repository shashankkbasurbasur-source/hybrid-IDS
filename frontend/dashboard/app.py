"""
Hybrid IDS Dashboard
Professional SOC-style interface
"""

import streamlit as st
from pathlib import Path
import sys

# Add backend to path just in case, but no direct logic imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from frontend.dashboard.dashboard_service import svc
from frontend.dashboard.components.theme import apply_theme

# ==================== PAGE CONFIGURATION ====================

st.set_page_config(
    page_title="Hybrid IDS - SOC Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==================== STYLING ====================

apply_theme()

# ==================== SESSION STATE ====================

if "selected_alert" not in st.session_state:
    st.session_state.selected_alert = None

if "auto_refresh" not in st.session_state:
    st.session_state.auto_refresh = True

if "manual_alerts" not in st.session_state:
    st.session_state.manual_alerts = []

# ==================== SIDEBAR ====================

with st.sidebar:
    st.markdown("<h1 style='color: #3b82f6; font-size: 24px; margin-bottom: 0px;'>🛡️ HYBRID IDS</h1>", unsafe_allow_html=True)
    st.markdown("<p style='color: #64748b; font-size: 12px; margin-top: 0px;'>SECURITY OPERATIONS CENTER</p>", unsafe_allow_html=True)
    st.markdown("---")
    
    # Navigation
    page = st.radio(
        "Navigation",
        [
            "1. System Overview",
            "2. Network Intrusion Detection (NIDS)",
            "3. Host Intrusion Detection (HIDS)",
            "4. Fusion Analysis",
            "5. Alert Center",
            "6. Investigation",
            "7. Threat Intelligence",
            "8. History & Reports"
        ],
        key="page_selection"
    )
    
    st.markdown("---")
    
    # Settings
    st.subheader("⚙️ Settings")
    
    auto_refresh = st.checkbox("Auto Refresh", value=True)
    refresh_interval = st.select_slider(
        "Refresh (sec)",
        options=[1, 2, 5, 10],
        value=5
    )
    
    st.markdown("---")
    
    # Quick Stats
    st.subheader("📊 System Stats")
    stats = svc.get_dashboard_statistics()
    
    st.metric("Total Packets", f"{stats.get('packets_captured', 0):,}")
    st.metric("Central Alerts Queue", f"{stats.get('alerts_total', {}).get('total_alerts', 0)}")

# ==================== PAGE ROUTING ====================

if page == "1. System Overview":
    from frontend.dashboard.page_module import system_overview
    system_overview.show()

elif page == "2. Network Intrusion Detection (NIDS)":
    from frontend.dashboard.page_module import nids_monitor
    nids_monitor.show()

elif page == "3. Host Intrusion Detection (HIDS)":
    from frontend.dashboard.page_module import hids
    hids.show()

elif page == "4. Fusion Analysis":
    # Let's create page_module/fusion_analysis.py if it doesn't exist
    from frontend.dashboard.page_module import fusion_analysis
    fusion_analysis.show()

elif page == "5. Alert Center":
    from frontend.dashboard.page_module import alert_center
    alert_center.show()

elif page == "6. Investigation":
    from frontend.dashboard.page_module import investigation
    investigation.show()

elif page == "7. Threat Intelligence":
    from frontend.dashboard.page_module import threat_intelligence
    threat_intelligence.show()

elif page == "8. History & Reports":
    from frontend.dashboard.page_module import history
    history.show()

# ==================== AUTO REFRESH ====================

if auto_refresh:
    import time
    time.sleep(refresh_interval)
    st.rerun()