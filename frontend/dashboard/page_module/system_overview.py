"""
System Overview Page
Shows overall health of the Hybrid IDS
"""

import streamlit as st
import pandas as pd
from frontend.dashboard.dashboard_service import svc
from frontend.dashboard.components.cards import metric_card
from frontend.dashboard.components.tables import render_dataframe

def show():
    st.header("🖥️ System Overview")
    st.markdown("---")

    stats = svc.get_dashboard_statistics()

    # Overall system health indicator
    st.subheader("🏥 Overall System Health")
    health_status = stats.get("backend_status", "Operational")
    if health_status == "Operational":
        st.success("🟢 SYSTEM STATE: HEALTHY - All monitoring layers are functioning normally.")
    else:
        st.warning("🟡 SYSTEM STATE: DEGRADED - Some subsystems may not be fully active.")

    st.markdown("---")

    # Quick Statistics Row
    st.subheader("📊 Quick Statistics")
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        metric_card("Total Packets", f"{stats.get('packets_captured', 0):,}", "green", "ACTIVE CAPTURE")
    with col2:
        metric_card("Auth Events", f"{stats.get('total_auth_events', 0):,}", "green", "MONITORING LOGS")
    with col3:
        metric_card("Syscall Events", f"{stats.get('total_syscall_events', 0):,}", "green", "AUDITD LOGGED")
    with col4:
        metric_card("Total Alerts", f"{stats.get('total_alerts', 0)}", "orange", "QUEUED")

    st.markdown("---")

    # Subsystem Health Status Matrix
    st.subheader("📋 Subsystem Health Matrix")
    
    health_data = {
        "Subsystem Component": [
            "Backend Service",
            "Database Connection",
            "REST API Layer",
            "Packet Capture Service (libpcap)",
            "Authentication Log Monitor (HIDS)",
            "Syscall Monitor (auditd)",
            "Decision Fusion Engine",
            "Threat Intelligence Service"
        ],
        "Current Status": [
            f"🟢 {stats.get('backend_status')}",
            f"🟢 {stats.get('database_status')}",
            f"🟢 {stats.get('rest_api_status')}",
            f"🟢 {stats.get('packet_capture_status')}",
            f"🟢 {stats.get('auth_monitoring_status')}",
            f"🟢 {stats.get('syscall_monitoring_status')}",
            f"🟢 {stats.get('fusion_engine_status')}",
            f"🟢 {stats.get('threat_intel_status')}"
        ]
    }
    render_dataframe(pd.DataFrame(health_data), height=280)

    st.markdown("---")

    # Detailed System Metadata
    col_left, col_right = st.columns(2)
    with col_left:
        st.subheader("⚙️ System Configuration Summary")
        st.write(f"**Loaded ML Models:** {', '.join(stats.get('loaded_ml_models', []))}")
        st.write(f"**Monitoring State:** {stats.get('monitoring_state')}")
        st.write(f"**Active System Services:** {', '.join(stats.get('active_services', []))}")
        st.write(f"**System Uptime:** {stats.get('uptime')}")

    with col_right:
        st.subheader("📡 Recent Activity Timeline")
        health = svc.get_health()
        activity = health.get("activity_feed", [])
        if activity:
            activity_df = pd.DataFrame(activity)
            # format columns
            activity_df.columns = ["Timestamp", "Activity Event"]
            render_dataframe(activity_df, height=180)
        else:
            st.info("No activity logged recently.")
