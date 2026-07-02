"""
HIDS Monitor Page
Host-based intrusion detection view
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from backend.dashboard.data_service import dashboard_data_service
from backend.dashboard.cache_manager import cache_manager


def show():
    """Display HIDS monitoring"""
    
    st.header("🖥️ Host Intrusion Detection (HIDS)")
    
    st.markdown("""
    Real-time authentication and system log monitoring.
    All data comes directly from system authentication logs.
    """)
    
    st.markdown("---")
    
    # ==================== MONITORING STATUS ====================
    
    col1, col2, col3, col4 = st.columns(4)
    
    hids_status = dashboard_data_service.get_hids_status()
    
    with col1:
        st.metric("Status", "🟢 Monitoring" if hids_status.get("is_monitoring") else "⚫ Idle")
    
    with col2:
        st.metric("Events Parsed", f"{hids_status.get('stats', {}).get('events_parsed', 0)}")
    
    with col3:
        st.metric("Active Sessions", f"{hids_status.get('event_builder', {}).get('sessions_active', 0)}")
    
    with col4:
        st.metric("Detections", f"{hids_status.get('stats', {}).get('detections', 0)}")
    
    st.markdown("---")
    
    # ==================== FAILED LOGIN STATS ====================
    
    st.subheader("🔐 Authentication Statistics")
    
    failed_stats = dashboard_data_service.get_failed_login_stats()
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric(
            "Total Sessions",
            failed_stats.get("total_sessions", 0)
        )
    
    with col2:
        st.metric(
            "Failed Logins",
            failed_stats.get("total_failed", 0)
        )
    
    with col3:
        st.metric(
            "Successful Logins",
            failed_stats.get("total_successful", 0)
        )
    
    st.markdown("---")
    
    # ==================== TOP ATTACKERS ====================
    
    st.subheader("🎯 Top Attack Sources")
    
    col1, col2 = st.columns(2)
    
    with col1:
        top_users = failed_stats.get("top_users", [])
        if top_users:
            users, counts = zip(*top_users[:10])
            
            fig = go.Figure(data=[
                go.Bar(
                    y=users,
                    x=counts,
                    orientation='h',
                    marker=dict(color='#ff9800')
                )
            ])
            
            fig.update_layout(
                title="Top Targeted Users",
                xaxis_title="Failed Attempts",
                height=300,
                showlegend=False
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        top_ips = failed_stats.get("top_source_ips", [])
        if top_ips:
            ips, counts = zip(*top_ips[:10])
            
            fig = go.Figure(data=[
                go.Bar(
                    y=ips,
                    x=counts,
                    orientation='h',
                    marker=dict(color='#f44')
                )
            ])
            
            fig.update_layout(
                title="Top Attacking IPs",
                xaxis_title="Attempts",
                height=300,
                showlegend=False
            )
            st.plotly_chart(fig, use_container_width=True)
    
    st.markdown("---")
    
    # ==================== ACTIVE SESSIONS ====================
    
    st.subheader("🔄 Active Authentication Sessions")
    
    sessions = dashboard_data_service.get_active_sessions()
    
    if sessions:
        session_data = []
        for session in sessions[:20]:
            session_data.append({
                "Session ID": session.get("session_id", "")[:8],
                "Source IP": session.get("source_ip"),
                "Users": ", ".join(session.get("users", [])),
                "Failed": session.get("failed_attempts", 0),
                "Successful": session.get("successful_attempts", 0),
                "Duration (s)": int(session.get("duration", 0))
            })
        
        session_df = pd.DataFrame(session_data)
        st.dataframe(session_df, use_container_width=True, hide_index=True)
    else:
        st.info("No active authentication sessions.")
    
    st.markdown("---")
    
    # ==================== HIDS DETECTIONS ====================
    
    st.subheader("🚨 HIDS Detections")
    
    hids_detections = dashboard_data_service.get_hids_detections(20)
    
    if hids_detections:
        det_data = []
        for det in hids_detections[:20]:
            det_data.append({
                "Timestamp": det.get("timestamp", "")[:19],
                "Session ID": det.get("session_id", "")[:8],
                "Attack Type": det.get("attack_type"),
                "Confidence": f"{det.get('confidence', 0):.2%}",
                "Prediction": det.get("prediction")
            })
        
        det_df = pd.DataFrame(det_data)
        st.dataframe(det_df, use_container_width=True, hide_index=True)
    else:
        st.info("No HIDS detections yet.")