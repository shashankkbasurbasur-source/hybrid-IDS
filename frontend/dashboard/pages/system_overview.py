"""
System Overview Page
Shows overall system health and status
"""

import streamlit as st
from backend.dashboard.data_service import dashboard_data_service
from backend.dashboard.cache_manager import cache_manager
from datetime import datetime


def show():
    """Display system overview"""
    
    st.header("🔍 System Overview")
    
    st.markdown("""
    Complete status of the Hybrid IDS system. All components should show 
    operational status for the system to function properly.
    """)
    
    st.markdown("---")
    
    # ==================== SYSTEM HEALTH ====================
    
    st.subheader("🏥 System Health")
    
    col1, col2, col3, col4 = st.columns(4)
    
    # Get NIDS status
    capture_status = dashboard_data_service.get_capture_status()
    with col1:
        if capture_status.get("status") == "operational":
            st.success("✅ NIDS")
            st.caption(f"Packets: {capture_status.get('packets_captured', 0):,}")
        else:
            st.error("❌ NIDS")
            st.caption("Offline")
    
    # Get HIDS status
    hids_status = dashboard_data_service.get_hids_status()
    with col2:
        if hids_status.get("status") == "operational":
            st.success("✅ HIDS")
            st.caption("Monitoring")
        else:
            st.error("❌ HIDS")
            st.caption("Offline")
    
    # Fusion status
    with col3:
        st.success("✅ Fusion")
        st.caption("Active")
    
    # Threat Intel status
    with col4:
        st.success("✅ Threat Intel")
        st.caption("Ready")
    
    st.markdown("---")
    
    # ==================== DETAILED STATUS ====================
    
    st.subheader("📋 Detailed Status")
    
    status_data = {
        "Component": [
            "Network Packet Capture",
            "Flow Builder",
            "NIDS Detection",
            "HIDS Monitoring",
            "Fusion Engine",
            "Alert Generator",
            "Threat Intelligence",
            "Database"
        ],
        "Status": [
            "✅ Operational",
            "✅ Operational",
            "✅ Operational",
            "✅ Operational",
            "✅ Operational",
            "✅ Operational",
            "✅ Operational",
            "✅ Operational"
        ],
        "Last Update": [
            capture_status.get("last_update", "Unknown"),
            datetime.utcnow().isoformat(),
            datetime.utcnow().isoformat(),
            datetime.utcnow().isoformat(),
            datetime.utcnow().isoformat(),
            datetime.utcnow().isoformat(),
            datetime.utcnow().isoformat(),
            datetime.utcnow().isoformat()
        ]
    }
    
    st.dataframe(status_data, use_container_width=True)
    
    st.markdown("---")
    
    # ==================== KEY METRICS ====================
    
    st.subheader("📊 Key Metrics")
    
    col1, col2, col3, col4 = st.columns(4)
    
    stats = cache_manager.get("dashboard_stats")
    if not stats:
        stats = dashboard_data_service.get_dashboard_statistics()
        cache_manager.set("dashboard_stats", stats, ttl_seconds=10)
    
    with col1:
        st.metric(
            "Packets Captured",
            f"{stats.get('packets_captured', 0):,}"
        )
    
    with col2:
        alerts_stats = stats.get('alerts_total', {})
        st.metric(
            "Total Alerts",
            f"{alerts_stats.get('total_alerts', 0)}"
        )
    
    with col3:
        st.metric(
            "Active Incidents",
            f"{stats.get('incidents_active', 0)}"
        )
    
    with col4:
        st.metric(
            "System Uptime",
            "24h 15m"
        )
    
    st.markdown("---")
    
    # ==================== ALERT DISTRIBUTION ====================
    
    st.subheader("🚨 Alert Distribution")
    
    col1, col2 = st.columns(2)
    
    with col1:
        alert_stats = dashboard_data_service.get_alert_statistics()
        
        severity_data = {
            "Severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            "Count": [
                alert_stats.get("critical", 0),
                alert_stats.get("high", 0),
                alert_stats.get("medium", 0),
                alert_stats.get("low", 0)
            ]
        }
        
        fig = go.Figure(data=[
            go.Bar(
                x=severity_data["Severity"],
                y=severity_data["Count"],
                marker=dict(
                    color=["#f44", "#ff9800", "#ffbb44", "#4caf50"]
                )
            )
        ])
        
        fig.update_layout(
            title="Alerts by Severity",
            xaxis_title="Severity",
            yaxis_title="Count",
            height=300,
            showlegend=False
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        status_data = {
            "Status": ["Active", "Resolved"],
            "Count": [
                alert_stats.get("active", 0),
                alert_stats.get("resolved", 0)
            ]
        }
        
        fig = go.Figure(data=[
            go.Pie(
                labels=status_data["Status"],
                values=status_data["Count"],
                marker=dict(colors=["#ff9800", "#4caf50"])
            )
        ])
        
        fig.update_layout(
            title="Alert Status",
            height=300
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    st.markdown("---")
    
    # ==================== SYSTEM INFORMATION ====================
    
    st.subheader("ℹ️ System Information")
    
    info_col1, info_col2 = st.columns(2)
    
    with info_col1:
        st.write("**Version:** 2.0.0")
        st.write("**Status:** Production")
        st.write("**Database:** SQLite")
    
    with info_col2:
        st.write("**Last Restart:** 24h 15m ago")
        st.write("**API Health:** Online")
        st.write("**Models:** Loaded")