"""
Alert Center Page
Incident management and alert viewing
"""

import streamlit as st
import pandas as pd
from datetime import datetime
from backend.dashboard.data_service import dashboard_data_service


def show():
    """Display alert center"""
    
    st.header("🚨 Alert Center")
    
    st.markdown("""
    Real-time incident management dashboard.
    View, filter, and manage security alerts.
    """)
    
    st.markdown("---")
    
    # ==================== FILTERS ====================
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        severity_filter = st.multiselect(
            "Severity",
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            default=["CRITICAL", "HIGH"]
        )
    
    with col2:
        status_filter = st.multiselect(
            "Status",
            ["active", "acknowledged", "resolved"],
            default=["active"]
        )
    
    with col3:
        limit = st.slider("Show last N alerts", 10, 500, 50)
    
    st.markdown("---")
    
    # ==================== ALERTS TABLE ====================
    
    st.subheader("📋 Active Incidents")
    
    incidents = dashboard_data_service.get_incidents(limit)
    
    if incidents:
        alert_data = []
        for incident in incidents:
            # Apply filters
            if incident.get("severity") not in severity_filter:
                continue
            if incident.get("status") not in status_filter:
                continue
            
            alert_data.append({
                "ID": incident.get("incident_id", "")[:8],
                "Time": incident.get("created_at", "")[:19],
                "Type": incident.get("attack_type"),
                "Severity": incident.get("severity"),
                "Status": incident.get("status"),
                "Confidence": f"{incident.get('confidence', 0):.1%}",
                "Source": incident.get("source_ips", [""])[0] if incident.get("source_ips") else "?"
            })
        
        if alert_data:
            df = pd.DataFrame(alert_data)
            
            # Color severity column - using map() instead of applymap()
            def color_severity(val):
                if val == "CRITICAL":
                    return 'background-color: #ffdddd'
                elif val == "HIGH":
                    return 'background-color: #ffe6cc'
                elif val == "MEDIUM":
                    return 'background-color: #ffffcc'
                return 'background-color: #ccffcc'
            
            df_styled = df.style.map(
                lambda val: color_severity(val) if isinstance(val, str) else "",
                subset=['Severity']
            )
            
            st.dataframe(df_styled, use_container_width=True, hide_index=True)
            
            # Incident detail selector
            st.markdown("---")
            st.subheader("📌 Incident Details")
            
            selected_id = st.selectbox(
                "Select incident to view details",
                [row['ID'] for _, row in df.iterrows()],
                key="incident_selector"
            )
            
            if selected_id:
                # Find full incident ID
                full_id = None
                for incident in incidents:
                    if incident.get("incident_id", "")[:8] == selected_id:
                        full_id = incident.get("incident_id")
                        break
                
                if full_id:
                    show_incident_details(full_id)
        else:
            st.info("No incidents match selected filters.")
    else:
        st.info("No alerts generated yet. Start NIDS/HIDS monitoring to see alerts.")


def show_incident_details(incident_id: str):
    """Show detailed incident information"""
    
    incident = dashboard_data_service.get_incident_detail(incident_id)
    
    if not incident:
        st.error("Incident not found")
        return
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Decision", incident.get("decision"))
    
    with col2:
        st.metric("Severity", incident.get("severity"))
    
    with col3:
        st.metric("Confidence", f"{incident.get('confidence', 0):.1%}")
    
    st.markdown("---")
    
    st.write("**Evidence:**")
    
    # NIDS Evidence
    if incident.get("nids_detection"):
        with st.expander("Network Detection"):
            nids = incident["nids_detection"]
            st.write(f"**Type:** {nids.get('attack_type')}")
            st.write(f"**Source:** {nids.get('src_ip')}")
            st.write(f"**Destination:** {nids.get('dst_ip')}")
            st.write(f"**Confidence:** {nids.get('confidence'):.1%}")
    
    # HIDS Evidence
    if incident.get("hids_detection"):
        with st.expander("Host Detection"):
            hids = incident["hids_detection"]
            st.write(f"**Type:** {hids.get('attack_type')}")
            st.write(f"**Source IP:** {hids.get('source_ip')}")
            st.write(f"**User:** {hids.get('username')}")
            st.write(f"**Failed Attempts:** {hids.get('failed_attempts')}")
            st.write(f"**Confidence:** {hids.get('confidence'):.1%}")
    
    # Reasoning
    if incident.get("reasoning"):
        with st.expander("Detection Reasoning"):
            for reason in incident["reasoning"]:
                st.write(f"• {reason}")
