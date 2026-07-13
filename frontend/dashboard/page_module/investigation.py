"""
Investigation Page
Complete incident investigation workflow
"""

import streamlit as st
from backend.dashboard.data_service import dashboard_data_service


def show():
    """Display investigation workflow"""
    
    st.header("🔬 Incident Investigation")
    
    st.markdown("""
    Complete investigation workflow from detection through threat analysis.
    """)
    
    st.markdown("---")
    
    # ==================== INCIDENT SELECTION ====================
    
    incidents = dashboard_data_service.get_incidents(100)
    
    if not incidents:
        st.info("No incidents to investigate.")
        return
    
    incident_options = {
        f"{i.get('incident_id', '')[:8]} ({i.get('attack_type')})": i.get('incident_id')
        for i in incidents
    }
    
    selected = st.selectbox("Select Incident", list(incident_options.keys()))
    incident_id = incident_options[selected]
    
    st.markdown("---")
    
    # ==================== INVESTIGATION WORKFLOW ====================
    
    # Create tabs for different aspects
    tab1, tab2, tab3, tab4, tab5 = st.tabs(
        ["Incident", "Network Evidence", "Host Evidence", "Fusion Analysis", "Threat Report"]
    )
    
    incident = dashboard_data_service.get_incident_detail(incident_id)
    
    with tab1:
        st.subheader("Incident Summary")
        
        if incident:
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Type", incident.get("attack_type"))
                st.metric("Severity", incident.get("severity"))
            
            with col2:
                st.metric("Status", incident.get("status"))
                st.metric("Confidence", f"{incident.get('confidence', 0):.1%}")
            
            with col3:
                st.metric("Decision", incident.get("decision"))
                st.metric("Domain", incident.get("attack_category"))
            
            st.markdown("---")
            st.write("**Timeline:**")
            
            if incident.get("timeline"):
                for event in incident["timeline"]:
                    st.write(f"**{event.get('timestamp')}** - {event.get('description')}")
    
    with tab2:
        st.subheader("Network Evidence")
        
        if incident and incident.get("nids_detection"):
            nids = incident["nids_detection"]
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**Flow Information**")
                st.write(f"Source IP: `{nids.get('src_ip')}`")
                st.write(f"Destination IP: `{nids.get('dst_ip')}`")
                st.write(f"Protocol: `{nids.get('protocol')}`")
            
            with col2:
                st.write("**Detection**")
                st.write(f"Attack Type: {nids.get('attack_type')}")
                st.write(f"Confidence: {nids.get('confidence'):.1%}")
                st.write(f"Flow ID: `{nids.get('flow_id', 'N/A')[:8]}`")
            
            st.markdown("---")
            st.write("**Flow Statistics**")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Packets", nids.get('packet_count', 0))
            
            with col2:
                st.metric("Bytes", nids.get('byte_count', 0))
            
            with col3:
                st.metric("Duration", f"{nids.get('duration', 0):.2f}s")
        else:
            st.info("No network evidence for this incident.")
    
    with tab3:
        st.subheader("Host Evidence")
        
        if incident and incident.get("hids_detection"):
            hids = incident["hids_detection"]
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**Session Information**")
                st.write(f"Source IP: `{hids.get('source_ip')}`")
                st.write(f"Username: `{hids.get('username')}`")
                st.write(f"Hostname: `{hids.get('hostname')}`")
            
            with col2:
                st.write("**Detection**")
                st.write(f"Attack Type: {hids.get('attack_type')}")
                st.write(f"Confidence: {hids.get('confidence'):.1%}")
                st.write(f"Session ID: `{hids.get('session_id', 'N/A')[:8]}`")
            
            st.markdown("---")
            st.write("**Authentication Events**")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Failed Attempts", hids.get('failed_attempts', 0))
            
            with col2:
                st.metric("Successful Attempts", hids.get('successful_attempts', 0))
            
            with col3:
                st.metric("Duration", f"{hids.get('duration', 0):.0f}s")
        else:
            st.info("No host evidence for this incident.")
    
    with tab4:
        st.subheader("Fusion Analysis")
        
        if incident:
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.write("**Correlation**")
                st.write(f"Correlated: {'Yes' if incident.get('is_correlated') else 'No'}")
                st.write(f"Score: {incident.get('correlation_score', 0):.2%}")
            
            with col2:
                st.write("**Fusion Result**")
                st.write(f"Decision: {incident.get('decision')}")
                st.write(f"Final Score: {incident.get('confidence', 0):.1%}")
            
            with col3:
                st.write("**Sources**")
                triggered = incident.get('triggered_by', [])
                st.write(f"Triggered by: {', '.join(triggered) if triggered else 'Unknown'}")
            
            if incident.get("reasoning"):
                st.markdown("---")
                st.write("**Reasoning**")
                for reason in incident["reasoning"]:
                    st.write(f"• {reason}")
    
    with tab5:
        st.subheader("Threat Intelligence Report")
        
        threat_report = dashboard_data_service.get_threat_report(incident_id)
        
        if threat_report:
            attack = threat_report.get("attack", {})
            
            st.write(f"**Description:** {attack.get('description')}")
            st.write(f"**MITRE Techniques:** {', '.join(attack.get('mitre', {}).get('techniques', []))}")
            
            response = threat_report.get("response", {})
            
            if response.get("immediate_actions"):
                st.markdown("---")
                st.write("**Recommended Immediate Actions:**")
                for action in response["immediate_actions"]:
                    st.write(f"• {action}")
        else:
            st.info("Threat report not available.")