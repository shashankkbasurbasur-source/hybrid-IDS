"""
Threat Intelligence Page
Detailed threat analysis and recommendations
"""

import streamlit as st
from backend.dashboard.data_service import dashboard_data_service


def show():
    """Display threat intelligence"""
    
    st.header("🎯 Threat Intelligence")
    
    st.markdown("""
    Detailed threat analysis powered by MITRE ATT&CK framework.
    Select an incident to view threat intelligence report.
    """)
    
    st.markdown("---")
    
    # ==================== INCIDENT SELECTOR ====================
    
    incidents = dashboard_data_service.get_incidents(100)
    
    if not incidents:
        st.info("No incidents to analyze.")
        return
    
    incident_options = {
        f"{i.get('incident_id', '')[:8]} - {i.get('attack_type')}": i.get('incident_id')
        for i in incidents
    }
    
    selected = st.selectbox("Select Incident", list(incident_options.keys()))
    
    if not selected:
        return
    
    incident_id = incident_options[selected]
    
    st.markdown("---")
    
    # ==================== THREAT REPORT ====================
    
    threat_report = dashboard_data_service.get_threat_report(incident_id)
    
    if not threat_report:
        st.warning("Threat intelligence report not available for this incident.")
        return
    
    # Attack Info
    st.subheader("🎯 Attack Information")
    
    attack = threat_report.get("attack", {})
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.write(f"**Type:** {attack.get('type')}")
        st.write(f"**Category:** {attack.get('category')}")
    
    with col2:
        st.write(f"**Severity:** {attack.get('severity')}")
        st.write(f"**Decision:** {attack.get('decision')}")
    
    with col3:
        mitre = attack.get('mitre', {})
        st.write(f"**MITRE:** {', '.join(mitre.get('techniques', []))}")
    
    st.markdown(f"\n{attack.get('description')}")
    
    st.markdown("---")
    
    # ==================== ATTACK LIFECYCLE ====================
    
    st.subheader("🔄 Attack Lifecycle")
    
    lifecycle = threat_report.get("lifecycle", {})
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write(f"**Current Stage:** {lifecycle.get('current_stage')}")
        st.write(f"{lifecycle.get('stage_description')}")
    
    with col2:
        if lifecycle.get('next_likely_stage'):
            st.write(f"**Next Likely Stage:** {lifecycle.get('next_likely_stage')}")
    
    st.markdown("---")
    
    # ==================== INDICATORS ====================
    
    st.subheader("🔎 Indicators of Compromise (IOCs)")
    
    iocs = threat_report.get("iocs", {})
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Network IOCs:**")
        for ioc in iocs.get("network", []):
            st.write(f"• {ioc.get('type')}: `{ioc.get('value')}`")
    
    with col2:
        st.write("**Host IOCs:**")
        for ioc in iocs.get("host", []):
            st.write(f"• {ioc.get('type')}: `{ioc.get('value')}`")
    
    st.markdown("---")
    
    # ==================== RISK ASSESSMENT ====================
    
    st.subheader("📊 Risk Assessment")
    
    risk = threat_report.get("risk", {})
    
    col1, col2 = st.columns(2)
    
    with col1:
        overall = risk.get("overall_risk", {})
        st.write(f"**Risk Level:** {overall.get('level')}")
        st.write(f"**Priority:** {overall.get('priority')}")
    
    with col2:
        business = risk.get("business_risk", {})
        st.write(f"**Business Impact:** {business.get('level')}")
        st.write(f"**Impact:** {business.get('impact')}")
    
    st.markdown("---")
    
    # ==================== RESPONSE ====================
    
    st.subheader("🛡️ Recommended Response")
    
    response = threat_report.get("response", {})
    
    if response.get("immediate_actions"):
        st.write("**Immediate Actions:**")
        for action in response["immediate_actions"]:
            st.write(f"• {action}")
    
    if response.get("short_term_actions"):
        st.write("\n**Short-term Actions:**")
        for action in response["short_term_actions"]:
            st.write(f"• {action}")
    
    if response.get("prevention_measures"):
        st.write("\n**Prevention Measures:**")
        for measure in response["prevention_measures"]:
            st.write(f"• {measure}")
    
    st.markdown("---")
    
    # ==================== EXPORT ====================
    
    st.subheader("📥 Export Report")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("📄 Export as JSON"):
            import json
            json_str = json.dumps(threat_report, indent=2)
            st.download_button(
                "Download JSON",
                json_str,
                file_name=f"threat_report_{incident_id[:8]}.json",
                mime="application/json"
            )
    
    with col2:
        if st.button("📊 Export as PDF"):
            st.info("PDF export coming soon")