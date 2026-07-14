"""
Threat Intelligence Page
Contextual threat reports and MITRE ATT&CK mapping for investigated Alert IDs.
"""

import streamlit as st
from frontend.dashboard.dashboard_service import svc
from frontend.dashboard.components.cards import metric_card

def show():
    st.header("🌐 Threat Intelligence & ATT&CK Mapping")
    st.markdown("Contextual intelligence, mapping, risk assessment, and containment recommendations for investigated alerts.")
    st.markdown("---")

    # Get investigated alerts
    investigated_alerts = svc.get_incidents(limit=50, status="investigated")
    
    # We allow selecting from investigated alerts, or typing any Alert ID for lookup
    col_sel1, col_sel2 = st.columns(2)
    with col_sel1:
        if investigated_alerts:
            options = {a.get("alert_id"): f"{a.get('alert_id')} - {a.get('attack_type')}" for a in investigated_alerts if a.get("alert_id")}
            selected_id = st.selectbox("Select Investigated Alert ID for Threat Analysis", options=list(options.keys()), format_func=lambda x: options[x])
        else:
            st.info("No alerts investigated yet. Showing default simulated report.")
            selected_id = "ALT-2026-001"
            
    with col_sel2:
        manual_id = st.text_input("Or Manually Enter Alert ID for lookup")
        if st.button("Lookup Manual ID") and manual_id:
            selected_id = manual_id

    st.markdown("---")

    if selected_id:
        report = svc.get_threat_report(selected_id)
        
        if report:
            st.subheader(f"📑 Threat Intelligence Report: {selected_id}")
            st.markdown(f"**Description:** {report.get('attack_description')}")
            
            st.markdown("---")
            
            # ATT&CK & Lifecycle Grid
            col_mit1, col_mit2 = st.columns(2)
            with col_mit1:
                st.subheader("🛡️ MITRE ATT&CK Mapping")
                st.write(f"**Tactic:** `{report.get('mitre_tactic')}`")
                st.write(f"**Technique:** `{report.get('mitre_technique')}`")
                
            with col_mit2:
                st.subheader("🔁 Attack Lifecycle Stage")
                st.info(report.get("attack_lifecycle"))

            st.markdown("---")

            # Risk Assessment & Actions
            st.subheader("⚡ Risk & Containment Playbook")
            col_play1, col_play2 = st.columns(2)
            
            with col_play1:
                st.markdown("### Risk Assessment")
                st.error(report.get("risk_assessment"))
                
                st.markdown("### Immediate Response Actions")
                st.warning(report.get("immediate_response"))

            with col_play2:
                st.markdown("### Containment Playbook")
                st.info(report.get("containment"))
                
                st.markdown("### Recovery Playbook")
                st.success(report.get("recovery"))

            st.markdown("---")
            
            st.subheader("📋 Long-Term Security Recommendations")
            st.write(report.get("long_term_recommendations"))
        else:
            st.error(f"No threat intelligence record found for Alert ID: `{selected_id}`")