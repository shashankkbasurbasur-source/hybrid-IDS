"""
Investigation Page
Analyst Workspace: Workflow: Alert -> Investigation Workspace -> Mark Investigated (moves to History & Reports)
"""

import streamlit as st
import pandas as pd
from frontend.dashboard.dashboard_service import svc
from frontend.dashboard.components.cards import metric_card
from frontend.dashboard.components.tables import render_dataframe

def show():
    st.header("🔍 SOC Investigation Workspace")
    st.markdown("Detailed forensic analysis and correlation workspace for selected Alert IDs.")
    st.markdown("---")

    # Get active alerts (incidents) to investigate
    active_alerts = svc.get_incidents(limit=50, status="active")
    
    if not active_alerts:
        st.success("🟢 No active alerts require investigation. All alerts have been triaged!")
        return

    # Select alert dropdown
    options = {a.get("alert_id"): f"{a.get('alert_id')} - {a.get('attack_type')} ({a.get('severity')})" for a in active_alerts if a.get("alert_id")}
    
    selected_id = st.selectbox("Select Alert ID to Investigate", options=list(options.keys()), format_func=lambda x: options[x])

    if selected_id:
        st.markdown("---")
        details = svc.get_incident_detail(selected_id)
        
        if details:
            # Complete Incident Summary Header
            st.subheader(f"📁 Alert Case File: {selected_id}")
            st.info(f"**Complete Incident Summary:** {details.get('incident_summary')}")
            
            # Overview Metrics Row
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                metric_card("Target Host", details.get("dest_ip", "N/A"), "orange")
            with col2:
                metric_card("Source IP", details.get("source_ips", ["N/A"])[0], "red")
            with col3:
                metric_card("Threat Severity", details.get("severity"), "red")
            with col4:
                metric_card("Overall Confidence", f"{details.get('confidence', 0.0):.2%}", "orange")

            st.markdown("---")

            # Evidence columns
            st.subheader("🕵️ Evidence & Forensic Logs")
            
            tab_net, tab_host, tab_auth, tab_sys = st.tabs([
                "🔗 Network Evidence", 
                "🖥️ Host Evidence", 
                "🔐 Authentication Logs", 
                "⚙️ Syscall Logs"
            ])
            
            with tab_net:
                net_ev = details.get("nids_detection", {})
                if net_ev:
                    st.write("**NIDS Anomaly Details:**")
                    st.json(net_ev)
                else:
                    st.write("No direct network anomalies were recorded for this alert.")

            with tab_host:
                host_ev = details.get("hids_detection", {})
                if host_ev:
                    st.write("**HIDS Anomaly Details:**")
                    st.json(host_ev)
                else:
                    st.write("No HIDS status anomalies recorded.")

            with tab_auth:
                auth_ev = details.get("auth_evidence", {})
                if auth_ev:
                    st.write("**Authentication Attempts Details:**")
                    st.json(auth_ev)
                else:
                    st.write("No authentication brute force evidence recorded.")

            with tab_sys:
                sys_ev = details.get("syscall_evidence", {})
                if sys_ev:
                    st.write("**System Call Sequence Violation Details:**")
                    st.json(sys_ev)
                else:
                    st.write("No direct auditd syscall logs matching signature.")

            st.markdown("---")

            # Fusion Reasoning, MITRE, and Confidence Breakdown
            col_left, col_right = st.columns(2)
            with col_left:
                st.subheader("🧠 Fusion Engine Reasoning")
                st.info(details.get("fusion_reasoning"))
                
                st.subheader("🛡️ MITRE ATT&CK Mapping")
                mitre = details.get("mitre_mapping", {})
                st.success(f"**Tactic:** {mitre.get('Tactic')} | **Technique:** {mitre.get('Technique')}")

            with col_right:
                st.subheader("📊 Confidence Score Breakdown")
                breakdown = details.get("confidence_breakdown", {})
                st.write(f"- Network Feature Weight: `{breakdown.get('network_factor', 0):.0%}`")
                st.write(f"- Host Log Feature Weight: `{breakdown.get('host_factor', 0):.0%}`")
                st.write(f"- Threat Intelligence Correlation Weight: `{breakdown.get('threat_intel_factor', 0):.0%}`")

                st.subheader("📋 Recommended SOC Actions")
                for action in details.get("recommended_actions", []):
                    st.warning(f"⚠️ {action}")

            st.markdown("---")
            
            # Timeline & Action
            st.subheader("⏱️ Investigation Timeline")
            # We can mock a simple timeline matching this Alert ID
            timeline_data = [
                {"Timestamp": details.get("created_at"), "Event": "Alert Generated & Sent to Central Queue"},
                {"Timestamp": details.get("updated_at"), "Event": "Fusion Correlation Verified"},
            ]
            render_dataframe(pd.DataFrame(timeline_data), height=120)
            
            st.markdown("---")
            
            # Action button
            notes = st.text_area("Analyst Investigation & Triage Notes", placeholder="Provide final forensic notes...")
            if st.button("Complete Investigation & Archive Report"):
                if notes:
                    svc.mark_investigated(selected_id, notes)
                    st.success(f"Investigation complete for `{selected_id}`. Incident archived to History & Reports.")
                    st.rerun()
                else:
                    st.error("Please provide investigation notes prior to completing triage.")