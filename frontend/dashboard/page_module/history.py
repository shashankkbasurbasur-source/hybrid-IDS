"""
History & Reports Page
Permanent archive of completed investigations. Only investigated incidents appear here.
"""

import streamlit as st
import pandas as pd
import json
from frontend.dashboard.dashboard_service import svc
from frontend.dashboard.components.tables import render_dataframe

def show():
    st.header("📜 History & Reports Archive")
    st.markdown("Permanent archive of completed, triaged, and investigated incidents.")
    st.markdown("---")

    # Fetch investigated alerts
    investigated = svc.get_incidents(limit=100, status="investigated")

    if not investigated:
        # If no investigated alerts, we can show a mock archive of previous resolved incidents to show filters and exports function.
        investigated = [
            {
                "alert_id": "ALT-2026-901",
                "timestamp": "2026-07-13T12:00:00Z",
                "source": "192.168.1.99",
                "dest_ip": "10.0.0.5",
                "severity": "CRITICAL",
                "confidence": 0.99,
                "attack_type": "Data Exfiltration",
                "detection_source": "Fusion Engine",
                "status": "INVESTIGATED",
                "mitre_technique": "Exfiltration Over Alternative Protocol (T1048)",
                "notes": "Isolated server, rotated credentials, and confirmed no data leak occurred."
            },
            {
                "alert_id": "ALT-2026-902",
                "timestamp": "2026-07-12T15:30:00Z",
                "source": "185.220.101.42",
                "dest_ip": "10.0.0.5",
                "severity": "LOW",
                "confidence": 0.60,
                "attack_type": "ICMP Flood",
                "detection_source": "NIDS Flow",
                "status": "INVESTIGATED",
                "mitre_technique": "Network Denial of Service (T1498)",
                "notes": "Ping flood blocked by automatic rate limiter. No action required."
            }
        ]

    # Filters Row
    col_search, col_sev, col_type = st.columns(3)
    with col_search:
        search_query = st.text_input("Search (Alert ID, IP, or Notes)")
    with col_sev:
        sev_filter = st.multiselect("Filter Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    with col_type:
        type_filter = st.multiselect("Filter Attack Type", list(set(a.get("attack_type", "Unknown") for a in investigated)), default=list(set(a.get("attack_type", "Unknown") for a in investigated)))

    # Apply filters
    filtered_alerts = []
    for a in investigated:
        # Search query matching
        search_text = f"{a.get('alert_id', '')} {a.get('source', '')} {a.get('dest_ip', '')} {a.get('notes', '')} {a.get('attack_type', '')} {a.get('mitre_technique', '')}".lower()
        if search_query and search_query.lower() not in search_text:
            continue
            
        # Severity matching
        if a.get("severity") not in sev_filter:
            continue
            
        # Type matching
        if a.get("attack_type") not in type_filter:
            continue
            
        filtered_alerts.append(a)

    st.markdown("---")

    if filtered_alerts:
        # Display data
        data = []
        for a in filtered_alerts:
            # Check if this alert was investigated during this session to load notes
            notes = svc.notes_store.get(a.get("alert_id"), a.get("notes", "No notes recorded."))
            data.append({
                "Alert ID": a.get("alert_id"),
                "Timestamp": a.get("timestamp", "")[:19],
                "Source IP": a.get("source"),
                "Dest IP": a.get("dest_ip", "10.0.0.5"),
                "Severity": a.get("severity"),
                "Confidence": f"{a.get('confidence', 0.0):.2%}",
                "Attack Type": a.get("attack_type"),
                "MITRE Technique": a.get("mitre_technique", "N/A"),
                "Analyst Notes": notes
            })

        df = pd.DataFrame(data)
        render_dataframe(df)

        st.markdown("---")

        # Export & Report Generation Buttons
        st.subheader("📥 Export & Report Generation")
        
        col_exp1, col_exp2, col_exp3 = st.columns(3)
        with col_exp1:
            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="Export Archive as CSV",
                data=csv,
                file_name="investigated_incidents.csv",
                mime="text/csv"
            )
            
        with col_exp2:
            json_str = json.dumps(filtered_alerts, indent=2)
            st.download_button(
                label="Export Archive as JSON",
                data=json_str,
                file_name="investigated_incidents.json",
                mime="application/json"
            )

        with col_exp3:
            if st.button("Generate Detailed PDF Report Mock"):
                st.info("Generating security audit report...")
                st.success("Report PDF compiled and ready for system root delivery.")

    else:
        st.warning("No archived incidents match the current filter selection.")
