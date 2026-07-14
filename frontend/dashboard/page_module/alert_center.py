"""
Alert Center Page
Central queue for all alerts (NIDS, HIDS, Manual Upload).
No alert should bypass this page.
"""

import streamlit as st
import pandas as pd
from frontend.dashboard.dashboard_service import svc
from frontend.dashboard.components.badges import severity_badge
from frontend.dashboard.components.tables import render_dataframe

def show():
    st.header("🚨 Alert Center (Central SOC Queue)")
    st.markdown("Central queue containing every alert generated anywhere in the system (NIDS, HIDS Authentication, HIDS Syscall, and Forensic Log Uploads).")
    st.markdown("---")

    # Filters Row
    col_f1, col_f2, col_f3 = st.columns(3)
    with col_f1:
        status_filter = st.selectbox("Filter Status", ["active", "investigated", "all"], index=0)
    with col_f2:
        source_filter = st.selectbox("Filter Detection Source", ["All Sources", "NIDS Flow", "HIDS Authentication", "HIDS Syscall", "Uploaded Authentication Log"], index=0)
    with col_f3:
        limit = st.slider("Max Display Limit", 10, 100, 50)

    st.markdown("---")
    
    # We fetch alerts from dashboard service
    alerts = svc.get_incidents(limit=limit, status=status_filter)

    # Filter by detection source if selected
    if source_filter != "All Sources":
        alerts = [a for a in alerts if a.get("detection_source") == source_filter]

    if alerts:
        data = []
        for a in alerts:
            data.append({
                "Alert ID": a.get("alert_id"),
                "Timestamp": a.get("timestamp", a.get("created_at", ""))[:19],
                "Source IP": a.get("source"),
                "Dest IP": a.get("dest_ip", "10.0.0.5"),
                "Severity": a.get("severity", "MEDIUM"),
                "Confidence Score": f"{a.get('confidence', 0.0):.2%}",
                "Attack Type": a.get("attack_type", "Unknown"),
                "Detection Source": a.get("detection_source", "Unknown"),
                "Status": "INVESTIGATED" if a.get("alert_id") in svc.investigated_ids else "OPEN"
            })
            
        df = pd.DataFrame(data)
        render_dataframe(df)
        
        st.markdown("<br>", unsafe_allow_html=True)
        st.info("💡 **Operator Tip:** Copy any Alert ID from the table above and head to the **Investigation** page to review logs and mark the alert as Investigated.")
    else:
        st.success("🟢 Central Queue Clear. No active alerts found matching the active filters.")
