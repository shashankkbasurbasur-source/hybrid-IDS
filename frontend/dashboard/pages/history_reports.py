"""
History & Reports Page
Search, filter, and export historical data
"""

import streamlit as st
import pandas as pd
from backend.dashboard.data_service import dashboard_data_service


def show():
    """Display history and reports"""
    
    st.header("📚 History & Reports")
    
    st.markdown("""
    Search and analyze historical incidents, alerts, and threat reports.
    """)
    
    st.markdown("---")
    
    # ==================== SEARCH & FILTER ====================
    
    st.subheader("🔍 Search & Filter")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        search_type = st.selectbox(
            "Search by",
            ["All", "Source IP", "Username", "Attack Type", "Incident ID"]
        )
    
    with col2:
        search_value = st.text_input("Search value")
    
    with col3:
        if st.button("🔎 Search"):
            st.info(f"Searching {search_type}: {search_value}")
    
    st.markdown("---")
    
    # ==================== INCIDENTS TABLE ====================
    
    st.subheader("📋 Historical Incidents")
    
    incidents = dashboard_data_service.get_incidents(500)
    
    if incidents:
        incident_data = []
        for incident in incidents:
            incident_data.append({
                "Date": incident.get("created_at", "")[:10],
                "Time": incident.get("created_at", "")[-8:],
                "Type": incident.get("attack_type"),
                "Severity": incident.get("severity"),
                "Status": incident.get("status"),
                "Source": incident.get("source_ips", ["?"])[0] if incident.get("source_ips") else "?",
                "Confidence": f"{incident.get('confidence', 0):.0%}"
            })
        
        df = pd.DataFrame(incident_data).tail(100)
        
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No historical incidents.")
    
    st.markdown("---")
    
    # ==================== EXPORT ====================
    
    st.subheader("📥 Export Data")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📄 Export as CSV"):
            if incidents:
                csv_data = pd.DataFrame(incident_data).to_csv(index=False)
                st.download_button(
                    "Download CSV",
                    csv_data,
                    file_name="incidents_history.csv",
                    mime="text/csv"
                )
    
    with col2:
        if st.button("📊 Export as JSON"):
            if incidents:
                import json
                json_str = json.dumps(incidents[:100], indent=2, default=str)
                st.download_button(
                    "Download JSON",
                    json_str,
                    file_name="incidents_history.json",
                    mime="application/json"
                )
    
    with col3:
        if st.button("📑 Generate PDF Report"):
            st.info("PDF report generation coming soon")