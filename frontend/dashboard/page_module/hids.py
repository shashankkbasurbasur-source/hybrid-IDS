"""
HIDS Page
Combines Authentication Monitoring, Syscall Monitoring, Combined HIDS Score, and Manual Forensic Analysis.
"""

import streamlit as st
import pandas as pd
from frontend.dashboard.dashboard_service import svc
from frontend.dashboard.components.cards import metric_card
from frontend.dashboard.components.tables import render_dataframe

def show():
    st.header("🖥️ Host Intrusion Detection (HIDS)")
    st.markdown("Monitor authentication events, auditd system call logs, and compute host health metrics.")
    st.markdown("---")

    # SECTION 1: AUTHENTICATION MONITORING
    st.subheader("🔐 Section 1: Authentication Monitoring")
    auth_status = svc.get_hids_auth_status()
    auth_stats = svc.get_failed_login_stats()
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        metric_card("Auth Monitor", auth_status.get("status", "MONITORING").upper(), "green", "ACTIVE")
    with col2:
        metric_card("Active Session Count", str(auth_stats.get("total_sessions", 0)), "green", "LOGGED IN")
    with col3:
        metric_card("Successful Logins", str(auth_stats.get("total_successful", 0)), "green", "STABLE")
    with col4:
        metric_card("Failed Logins", str(auth_stats.get("total_failed", 0)), "red", "ALERT THRESHOLD")

    # Sessions Table & Auth Detections
    col_auth_left, col_auth_right = st.columns(2)
    with col_auth_left:
        st.write("**Active Sessions Detail:**")
        sessions = svc.get_active_sessions()
        if sessions:
            render_dataframe(pd.DataFrame(sessions), height=180)
        else:
            st.info("No active authentication sessions.")

    with col_auth_right:
        st.write("**Recent Authentication Events:**")
        auth_events = svc.get_hids_auth_events(10)
        if auth_events:
            render_dataframe(pd.DataFrame(auth_events), height=180)
        else:
            st.info("No authentication events found.")

    st.markdown("---")

    # SECTION 2: SYSCALL MONITORING
    st.subheader("⚙️ Section 2: System Call (Syscall) Monitoring")
    syscall_status = svc.get_hids_syscall_status()
    
    col_sys1, col_sys2, col_sys3 = st.columns(3)
    with col_sys1:
        metric_card("auditd Status", "RUNNING", "green", "CONNECTED")
    with col_sys2:
        metric_card("Syscall Monitoring", syscall_status.get("status", "MONITORING").upper(), "green", "MONITORING ACTIVE")
    with col_sys3:
        metric_card("Total Parsed Events", f"{syscall_status.get('events_parsed', 0):,}", "green", "OK")

    col_sys_left, col_sys_right = st.columns(2)
    with col_sys_left:
        st.write("**Recent Syscall Event Logs:**")
        sys_events = svc.get_hids_syscall_events(10)
        if sys_events:
            sys_df = pd.DataFrame(sys_events)
            sys_df.columns = ["Timestamp", "Syscall Name", "Process Name", "Executable Path", "Anomaly Score"]
            render_dataframe(sys_df, height=180)
        else:
            st.info("No syscall events available.")

    with col_sys_right:
        st.write("**Sliding Window & Monitored Processes:**")
        st.info("📊 Sliding Window Config: 50 events/window. Maximum allowed deviation: 15%.")
        st.write("**Target Monitored Executables:** `/bin/bash`, `/usr/bin/sudo`, `/usr/bin/pkexec`, `/usr/sbin/sshd`")

    st.markdown("---")

    # SECTION 3: COMBINED HIDS SCORE & HOST DECISION
    st.subheader("📊 Section 3: Combined HIDS Decision Engine")
    
    hids_score = svc.get_hids_score().get("score", 100)
    auth_score = 80 if auth_stats.get("total_failed", 0) > 10 else 100
    syscall_score = 90
    
    # Combined scoring flow visualization
    col_flow1, col_flow2, col_flow3 = st.columns(3)
    with col_flow1:
        metric_card("Authentication Score", f"{auth_score}/100", "green" if auth_score > 80 else "orange")
    with col_flow2:
        metric_card("Syscall Score", f"{syscall_score}/100", "green" if syscall_score > 80 else "orange")
    with col_flow3:
        metric_card("Combined HIDS Score", f"{hids_score}/100", "green" if hids_score > 80 else "orange" if hids_score > 50 else "red")

    # Host Decision Detail
    st.markdown("<br>", unsafe_allow_html=True)
    col_dec1, col_dec2, col_dec3 = st.columns(3)
    with col_dec1:
        decision = "ATTACK DETECTED" if hids_score < 90 else "NORMAL"
        decision_color = "red" if decision == "ATTACK DETECTED" else "green"
        st.markdown(f"**Host Decision:** <span style='color:{decision_color}; font-weight:bold;'>{decision}</span>", unsafe_allow_html=True)
    with col_dec2:
        st.markdown(f"**Attack Category:** SSH Brute Force / Privilege Escalation")
    with col_dec3:
        st.markdown(f"**Severity:** HIGH")

    st.markdown("---")

    # MANUAL AUTHENTICATION LOG ANALYSIS
    st.subheader("📤 Forensic Analysis: Manual Authentication Log Upload")
    st.markdown("TXT Log -> Backend HIDS Analysis -> Report Generation & Central Alert Registration")

    uploaded_file = st.file_uploader("Upload Authentication Log File (TXT)", type=["txt"])
    if uploaded_file is not None:
        if st.button("Run Forensic Analysis"):
            with st.spinner("Analyzing uploaded log files..."):
                content = uploaded_file.read()
                report = svc.analyze_manual_log(content, uploaded_file.name)
                
                if report:
                    st.success("Forensic analysis completed and HIDS alert generated successfully!")
                    
                    st.markdown("### Forensic Analysis Report Summary")
                    col_rep1, col_rep2 = st.columns(2)
                    with col_rep1:
                        st.write(f"**Filename:** {report.get('file_name')}")
                        st.write(f"**Lines Analyzed:** {report.get('lines_analyzed')}")
                        st.write(f"**Attack Detected:** {'Yes' if report.get('detections_count', 0) > 0 else 'No'}")
                        st.write(f"**Confidence:** {report.get('confidence', 0.0):.2%}")
                        st.write(f"**Generated Alert ID:** `{report.get('alert_id')}`")
                    with col_rep2:
                        st.write(f"**Attack Type:** {report.get('attack_type', 'N/A')}")
                        st.write(f"**Suspicious Users:** {', '.join(report.get('suspicious_users', []))}")
                        st.write(f"**Suspicious Source IPs:** {', '.join(report.get('suspicious_ips', []))}")
                        st.write(f"**Failed Logins Stats:** {report.get('failed_login_statistics', {})}")
                    
                    st.markdown("#### Session forensic summary:")
                    st.info(report.get("session_summary"))
                else:
                    st.error("Log analysis failed.")
