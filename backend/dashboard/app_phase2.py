"""
backend/dashboard/app_phase2.py

PHASE 2: Enhanced SOC Dashboard
Real-time network monitoring + threat research + attack scenarios

Run with:
  streamlit run backend/dashboard/app_phase2.py --logger.level=error
"""

import requests
import streamlit as st
import pandas as pd
import time
import json

API_BASE = "http://127.0.0.1:8000"

st.set_page_config(
    page_title="Hybrid IDS v2.0 - Network + Host Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""<style>
    .block-container { padding-top: 1rem; }
    .metric-large { font-size: 24px !important; }
</style>""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────────────────────

st.sidebar.title("🛡️ Hybrid IDS v2.0")
st.sidebar.caption("NIDS • HIDS • Fusion • Threat Research")
st.sidebar.divider()

mode = st.sidebar.radio(
    "📊 Operation Mode",
    ["Dashboard", "Packet Capture", "Test Scenarios", "Threat Analysis"]
)

auto_refresh = st.sidebar.checkbox("🔄 Auto-refresh (5s)", value=False)
api_status = requests.get(f"{API_BASE}/health", timeout=2).status_code == 200
st.sidebar.metric("API Status", "🟢 Online" if api_status else "🔴 Offline")

if not api_status:
    st.error("❌ API unreachable. Run: `python backend/app.py`")
    st.stop()

# ─────────────────────────────────────────────────────────────────────────────
# PAGE: DASHBOARD (main monitoring view)
# ─────────────────────────────────────────────────────────────────────────────

if mode == "Dashboard":
    st.title("🔐 Hybrid IDS — SOC Console v2.0")
    st.caption("Real-time Network + Host Intrusion Detection with Threat Analysis")
    st.divider()

    # Fetch recent alerts
    try:
        r = requests.get(f"{API_BASE}/alerts/", params={"limit": 100}, timeout=5)
        alerts = r.json().get("alerts", []) if r.status_code == 200 else []
        stats = requests.get(f"{API_BASE}/alerts/stats", timeout=5).json() if r.status_code == 200 else {}
    except Exception as e:
        st.error(f"Failed to fetch alerts: {e}")
        alerts, stats = [], {}

    # Summary metrics
    col1, col2, col3, col4, col5, col6 = st.columns(6)
    sev = stats.get("by_severity", {})
    dec = stats.get("by_decision", {})
    
    col1.metric("Total Events", stats.get("total", 0))
    col2.metric("🔴 Critical", sev.get("CRITICAL", 0))
    col3.metric("🟠 High", sev.get("HIGH", 0))
    col4.metric("🟡 Medium", sev.get("MEDIUM", 0))
    col5.metric("🟢 Low", sev.get("LOW", 0))
    col6.metric("✅ Normal", dec.get("Normal", 0))

    st.divider()

    # Tabs
    tab1, tab2, tab3, tab4 = st.tabs(["🚨 Alerts", "📡 Network Stats", "🔍 Threat Details", "📊 Dashboard"])

    # ─── Tab 1: Alert Log (FIXED: Real-time, sortable) ────────────────
    with tab1:
        st.subheader("🚨 Alert Log (Real-Time)")
        
        # Severity filter
        col_filter1, col_filter2 = st.columns(2)
        with col_filter1:
            sev_filter = st.selectbox(
                "Filter by Severity",
                ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
                index=0
            )
        with col_filter2:
            alert_limit = st.number_input("Show latest N alerts", 10, 500, 50)
        
        # Filter and prepare data
        filtered_alerts = (
            alerts if sev_filter == "ALL"
            else [a for a in alerts if a.get("severity") == sev_filter]
        )
        filtered_alerts = filtered_alerts[:alert_limit]
        
        if filtered_alerts:
            st.info(f"Showing {len(filtered_alerts)} of {len(alerts)} total alerts")
            
            # Build dataframe
            df_data = []
            for a in filtered_alerts:
                df_data.append({
                    "Time": a.get("timestamp", "")[:19].replace("T", " "),
                    "Severity": a.get("severity", ""),
                    "Decision": a.get("type", ""),
                    "Attack": a.get("attack_type", ""),
                    "NIDS Score": f"{a.get('network_score', 0):.3f}",
                    "HIDS Score": f"{a.get('host_score', 0):.3f}",
                    "Final Score": f"{a.get('confidence', 0):.3f}",
                    "MITRE": a.get("mitre", "N/A")[:20],
                    "Triggered By": a.get("triggered_by", [])
                })
            
            df_alerts = pd.DataFrame(df_data)
            
            # FIXED: Use st.dataframe instead of deprecated display
            st.dataframe(
                df_alerts,
                use_container_width=True,
                hide_index=True,
                height=400
            )
            
            # Show detailed info for latest alert
            if df_data:
                st.divider()
                st.subheader("📋 Latest Alert Details")
                latest = filtered_alerts[0]
                
                col_d1, col_d2, col_d3 = st.columns(3)
                col_d1.metric("Decision", latest.get("type", "?"))
                col_d2.metric("Severity", latest.get("severity", "?"))
                col_d3.metric("Confidence", f"{latest.get('confidence', 0):.4f}")
                
                col_d4, col_d5 = st.columns(2)
                col_d4.write(f"**Attack:** {latest.get('attack_type', 'N/A')}")
                col_d5.write(f"**Domain:** {latest.get('attack_domain', 'N/A')}")
        
        else:
            st.info("ℹ️ No alerts matching filter. Run 'Test Scenarios' to generate alerts.")
    # ─── Tab 2: Network Statistics ───────────────────────────────────────────
    with tab2:
        st.subheader("Network Monitoring")
        col_a, col_b = st.columns(2)
        
        with col_a:
            st.write("**Packet Capture Stats**")
            if st.button("📡 Capture Live Packets (100)", key="cap_btn"):
                with st.spinner("Capturing packets..."):
                    try:
                        r = requests.post(f"{API_BASE}/packets/capture",
                                        json={"packet_count": 100, "timeout": 10}, timeout=15)
                        if r.status_code == 200:
                            result = r.json()
                            st.success(f"Captured {result.get('packets_captured', 0)} packets")
                            st.json(result.get("network_features", {}))
                            
                            det = result.get("detection_result", {})
                            st.write(f"**Detection Result:** {det.get('decision', '?')} "
                                   f"(score: {det.get('final_score', 0):.3f})")
                        else:
                            st.error(f"Capture failed: {r.text}")
                    except Exception as e:
                        st.error(f"Error: {e}")

        with col_b:
            st.write("**Packet Capture History**")
            try:
                r = requests.get(f"{API_BASE}/packets/stats", timeout=5)
                if r.status_code == 200:
                    pstats = r.json()
                    st.metric("Total Packets Captured", pstats.get("total_packets", 0))
                    st.metric("Alerts Generated", pstats.get("alerts_generated", 0))
            except Exception:
                st.info("No packet history yet")

    # ─── Tab 3: Threat Details ──────────────────────────────────────────────
    with tab3:
        st.subheader("Threat Research & Analysis")
        if alerts:
            selected_alert = st.selectbox(
                "Select alert for analysis",
                [f"{a.get('timestamp', '')} - {a.get('attack_type', '')}" for a in alerts[:20]]
            )
            alert_idx = [f"{a.get('timestamp', '')} - {a.get('attack_type', '')}" for a in alerts[:20]].index(selected_alert)
            alert = alerts[alert_idx]
            
            attack_type = alert.get("attack_type", "Suspicious Activity")
            
            # Fetch threat analysis
            try:
                r = requests.get(f"{API_BASE}/threats/analysis/{attack_type}",
                               params={
                                   "attack_domain": alert.get("attack_domain", "Unknown"),
                                   "network_score": alert.get("network_score", 0),
                                   "host_score": alert.get("host_score", 0),
                               }, timeout=5)
                if r.status_code == 200:
                    threat = r.json().get("analysis", {})
                    scenario = threat.get("scenario", {})
                    
                    col_m1, col_m2 = st.columns(2)
                    col_m1.metric("Risk Level", scenario.get("risk_level", "?"))
                    col_m2.metric("Confidence", f"{threat.get('confidence', 0):.2%}")
                    
                    with st.expander("🎯 Attack Description"):
                        st.write(f"**Phase:** {scenario.get('phase', '?')}")
                        st.write(f"**Detection Method:** {scenario.get('detection_method', '?')}")
                    
                    with st.expander("⚠️ Indicators (IOCs)"):
                        for ioc in scenario.get("indicators", []):
                            st.write(f"• {ioc}")
                    
                    with st.expander("🛡️ Mitigation"):
                        for step in scenario.get("response", "").split(", "):
                            st.write(f"• {step}")
                    
                    mitre = threat.get("mitre", {})
                    if mitre:
                        with st.expander("🔗 MITRE ATT&CK"):
                            st.write(f"**Tactic:** {mitre.get('tactic', '?')}")
                            st.write(f"**Description:** {mitre.get('description', '?')}")
            except Exception as e:
                st.error(f"Threat analysis error: {e}")

    # ─── Tab 4: Dashboard ───────────────────────────────────────────────────
    with tab4:
        st.subheader("System Overview")
        
        col_d1, col_d2 = st.columns(2)
        with col_d1:
            st.write("**Detection Quality**")
            if stats.get("total", 0) > 0:
                intrusions = dec.get("Intrusion", 0)
                detection_rate = (intrusions / stats["total"]) * 100
                st.metric("Detection Rate", f"{detection_rate:.1f}%")
                
                # Severity distribution
                sev_dist = pd.DataFrame({
                    "Severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    "Count": [sev.get(s, 0) for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]]
                })
                st.bar_chart(sev_dist.set_index("Severity"))
            else:
                st.info("Run test scenarios to generate alerts")

        with col_d2:
            st.write("**Attack Types Detected**")
            attack_counts = {}
            for a in alerts:
                atype = a.get("attack_type", "Unknown")
                attack_counts[atype] = attack_counts.get(atype, 0) + 1
            if attack_counts:
                df_attacks = pd.DataFrame(
                    list(attack_counts.items()),
                    columns=["Attack Type", "Count"]
                )
                st.bar_chart(df_attacks.set_index("Attack Type"))
            else:
                st.info("No attacks detected yet")
                
# ─────────────────────────────────────────────────────────────────────────────
# PAGE: PACKET CAPTURE (FIXED: Real-time stats that actually update)
# ─────────────────────────────────────────────────────────────────────────────

elif mode == "Packet Capture":
    st.title("📡 Live Packet Capture & Network Analysis")
    st.caption("Real-time NIDS detection from network traffic")
    
    # ─────────────────────────────────────────────────────────────────────
    # PACKET CAPTURE CONTROLS
    # ─────────────────────────────────────────────────────────────────────
    col_p1, col_p2, col_p3 = st.columns(3)
    with col_p1:
        pkt_count = st.number_input("Packets to capture", 10, 500, 100)
    with col_p2:
        timeout_sec = st.number_input("Timeout (seconds)", 1, 60, 10)
    with col_p3:
        interface_name = st.text_input("Interface (optional)", "")
    
    if st.button("▶ START PACKET CAPTURE", type="primary", key="start_capture_btn"):
        with st.spinner(f"Capturing {pkt_count} packets (timeout: {timeout_sec}s)..."):
            try:
                capture_response = requests.post(
                    f"{API_BASE}/packets/capture",
                    json={
                        "packet_count": pkt_count,
                        "timeout": timeout_sec,
                        "interface": interface_name if interface_name else None
                    },
                    timeout=timeout_sec + 20
                )
                
                if capture_response.status_code == 200:
                    capture_result = capture_response.json()
                    packets_captured = capture_result.get('packets_captured', 0)
                    
                    # FIXED: Show actual captured count
                    if packets_captured > 0:
                        st.success(f"✅ Successfully captured {packets_captured} packets")
                    else:
                        st.warning("⚠️ No packets captured (this is normal if Scapy unavailable)")
                    
                    # ─────────────────────────────────────────────────────
                    # DISPLAY RESULTS IN 3 COLUMNS
                    # ─────────────────────────────────────────────────────
                    col_cap1, col_cap2, col_cap3 = st.columns(3)
                    
                    # Column 1: Network features
                    with col_cap1:
                        st.subheader("🌐 Network Features")
                        net_features = capture_result.get("network_features", {})
                        if net_features:
                            for key, value in net_features.items():
                                st.metric(key.replace("_", " ").title(), value)
                        else:
                            st.info("No network features extracted")
                    
                    # Column 2: Detection result
                    with col_cap2:
                        st.subheader("🎯 Detection Result")
                        det = capture_result.get("detection_result", {})
                        st.metric("Decision", det.get("decision", "?"))
                        st.metric("Attack Type", det.get("attack_type", "?")[:25])  # Truncate long names
                        st.metric("Severity", det.get("severity", "?"))
                    
                    # Column 3: Scores
                    with col_cap3:
                        st.subheader("📊 Confidence Scores")
                        st.metric("NIDS Score", f"{det.get('network_score', 0):.4f}")
                        st.metric("HIDS Score", f"{det.get('host_score', 0):.4f}")
                        st.metric("Final Score", f"{det.get('final_score', 0):.4f}")
                    
                    # ─────────────────────────────────────────────────────
                    # DETAILED ALERT INFO (if intrusion detected)
                    # ─────────────────────────────────────────────────────
                    if det.get("decision") == "Intrusion":
                        st.divider()
                        st.subheader("🚨 Intrusion Alert Details")
                        
                        alert_info = det.get("alert", {})
                        col_alert1, col_alert2 = st.columns(2)
                        
                        with col_alert1:
                            st.write(f"**Alert ID:** {alert_info.get('alert_id', 'N/A')[:12]}")
                            st.write(f"**Triggered By:** {', '.join(det.get('triggered_by', []))}")
                            st.write(f"**Attack Domain:** {det.get('attack_domain', 'Unknown')}")
                        
                        with col_alert2:
                            st.write(f"**Reason:** {'; '.join(det.get('reason', []))}")
                            st.write(f"**MITRE ATT&CK:** {det.get('mitre', 'N/A')}")
                
                else:
                    st.error(f"❌ Capture failed: {capture_response.text[:100]}")
            
            except requests.exceptions.Timeout:
                st.error("❌ Capture timeout. API may be slow or unavailable.")
            except Exception as e:
                st.error(f"❌ Error: {str(e)[:100]}")
    
    # ─────────────────────────────────────────────────────────────────────
    # REAL-TIME STATISTICS (Updates without button click)
    # ─────────────────────────────────────────────────────────────────────
    st.divider()
    st.subheader("📈 Live Packet Statistics")
    
    # FIXED: Actually fetch and display real statistics
    try:
        stats_response = requests.get(f"{API_BASE}/packets/stats", timeout=5)
        if stats_response.status_code == 200:
            pstats = stats_response.json()
            
            col_stat1, col_stat2, col_stat3, col_stat4 = st.columns(4)
            
            col_stat1.metric(
                "Total Packets Captured",
                pstats.get("total_packets_captured", 0),
                delta="packets"
            )
            col_stat2.metric(
                "Alerts Generated",
                pstats.get("total_alerts_generated", 0),
                delta="alerts"
            )
            col_stat3.metric(
                "Capture Active",
                "🟢 Yes" if pstats.get("capture_active") else "🔴 No"
            )
            col_stat4.metric(
                "Last Updated",
                pstats.get("timestamp", "N/A")[-8:]  # Show time only
            )
            
            # FIXED: Show severity breakdown
            sev_data = pstats.get("alerts_by_severity", {})
            if sev_data:
                st.write("**Alerts by Severity:**")
                sev_df = pd.DataFrame({
                    "Severity": list(sev_data.keys()),
                    "Count": list(sev_data.values())
                })
                st.bar_chart(sev_df.set_index("Severity"))
        else:
            st.warning("⚠️ Could not retrieve live statistics")
    
    except Exception as e:
        st.warning(f"⚠️ Statistics loading... ({str(e)[:30]})")

# ─────────────────────────────────────────────────────────────────────────────
# PAGE: TEST SCENARIOS
# ─────────────────────────────────────────────────────────────────────────────

elif mode == "Test Scenarios":
    st.title("🎮 Attack Scenario Testing")
    st.caption("Generate simulated attacks to test NIDS/HIDS detection")
    
    st.write("""
    Test the Hybrid IDS against realistic attack scenarios:
    - **Normal**: Benign web browsing & system activity
    - **Port Scan**: Nmap-like reconnaissance
    - **DDoS**: UDP/SYN flooding attack
    - **Brute Force**: SSH authentication attacks
    - **Hybrid**: Multi-stage network + host attack
    """)
    
    scenario = st.selectbox(
        "Select scenario",
        ["normal", "port_scan", "ddos", "brute_force", "hybrid"],
        format_func=lambda x: {
            "normal": "✅ Normal Traffic",
            "port_scan": "🔍 Port Scan (Nmap)",
            "ddos": "💥 DDoS / Flood (Hping3)",
            "brute_force": "🔐 SSH Brute Force",
            "hybrid": "⚔️ Hybrid Attack (Multi-stage)"
        }[x]
    )
    
    pkt_count_scen = st.number_input("Events to generate", 10, 500, 50)
    
    if st.button("▶ Run Scenario Test", type="primary"):
        with st.spinner(f"Running {scenario} scenario..."):
            try:
                r = requests.post(f"{API_BASE}/packets/scenario/test",
                                json={"scenario": scenario, "packet_count": pkt_count_scen},
                                timeout=15)
                if r.status_code == 200:
                    result = r.json()
                    st.success("✓ Scenario executed")
                    
                    col_s1, col_s2 = st.columns(2)
                    with col_s1:
                        st.write("**Events Generated**")
                        for k, v in result.get("events_generated", {}).items():
                            st.write(f"• {k}: {v}")
                    
                    with col_s2:
                        det = result.get("detection_result", {})
                        st.write("**Detection Result**")
                        st.metric("Decision", det.get("decision", "?"), 
                                 delta=det.get("severity", "?"))
                        st.metric("Score", f"{det.get('final_score', 0):.4f}")
                        st.metric("Attack Type", det.get("attack_type", "?"))
                else:
                    st.error(f"Failed: {r.text}")
            except Exception as e:
                st.error(f"Error: {e}")

# ─────────────────────────────────────────────────────────────────────────────
# PAGE: THREAT ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────

elif mode == "Threat Analysis":
    st.title("🔬 Threat Intelligence & Research")
    st.caption("MITRE ATT&CK mapping, IOCs, and attack intelligence")
    
    attack_types = [
        "Brute Force / Unauthorized Access",
        "Reconnaissance / Port Scan",
        "Network Attack (DoS / Scan)",
        "Multi-Stage Hybrid Attack",
        "Suspicious Activity"
    ]
    
    selected_attack = st.selectbox("Select attack type", attack_types)
    
    if st.button("🔍 Get Threat Intelligence", type="primary"):
        try:
            r = requests.get(f"{API_BASE}/threats/analysis/{selected_attack}", timeout=5)
            if r.status_code == 200:
                threat = r.json().get("analysis", {})
                scenario = threat.get("scenario", {})
                
                col_t1, col_t2, col_t3 = st.columns(3)
                col_t1.metric("Risk Level", scenario.get("risk_level", "?"))
                col_t2.metric("Phase", scenario.get("phase", "?").split()[0])
                col_t3.metric("Threat Actors", "Varies")
                
                st.subheader("📋 Attack Description")
                st.write(scenario.get("description", "N/A"))
                
                st.subheader("⚠️ Indicators of Compromise")
                for ioc in scenario.get("indicators", []):
                    st.write(f"✓ {ioc}")
                
                st.subheader("🛡️ Mitigation & Response")
                response_steps = scenario.get("response", "").split(", ")
                for i, step in enumerate(response_steps, 1):
                    st.write(f"{i}. {step}")
                
                # MITRE mapping
                r_mitre = requests.get(f"{API_BASE}/threats/mitre/{selected_attack}", timeout=5)
                if r_mitre.status_code == 200:
                    mitre = r_mitre.json().get("mitre", {})
                    st.subheader("🔗 MITRE ATT&CK Framework")
                    col_m1, col_m2 = st.columns(2)
                    col_m1.write(f"**Tactic:** {mitre.get('tactic', 'N/A')}")
                    col_m2.write(f"**Technique ID:** {mitre.get('tactic_id', 'N/A')}")
                    st.write(f"**Description:** {mitre.get('description', 'N/A')}")
            else:
                st.error("Threat analysis unavailable")
        except Exception as e:
            st.error(f"Error: {e}")

# ─────────────────────────────────────────────────────────────────────────────
# Auto-refresh
# ─────────────────────────────────────────────────────────────────────────────

if auto_refresh:
    time.sleep(5)
    st.rerun()
    
