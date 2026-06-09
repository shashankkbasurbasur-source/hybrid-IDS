# backend/dashboard/app.py

"""
Streamlit SOC Dashboard — Hybrid IDS
Real pipeline: file → ingest → features → API → display
"""

import streamlit as st
import requests
import json
import time
from pathlib import Path

API_BASE = "http://127.0.0.1:8000"

st.set_page_config(page_title="Hybrid IDS — SOC Dashboard", layout="wide", page_icon="🛡️")

# ── Sidebar ─────────────────────────────────────────────────────────────────
st.sidebar.title("🛡️ Hybrid IDS")
st.sidebar.markdown("---")
mode       = st.sidebar.radio("Detection mode", ["Log file", "Manual features"])
log_file   = st.sidebar.text_input("Log file path", "sample_logs.txt")
auto_mode  = st.sidebar.checkbox("⏵ Auto-refresh (5s)")
run_btn    = st.sidebar.button("▶ Run detection now")

st.title("🔐 Hybrid IDS — SOC Dashboard")
st.caption("NIDS · HIDS · Fusion Engine · Real-time Threat Analysis")

# ── Metric row ───────────────────────────────────────────────────────────────
col1, col2, col3, col4, col5 = st.columns(5)

def load_stats():
    try:
        r = requests.get(f"{API_BASE}/alerts/stats", timeout=3)
        return r.json() if r.status_code == 200 else {}
    except Exception:
        return {}

stats = load_stats()
col1.metric("Total Events",  stats.get("total",    "—"))
col2.metric("🔴 Critical",   stats.get("CRITICAL", "—"))
col3.metric("🟠 High",       stats.get("HIGH",     "—"))
col4.metric("🟡 Medium",     stats.get("MEDIUM",   "—"))
col5.metric("🟢 Normal",     stats.get("NORMAL",   "—"))

st.markdown("---")

# ── Main columns ─────────────────────────────────────────────────────────────
left, right = st.columns([2, 1])

# ── Detection function ────────────────────────────────────────────────────────
def run_detection():
    if mode == "Log file" and Path(log_file).exists():
        with open(log_file, "r") as f:
            lines = f.readlines()
        payload = {"log_lines": lines, "source": "ssh"}
        r = requests.post(f"{API_BASE}/ingest/logs", json=payload, timeout=10)
        if r.status_code == 200:
            return r.json()
        st.error(f"Ingest API error: {r.text}")
        return None

    elif mode == "Manual features":
        payload = {
            "network_features": [0.05] * 78,
            "host_features"   : [0.10] * 100,
        }
        r = requests.post(f"{API_BASE}/detect/", json=payload, timeout=10)
        return r.json() if r.status_code == 200 else None

    else:
        st.warning(f"Log file not found: {log_file}")
        return None

# ── Show result ───────────────────────────────────────────────────────────────
def show_result(result):
    decision     = result.get("decision", "Unknown")
    final_score  = result.get("final_score", 0)
    nids         = result.get("network_score", 0)
    hids         = result.get("host_score", 0)
    attack_type  = result.get("attack_type", "None")
    location     = result.get("location", "None")
    severity     = result.get("severity", "LOW")
    reason       = result.get("reason", [])
    triggered_by = result.get("triggered_by", [])

    with left:
        if decision.lower() == "intrusion":
            st.error(f"🚨 INTRUSION DETECTED — {severity}  |  Score: {final_score:.4f}")
        else:
            st.success(f"✅ Normal Traffic  |  Score: {final_score:.4f}")

        c1, c2, c3 = st.columns(3)
        c1.metric("NIDS Score",  f"{nids:.4f}")
        c2.metric("HIDS Score",  f"{hids:.4f}")
        c3.metric("Fusion Score", f"{final_score:.4f}")

        with st.expander("🔍 Attack Analysis", expanded=True):
            st.write(f"**Type:** {attack_type}")
            st.write(f"**Location:** {location}")
            st.write(f"**Severity:** {severity}")
            st.write(f"**Triggered by:** {', '.join(triggered_by) if triggered_by else 'None'}")
            st.write("**Reasons:**")
            for r in reason:
                st.write(f"  • {r}")

    with right:
        st.subheader("🚨 Alert Details")
        alert = result.get("alert", {})
        st.json(alert)

# ── Alert history table ───────────────────────────────────────────────────────
def show_alert_table():
    try:
        r = requests.get(f"{API_BASE}/alerts/?limit=50", timeout=3)
        if r.status_code == 200:
            alerts = r.json().get("alerts", [])
            if alerts:
                st.subheader("📋 Alert Log")
                import pandas as pd
                df = pd.DataFrame(alerts)[["id","timestamp","decision","attack_type","severity","confidence","network_score","host_score"]]
                st.dataframe(df, use_container_width=True)
    except Exception:
        pass

# ── Run ───────────────────────────────────────────────────────────────────────
if run_btn:
    with st.spinner("Running detection pipeline..."):
        result = run_detection()
    if result:
        show_result(result)

show_alert_table()

if auto_mode:
    time.sleep(5)
    st.rerun()