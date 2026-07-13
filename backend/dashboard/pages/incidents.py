"""
Incident & Alert Dashboard — Module 9.
Reads exclusively from backend APIs.
"""

import streamlit as st
import requests
import pandas as pd

API_BASE = "http://127.0.0.1:8000"

st.set_page_config(page_title="Incidents — Hybrid IDS", layout="wide")
st.title("🚨 Alert & Incident Management")


def get(endpoint, params=None):
    try:
        resp = requests.get(f"{API_BASE}{endpoint}", params=params or {})
        return resp.json() if resp.status_code == 200 else None
    except Exception:
        return None


def post(endpoint, json_body=None, params=None):
    try:
        resp = requests.post(f"{API_BASE}{endpoint}", json=json_body, params=params or {})
        return resp.json() if resp.status_code == 200 else {"error": resp.text}
    except Exception as e:
        return {"error": str(e)}


# -----------------------------
# Overview metrics
# -----------------------------
alerts_data = get("/alerts", params={"limit": 500})
incidents_data = get("/incidents", params={"limit": 200})
severity_dist = get("/alerts/severity/distribution")

c1, c2, c3, c4 = st.columns(4)
if alerts_data:
    c1.metric("Total Alerts", len(alerts_data["alerts"]))
if incidents_data:
    active_incidents = [i for i in incidents_data["incidents"] if i["status"] not in ("RESOLVED", "CLOSED")]
    c2.metric("Active Incidents", len(active_incidents))
    c3.metric("Total Incidents", len(incidents_data["incidents"]))
    hybrid_count = sum(1 for i in incidents_data["incidents"] if i.get("fusion_type") == "HYBRID")
    c4.metric("Hybrid (NIDS+HIDS) Incidents", hybrid_count)

# -----------------------------
# Severity distribution
# -----------------------------
st.markdown("### 📊 Severity Distribution")
if severity_dist and severity_dist["distribution"]:
    df = pd.DataFrame(severity_dist["distribution"])
    st.bar_chart(df.set_index("severity"))

# -----------------------------
# Active Incidents
# -----------------------------
st.markdown("### 🔥 Active Incidents")
if incidents_data and incidents_data["incidents"]:
    df = pd.DataFrame(incidents_data["incidents"])
    display_cols = ["incident_id", "title", "status", "severity", "fusion_type",
                     "alert_count", "created_at", "updated_at"]
    available = [c for c in display_cols if c in df.columns]
    st.dataframe(df[available], use_container_width=True, height=300)

    st.markdown("#### 🔍 Investigate an Incident")
    incident_id = st.text_input("Incident ID")

    if incident_id:
        detail = get(f"/incidents/{incident_id}")
        if detail:
            st.markdown(f"**Title:** {detail['title']}")
            st.markdown(f"**Status:** {detail['status']} · **Severity:** {detail['severity']} · **Fusion:** {detail['fusion_type']}")
            st.markdown(f"**Source:** {detail['source_ip']} → **Dest:** {detail['dest_ip']}")

            c1, c2, c3, c4 = st.columns(4)
            if c1.button("Acknowledge"):
                st.write(post(f"/incident/{incident_id}/ack"))
                st.rerun()
            if c2.button("Investigate"):
                st.write(post(f"/incident/{incident_id}/investigate"))
                st.rerun()
            if c3.button("Resolve"):
                st.write(post(f"/incident/{incident_id}/resolve"))
                st.rerun()
            if c4.button("Close"):
                st.write(post(f"/incident/{incident_id}/close"))
                st.rerun()

            with st.expander(f"Related Alerts ({len(detail['alerts'])})"):
                if detail["alerts"]:
                    st.dataframe(pd.DataFrame(detail["alerts"]), use_container_width=True)

            with st.expander(f"Timeline ({len(detail['history'])} events)"):
                for h in detail["history"]:
                    st.write(f"`{h['timestamp']}` **{h['event']}** ({h.get('old_status')} → {h.get('new_status')}) by {h['actor']}")

            with st.expander(f"Notes ({len(detail['notes'])})"):
                for n in detail["notes"]:
                    st.write(f"`{n['timestamp']}` **{n['analyst']}**: {n['note']}")

                new_note = st.text_area("Add a note")
                if st.button("Submit Note") and new_note:
                    post(f"/incident/{incident_id}/note", json_body={"note": new_note})
                    st.rerun()
        else:
            st.warning("Incident not found.")
else:
    st.info("No incidents yet.")

# -----------------------------
# Recent Alerts (raw feed)
# -----------------------------
st.markdown("### 📋 Recent Alerts")
if alerts_data and alerts_data["alerts"]:
    df = pd.DataFrame(alerts_data["alerts"])
    display_cols = ["timestamp", "attack_type", "severity", "risk_level",
                     "source_ip", "dest_ip", "confidence", "incident_id"]
    available = [c for c in display_cols if c in df.columns]
    st.dataframe(df[available], use_container_width=True, height=400)
else:
    st.info("No alerts yet.")