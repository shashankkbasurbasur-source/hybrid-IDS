import streamlit as st
import requests
import time

API_URL = "http://127.0.0.1:8000/detect/"

# -----------------------------
# Page Config
# -----------------------------
st.set_page_config(page_title="Hybrid IDS", layout="wide")

st.title("🔐 Hybrid Intrusion Detection System")
st.markdown("Real-time Network + Host-based Intrusion Detection")

# -----------------------------
# Sidebar Controls
# -----------------------------
st.sidebar.header("Controls")

run_btn = st.sidebar.button("Run Detection")
auto_mode = st.sidebar.checkbox("Auto Refresh (5s)")

# -----------------------------
# UI Containers
# -----------------------------
decision_box = st.empty()

col1, col2, col3 = st.columns(3)

analysis_box = st.container()
alert_box = st.container()

# -----------------------------
# API Call
# -----------------------------
def get_detection():
    payload = {
        "network_features": [0.05] * 78,
        "host_features": [0.1] * 100
    }

    try:
        response = requests.post(API_URL, json=payload)

        if response.status_code == 200:
            return response.json()
        else:
            st.error(f"{response.status_code}: {response.text}")
            return None

    except Exception as e:
        st.error(f"Connection Error: {e}")
        return None


# -----------------------------
# Display Result
# -----------------------------
def show_result(result):

    decision = result.get("decision", "Unknown")
    final_score = result.get("final_score", 0)
    nids = result.get("network_score", 0)
    hids = result.get("host_score", 0)

    attack_type = result.get("attack_type", "None")
    location = result.get("location", "Unknown")
    reason = result.get("reason", [])
    severity = result.get("severity", "LOW")

    # -----------------------------
    # Decision Banner
    # -----------------------------
    if decision.lower() in ["intrusion", "attack"]:
        decision_box.error(f"🚨 INTRUSION DETECTED ({final_score:.2f})")
    else:
        decision_box.success(f"✅ SYSTEM NORMAL ({final_score:.2f})")

    # -----------------------------
    # Metrics
    # -----------------------------
    col1.metric("NIDS Score", f"{nids:.3f}")
    col2.metric("HIDS Score", f"{hids:.3f}")
    col3.metric("Final Score", f"{final_score:.3f}")

    # -----------------------------
    # Attack Analysis
    # -----------------------------
    with analysis_box:
        st.markdown("### 🔍 Attack Analysis")

        st.write(f"**Type:** {attack_type}")
        st.write(f"**Location:** {location}")
        st.write(f"**Severity:** {severity}")

        st.write("**Reason:**")
        for r in reason:
            st.write(f"- {r}")

    # -----------------------------
    # Alert Details
    # -----------------------------
    with alert_box:
        st.markdown("### 🚨 Alert Details")

        st.write(f"Confidence: {final_score}")
        st.write(f"Timestamp: {result.get('timestamp', 'N/A')}")


# -----------------------------
# Run Once
# -----------------------------
if run_btn:
    result = get_detection()
    if result:
        show_result(result)
    else:
        st.error("❌ API not reachable")

# -----------------------------
# Auto Refresh Mode
# -----------------------------
if auto_mode:
    while True:
        result = get_detection()
        if result:
            show_result(result)
        time.sleep(5)