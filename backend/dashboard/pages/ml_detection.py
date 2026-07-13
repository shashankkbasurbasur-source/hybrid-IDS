"""
ML Detection Dashboard Page
Reads exclusively from backend APIs — no direct DB or model access.
"""

import streamlit as st
import requests
import pandas as pd

API_BASE = "http://127.0.0.1:8000/ml"

st.set_page_config(page_title="ML Detection — Hybrid IDS", layout="wide")
st.title("🧠 ML Detection Pipeline")


def get(endpoint, params=None):
    try:
        resp = requests.get(f"{API_BASE}{endpoint}", params=params or {})
        return resp.json() if resp.status_code == 200 else None
    except Exception:
        return None


# -----------------------------
# Model Status
# -----------------------------
st.markdown("### 🧩 Model Status")
status = get("/model/status")

if status:
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Model Loaded", "✅" if status["model_loaded"] else "❌")
    c2.metric("Scaler Loaded", "✅" if status["scaler_loaded"] else "❌")
    c3.metric("Feature Metadata", "✅" if status["feature_metadata_loaded"] else "❌")
    c4.metric("Expected Features", status["expected_feature_count"] or "N/A")

    if not status["feature_metadata_loaded"]:
        st.error(
            "feature_metadata.json is missing. Predictions cannot be trusted "
            "until you run the training script to regenerate it."
        )

    with st.expander("Model Metadata (reproducibility)"):
        meta = get("/model/metadata")
        if meta:
            st.json(meta)
else:
    st.warning("ML API unreachable.")

# -----------------------------
# Prediction Summary
# -----------------------------
st.markdown("### 📊 Prediction Summary")
stats = get("/model/statistics")

if stats:
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Predictions", stats["total_predictions"])
    c2.metric("Normal", stats["normal_count"])
    c3.metric("Attack", stats["attack_count"])
    c4.metric("Detection Rate", f"{stats['detection_rate'] * 100:.1f}%")

    if stats["attack_types"]:
        st.markdown("**Attack Type Breakdown** *(heuristic classification — see note below)*")
        df = pd.DataFrame(stats["attack_types"])
        st.bar_chart(df.set_index("attack_type"))
        st.caption(
            "⚠️ Attack types are inferred from flow shape heuristics, not a trained "
            "multi-class model. The underlying classifier is binary (Normal/Attack)."
        )

# -----------------------------
# Performance
# -----------------------------
st.markdown("### ⚡ Performance")
perf = get("/detection/performance")

if perf:
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Predictions/sec", perf["predictions_per_sec"])
    c2.metric("Avg Inference (ms)", perf["avg_inference_time_ms"])
    c3.metric("Feature Queue", perf["feature_queue_size"])
    c4.metric("Detection Queue", perf["detection_queue_size"])

    c5, c6 = st.columns(2)
    if perf.get("memory_mb") is not None:
        c5.metric("Memory (MB)", perf["memory_mb"])
    if perf.get("cpu_percent") is not None:
        c6.metric("CPU %", perf["cpu_percent"])

# -----------------------------
# Recent Predictions
# -----------------------------
st.markdown("### 🔍 Recent Predictions")
recent = get("/predictions", params={"limit": 30})

if recent and recent["predictions"]:
    df = pd.DataFrame(recent["predictions"])
    display_cols = ["timestamp", "flow_key", "prediction", "attack_type", "confidence", "severity"]
    available_cols = [c for c in display_cols if c in df.columns]
    st.dataframe(df[available_cols], use_container_width=True, height=400)
else:
    st.info("No predictions yet.")

# -----------------------------
# Dead Letter Queue (operational visibility)
# -----------------------------
dead_letters = get("/detection/dead-letters", params={"limit": 20})
if dead_letters and dead_letters["dead_letters"]:
    with st.expander(f"⚠️ Dead Letter Queue ({len(dead_letters['dead_letters'])} items)"):
        st.dataframe(pd.DataFrame(dead_letters["dead_letters"]), use_container_width=True)