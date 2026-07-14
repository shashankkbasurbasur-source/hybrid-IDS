"""
Fusion Analysis Page
Visualizes the decision-level fusion process and score correlation.
"""

import streamlit as st
import pandas as pd
from frontend.dashboard.dashboard_service import svc
from frontend.dashboard.components.cards import metric_card
from frontend.dashboard.components.tables import render_dataframe

def show():
    st.header("🧠 Decision-Level Fusion Analysis")
    st.markdown("Combines network (NIDS) and host (HIDS) features to produce a unified, confident security decision.")
    st.markdown("---")

    # Fetch fusion engine status
    fusion = svc.get_fusion_status()

    # Scores Flow Visualization
    st.subheader("📊 Score Fusion Flow")
    
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        metric_card("NIDS Score", "87/100", "green" if 87 < 90 else "orange")
    with col2:
        metric_card("HIDS Auth Score", "80/100", "orange")
    with col3:
        metric_card("HIDS Syscall Score", "90/100", "green")
    with col4:
        metric_card("Combined HIDS Score", "85/100", "orange")
    with col5:
        metric_card("Decision Fusion Score", f"{fusion.get('current_score', 88)}/100", "orange")

    # Scores progression path diagram using CSS
    st.markdown("""
        <div style='display: flex; align-items: center; justify-content: space-around; background-color: #111524; padding: 15px; border-radius: 8px; border: 1px solid #1e293b; margin-top: 15px;'>
            <div style='text-align: center;'><span style='color: #3b82f6; font-weight: bold;'>NIDS (87)</span></div>
            <div style='color: #64748b;'>➔</div>
            <div style='text-align: center;'><span style='color: #10b981; font-weight: bold;'>Auth Log (80)</span></div>
            <div style='color: #64748b;'>✚</div>
            <div style='text-align: center;'><span style='color: #10b981; font-weight: bold;'>Syscall (90)</span></div>
            <div style='color: #64748b;'>➔</div>
            <div style='text-align: center;'><span style='color: #f59e0b; font-weight: bold;'>Combined HIDS (85)</span></div>
            <div style='color: #64748b;'>➔</div>
            <div style='text-align: center;'><span style='color: #ef4444; font-weight: bold;'>Fusion Decision (88)</span></div>
        </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    # Fusion reasoning and decision metrics
    st.subheader("🧠 Correlation & Fusion Metrics")
    col_l, col_r = st.columns(2)
    
    with col_l:
        st.write("**Correlation Status:** `ACTIVE CORRELATION`")
        st.write("**Attack Category:** Cross-layer Brute Force pivoting to local Privilege Escalation")
        st.write("**Severity:** HIGH")
        st.write("**Detection Source:** Network & Host (Fused)")
        st.write("**Confidence Calculation:** `0.35 * NIDS + 0.45 * HIDS + 0.20 * ThreatIntel = 0.88`")
        
        st.markdown("**Final Decision:** <span style='color: #ef4444; font-weight: bold;'>ATTACK / COMPROMISE CONFIRMED</span>", unsafe_allow_html=True)

    with col_r:
        st.write("**Fusion Reasoning:**")
        reasoning = fusion.get("reasoning", [])
        for r in reasoning:
            st.info(f"💡 {r}")

    st.markdown("---")

    # Correlation Timeline
    st.subheader("⏱️ Correlation Timeline")
    timeline = fusion.get("timeline", [])
    if timeline:
        timeline_df = pd.DataFrame(timeline)
        timeline_df.columns = ["Timestamp", "Fused Event Details"]
        render_dataframe(timeline_df, height=180)
    else:
        st.info("No correlation events in timeline.")
