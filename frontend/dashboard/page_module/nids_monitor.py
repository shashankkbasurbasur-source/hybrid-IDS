"""
NIDS Monitor Page
Network-based intrusion detection view
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from frontend.dashboard.dashboard_service import svc
from frontend.dashboard.components.cards import metric_card
from frontend.dashboard.components.tables import render_dataframe

def show():
    st.header("🔗 Network Intrusion Detection (NIDS)")
    st.markdown("Real-time network traffic analysis, live packet capture stream, and active flows monitor.")
    st.markdown("---")

    # Traffic Statistics Row
    st.subheader("📈 Real-time Traffic Statistics")
    capture_status = svc.get_capture_status()
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        metric_card("Live Capture Packets", f"{capture_status.get('packets_captured', 0):,}", "green", "CAPTURING")
    with col2:
        metric_card("Active Flows", f"{capture_status.get('active_flows', 0)}", "green", "TRACKING")
    with col3:
        metric_card("Packet Rate", "145 pps", "green", "NORMAL RATE")
    with col4:
        metric_card("Bandwidth Usage", "425 KB/s", "green", "STABLE")

    st.markdown("---")

    # Charts Row
    st.subheader("📊 Network Traffic Distribution")
    col_chart1, col_chart2 = st.columns(2)
    
    with col_chart1:
        protocol_dist = svc.get_protocol_distribution()
        if protocol_dist:
            fig = px.pie(
                values=list(protocol_dist.values()),
                names=list(protocol_dist.keys()),
                title="Protocol Distribution",
                hole=0.4,
                color_discrete_sequence=px.colors.sequential.Bluyl
            )
            fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font_color="#f8fafc",
                height=300,
                margin=dict(l=20, r=20, t=40, b=20)
            )
            st.plotly_chart(fig, use_container_width=True)

    with col_chart2:
        top_ips = svc.get_top_ips()
        src_ips = top_ips.get("source_ips", [])
        if src_ips:
            ips, counts = zip(*src_ips)
            fig = px.bar(
                x=counts,
                y=ips,
                orientation='h',
                title="Top Source IP Address Volume",
                labels={"x": "Packets Count", "y": "IP Address"},
                color_discrete_sequence=["#3b82f6"]
            )
            fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font_color="#f8fafc",
                height=300,
                margin=dict(l=20, r=20, t=40, b=20)
            )
            st.plotly_chart(fig, use_container_width=True)

    st.markdown("---")

    # Captured Packets & Flow Summaries
    col_t1, col_t2 = st.columns(2)
    
    with col_t1:
        st.subheader("📦 Recent Captured Packets")
        packets = svc.get_recent_packets(10)
        if packets:
            packet_df = pd.DataFrame(packets)
            # Standardize columns
            packet_df = packet_df[["timestamp", "src_ip", "dst_ip", "protocol", "length"]]
            packet_df.columns = ["Timestamp", "Source IP", "Destination IP", "Protocol", "Length (B)"]
            render_dataframe(packet_df, height=250)
        else:
            st.info("No packets captured yet.")

    with col_t2:
        st.subheader("🔁 Active Flow Summaries")
        flows = svc.get_nids_flows(10)
        if flows:
            flow_df = pd.DataFrame(flows)
            flow_df = flow_df[["flow_key", "src_ip", "dst_ip", "protocol", "packet_count", "status"]]
            flow_df.columns = ["Flow Key", "Source", "Destination", "Proto", "Packets", "State"]
            render_dataframe(flow_df, height=250)
        else:
            st.info("No active flows detected.")

    st.markdown("---")

    # NIDS Detections
    st.subheader("🚨 NIDS Detections & Alert Category")
    alerts = svc.get_alerts()
    nids_alerts = [a for a in alerts if "NIDS" in a.get("detection_source", "")]
    
    if nids_alerts:
        nids_df = pd.DataFrame(nids_alerts)
        nids_disp = nids_df[["alert_id", "timestamp", "source", "dest_ip", "attack_type", "confidence", "severity"]]
        nids_disp.columns = ["Alert ID", "Timestamp", "Source IP", "Destination IP", "Attack Category", "Confidence Score", "Severity"]
        render_dataframe(nids_disp, height=250)
    else:
        st.success("No network-based intrusions detected.")
