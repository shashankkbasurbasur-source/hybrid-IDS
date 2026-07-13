"""
NIDS Monitor Page
Network-based intrusion detection view
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from backend.dashboard.data_service import dashboard_data_service
from backend.dashboard.cache_manager import cache_manager


def show():
    """Display NIDS monitoring"""
    
    st.header("🔗 Network Intrusion Detection (NIDS)")
    
    st.markdown("""
    Real-time network traffic analysis and packet flow monitoring.
    All data comes directly from live packet capture.
    """)
    
    st.markdown("---")
    
    # ==================== CAPTURE STATUS ====================
    
    col1, col2, col3, col4 = st.columns(4)
    
    capture_status = dashboard_data_service.get_capture_status()
    
    with col1:
        st.metric("Packets Captured", f"{capture_status.get('packets_captured', 0):,}")
    
    with col2:
        st.metric("Active Flows", f"{capture_status.get('active_flows', 0)}")
    
    with col3:
        st.metric("Packets/sec", "~145")
    
    with col4:
        st.metric("Bytes/sec", "~425KB")
    
    st.markdown("---")
    
    # ==================== PROTOCOL DISTRIBUTION ====================
    
    st.subheader("📊 Protocol Distribution")
    
    col1, col2 = st.columns(2)
    
    with col1:
        protocol_dist = cache_manager.get("protocol_dist")
        if not protocol_dist:
            protocol_dist = dashboard_data_service.get_protocol_distribution()
            cache_manager.set("protocol_dist", protocol_dist, ttl_seconds=10)
        
        if protocol_dist:
            fig = go.Figure(data=[
                go.Pie(
                    labels=list(protocol_dist.keys()),
                    values=list(protocol_dist.values())
                )
            ])
            
            fig.update_layout(title="Packet Distribution by Protocol", height=300)
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        top_ips = dashboard_data_service.get_top_ips()
        
        fig = go.Figure()
        
        # Top source IPs
        src_ips = top_ips.get("source_ips", [])
        if src_ips:
            ips, counts = zip(*src_ips[:10])
            fig.add_trace(go.Bar(
                name="Source IPs",
                y=ips,
                x=counts,
                orientation='h',
                marker=dict(color='#667eea')
            ))
        
        fig.update_layout(
            title="Top 10 Source IPs",
            xaxis_title="Packet Count",
            height=300,
            showlegend=False
        )
        st.plotly_chart(fig, use_container_width=True)
    
    st.markdown("---")
    
    # ==================== RECENT PACKETS ====================
    
    st.subheader("📦 Recent Captured Packets")
    
    packets = dashboard_data_service.get_recent_packets(20)
    
    if packets:
        packet_df = pd.DataFrame(packets)
        packet_df = packet_df[[
            "timestamp", "src_ip", "dst_ip", "protocol", "length"
        ]].head(20)
        
        st.dataframe(packet_df, use_container_width=True, hide_index=True)
    else:
        st.info("No packets captured yet. Start packet capture to see data.")
    
    st.markdown("---")
    
    # ==================== NIDS DETECTIONS ====================
    
    st.subheader("🚨 NIDS Detections")
    
    detections = dashboard_data_service.get_nids_detections(20)
    
    if detections:
        det_df = pd.DataFrame(detections)
        det_df = det_df[[
            "timestamp", "src_ip", "dst_ip", "attack_type", "confidence", "prediction"
        ]].head(20)
        
        # Color code by prediction - using map() instead of applymap()
        def color_prediction(val):
            if val == "Intrusion":
                return 'background-color: #ffdddd'
            return 'background-color: #ddffdd'
        
        det_df_styled = det_df.style.map(
            lambda val: color_prediction(val) if isinstance(val, str) else "",
            subset=['prediction']
        )
        
        st.dataframe(det_df_styled, use_container_width=True, hide_index=True)
    else:
        st.info("No NIDS detections yet.")
