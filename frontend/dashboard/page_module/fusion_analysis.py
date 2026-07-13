"""
Fusion Analysis Page
Shows hybrid NIDS + HIDS correlation
"""

import streamlit as st
import plotly.graph_objects as go
from backend.dashboard.data_service import dashboard_data_service


def show():
    """Display fusion analysis"""
    
    st.header("🔀 Hybrid Fusion Analysis")
    
    st.markdown("""
    Visualization of how NIDS and HIDS detections are correlated
    into unified incidents and decisions.
    """)
    
    st.markdown("---")
    
    # ==================== FUSION WORKFLOW ====================
    
    st.subheader("📊 Fusion Workflow")
    
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.markdown("### NIDS Score")
        st.markdown("**0.78**")
        st.caption("Network Detection")
    
    with col2:
        st.markdown("### →")
    
    with col3:
        st.markdown("### HIDS Score")
        st.markdown("**0.85**")
        st.caption("Host Detection")
    
    with col4:
        st.markdown("### →")
    
    with col5:
        st.markdown("### Fusion Score")
        st.markdown("**0.81**")
        st.caption("Final Decision")
    
    st.markdown("---")
    
    # ==================== INCIDENT STATISTICS ====================
    
    st.subheader("📈 Incident Statistics")
    
    incidents = dashboard_data_service.get_incidents(1000)
    
    if incidents:
        # Count by category
        categories = {}
        for incident in incidents:
            category = incident.get("attack_category", "Unknown")
            categories[category] = categories.get(category, 0) + 1
        
        fig = go.Figure(data=[
            go.Bar(
                x=list(categories.keys()),
                y=list(categories.values()),
                marker=dict(color=['#667eea', '#764ba2', '#f093fb', '#4facfe'])
            )
        ])
        
        fig.update_layout(
            title="Incidents by Category",
            xaxis_title="Category",
            yaxis_title="Count",
            height=300,
            showlegend=False
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    st.markdown("---")
    
    # ==================== CORRELATION PATTERNS ====================
    
    st.subheader("🔗 Correlation Patterns")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Network Only**")
        network_only = len([i for i in incidents if i.get("attack_category") == "Network Only"])
        st.metric("Incidents", network_only)
    
    with col2:
        st.write("**Host Only**")
        host_only = len([i for i in incidents if i.get("attack_category") == "Host Only"])
        st.metric("Incidents", host_only)
    
    col3, col4 = st.columns(2)
    
    with col3:
        st.write("**Hybrid**")
        hybrid = len([i for i in incidents if i.get("attack_category") == "Hybrid"])
        st.metric("Incidents", hybrid)
    
    with col4:
        st.write("**Multi-Stage**")
        multi_stage = len([i for i in incidents if i.get("attack_category") == "Multi-Stage"])
        st.metric("Incidents", multi_stage)
    
    st.markdown("---")
    
    # ==================== RECENT CORRELATIONS ====================
    
    st.subheader("📋 Recent Correlated Incidents")
    
    correlated = [i for i in incidents if i.get("is_correlated")]
    
    if correlated:
        import pandas as pd
        
        corr_data = []
        for incident in correlated[:20]:
            corr_data.append({
                "ID": incident.get("incident_id", "")[:8],
                "Time": incident.get("created_at", "")[:19],
                "Type": incident.get("attack_type"),
                "Score": f"{incident.get('confidence', 0):.2%}",
                "Category": incident.get("attack_category")
            })
        
        df = pd.DataFrame(corr_data)
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No correlated incidents yet.")