import streamlit as st

def severity_badge(severity: str):
    colors = {
        "CRITICAL": {"bg": "rgba(239, 68, 68, 0.2)", "fg": "#ef4444"},
        "HIGH": {"bg": "rgba(245, 158, 11, 0.2)", "fg": "#f59e0b"},
        "MEDIUM": {"bg": "rgba(59, 130, 246, 0.2)", "fg": "#3b82f6"},
        "LOW": {"bg": "rgba(16, 185, 129, 0.2)", "fg": "#10b981"}
    }
    badge_colors = colors.get(severity.upper(), {"bg": "rgba(148, 163, 184, 0.2)", "fg": "#94a3b8"})
    
    st.markdown(
        f'<span class="soc-badge" style="background-color: {badge_colors["bg"]}; color: {badge_colors["fg"]}; border: 1px solid {badge_colors["fg"]}; padding: 4px 10px; border-radius: 9999px;">{severity.upper()}</span>', 
        unsafe_allow_html=True
    )
