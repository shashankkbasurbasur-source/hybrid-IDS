import streamlit as st

def metric_card(title: str, value: str, status: str = None, status_text: str = None):
    indicator_html = ""
    if status and status_text:
        color_class = "indicator-green" if status == "green" else "indicator-red" if status == "red" else "indicator-orange"
        indicator_html = f'<div class="soc-indicator {color_class}">{status_text}</div>'
        
    st.markdown(f"""
        <div class="soc-card">
            <div class="soc-title">{title}</div>
            <div class="soc-value">{value}</div>
            {indicator_html}
        </div>
    """, unsafe_allow_html=True)
