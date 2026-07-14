import streamlit as st

def apply_theme():
    st.markdown("""
    <style>
        /* Modern Font and SOC Dark Theme Tweaks */
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap');
        
        html, body, [class*="css"] {
            font-family: 'Outfit', sans-serif;
        }

        /* SOC Dashboard Metric Card */
        .soc-card {
            background-color: #111524;
            border: 1px solid #1e293b;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 15px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
            transition: all 0.3s ease;
        }
        .soc-card:hover {
            border-color: #3b82f6;
            box-shadow: 0 10px 15px -3px rgba(59, 130, 246, 0.1);
        }
        .soc-title {
            color: #94a3b8;
            font-size: 0.875rem;
            font-weight: 500;
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .soc-value {
            color: #f8fafc;
            font-size: 1.875rem;
            font-weight: 700;
        }
        .soc-indicator {
            display: inline-flex;
            align-items: center;
            padding: 4px 8px;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            margin-top: 10px;
        }
        .indicator-green {
            background-color: rgba(16, 185, 129, 0.1);
            color: #10b981;
        }
        .indicator-red {
            background-color: rgba(239, 68, 68, 0.1);
            color: #ef4444;
        }
        .indicator-orange {
            background-color: rgba(245, 158, 11, 0.1);
            color: #f59e0b;
        }
        
        /* Status Badges */
        .soc-badge {
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
    </style>
    """, unsafe_allow_html=True)
