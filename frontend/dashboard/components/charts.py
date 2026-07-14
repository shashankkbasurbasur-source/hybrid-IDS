import streamlit as st
import plotly.graph_objects as go

def render_bar_chart(x_data, y_data, title, x_title, color='#ff9800'):
    fig = go.Figure(data=[
        go.Bar(y=x_data, x=y_data, orientation='h', marker=dict(color=color))
    ])
    fig.update_layout(title=title, xaxis_title=x_title, height=300, showlegend=False)
    st.plotly_chart(fig, use_container_width=True)
