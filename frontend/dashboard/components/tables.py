import streamlit as st
import pandas as pd

def render_dataframe(df: pd.DataFrame, height=400):
    st.dataframe(df, use_container_width=True, hide_index=True, height=height)
