INTERFACE_API_URL = "http://127.0.0.1:8000/interfaces"

import streamlit as st
from fastapi import requests

st.sidebar.header("Network Interface")

@st.cache_data(ttl=60)
def fetch_interfaces():
    try:
        resp = requests.get(f"{INTERFACE_API_URL}/")
        if resp.status_code == 200:
            return resp.json()["interfaces"]
    except Exception:
        pass
    return []

def fetch_current():
    try:
        resp = requests.get(f"{INTERFACE_API_URL}/current")
        if resp.status_code == 200:
            return resp.json()
        return None
    except Exception:
        return None

if st.sidebar.button("🔄 Refresh Interfaces"):
    fetch_interfaces.clear()

interfaces = fetch_interfaces()
iface_names = [i["name"] for i in interfaces]
current = fetch_current()

if not current and iface_names:
    st.sidebar.error("No interface currently selected or reachable — pick one below.")

if iface_names:
    current_name = current["interface"]["name"] if current else None
    default_idx = iface_names.index(current_name) if current_name in iface_names else 0

    selected_iface = st.sidebar.selectbox("Select Interface", iface_names, index=default_idx)

    if selected_iface != current_name:
        with st.spinner(f"Testing capture on {selected_iface}..."):
            sel_resp = requests.post(f"{INTERFACE_API_URL}/select", json={"name": selected_iface})
        if sel_resp.status_code != 200:
            detail = sel_resp.json().get("detail", "Selection failed")
            st.sidebar.error(detail)
            skip = st.sidebar.checkbox("Select anyway (skip capture test)")
            if skip and st.sidebar.button("Force select"):
                requests.post(
                    f"{INTERFACE_API_URL}/select",
                    json={"name": selected_iface, "skip_test": True}
                )
                st.rerun()
        else:
            current = sel_resp.json()
            st.sidebar.success(f"{selected_iface} verified and selected ✅")

    if current:
        info = current["interface"]
        st.sidebar.markdown(f"**Type:** {info['type']}")
        st.sidebar.markdown(f"**IPv4:** {info['ipv4']}  ·  **Subnet:** {info['subnet']}")
        st.sidebar.markdown(f"**Gateway:** {info['gateway']}")
        st.sidebar.markdown(f"**MAC:** {info['mac']}")
        st.sidebar.markdown(f"**Status:** {info['status']}")
        st.sidebar.markdown(f"**Speed:** {info['speed_mbps']} Mbps")
        st.sidebar.markdown(f"**Capture State:** {current['capture_state']}")
        if current.get("state_started_at"):
            st.sidebar.caption(f"Started: {current['state_started_at']}")
        if current.get("last_packet_at"):
            st.sidebar.caption(f"Last packet: {current['last_packet_at']}")

        with st.sidebar.expander("Selection history"):
            for h in reversed(current.get("history", [])):
                st.write(f"{h['name']} — {h['selected_at']}")
else:
    st.sidebar.warning("No interfaces detected.")

# --- Status card on main NIDS page ---
st.markdown("### 🌐 Current Interface")
if current:
    info = current["interface"]
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Interface", info["name"])
    c2.metric("Status", info["status"])
    c3.metric("IPv4", info["ipv4"])
    c4.metric("Speed", f"{info['speed_mbps']} Mbps")
    st.caption(
        f"MAC: {info['mac']} · Type: {info['type']} · Gateway: {info['gateway']} · "
        f"Subnet: {info['subnet']} · Packets sent/recv: {info['packets_sent']}/{info['packets_received']}"
    )
else:
    st.error("No interface available. Please select one from the sidebar.")