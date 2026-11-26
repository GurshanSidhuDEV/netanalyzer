"""
Usage: streamlit run src/netanalyzer/dashboard.py
Run it after storing captures with:
python3 -m netanalyzer.save_captures <capture files>
"""
import os
from pathlib import Path
import pandas as pd
import streamlit as st
from netanalyzer.storage import (alerts_for, connect, list_captures, protocol_breakdown, top_talkers, traffic_over_time)

DB_PATH = os.environ.get("NETANALYZER_DB", "netanalyzer.db")
st.set_page_config(page_title="Network Traffic Analyzer", layout="wide")
st.title("Network Traffic Analyzer")

conn = connect(DB_PATH)
captures = list_captures(conn)
if captures.empty:
    st.info("No captures stored yet. Run: python3 -m netanalyzer.save_captures <capture files>")
    st.stop()
labels = {int(row.id): f"{Path(row.path).name} "
                       f"({row.alerts} alert{'' if row.alerts == 1 else 's'})"
          for row in captures.itertuples()}
capture_id = st.sidebar.selectbox("Capture", options=list(labels), format_func=labels.get)
bucket = st.sidebar.select_slider("Time bucket (seconds)", options=[1, 5, 10, 30, 60, 300], value=60)

chosen = captures[captures["id"] == capture_id].iloc[0]
proto = protocol_breakdown(conn, capture_id)
talkers = top_talkers(conn, capture_id, 10)
traffic = traffic_over_time(conn, capture_id, bucket)
alerts = alerts_for(conn, capture_id)
conn.close()

col1, col2, col3 = st.columns(3)
col1.metric("Packets", f"{int(chosen['packets']):,}")
col2.metric("Alerts", int(chosen["alerts"]))
col3.metric("Protocols seen", len(proto))

st.subheader("Alerts")
if alerts.empty:
    st.success("No alerts for this capture.")
else:
    alerts["first_seen"] = pd.to_datetime(alerts["first_seen"], unit="s")
    st.dataframe(alerts, hide_index=True)

left, right = st.columns(2)
with left:
    st.subheader("Protocol breakdown")
    st.bar_chart(proto, x="protocol", y="packets")
with right:
    st.subheader("Traffic over time")
    traffic["time"] = pd.to_datetime(traffic["bucket"], unit="s")
    st.line_chart(traffic, x="time", y="packets")

st.subheader("Top sources by bytes")
st.dataframe(talkers, hide_index=True)

st.caption("Detections: port scan (NA-001), SYN flood (NA-002), DNS tunneling (NA-003). "
"Rules are defined in the rules/ folder.")