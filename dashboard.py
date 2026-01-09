import streamlit as st
import requests
import pandas as pd

API = "http://localhost:5000"

st.set_page_config(layout="wide")
st.title("🔐 DevSecOps Security Analytics Dashboard")

# -----------------------------
# Summary Metrics
# -----------------------------
summary = requests.get(f"{API}/summary").json()

c1, c2, c3, c4 = st.columns(4)
c1.metric("CRITICAL", summary.get("CRITICAL", 0))
c2.metric("HIGH", summary.get("HIGH", 0))
c3.metric("MEDIUM", summary.get("MEDIUM", 0))
c4.metric("LOW", summary.get("LOW", 0))

# -----------------------------
# Latest Vulnerabilities
# -----------------------------
data = requests.get(f"{API}/latest").json()

df = pd.DataFrame(data, columns=[
    "Timestamp",
    "Image",
    "Severity",
    "Vulnerability ID",
    "Package",
    "Fixed Version",
    "Title"
])

st.subheader("Latest Vulnerabilities (Last 1000)")
st.dataframe(df, use_container_width=True)
