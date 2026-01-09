import streamlit as st
import requests
import pandas as pd
import plotly.express as px

API = "http://localhost:5000"

st.set_page_config(page_title="DevSecOps Security Analytics", layout="wide")
st.title("DevSecOps Security Analytics Dashboard")

# -----------------------------
# Fetch Latest Summary Metrics
# -----------------------------
try:
    summary = requests.get(f"{API}/summary").json()
except:
    st.error("Could not fetch API data. Make sure Flask API is running on localhost:5000")
    st.stop()

# -----------------------------
# Metrics Panel
# -----------------------------
c1, c2, c3, c4 = st.columns(4)
c1.metric("CRITICAL", summary.get("CRITICAL", 0))
c2.metric("HIGH", summary.get("HIGH", 0))
c3.metric("MEDIUM", summary.get("MEDIUM", 0))
c4.metric("LOW", summary.get("LOW", 0))

# -----------------------------
# Pie Chart for Severity Distribution
# -----------------------------
severity_df = pd.DataFrame({
    'Severity': ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
    'Count': [summary.get('CRITICAL', 0),
              summary.get('HIGH', 0),
              summary.get('MEDIUM', 0),
              summary.get('LOW', 0)]
})

fig_pie = px.pie(severity_df, names='Severity', values='Count',
                 color='Severity',
                 color_discrete_map={'CRITICAL':'red','HIGH':'orange','MEDIUM':'yellow','LOW':'green'},
                 title="Vulnerabilities by Severity")
st.plotly_chart(fig_pie, use_container_width=True)

# -----------------------------
# Latest Vulnerabilities Table
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

# -----------------------------
# Top 10 Images by Critical/High
# -----------------------------
top_images = df[df['Severity'].isin(['CRITICAL','HIGH'])].groupby('Image')['Severity'].count().reset_index()
top_images = top_images.sort_values(by='Severity', ascending=False).head(10)
if not top_images.empty:
    fig_bar = px.bar(top_images, x='Image', y='Severity',
                     color='Severity',
                     color_discrete_sequence=px.colors.sequential.Oranges,
                     title="Top 10 Images by Critical/High Vulnerabilities")
    st.plotly_chart(fig_bar, use_container_width=True)
else:
    st.info("No Critical/High vulnerabilities found for top images chart.")

# -----------------------------
# Historical Trend Chart
# -----------------------------
history_data = requests.get(f"{API}/history").json()
history_df = pd.DataFrame(history_data, columns=['Timestamp','Severity','Count'])
history_df['Timestamp'] = pd.to_datetime(history_df['Timestamp'])

if not history_df.empty:
    fig_trend = px.line(history_df, x='Timestamp', y='Count', color='Severity',
                        title="Vulnerability Trend Over Time")
    st.plotly_chart(fig_trend, use_container_width=True)
