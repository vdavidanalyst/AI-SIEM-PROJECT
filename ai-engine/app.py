#!/usr/bin/env python
# coding: utf-8

# In[4]:


import streamlit as st
import pandas as pd
import plotly.express as px
import os
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# === FILE WATCHER SETUP ===
class FileChangeHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path.endswith("anomalies.csv"):
            print("🔁 Detected anomalies.csv update, refreshing dashboard...")
            st.experimental_rerun()

def start_file_watcher():
    observer = Observer()
    handler = FileChangeHandler()
    observer.schedule(handler, path=".", recursive=False)
    observer.start()

# Start the file watcher in a background thread
threading.Thread(target=start_file_watcher, daemon=True).start()

# === DASHBOARD LOGIC BELOW ===

st.set_page_config(page_title="Anomaly Dashboard", layout="wide")
st.title("🔍 AI SIEM Anomaly Detection Dashboard")

# Load anomalies if available
anomalies_file = "anomalies.csv"
if os.path.exists(anomalies_file):
    df = pd.read_csv(anomalies_file)
    
    st.success(f"✅ Loaded {len(df)} anomalies")

    st.subheader("📊 Anomaly Summary")
    st.dataframe(df.head(20), use_container_width=True)

    st.subheader("📈 Top Attacking IPs")
    top_ips = df['src_ip'].value_counts().head(10).reset_index()
    top_ips.columns = ['IP Address', 'Count']
    st.plotly_chart(px.bar(top_ips, x='IP Address', y='Count', title="Top Attacking IPs"))

    st.subheader("💻 Suspicious Commands")
    top_cmds = df['command'].value_counts().head(10).reset_index()
    top_cmds.columns = ['Command', 'Count']
    st.plotly_chart(px.bar(top_cmds, x='Command', y='Count', title="Top Commands"))

else:
    st.warning("⚠️ No anomalies.csv file found. Run the detection script to generate it.")


# In[ ]:




