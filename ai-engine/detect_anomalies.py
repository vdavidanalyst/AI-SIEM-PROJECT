#!/usr/bin/env python
# coding: utf-8

# In[29]:


import warnings
from datetime import datetime
from elasticsearch import Elasticsearch
from sklearn.ensemble import IsolationForest
import pandas as pd


# In[30]:


import warnings
import pandas as pd
from sklearn.ensemble import IsolationForest
from elasticsearch import Elasticsearch
from ipaddress import ip_network, ip_address
import numpy as np

warnings.filterwarnings("ignore")

# Configuration
SUSPICIOUS_SUBNETS = ["10.0.0.0/8", "192.168.0.0/16"]
FAILURE_THRESHOLD = 5
MIN_SESSION_DURATION = 5
MAX_SESSION_DURATION = 1800

def safe_get(obj, key, default=""):
    """Safely get value from nested dicts/lists."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    elif isinstance(obj, list):
        return obj[0].get(key, default) if len(obj) > 0 else default
    return default

def fetch_logs(es_client, index_pattern="cowrie-*", size=5000):
    """Fetch logs with error handling."""
    try:
        response = es_client.search(
            index=index_pattern,
            body={"query": {"match_all": {}}, "size": size}
        )
        print(f"Fetched {len(response['hits']['hits'])} logs")
        return response['hits']['hits']
    except Exception as e:
        print(f"Elasticsearch error: {e}")
        return []

def is_suspicious_ip(ip):
    """Check if IP is in suspicious ranges."""
    try:
        return any(ip_address(ip) in ip_network(subnet) for subnet in SUSPICIOUS_SUBNETS)
    except:
        return False

def calculate_features(logs):
    """Engineer features with debug output."""
    df = pd.DataFrame([hit['_source'] for hit in logs])
    
    # Debug: Show available columns
    print("\n[DEBUG] Available columns in logs:")
    print(df.columns.tolist())
    
    # Timestamp features
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['hour'] = df['timestamp'].dt.hour
    df['day_of_week'] = df['timestamp'].dt.dayofweek
    
    # Enhanced command extraction
    def get_command(x):
        if isinstance(x.get('input'), str):
            return x['input']
        elif isinstance(x.get('input'), list) and len(x['input']) > 0:
            return x['input'][0]
        elif isinstance(x.get('message'), str):
            return x['message']
        return str(x.get('eventid', ''))

    df['command'] = df.apply(get_command, axis=1)
    print("\n[DEBUG] Top 10 commands found:")
    print(df['command'].value_counts().head(10))
    
    # Command frequency
    df['command_count'] = df['command'].map(
        lambda x: df['command'].value_counts().get(x, 0))
    
    # IP analysis
    df['src_ip'] = df['src_ip'].fillna('0.0.0.0')
    df['is_private_ip'] = df['src_ip'].apply(is_suspicious_ip)
    df['ip_frequency'] = df['src_ip'].map(
        lambda x: df['src_ip'].value_counts().get(x, 0))
    
    # Session analysis
    df['session'] = df['session'].fillna('no-session')
    session_groups = df.groupby('session')['timestamp']
    df['session_duration'] = session_groups.transform(
        lambda x: (x.max() - x.min()).total_seconds()
    ).fillna(0)
    
    # Failed logins
    df['is_failed'] = df['eventid'] == 'cowrie.login.failed'
    df['failures_per_ip'] = df['src_ip'].map(
        df[df['is_failed']]['src_ip'].value_counts()).fillna(0)
    
    return df

def detect_anomalies(logs):
    """Run anomaly detection with detailed reporting."""
    if not logs:
        print("No logs to analyze")
        return None

    try:
        df = calculate_features(logs)
        
        # Feature selection
        features = df[[
            'hour',
            'day_of_week',
            'command_count',
            'ip_frequency',
            'failures_per_ip',
            'session_duration'
        ]].fillna(0).astype(float)
        
        # Dynamic contamination
        contamination = min(0.1, max(0.01, 10 / len(df)))
        print(f"\nAnalyzing {len(df)} events with contamination={contamination:.2f}")
        
        model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=200
        )
        df['anomaly_score'] = model.fit_predict(features)
        df['is_anomaly'] = df['anomaly_score'] == -1
        
        return df
    except Exception as e:
        print(f"Detection failed: {e}")
        return None

if __name__ == "__main__":
    es = Elasticsearch("http://localhost:9200")
    print("Fetching logs...")
    logs = fetch_logs(es)
    
    if logs:
        print("\nDetecting anomalies...")
        results = detect_anomalies(logs)
        
        if results is not None:
            anomalies = results[results['is_anomaly']]
            if not anomalies.empty:
                print("\n=== SECURITY ALERTS ===")
                print(f"Detected {len(anomalies)} suspicious events")
                
                print("\n[ATTACK PATTERNS]")
                print("Top malicious commands:")
                print(anomalies['command'].value_counts().head(10))
                
                print("\nTop attacking IPs:")
                print(anomalies['src_ip'].value_counts().head(5))
                
                print("\n[SAMPLE EVENTS]")
                print(anomalies[['timestamp', 'src_ip', 'command', 
                               'session_duration', 'failures_per_ip']].head())
                
                anomalies.to_csv("anomalies.csv", index=False)
                print(f"\nSaved {len(anomalies)} anomalies to anomalies.csv")
            else:
                print("No anomalies detected")
# At the end of your anomaly detection logic (after anomalies.to_csv())
if not anomalies.empty:
    try:
        from alerting.alert_manager import AlertManager
        alert_manager = AlertManager()
        alert_manager.send_alert("anomalies.csv")
    except ImportError:
        print("Alerting module not found - skipping notifications")
    except Exception as e:
        print(f"Alerting failed: {e}")


# In[ ]:




