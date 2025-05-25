# 🛡️ AI-Powered SIEM for SSH Honeypot Logs

This project implements an AI-driven SIEM system that collects and monitors SSH honeypot activity (via Cowrie), detects anomalies using machine learning, visualizes data through a real-time dashboard, and sends alert notifications via email.

## 🚀 Features

- 🔐 SSH honeypot via Dockerized Cowrie
- 📦 Logs shipped to Elasticsearch using Filebeat
- 📊 Real-time anomaly detection with Isolation Forest
- 📈 Streamlit dashboard with live plots and filters
- 📬 Email alerts using Brevo API (SMTP)
- 🧠 Automatically launches dashboard on detection

---

## 🧰 Tech Stack

- **Cowrie** – SSH honeypot
- **Docker + ELK Stack** – Log ingestion and search
- **Python** – Data processing and ML
- **Scikit-learn** – Anomaly detection
- **Plotly** – Data visualization
- **Streamlit** – Interactive dashboard
- **Brevo** – Email alerting

---

## 📂 Project Structure

```
cowrie/
├── docker-compose.yml         # Deploys Cowrie + Elasticsearch + Kibana
├── filebeat-config.yml        # Configures log shipping
├── cowrie-logs/               # Cowrie log output
├── session-logs/              # Captured attacker sessions

ai-engine/
├── detect_anomalies.py        # Runs ML detection, saves anomalies
├── app.py                     # Streamlit dashboard UI
├── anomalies.csv              # Anomaly output
├── requirements.txt           # Python dependencies

alerting/
├── alert_manager.py           # Sends Brevo email alerts
```

---

## 🛠️ Setup & Usage

### 1. 🚦 Start Honeypot (Cowrie)

```bash
cd cowrie
docker-compose up -d
```

- Cowrie logs are saved locally and shipped to Elasticsearch using Filebeat.
- Confirm logs are visible in Kibana or via Elasticsearch queries.

### 2. 📦 Install Python Dependencies

```bash
pip install -r ai-engine/requirements.txt
```

### 3. 🧪 Run Detection Script

```bash
python ai-engine/detect_anomalies.py
```

- Performs log query, processes features, and applies anomaly detection
- If anomalies are detected:
  - Saves to `anomalies.csv`
  - Triggers Streamlit dashboard (if not already open)
  - Sends email alerts via Brevo

### 4. 📊 Launch Dashboard Manually (Optional)

```bash
streamlit run ai-engine/app.py
```

---

## 📬 Email Alerts

- Configure your SMTP/Brevo credentials inside `alerting/alert_manager.py`
- Alerts are triggered automatically on detection of anomalies

---

## 🧠 Machine Learning

- **Model**: Isolation Forest
- **Features Used**:
  - Time of day
  - Command frequency
  - IP frequency
  - Session duration
  - Login attempts

---

## 📌 Sample Dashboard

- Top IPs and session stats
- Command pattern visualizations
- Auto-refreshing plots

---

## 👤 Author

Victor David Sarkibaka  
[GitHub](https://github.com/yourusername) | [LinkedIn](https://linkedin.com/in/yourprofile) | victor.baka16@gmail.com

---
