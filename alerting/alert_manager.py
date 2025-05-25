#!/usr/bin/env python
# coding: utf-8

# In[22]:


# alerting/alert_manager.py
import pandas as pd
import socket
from pathlib import Path
from pprint import pprint
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException


# In[23]:


class AlertManager:
    def __init__(self):
        """Brevo (Sendinblue) API configuration"""
        self.api_key = "API_KEY"  # Replace with your actual Brevo API key
        self.sender_email = "vdanalyst3@gmail.com"  # Must be verified in Brevo
        self.sender_name = "SIEM Alert System"
        self.recipients = ["security.alerts@yourdomain.com", "vdanalyst1@gmail.com"]
        self.hostname = socket.gethostname()

        # Set up Brevo API client
        configuration = sib_api_v3_sdk.Configuration()
        configuration.api_key['api-key'] = self.api_key
        self.api_instance = sib_api_v3_sdk.TransactionalEmailsApi(
            sib_api_v3_sdk.ApiClient(configuration)
        )

    def _generate_html_body(self, body_text):
        """Generate styled HTML email body"""
        return f"""
        <html>
        <body style="font-family: Arial, sans-serif;">
            <h2 style="color: #d9534f;">SIEM Security Alert</h2>
            <div style="background: #f8f9fa; padding: 15px; border-left: 4px solid #d9534f;">
                {body_text.replace('\n', '<br>')}
            </div>
            <p style="color: #6c757d; font-size: 0.9em;">
                Host: {self.hostname} | {pd.Timestamp.now()}
            </p>
        </body>
        </html>
        """

    def send_alert(self, anomalies_file="anomalies.csv"):
        """Send alert using Brevo"""
        try:
            if not Path(anomalies_file).exists():
                print(f"⚠️ File not found: {anomalies_file}")
                return False

            df = pd.read_csv(anomalies_file)
            if df.empty:
                print("✅ No anomalies detected.")
                return False

            # Handle session duration stats safely
            if 'session_duration' in df.columns:
                longest = df['session_duration'].max()
                shortest = df['session_duration'].min()
                session_stats = [
                    f"Longest: {longest:.1f}s",
                    f"Shortest: {shortest:.1f}s"
                ]
            else:
                session_stats = ["Duration data not available"]

            alert_content = [
                f"🚨 {len(df)} Security Anomalies Detected",
                "",
                "🔍 Top Threats:",
                df['command'].value_counts().head(5).to_string(),
                "",
                "🌐 Attack Sources:",
                df['src_ip'].value_counts().head(3).to_string(),
                "",
                "⏱️ Session Analysis:",
                *session_stats,
                "",
                "⚠️ Recommended Action:",
                "1. Review anomalies.csv",
                "2. Check Kibana dashboard",
                "3. Block suspicious IPs if needed"
            ]

            # Build the HTML email
            html_body = self._generate_html_body("\n".join(alert_content))

            send_email = sib_api_v3_sdk.SendSmtpEmail(
                to=[{"email": r, "name": "SIEM Recipient"} for r in self.recipients],
                sender={"email": self.sender_email, "name": self.sender_name},
                subject=f"[SIEM Alert] Cowrie Honeypot - {self.hostname}",
                html_content=html_body
            )

            # Send email via Brevo
            response = self.api_instance.send_transac_email(send_email)
            pprint(response)
            print("✅ Brevo alert sent successfully.")
            return True

        except ApiException as e:
            print(f"⚠️ Brevo API error: {e}")
            return False
        except Exception as e:
            print(f"⚠️ Alert failed: {type(e).__name__}: {str(e)}")
            return False


# In[ ]:




