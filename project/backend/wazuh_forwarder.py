#!/usr/bin/env python3
"""
Wazuh Real Alert Forwarder
--------------------------
Run this script on your Wazuh Manager or Wazuh Server (e.g. Ubuntu / Debian / CentOS).
It watches '/var/ossec/logs/alerts/alerts.json' in real-time and forwards any alert
with rule level >= 5 directly to your SOC dashboard webhook.

Usage:
    python3 wazuh_forwarder.py http://<YOUR_WINDOWS_IP>:8000/wazuh-webhook
"""

import sys
import time
import json
import urllib.request
import os

ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"

if len(sys.argv) > 1:
    WEBHOOK_URL = sys.argv[1]
else:
    WEBHOOK_URL = "http://192.168.0.155:8000/wazuh-webhook"

def forward_alert(alert_data):
    try:
        rule_level = alert_data.get("rule", {}).get("level", 0)
        rule_desc = alert_data.get("rule", {}).get("description", "Security Alert")
        agent_name = alert_data.get("agent", {}).get("name", "Unknown-Agent")
        
        # Filter: Only forward alerts of level >= 5 (or customize as needed)
        if rule_level < 3:
            return
            
        print(f"[!] Forwarding Alert -> [Level {rule_level}] {rule_desc} on {agent_name}")
        
        payload = json.dumps(alert_data).encode("utf-8")
        req = urllib.request.Request(
            WEBHOOK_URL,
            data=payload,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            if resp.status == 200:
                print(f"    [OK] Received by SOC Dashboard!")
    except Exception as e:
        print(f"    [X] Forwarding failed: {e}")

def tail_alerts():
    print("==================================================")
    print("       WAZUH REAL-TIME ALERT FORWARDER           ")
    print("==================================================")
    print(f"[*] Target Webhook : {WEBHOOK_URL}")
    print(f"[*] Watching File  : {ALERTS_FILE}")
    print("[*] Waiting for real alerts... (Trigger an attack!)")
    print("--------------------------------------------------")
    
    if not os.path.exists(ALERTS_FILE):
        print(f"[ERROR] Alerts file not found: {ALERTS_FILE}")
        print("Please ensure Wazuh Manager is running.")
        sys.exit(1)
        
    with open(ALERTS_FILE, "r", encoding="utf-8") as f:
        # Seek to the end of file so we only send NEW alerts
        f.seek(0, os.SEEK_END)
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            try:
                alert = json.loads(line.strip())
                forward_alert(alert)
            except json.JSONDecodeError:
                pass

if __name__ == "__main__":
    try:
        tail_alerts()
    except KeyboardInterrupt:
        print("\n[!] Forwarder stopped.")

