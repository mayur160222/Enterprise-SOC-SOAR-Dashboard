import urllib.request
import json
import time
import sys

BACKEND_URL = "http://127.0.0.1:8000/wazuh-webhook"

sample_attacks = [
    {
        "name": "SSH Brute Force Attack",
        "payload": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "rule": {
                "level": 12,
                "description": "sshd: brute force trying to get access to the system",
                "id": "5712",
                "groups": ["syslog", "sshd", "authentication_failures"]
            },
            "agent": {
                "id": "001",
                "name": "Ubuntu-Server-Lab",
                "ip": "192.168.1.50"
            },
            "data": {
                "srcip": "185.220.101.5",
                "dstuser": "root"
            },
            "full_log": "Nov 06 14:30:10 Ubuntu-Server-Lab sshd[14512]: Failed password for root from 185.220.101.5 port 48210 ssh2"
        }
    },
    {
        "name": "Port Scan Reconnaissance",
        "payload": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "rule": {
                "level": 8,
                "description": "Nmap / SYN stealth port scan detected",
                "id": "5301",
                "groups": ["firewall", "ids"]
            },
            "agent": {
                "id": "001",
                "name": "Ubuntu-Server-Lab",
                "ip": "192.168.1.50"
            },
            "data": {
                "srcip": "193.32.162.19"
            },
            "full_log": "Nov 06 14:31:00 Ubuntu-Server-Lab kernel: [UFW BLOCK] IN=eth0 OUT= SRC=193.32.162.19 DST=192.168.1.50 PROTO=TCP SPT=54321 DPT=22"
        }
    },
    {
        "name": "Malware / Encoded PowerShell Execution",
        "payload": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "rule": {
                "level": 14,
                "description": "Malware: Suspicious PowerShell encoded command detected",
                "id": "92001",
                "groups": ["windows", "malware", "powershell"]
            },
            "agent": {
                "id": "002",
                "name": "DESK-SEC-04",
                "ip": "10.0.0.45"
            },
            "data": {
                "dstuser": "mlee"
            },
            "full_log": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcA -WindowStyle Hidden"
        }
    }
]

def send_alert(attack):
    print(f"\n[+] Sending practical simulation: '{attack['name']}'...")
    try:
        data_bytes = json.dumps(attack["payload"]).encode("utf-8")
        req = urllib.request.Request(
            BACKEND_URL,
            data=data_bytes,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            res_data = json.loads(response.read().decode("utf-8"))
            print(f"[✓] Success! Server response: {res_data.get('status')}")
            alert = res_data.get("alert", {})
            print(f"    Alert ID:   {alert.get('id')}")
            print(f"    Title:      {alert.get('title')}")
            print(f"    Severity:   {alert.get('severity')}")
            print(f"    Risk Score: {alert.get('triage', {}).get('risk_score')}/100")
            print(f"    Status:     {alert.get('status')}")
            print(f"--> Look at your frontend browser: the alert appears at the top automatically!")
    except Exception as e:
        print(f"[X] Failed to send alert to {BACKEND_URL}: {e}")
        print("    Make sure the FastAPI backend is running: python backend/server.py")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        idx = int(sys.argv[1]) % len(sample_attacks)
        send_alert(sample_attacks[idx])
    else:
        # Send first attack by default
        send_alert(sample_attacks[0])

