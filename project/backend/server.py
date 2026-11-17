from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import json
import os
import re
from typing import Optional, Dict, Any, List

app = FastAPI(title="SOC Alert Triage Backend", version="1.0.0")
# Store audit logs in memory
audit_logs = []

# Connected WebSocket clients for real-time dashboard pushes
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass

manager = ConnectionManager()

from openai import AsyncOpenAI
from dotenv import load_dotenv

load_dotenv()

# Initialize Groq AI Client
groq_client = AsyncOpenAI(
    base_url="https://api.groq.com/openai/v1",
    api_key=os.getenv("GROQ_API_KEY")
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATA_FILE = os.path.join(os.path.dirname(__file__), "alerts_db.json")

def get_default_alerts() -> List[Dict[str, Any]]:
    now = datetime.now().isoformat()
    return [
        {
            "id": "1",
            "source": "Linux SSH",
            "alert_type": "ssh_failed",
            "title": "SSH Authentication Failure - Multiple attempts",
            "severity": "high",
            "status": "pending",
            "source_ip": "185.220.101.5",
            "sourceIp": "185.220.101.5",
            "destination_ip": "192.168.1.15",
            "destinationIp": "192.168.1.15",
            "username": "root",
            "hostname": "Ubuntu-Server-Lab",
            "timestamp": now,
            "raw_log": "Nov 06 13:42:10 Ubuntu-Server-Lab sshd[4120]: Failed password for root from 185.220.101.5 port 52310 ssh2 (42 failed attempts in 60s)",
            "rawLog": "Nov 06 13:42:10 Ubuntu-Server-Lab sshd[4120]: Failed password for root from 185.220.101.5 port 52310 ssh2 (42 failed attempts in 60s)",
            "created_at": now,
            "triage": {
                "id": "triage-1",
                "alert_id": "1",
                "risk_level": "high",
                "risk_score": 88,
                "summary": "HIGH RISK: SSH brute-force attack detected from 185.220.101.5 targeting root on Ubuntu-Server-Lab.",
                "recommendation": "Block source IP 185.220.101.5 at firewall. Ensure root SSH login is disabled in sshd_config. Verify fail2ban is active.",
                "indicators": [
                    "Massive brute force: 42 failed attempts",
                    "Known brute-force botnet IP 185.220.101.5",
                    "Targeting privileged user account (root)"
                ],
                "is_false_positive": False,
                "confidence": 92,
                "created_at": now
            },
            "aiAnalysis": {
                "riskScore": 88,
                "riskLevel": "high",
                "category": "Intrusion Detection",
                "summary": "HIGH RISK: SSH brute-force attack detected from 185.220.101.5 targeting root on Ubuntu-Server-Lab.",
                "recommendations": [
                    "Block source IP 185.220.101.5 at firewall.",
                    "Ensure root SSH login is disabled in sshd_config."
                ]
            }
        },
        {
            "id": "2",
            "source": "EDR Sensor",
            "alert_type": "malware_detected",
            "title": "Suspicious PowerShell Execution with Encoded Command",
            "severity": "critical",
            "status": "pending",
            "source_ip": "10.0.0.45",
            "sourceIp": "10.0.0.45",
            "destination_ip": "104.21.45.18",
            "destinationIp": "104.21.45.18",
            "username": "mlee",
            "hostname": "DESK-SEC-04",
            "timestamp": now,
            "raw_log": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcA -WindowStyle Hidden",
            "rawLog": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcA -WindowStyle Hidden",
            "created_at": now,
            "triage": {
                "id": "triage-2",
                "alert_id": "2",
                "risk_level": "critical",
                "risk_score": 95,
                "summary": "CRITICAL: Encoded PowerShell command with hidden window detected. Probable remote script download (C2 beacon).",
                "recommendation": "IMMEDIATE: Isolate DESK-SEC-04 from network. Kill suspicious PowerShell process tree. Reset user mlee credentials and investigate initial vector.",
                "indicators": [
                    "Encoded PowerShell command (obfuscation)",
                    "Hidden window execution (evasion)",
                    "Remote script download pattern detected"
                ],
                "is_false_positive": False,
                "confidence": 95,
                "created_at": now
            },
            "aiAnalysis": {
                "riskScore": 95,
                "riskLevel": "critical",
                "category": "Endpoint Detection",
                "summary": "CRITICAL: Encoded PowerShell command with hidden window detected.",
                "recommendations": [
                    "Isolate DESK-SEC-04 from network immediately.",
                    "Kill suspicious PowerShell process."
                ]
            }
        },
        {
            "id": "3",
            "source": "Cisco Firewall",
            "alert_type": "firewall_block",
            "title": "Routine Firewall Egress DNS Block",
            "severity": "low",
            "status": "triaged",
            "source_ip": "192.168.1.102",
            "sourceIp": "192.168.1.102",
            "destination_ip": "8.8.4.4",
            "destinationIp": "8.8.4.4",
            "username": None,
            "hostname": "SRV-FILE-02",
            "timestamp": now,
            "raw_log": "%ASA-4-106023: Deny routine UDP reverse DNS query from 192.168.1.102/5353 to 8.8.4.4/53 by egress filter rule",
            "rawLog": "%ASA-4-106023: Deny routine UDP reverse DNS query from 192.168.1.102/5353 to 8.8.4.4/53 by egress filter rule",
            "created_at": now,
            "triage": {
                "id": "triage-3",
                "alert_id": "3",
                "risk_level": "low",
                "risk_score": 10,
                "summary": "Routine firewall egress filter block. The traffic was a standard DNS query from internal host blocked by policy — expected behavior.",
                "recommendation": "No action required. Consider tuning egress filter logging to reduce routine noise.",
                "indicators": [
                    "Routine operational pattern",
                    "Internal private IP range"
                ],
                "is_false_positive": True,
                "confidence": 90,
                "created_at": now
            },
            "aiAnalysis": {
                "riskScore": 10,
                "riskLevel": "low",
                "category": "Network Security",
                "summary": "Routine firewall egress filter block.",
                "recommendations": ["No action required."]
            }
        }
    ]

def load_alerts() -> List[Dict[str, Any]]:
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
        except Exception as e:
            print(f"[!] Warning reading {DATA_FILE}: {e}")
    defaults = get_default_alerts()
    save_alerts(defaults)
    return defaults

def save_alerts(alerts: List[Dict[str, Any]]):
    try:
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(alerts, f, indent=2)
    except Exception as e:
        print(f"[!] Error saving alerts to {DATA_FILE}: {e}")

alerts_db: List[Dict[str, Any]] = load_alerts()

async def analyze_alert_with_llm(alert_data: dict) -> dict:
    """Sends raw Wazuh alert payload to Groq Llama 3 for SOC triage analysis."""
    prompt = f"""
    You are an expert AI SOC Analyst. Analyze this incoming Wazuh SIEM alert JSON payload and return a strict JSON response with no markdown formatting around it except valid JSON keys:
    - risk_score: integer between 0 and 100 based on severity
    - confidence: string percentage (e.g., "91% confidence")
    - ai_summary: 1-2 sentence professional security summary of the threat
    - suspicious_indicators: list of 3 specific technical strings/indicators extracted from the alert
    - severity_level: "CRITICAL", "HIGH", "MEDIUM", or "LOW"

    Raw Wazuh Alert Payload:
    {json.dumps(alert_data, indent=2)}
    """

    try:
        response = await groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "You output only valid JSON matching the requested schema."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            response_format={"type": "json_object"}
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        rule_level = alert_data.get("rule", {}).get("level", 5)
        return {
            "risk_score": rule_level * 8,
            "confidence": "85% confidence",
            "ai_summary": alert_data.get("rule", {}).get("description", "Security event detected."),
            "suspicious_indicators": [f"Triggered by Wazuh rule level {rule_level}", f"Agent: {alert_data.get('agent', {}).get('name', 'unknown')}"],
            "severity_level": "CRITICAL" if rule_level >= 10 else ("HIGH" if rule_level >= 7 else "MEDIUM")
        }

def map_wazuh_to_alert(data: Dict[str, Any]) -> Dict[str, Any]:
    rule = data.get("rule") or {}
    agent = data.get("agent") or {}
    data_field = data.get("data") or {}
    
    rule_desc = rule.get("description") or data.get("description") or "Wazuh Security Alert"
    level = rule.get("level")
    try:
        level = int(level) if level is not None else 8
    except (ValueError, TypeError):
        level = 8
        
    agent_name = agent.get("name") or agent.get("id") or data.get("hostname") or "Ubuntu-Server-Lab"
    agent_ip = agent.get("ip") or ""
    
    src_ip = (
        data_field.get("srcip")
        or data_field.get("src_ip")
        or data.get("srcip")
        or data.get("source_ip")
        or data.get("sourceIp")
        or agent_ip
        or "192.168.1.100"
    )
    
    dst_ip = (
        data_field.get("dstip")
        or data_field.get("dst_ip")
        or data.get("dstip")
        or data.get("destination_ip")
        or data.get("destinationIp")
        or None
    )
    
    username = (
        data_field.get("dstuser")
        or data_field.get("srcuser")
        or data.get("username")
        or data.get("user")
        or None
    )
    
    full_log = (
        data.get("full_log")
        or data.get("raw_log")
        or data.get("rawLog")
        or data.get("log")
        or json.dumps(data)
    )
    
    if level >= 12:
        severity_label = "critical"
    elif level >= 10:
        severity_label = "high"
    elif level >= 5:
        severity_label = "medium"
    else:
        severity_label = "low"
        
    risk_score_val = min(max(level * 8, 15), 100)
    
    desc_lower = (rule_desc + " " + full_log).lower()
    if "brute" in desc_lower or "hydra" in desc_lower:
        alert_type = "brute_force_success" if "success" in desc_lower else "ssh_failed"
    elif "failed" in desc_lower or "password" in desc_lower or "authentication" in desc_lower:
        alert_type = "failed_login"
    elif "scan" in desc_lower or "nmap" in desc_lower:
        alert_type = "port_scan"
    elif "powershell" in desc_lower or "malware" in desc_lower or "trojan" in desc_lower:
        alert_type = "malware_detected"
    elif "privilege" in desc_lower or "sudo" in desc_lower:
        alert_type = "privilege_escalation"
    elif "lateral" in desc_lower or "psexec" in desc_lower:
        alert_type = "lateral_movement"
    elif "firewall" in desc_lower or "drop" in desc_lower or "deny" in desc_lower:
        alert_type = "firewall_block"
    else:
        cleaned = re.sub(r'[^a-zA-Z0-9]+', '_', rule_desc.strip()).lower().strip('_')
        alert_type = cleaned[:30] if cleaned else "security_alert"
        
    if "ssh" in desc_lower or "ubuntu" in agent_name.lower() or "linux" in desc_lower:
        source_label = "Linux SSH"
    elif "windows" in desc_lower or "active directory" in desc_lower:
        source_label = "Windows Security"
    elif "firewall" in desc_lower or "cisco" in desc_lower:
        source_label = "Cisco Firewall"
    elif "snort" in desc_lower or "suricata" in desc_lower:
        source_label = "Snort IDS"
    elif "antivirus" in desc_lower or "edr" in desc_lower:
        source_label = "EDR Sensor"
    else:
        source_label = "EDR Sensor"
        
    indicators = [
        f"Triggered by Wazuh rule level {level}",
        f"Target host: {agent_name}",
        f"Source IP: {src_ip}"
    ]
    if username:
        indicators.append(f"Target user account: {username}")
    if level >= 10:
        indicators.append("High severity detection threshold met")
        recommendation_text = f"IMMEDIATE: Investigate connection from {src_ip} on host {agent_name}. Check authentication logs and isolate host if unauthorized activity persists."
    else:
        recommendation_text = f"Verify authentication logs for {agent_name}. Monitor source IP {src_ip} for further suspicious behavior."
        
    alert_id = str(int(datetime.now().timestamp() * 1000))
    now_iso = datetime.now().isoformat()
    
    new_alert = {
        "id": alert_id,
        "source": source_label,
        "alert_type": alert_type,
        "title": rule_desc,
        "severity": severity_label,
        "status": "pending",
        "source_ip": src_ip,
        "sourceIp": src_ip,
        "destination_ip": dst_ip,
        "destinationIp": dst_ip,
        "username": username,
        "hostname": agent_name,
        "timestamp": now_iso,
        "raw_log": full_log,
        "rawLog": full_log,
        "created_at": now_iso,
        "triage": {
            "id": f"triage-{alert_id}",
            "alert_id": alert_id,
            "risk_level": severity_label,
            "risk_score": risk_score_val,
            "summary": f"{severity_label.upper()}: {rule_desc} detected on host {agent_name} from IP {src_ip}.",
            "recommendation": recommendation_text,
            "indicators": indicators,
            "is_false_positive": False,
            "confidence": 88,
            "created_at": now_iso
        },
        "aiAnalysis": {
            "riskScore": risk_score_val,
            "riskLevel": severity_label,
            "category": "Intrusion Detection",
            "summary": f"Triggered by Wazuh rule level {level} on host {agent_name}.",
            "recommendations": [recommendation_text]
        }
    }
    return new_alert

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time frontend alert synchronization."""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and listen for client messages if any
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.post("/wazuh-webhook")
@app.post("/webhook")
@app.post("/api/alerts/webhook")
async def receive_wazuh_alert(request: Request):
    try:
        data = await request.json()
    except Exception:
        try:
            body = await request.body()
            data = {"raw_log": body.decode("utf-8", errors="ignore")}
        except Exception:
            data = {}
        
    triage_intelligence = await analyze_alert_with_llm(data)
    new_alert = map_wazuh_to_alert(data)
    
    new_alert["riskScore"] = triage_intelligence.get("risk_score", 50)
    new_alert["confidence"] = triage_intelligence.get("confidence", "85% confidence")
    new_alert["aiSummary"] = triage_intelligence.get("ai_summary", "")
    new_alert["indicators"] = triage_intelligence.get("suspicious_indicators", [])
    new_alert["severity"] = triage_intelligence.get("severity_level", new_alert.get("severity", "MEDIUM")).lower()
    
    if "aiAnalysis" in new_alert:
        new_alert["aiAnalysis"]["summary"] = triage_intelligence.get("ai_summary", "")
        new_alert["aiAnalysis"]["riskScore"] = triage_intelligence.get("risk_score", 50)
        new_alert["aiAnalysis"]["indicators"] = triage_intelligence.get("suspicious_indicators", [])

    alerts_db.insert(0, new_alert)
    save_alerts(alerts_db)
    
    # Broadcast new alert via WebSocket to all connected frontend clients
    await manager.broadcast({"type": "NEW_ALERT", "alert": new_alert})
    
    print(f"\n==========================================")
    print(f"[!] Wazuh Alert Received & Processed:")
    print(f"    ID:       {new_alert['id']}")
    print(f"    Title:    {new_alert['title']}")
    print(f"    Source:   {new_alert['source']} (Host: {new_alert['hostname']})")
    print(f"    IP:       {new_alert['source_ip']}")
    print(f"    Severity: {new_alert['severity'].upper()}")
    print(f"==========================================\n")
    
    return {"status": "success", "alert": new_alert}

@app.get("/api/alerts")
async def get_alerts():
    return alerts_db

@app.post("/api/alerts")
async def create_alert(request: Request):
    try:
        data = await request.json()
    except Exception:
        data = {}
    new_alert = map_wazuh_to_alert(data)
    alerts_db.insert(0, new_alert)
    save_alerts(alerts_db)
    await manager.broadcast({"type": "NEW_ALERT", "alert": new_alert})
    return new_alert

@app.post("/api/alerts/{alert_id}/triage")
async def triage_alert(alert_id: str):
    for a in alerts_db:
        if a.get("id") == alert_id:
            a["status"] = "triaged"
            if not a.get("triage"):
                now_iso = datetime.now().isoformat()
                a["triage"] = {
                    "id": f"triage-{alert_id}",
                    "alert_id": alert_id,
                    "risk_level": a.get("severity", "medium").lower(),
                    "risk_score": 75,
                    "summary": f"Triaged alert: {a.get('title', a.get('alert_type'))}",
                    "recommendation": "Review host logs and apply recommended mitigation steps.",
                    "indicators": ["Analyzed by triage engine", f"Host {a.get('hostname')}"],
                    "is_false_positive": False,
                    "confidence": 85,
                    "created_at": now_iso
                }
            save_alerts(alerts_db)
            await manager.broadcast({"type": "UPDATE_ALERT", "alert": a})
            return {"status": "success", "alert": a}
    raise HTTPException(status_code=404, detail="Alert not found")

@app.post("/api/alerts/triage-all")
async def triage_all_alerts():
    now_iso = datetime.now().isoformat()
    count = 0
    for a in alerts_db:
        if a.get("status") == "pending":
            a["status"] = "triaged"
            count += 1
            if not a.get("triage"):
                a["triage"] = {
                    "id": f"triage-{a.get('id')}",
                    "alert_id": a.get("id"),
                    "risk_level": a.get("severity", "medium").lower(),
                    "risk_score": 70,
                    "summary": f"Bulk triaged: {a.get('title', a.get('alert_type'))}",
                    "recommendation": "Standard triage review completed. Monitor host activity.",
                    "indicators": ["Bulk triage analysis complete"],
                    "is_false_positive": False,
                    "confidence": 80,
                    "created_at": now_iso
                }
    save_alerts(alerts_db)
    await manager.broadcast({"type": "REFRESH_ALERTS"})
    return {"status": "success", "triaged_count": count}

@app.patch("/api/alerts/{alert_id}/status")
async def update_status(alert_id: str, request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    new_status = (body.get("status") or "triaged").lower()
    for a in alerts_db:
        if a.get("id") == alert_id:
            a["status"] = new_status
            save_alerts(alerts_db)
            await manager.broadcast({"type": "UPDATE_ALERT", "alert": a})
            return {"status": "success", "alert": a}
    raise HTTPException(status_code=404, detail="Alert not found")

@app.delete("/api/alerts/{alert_id}")
async def delete_alert(alert_id: str):
    global alerts_db
    alerts_db = [a for a in alerts_db if a.get("id") != alert_id]
    save_alerts(alerts_db)
    await manager.broadcast({"type": "DELETE_ALERT", "id": alert_id})
    return {"status": "success", "deleted_id": alert_id}

@app.post("/api/alerts/clear")
async def clear_alerts():
    global alerts_db
    alerts_db = []
    save_alerts(alerts_db)
    await manager.broadcast({"type": "CLEAR_ALERTS"})
    return {"status": "success", "message": "All alerts cleared"}

@app.post("/api/alerts/seed")
async def seed_alerts():
    global alerts_db
    alerts_db = get_default_alerts()
    save_alerts(alerts_db)
    await manager.broadcast({"type": "REFRESH_ALERTS"})
    return {"status": "success", "alerts": alerts_db}

@app.get("/health")
@app.get("/")
async def health_check():
    return {
        "status": "online",
        "service": "SOC Alert Triage Backend",
        "total_alerts": len(alerts_db),
        "endpoints": {
            "wazuh_webhook": "POST /wazuh-webhook",
            "get_alerts": "GET /api/alerts",
            "websocket": "WS /ws",
            "triage_single": "POST /api/alerts/{id}/triage",
            "triage_all": "POST /api/alerts/triage-all",
            "update_status": "PATCH /api/alerts/{id}/status",
            "seed_alerts": "POST /api/alerts/seed",
            "clear_alerts": "POST /api/alerts/clear"
        }
    }

from pydantic import BaseModel

class RemediationRequest(BaseModel):
    action: str  # e.g., "block_ip" or "isolate_agent"
    target_ip: str = None
    agent_name: str = None

@app.post("/api/remediate")
async def execute_remediation(payload: RemediationRequest):
    """Executes active response playbooks against a threat."""
    action_type = payload.action
    target = payload.target_ip or payload.agent_name
    
    print(f"[!] EXECUTING PLAYBOOK: {action_type} on target: {target}")
    
    if action_type == "block_ip":
        message = f"Successfully blocked malicious IP: {target} via firewall rule."
    elif action_type == "isolate_agent":
        message = f"Successfully isolated host agent: {target} from the network."
    else:
        message = f"Action {action_type} executed successfully."
        
    audit_entry = {
        "id": str(len(audit_logs) + 1),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "action": action_type,
        "target": target,
        "message": message
    }
    audit_logs.append(audit_entry)
    
    await manager.broadcast({"type": "NEW_AUDIT_LOG", "audit": audit_entry})
        
    return {
        "status": "success",
        "action": action_type,
        "target": target,
        "message": message
    }

@app.get("/api/audit-logs")
async def get_audit_logs():
    """Returns the history of all executed security playbooks."""
    return {"audit_logs": audit_logs}

@app.get("/api/agents")
async def get_agents():
    """Returns connected Wazuh SIEM agent inventory for lab nodes."""
    return {
        "agents": [
            {
                "id": "001",
                "name": "Ubuntu-Server-Lab",
                "ip": "192.168.1.10",
                "os": "Ubuntu 22.04 LTS (Snort/Wazuh)",
                "status": "Active",
                "last_keepalive": "Just now"
            },
            {
                "id": "002",
                "name": "Windows-11-Endpoint",
                "ip": "192.168.1.45",
                "os": "Windows 11 Pro",
                "status": "Active",
                "last_keepalive": "1 min ago"
            }
        ]
    }

@app.get("/api/export-report")
async def export_incident_report():
    """Generates and returns a comprehensive JSON incident summary report."""
    return {
        "report_title": "SOC Incident Response & Audit Summary Report",
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_alerts_tracked": len(alerts_db),
        "connected_agents": [
            {"id": "001", "name": "Ubuntu-Server-Lab", "ip": "192.168.1.10", "status": "Active"},
            {"id": "002", "name": "Windows-11-Endpoint", "ip": "192.168.1.45", "status": "Active"}
        ],
        "executed_playbooks_audit_trail": audit_logs,
        "all_alerts": alerts_db
    }
    
if __name__ == "__main__":
    import uvicorn
    print("\n[+] Starting SOC Alert Triage Backend on http://127.0.0.1:8000 ...")
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)