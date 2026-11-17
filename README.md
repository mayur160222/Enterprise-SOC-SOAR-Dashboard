# 🚀 Enterprise SOC Alert Triage & Response Platform (SOAR / EDR)

A full-stack Security Orchestration, Automation, and Response (SOAR) platform designed to simulate, ingest, triage, and remediate cybersecurity events in real time. Built specifically for Security Operations Center (SOC) L1 analysts and Blue Team defenders.

---

## 🚀 Key Features

- **Real-Time Webhook Ingestion:** Ingests raw security alerts and logs from virtualized lab nodes, Snort IDS sensors, and Wazuh SIEM forwarders.
- **AI-Powered Threat Triage (Groq Llama 3):** Automatically analyzes incoming security telemetry to calculate quantitative risk scores (0–100), extract Indicators of Compromise (IoCs), and generate executive summaries.
- **Real-Time WebSocket Synchronization:** Instant bidirectional communication (`/ws`) pushing new alerts to all active dashboard clients.
- **Active Response Playbooks:** One-click simulation of enterprise EDR/Firewall controls, including **Block Malicious IP** and **Isolate Host Agent**.
- **Connected Agent Inventory Panel:** Live monitoring of virtualized endpoint statuses, operating system specifications, and keepalive heartbeats.

---

## 🛠️ Tech Stack

| Component | Technologies |
|---|---|
| Frontend | React, TypeScript, Tailwind CSS, Lucide Icons, Vite |
| Backend | Python, FastAPI, Uvicorn |
| AI Engine | Groq API (Llama 3 Model) |
| Communication | WebSockets (`/ws`) and REST APIs |

---

## ⚙️ Installation & Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/mayur160222/Enterprise-SOC-SOAR-Dashboard.git

cd Enterprise-SOC-SOAR-Dashboard
```

### 2. Set Up the Backend

Navigate to the backend directory:

```bash
cd backend
```

Create and activate a Python virtual environment:

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**Mac/Linux:**
```bash
python -m venv venv
source venv/bin/activate
```

Install the required dependencies:

```bash
pip install fastapi uvicorn python-dotenv openai pydantic
```

### 3. Configure Environment Variables

Create a `.env` file inside the `backend/` directory and add your Groq API key:

```env
GROQ_API_KEY=your_groq_api_key_here
```

**Note:** Replace `your_groq_api_key_here` with your actual Groq API key. Never upload your `.env` file or expose your API key on GitHub.

### 4. Start the Backend Server

```bash
python server.py
```

### 5. Set Up the Frontend

Open a **new terminal** in the project root directory and run:

```bash
npm install
```

### 6. Start the Frontend Development Server

```bash
npm run dev
```

Open the local URL displayed in your terminal to access the SOC dashboard.

---

## 🔐 Security Notice

- Keep API keys and credentials in environment variables.
- Never commit `.env` files to GitHub.
- Use this platform in an authorized lab or testing environment.
- Active response actions are simulations unless connected to actual enforcement systems.

---

## 👨‍💻 Author

**Mayur Yadav**

GitHub: [@mayur160222](https://github.com/mayur160222)

---

⭐ If you find this project useful, consider giving it a star!
