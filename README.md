# MiniSOC ThreatLens

> **Turning security alerts into understandable attack stories.**

**MiniSOC ThreatLens** is an AI-assisted Security Operations Center (SOC) analyst layer that transforms raw security telemetry into correlated, explainable security incidents.

It combines **deterministic detection, alert correlation, attack reconstruction, MITRE ATT&CK mapping, network analytics, and AI-assisted incident explanation** into a single workflow.

[![Python](https://img.shields.io/badge/Python-3.12-blue)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104-009688)](https://fastapi.tiangolo.com/)
[![Next.js](https://img.shields.io/badge/Next.js-16-black)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue)](https://www.typescriptlang.org/)

---

## Overview

Modern security platforms can generate huge volumes of alerts. The challenge is not only detecting suspicious activity, but understanding **what those alerts mean when viewed together**.

ThreatLens focuses on the layer between detection and analyst understanding:

```text
Telemetry
    ↓
Detection
    ↓
Correlation
    ↓
Attack Reconstruction
    ↓
MITRE ATT&CK Mapping
    ↓
AI Explanation
    ↓
Response Guidance
```

### The Core Idea

ThreatLens does not try to replace established security platforms such as Wazuh, Splunk, Microsoft Sentinel, or Elastic.

Instead, it provides an **analyst intelligence layer** that helps turn individual security events and alerts into a coherent incident.

> **Existing security tools collect and detect. ThreatLens correlates, contextualizes, reconstructs, and explains.**

---

# Architecture

```text
┌──────────────────────────────────────────────────────────────────────┐
│                         MINISOC THREATLENS                          │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────┐      ┌──────────────────┐      ┌─────────────┐ │
│  │  NetSentinel    │ ───▶ │     MiniSOC      │ ───▶ │   TraceAI   │ │
│  │                 │      │                  │      │             │ │
│  │   Telemetry &   │      │ Detection +      │      │   Attack    │ │
│  │ Network Analytics│     │ Correlation      │      │Reconstruction││
│  └─────────────────┘      └────────┬─────────┘      └──────┬──────┘ │
│                                    │                         │        │
│                                    └──────────┬──────────────┘        │
│                                               ▼                       │
│                                    ┌────────────────────┐            │
│                                    │    AI Analyst      │            │
│                                    │ Explain + Guide    │            │
│                                    └─────────┬──────────┘            │
│                                              │                       │
│                         ┌────────────────────┼──────────────────┐    │
│                         ▼                    ▼                  ▼    │
│                    ┌─────────┐         ┌──────────┐       ┌────────┐│
│                    │  MITRE  │         │ AI Report│       │Response││
│                    │ ATT&CK  │         │          │       │Guidance││
│                    └─────────┘         └──────────┘       └────────┘│
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

## Three Core Layers

| Component       | Responsibility                | Key Question             |
| --------------- | ----------------------------- | ------------------------ |
| **NetSentinel** | Telemetry & network analytics | What is happening?       |
| **MiniSOC**     | Detection & correlation       | Is something suspicious? |
| **TraceAI**     | Attack reconstruction         | What actually happened?  |
| **AI Analyst**  | AI-assisted explanation       | What does it mean?       |

---

# Features

## Deterministic Detection Engine

ThreatLens uses rule-based detection rather than relying on an LLM to decide whether activity is malicious.

Current detection rules include:

| Rule ID    | Detection            | MITRE ATT&CK | Threshold             | Severity |
| ---------- | -------------------- | ------------ | --------------------- | -------- |
| `NET-001`  | Port Scanning        | T1046        | 4+ attempts / 30s     | Medium   |
| `AUTH-001` | SSH Brute Force      | T1110        | 5+ failures / 60s     | High     |
| `AUTH-002` | Login After Failures | T1078        | 3+ failures → success | High     |
| `HOST-001` | Suspicious Command   | T1059        | Known patterns        | Critical |

### Why deterministic detection?

The AI layer is deliberately separated from detection.

```text
Security Event
      ↓
Deterministic Rules
      ↓
Alert
      ↓
Correlation
      ↓
Incident
      ↓
AI Explanation
```

> **AI explains the evidence. It does not decide whether an event is an attack.**

---

## Alert Correlation

ThreatLens correlates related alerts into a unified incident using signals such as:

- Source IP
- Target host
- Time proximity
- Related entities
- Logical attack sequence
- Event relationships

Instead of presenting analysts with several disconnected alerts:

```text
Port Scan
    +
SSH Brute Force
    +
Successful Login
    +
Suspicious Command
```

ThreatLens can correlate them into a single attack narrative:

```text
Reconnaissance
      ↓
Credential Access
      ↓
Initial Access
      ↓
Execution
```

---

# TraceAI — Attack Reconstruction

TraceAI reconstructs the activity associated with an incident.

For each incident it can produce:

- **Timeline** — events in chronological order
- **Attack graph** — relationships between attackers, hosts, users, and stages
- **Kill chain stages**
- **Entities** — IP addresses, hosts, users, and other relevant objects
- **MITRE ATT&CK technique mappings**
- **Stage-by-stage incident context**

Example:

```text
10.10.10.50
      │
      ▼
Port Scan
      │
      ▼
SSH Brute Force
      │
      ▼
Successful Authentication
      │
      ▼
Suspicious Command
      │
      ▼
Execution
```

TraceAI is designed to be **deterministic and explainable**, without requiring an AI model for reconstruction.

---

# AI Analyst

ThreatLens uses AI for **incident explanation and analyst assistance**.

The AI layer can transform technical incident data into human-readable context such as:

- What happened
- Why the activity is suspicious
- Which systems and users are involved
- Relevant MITRE ATT&CK techniques
- Potential impact
- Recommended response actions

## Multi-Provider Failover

```text
Groq
  │
  │ failure
  ▼
Gemini
  │
  │ failure
  ▼
OpenRouter
  │
  │ failure
  ▼
Mock Response
```

This provides a fallback response path even when an external AI provider is unavailable.

> **AI is used for explanation, not detection.**

---

# 📡 Real-Time WebSocket Updates

ThreatLens provides real-time dashboard updates through WebSockets.

When new activity occurs:

```text
Event
  ↓
Detection
  ↓
Alert
  ↓
Incident
  ↓
WebSocket
  ↓
Dashboard
```

The dashboard can receive:

- New alerts
- Incident creation
- Incident updates
- Real-time notifications

---

# Attack Simulator

ThreatLens includes a built-in attack simulator for demonstrations and testing.

### Full Attack Simulation

```bash
curl -X POST http://localhost:8000/api/v1/simulate/full-attack
```

The simulator can demonstrate a multi-stage attack:

1. Reconnaissance
2. Credential Access
3. Initial Access
4. Execution
5. Privilege Escalation
6. Command & Control

Additional simulation endpoints are available for individual scenarios such as port scanning and SSH brute force.

> The simulator is intended for controlled demonstration and testing environments.

---

# NetSentinel

NetSentinel provides network-focused analytics over ingested telemetry.

Current capabilities include:

- Total events
- Recent activity
- Unique sources
- Unique targets
- Top source IPs
- Event-type distribution
- Network anomaly detection
- Port-scan detection
- Brute-force detection
- Beaconing detection
- Exfiltration-related anomaly detection

---

# Tech Stack

## Backend

- **Python 3.12**
- **FastAPI**
- **SQLAlchemy**
- **SQLite**
- **Pydantic**
- **WebSockets**

## Frontend

- **Next.js 16**
- **React 19**
- **TypeScript 5.7**
- **Tailwind CSS 4**
- **shadcn/ui**
- **Zustand**
- **Recharts**
- **Sonner**
- **Lucide React**

## AI Providers

- **Groq** — primary provider
- **Google Gemini** — fallback
- **OpenRouter** — fallback

## Security Intelligence

- **MITRE ATT&CK**

---

# Quick Start

## Prerequisites

Make sure you have:

- Python 3.12
- Node.js 18+
- Git
- An API key for the AI providers you intend to use

---

## 1. Clone the Repository

```bash
git clone https://github.com/shuva-kharel/ThreatLens.git
cd ThreatLens
```

---

## 2. Backend Setup

```bash
cd minisoc-backend
```

### Create a virtual environment

```bash
python -m venv .venv
```

### Windows

```powershell
.venv\Scripts\activate
```

### Linux / macOS

```bash
source .venv/bin/activate
```

### Install dependencies

```bash
pip install -r requirements.txt
```

### Create environment file

#### Windows

```powershell
copy .env.example .env
```

#### Linux / macOS

```bash
cp .env.example .env
```

Configure your `.env`:

```env
API_KEY=your-static-api-key
SECRET_KEY=your-secret-key
DATABASE_URL=sqlite:///./minisoc.db
HOST=0.0.0.0
PORT=8000

GROQ_API_KEY=your-groq-key
GEMINI_API_KEY=your-gemini-key
OPENROUTER_API_KEY=your-openrouter-key
```

### Start the backend

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Backend:

```text
http://localhost:8000
```

---

# Frontend Setup

Open another terminal:

```bash
cd minisoc-frontend
```

Install dependencies:

```bash
npm install
```

Or:

```bash
pnpm install
```

Create the environment file.

### Windows

```powershell
copy .env.example .env.local
```

### Linux / macOS

```bash
cp .env.example .env.local
```

Configure:

```env
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000/api/v1
NEXT_PUBLIC_WS_URL=ws://localhost:8000
NEXT_PUBLIC_API_KEY=your-static-api-key
NEXT_PUBLIC_APP_NAME=MiniSOC ThreatLens
```

Start the frontend:

```bash
npm run dev
```

Or:

```bash
pnpm dev
```

Frontend:

```text
http://localhost:3000
```

---

# Application URLs

| Service      | URL                            |
| ------------ | ------------------------------ |
| Dashboard    | `http://localhost:3000`        |
| Backend API  | `http://localhost:8000`        |
| Swagger Docs | `http://localhost:8000/docs`   |
| ReDoc        | `http://localhost:8000/redoc`  |
| Health Check | `http://localhost:8000/health` |

---

# Testing

## Run Backend Tests

```bash
cd minisoc-backend
pytest tests/ -v
```

## Coverage

```bash
pytest tests/ --cov=app --cov-report=html
```

## API Smoke Tests

### Health Check

```bash
curl http://localhost:8000/health
```

### Run Full Attack Simulation

```bash
curl -X POST http://localhost:8000/api/v1/simulate/full-attack
```

### List Incidents

```bash
curl http://localhost:8000/api/v1/incidents
```

---

#  API Reference

## Core

| Method | Endpoint  | Description         |
| ------ | --------- | ------------------- |
| `GET`  | `/`       | Service information |
| `GET`  | `/health` | Health check        |

## Events

| Method | Endpoint               | Description            |
| ------ | ---------------------- | ---------------------- |
| `POST` | `/api/v1/events`       | Submit an event        |
| `POST` | `/api/v1/events/batch` | Submit multiple events |
| `GET`  | `/api/v1/events`       | List recent events     |

## Alerts

| Method | Endpoint               | Description       |
| ------ | ---------------------- | ----------------- |
| `GET`  | `/api/v1/alerts`       | List alerts       |
| `GET`  | `/api/v1/alerts/{id}`  | Get alert details |
| `GET`  | `/api/v1/alerts/stats` | Alert statistics  |

## Incidents

| Method  | Endpoint                          | Description            |
| ------- | --------------------------------- | ---------------------- |
| `GET`   | `/api/v1/incidents`               | List incidents         |
| `GET`   | `/api/v1/incidents/search`        | Search incidents       |
| `GET`   | `/api/v1/incidents/{id}`          | Get incident details   |
| `PATCH` | `/api/v1/incidents/{id}`          | Update an incident     |
| `GET`   | `/api/v1/incidents/{id}/trace`    | TraceAI reconstruction |
| `GET`   | `/api/v1/incidents/{id}/mitre`    | MITRE ATT&CK mapping   |
| `POST`  | `/api/v1/incidents/{id}/analyze`  | AI analysis            |
| `POST`  | `/api/v1/incidents/{id}/response` | Record response action |

## Detection Rules

| Method | Endpoint                        | Description          |
| ------ | ------------------------------- | -------------------- |
| `GET`  | `/api/v1/detections/rules`      | List detection rules |
| `GET`  | `/api/v1/detections/rules/{id}` | Get rule details     |
| `GET`  | `/api/v1/detections/stats`      | Detection statistics |
| `GET`  | `/api/v1/detections/timeline`   | Detection timeline   |

## MITRE ATT&CK

| Method | Endpoint                        | Description                  |
| ------ | ------------------------------- | ---------------------------- |
| `GET`  | `/api/v1/mitre/techniques`      | List techniques              |
| `GET`  | `/api/v1/mitre/techniques/{id}` | Technique details            |
| `GET`  | `/api/v1/mitre/tactics`         | Techniques grouped by tactic |

## Network Analytics

| Method | Endpoint                      | Description               |
| ------ | ----------------------------- | ------------------------- |
| `GET`  | `/api/v1/network/stats`       | Network summary           |
| `GET`  | `/api/v1/network/hosts`       | Monitored hosts           |
| `GET`  | `/api/v1/network/connections` | Recent connections        |
| `GET`  | `/api/v1/network/timeline`    | Network activity timeline |
| `GET`  | `/api/v1/network/anomalies`   | Network anomalies         |

## Simulator

| Method | Endpoint                             | Description                |
| ------ | ------------------------------------ | -------------------------- |
| `GET`  | `/api/v1/simulate/scenarios`         | List simulation scenarios  |
| `POST` | `/api/v1/simulate/full-attack`       | Simulate full attack       |
| `POST` | `/api/v1/simulate/port-scan`         | Simulate port scan         |
| `POST` | `/api/v1/simulate/ssh-brute-force`   | Simulate SSH brute force   |
| `POST` | `/api/v1/simulate/credential-access` | Simulate credential access |

## Statistics & Storage

| Method | Endpoint                           | Description          |
| ------ | ---------------------------------- | -------------------- |
| `GET`  | `/api/v1/stats/overview`           | Dashboard statistics |
| `GET`  | `/api/v1/stats/incidents/timeline` | Incident timeline    |
| `GET`  | `/api/v1/storage/stats`            | Storage statistics   |

## Export

| Method | Endpoint                             | Description             |
| ------ | ------------------------------------ | ----------------------- |
| `GET`  | `/api/v1/incidents/{id}/export/csv`  | Export incident as CSV  |
| `GET`  | `/api/v1/incidents/{id}/export/json` | Export incident as JSON |
| `GET`  | `/api/v1/incidents/export/all`       | Export all incidents    |

## WebSocket

```text
ws://localhost:8000/api/v1/ws/events
```

Provides real-time event and incident updates to the frontend.

---

#  Demo

## 90-Second Attack-to-Incident Flow

### 1. Show the baseline

```bash
curl http://localhost:8000/api/v1/stats/overview
```

### 2. Trigger the simulated attack

```bash
curl -X POST http://localhost:8000/api/v1/simulate/full-attack
```

### 3. Watch the dashboard

Open:

```text
http://localhost:3000
```

The dashboard receives activity through the WebSocket connection.

### 4. Inspect the reconstructed attack

```bash
curl http://localhost:8000/api/v1/incidents/{incident_id}/trace
```

### 5. View MITRE ATT&CK mapping

```bash
curl http://localhost:8000/api/v1/incidents/{incident_id}/mitre
```

### 6. Generate AI analysis

```bash
curl -X POST http://localhost:8000/api/v1/incidents/{incident_id}/analyze
```

### 7. Record a response action

```bash
curl -X POST http://localhost:8000/api/v1/incidents/{incident_id}/response \
  -H "Content-Type: application/json" \
  -d '{"action":"block_ip","details":{"ip":"10.10.10.50"}}'
```

### Demo Flow

```text
Attack Simulation
       ↓
Telemetry
       ↓
Detection
       ↓
Alert Correlation
       ↓
Incident Creation
       ↓
TraceAI Reconstruction
       ↓
MITRE ATT&CK Mapping
       ↓
AI Analyst Explanation
       ↓
Response Action
```

---

# Project Structure

```text
ThreatLens/
│
├── minisoc-backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── events.py
│   │   │   ├── alerts.py
│   │   │   ├── incidents.py
│   │   │   ├── detections.py
│   │   │   ├── mitre.py
│   │   │   ├── netsentinel.py
│   │   │   ├── simulator.py
│   │   │   ├── stats.py
│   │   │   ├── export.py
│   │   │   └── websocket.py
│   │   │
│   │   ├── core/
│   │   │   ├── detection.py
│   │   │   ├── correlation.py
│   │   │   ├── trace_ai.py
│   │   │   ├── ai_analyst.py
│   │   │   ├── ai_providers.py
│   │   │   ├── network_anomaly.py
│   │   │   └── cleanup.py
│   │   │
│   │   ├── models/
│   │   │   ├── database.py
│   │   │   └── schemas.py
│   │   │
│   │   ├── services/
│   │   │   └── event_service.py
│   │   │
│   │   ├── db/
│   │   └── main.py
│   │
│   ├── tests/
│   ├── requirements.txt
│   ├── .env.example
│   └── .env
│
├── minisoc-frontend/
│   ├── app/
│   │   ├── page.tsx
│   │   ├── incidents/
│   │   ├── alerts/
│   │   └── layout.tsx
│   │
│   ├── components/
│   ├── lib/
│   ├── hooks/
│   ├── types/
│   ├── package.json
│   ├── .env.local.example
│   └── .env.local
│
├── docs/
│   └── screenshots/
│
├── .gitignore
├── LICENSE
└── README.md
```

---

# Security Considerations

ThreatLens is designed for a controlled development and hackathon environment.

### Environment Variables

Never commit secrets:

```text
.env
.env.local
```

Make sure they are included in `.gitignore`.

### API Keys

If an API key is accidentally exposed:

1. Revoke it.
2. Generate a replacement.
3. Update the local environment.
4. Check Git history if the key was committed.

### Authentication

The static API key used by the demo is intended for the hackathon environment.

A production deployment should use stronger authentication and authorization mechanisms, including per-agent credentials where appropriate.

### AI

AI output should be treated as **analyst assistance**, not authoritative security evidence.

Detection and correlation remain deterministic so that the system does not depend on an LLM to identify attacks.

---

# Roadmap

## v1.0 — Hackathon

- [x] Event ingestion
- [x] Deterministic detection rules
- [x] Alert correlation
- [x] MITRE ATT&CK mapping
- [x] Multi-provider AI failover
- [x] TraceAI attack reconstruction
- [x] Network anomaly detection
- [x] Attack simulator
- [x] WebSocket real-time updates
- [x] CSV/JSON export
- [x] Automated tests

## v2.0 — Post-Hackathon

- [ ] Real Linux agent
- [ ] Real Windows agent
- [ ] Wazuh integration
- [ ] Zeek integration
- [ ] Suricata integration
- [ ] PostgreSQL support
- [ ] Multi-tenancy
- [ ] Per-agent authentication
- [ ] Historical analytics
- [ ] Cross-host graph correlation

## v3.0 — Production Direction

- [ ] Kubernetes deployment
- [ ] Kafka / Redis Streams
- [ ] Real firewall integration
- [ ] EDR integration
- [ ] Threat intelligence feeds
- [ ] SOAR playbooks
- [ ] ML-assisted anomaly detection

---

# Contributing

Contributions, issues, and feature requests are welcome.

### Development Workflow

Create a feature branch:

```bash
git checkout -b feature/your-feature
```

Commit your changes:

```bash
git add .
git commit -m "Add: your feature description"
```

Push the branch:

```bash
git push origin feature/your-feature
```

Then open a Pull Request.

---

# License

This project is licensed under the **MIT License**.

See [LICENSE](LICENSE) for details.

---

#  Team

**Team Name:** KernelPanic

**Event:** Presidential SPARKX Hackathon 2026
**Track:** Cybersecurity
**Venue:** Presidential Graduate School, Kathmandu, Nepal
**Dates:** 17–18 September 2026

### Members

- **[Shuva Kharel]** — Backend / Detection Engine
- **[Aaragyo Upreti]** — Frontend / UI

---

# Acknowledgments

- **MITRE ATT&CK** — Adversary tactics and techniques framework
- **Groq** — AI inference
- **Google Gemini** — AI fallback provider
- **OpenRouter** — AI routing and fallback
- **Presidential Software Club** — Hackathon organizers
- **Wazuh, Zeek, and Suricata** — Inspiration for SOC workflows

---

# Contact

- **GitHub:** [shuva-kharel](https://github.com/shuva-kharel)
- **Repository:** [ThreatLens](https://github.com/pgs-software-club/Team-kernelPanic)

---

#  The Idea in One Sentence

> **ThreatLens transforms security telemetry and individual alerts into correlated, reconstructed, MITRE-mapped, and explainable security incidents — helping analysts understand what actually happened.**

---

<div align="center">

###  Built for security analysts who need clarity, not more alerts.

 **Star the repository if you find ThreatLens useful.**

</div>
