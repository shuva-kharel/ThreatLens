# ThreatLens

ThreatLens is a security operations application that turns endpoint and simulated telemetry into detections, correlated incidents, reconstructed attack timelines, bounded defensive responses, verification, and auditable human escalation.

## Architecture

```text
Endpoint Agent / Demo Lab
  -> NetSentinel normalized events
  -> deterministic detection
  -> alerts and incident correlation
  -> TraceAI and MITRE ATT&CK mapping
  -> AI Analyst
  -> structured ResponseProposal
  -> policy engine
  -> predefined playbook
  -> dry-run, demo, or authenticated endpoint execution
  -> verification and audit
  -> recurrence detection and human escalation
```

The LLM explains evidence and proposes a structured response. It cannot execute arbitrary commands. Only predefined playbooks can reach the response executor.

## Components

- `backend/`: FastAPI, SQLAlchemy, detection, correlation, TraceAI, response orchestration, Demo Lab, WebSockets, search, and Slack notifications.
- `frontend/`: Next.js SOC console with the Live Dashboard, incidents, Threat Map, Response Center, Demo Lab, global search, and agent health.
- `agent/`: authenticated endpoint collector and Windows firewall enforcement adapter with a bounded SQLite offline queue.

Threat Map relationships come from stored ThreatLens alerts/events. Private, loopback, and link-local addresses are represented as internal entities; ThreatLens does not invent geographic coordinates.

## Setup

Requirements: Python 3.12+, Node.js 18+, and npm.

```powershell
cd backend
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env

cd ..\frontend
npm install
Copy-Item .env.example .env.local
```

Start the services in separate terminals:

```powershell
cd backend
.venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000

cd frontend
npm run dev
```

Open `http://localhost:3000`; API documentation is at `http://localhost:8000/docs`.

## Configuration

Important backend environment variables are documented in `backend/.env.example`:

- `DATABASE_URL`: persistent SQLite or another configured SQLAlchemy database.
- `AUTOMATIC_RESPONSE_ENABLED`: allows incidents to enter response orchestration automatically.
- `AUTOMATIC_RESPONSE_DRY_RUN`: prevents endpoint changes when true.
- `RESPONSE_EXECUTION_MODE`: `demo` records simulated enforcement; `real` requires an online authenticated agent.
- `AGENT_SHARED_SECRET`: shared agent credential. Use a long random lab-only value.
- `PROTECTED_ADDRESSES`: management, backend, gateway, DNS, and loopback addresses that must never be blocked.
- `DEMO_LAB_ASSETS`: JSON allowlist of private VMware lab targets.
- `SLACK_NOTIFICATIONS_ENABLED` and `SLACK_WEBHOOK_URL`: human escalation delivery.
- `GROQ_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY`: optional AI providers. Provider model availability changes; verify configured model IDs before judging.

The tested Gemini fallback model is `gemini-3.5-flash-lite`. When every provider is unavailable, core telemetry, detection, correlation, and incidents continue; AI Analyst uses its clearly deterministic fallback while response failures remain isolated.

## Endpoint Agent

Run `agent/threatlens_agent.py` on controlled endpoints only. Configure:

```text
THREATLENS_SERVER=http://BACKEND-IP:8000
THREATLENS_AGENT_TOKEN=<same value as AGENT_SHARED_SECRET>
THREATLENS_AGENT_ID=WIN-TARGET-01
THREATLENS_PROTECTED_ADDRESSES=<management and infrastructure IPs>
```

Run elevated on Windows for firewall enforcement and Windows event collection. The agent supports Sysmon, Windows Security/System logs, Linux syslog, and journald where available. It normalizes platform records into the existing ThreatLens event schema, batches ingestion, retries failures, and retains a bounded offline queue.

Real firewall mode is intentionally unavailable unless `RESPONSE_EXECUTION_MODE=real`, the secret is configured, and the matching online agent advertises `firewall.block_ip` and `firewall.unblock_ip`.

## Demo Lab

`DEMO_LAB_ASSETS` is the server-side allowlist. Targets must be private, non-loopback addresses. The browser cannot supply arbitrary targets. Scenarios include port scan, SSH failures, brute force, suspicious activity, bounded traffic load, full attack, and containment failure.

Simulator events are marked `synthetic: true` and still pass through normal ingestion, detection, correlation, TraceAI, MITRE, response, audit, dashboard, search, and Threat Map paths.

Use [JUDGE_DEMO.md](JUDGE_DEMO.md) for the 3-5 minute presentation. Complete its preflight before the event.

## Operations

- **Response Center:** proposals, approval queue, policies, playbooks, executions, verification, rollback history, audit, and escalations.
- **Live Dashboard:** persisted activity plus one shared WebSocket connection. WebSockets update views but never trigger defensive actions.
- **Global Search:** `Ctrl+K` or `/`; searches persisted incidents, alerts, events, IPs, hosts, agents, MITRE, responses, playbooks, escalations, and vulnerabilities.
- **Slack:** sent only for human escalation when enabled. Delivery failures are recorded and never prevent escalation creation.
- **Time:** backend/storage uses UTC-aware timestamps. User-visible times use `Asia/Kathmandu` (`UTC+05:45`).

## Testing

```powershell
cd backend
.venv\Scripts\python.exe -m pytest -q

cd ..\frontend
npx tsc --noEmit
npm run lint
npm run build
```

Fixture tests cover Sysmon, Windows Security, syslog, deduplication, buffering, the automatic response pipeline, endpoint task handling, Demo Lab scenarios, recurrence, Slack failures, Threat Map aggregation, timestamps, search, and persistence-facing response restoration.

Fixture success is not proof of a reachable VMware guest, installed firewall rule, real Sysmon stream, or real syslog stream. Those items must be verified against the actual lab and reported separately.
