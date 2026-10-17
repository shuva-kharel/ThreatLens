# ThreatLens Judge Demo

Target duration: 3-5 minutes. Use only the configured private VMware lab.

## Preflight

Complete this before judges arrive:

1. Set `DEMO_LAB_ASSETS` to the real private VMware target.
2. Set the same long secret in `AGENT_SHARED_SECRET` and `THREATLENS_AGENT_TOKEN`.
3. Add backend, gateway, DNS, and management addresses to `PROTECTED_ADDRESSES`.
4. Start the endpoint agent elevated and confirm it is `ONLINE` in Settings.
5. For real blocking, set `AUTOMATIC_RESPONSE_ENABLED=true`, `AUTOMATIC_RESPONSE_DRY_RUN=false`, and `RESPONSE_EXECUTION_MODE=real`.
6. Confirm Slack is enabled and send one labeled test notification before the session.
7. Confirm at least one AI provider with a current model succeeds. The tested Gemini model is `gemini-3.5-flash-lite`.
8. Start backend and frontend, then keep Dashboard, Demo Lab, Response Center, and Slack ready.

If the agent is not online, switch to `RESPONSE_EXECUTION_MODE=demo` and explicitly tell judges enforcement is simulated. Never describe demo mode as a real firewall change.

## Live Demo

1. Open **Dashboard**. Point out API/WebSocket status, real metrics, Live SOC Activity, and the pipeline.
2. Open **Settings** and show the configured VMware agent, telemetry sources, event count, and recent heartbeat.
3. Open **Demo Lab**, select the configured target, and run **Full Attack Chain**.
4. Return to **Dashboard**. Watch Event, Detection, Incident, TraceAI, AI Response, Policy, Response, and Verified records arrive from backend state.
5. Open the incident. Show its alerts, evidence timeline, MITRE techniques, AI Analyst explanation, response proposal, policy decision, execution, verification, and audit.
6. Open **Response Center**. Show the same incident and execution ID. In real mode, independently verify the `ThreatLens-*` firewall rule on the target before claiming containment.
7. Press `Ctrl+K`. Search the attacker IP, target hostname, incident ID, execution ID, and a mapped MITRE ID. Open the incident from a result.
8. Open **Threat Map**. Select the source-to-target relationship, show `Internal Network`, and navigate back to its incident.
9. In **Demo Lab**, run **Containment Failure Simulation** using a fresh controlled source. Explain that post-verification telemetry is deliberately injected; no firewall bypass is attempted.
10. Show the Human Escalation in **Response Center**, including recurrence count, previous verified response, reason, Slack status, and current incident.
11. Show the real Slack message. Finish on Dashboard with the Escalation and Slack activity entries.

## Containment Proof

Only call real containment successful after all three checks:

1. Response Center shows execution mode `REAL EXECUTION` and verified agent task details.
2. An independent command on the Windows target finds the matching `ThreatLens-*` firewall rule and blocked remote address.
3. A permitted lab connectivity attempt demonstrates the expected blocked behavior.

Use rollback after the demo and independently confirm the managed rule is gone.

## Recovery

- **No live feed:** confirm REST remains available, then restart the backend/frontend WebSocket connection. Defensive actions remain backend-owned.
- **AI unavailable:** continue the demo through deterministic detection/correlation and disclose deterministic analyst fallback.
- **Slack unavailable:** show the persisted escalation and `FAILED` Slack status; escalation remains valid.
- **Agent offline:** switch to demo mode, restart the backend, and state that endpoint enforcement is simulated.
- **Run stuck:** use Emergency Stop, wait for `stopped`, then start a fresh run.
