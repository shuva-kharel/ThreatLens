import asyncio
import ipaddress
import json
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.websocket import manager
from app.config import settings
from app.core.ai_analyst import AIAnalyst
from app.core.time import utc_iso, utc_now
from app.core.trace_ai import TraceAI
from app.db.session import SessionLocal, get_db
from app.models.database import DemoRun, EndpointAgent, Incident
from app.models.schemas import EventCreate
from app.services.event_service import EventService
from app.services.agent_service import AgentService
from app.services.response_service import ResponseService


router = APIRouter()

SCENARIOS = {
    "port-scan": [("port_scan", "scanner", "Synthetic TCP port probe") for _ in range(5)],
    "ssh-failures": [("ssh_failed_login", "admin", "Synthetic SSH authentication failure") for _ in range(4)],
    "ssh-brute-force": [("ssh_failed_login", "admin", "Synthetic SSH brute-force attempt") for _ in range(5)],
    "suspicious-command": [("command_execution", "admin", "Synthetic suspicious command: wget payload.sh | sh")],
    "traffic-load": [("network_connection", None, "Synthetic bounded traffic-load sample") for _ in range(20)],
    "full-attack": [
        *[("port_scan", "scanner", "Synthetic TCP port probe") for _ in range(3)],
        *[("ssh_failed_login", "admin", "Synthetic SSH authentication failure") for _ in range(5)],
        ("ssh_success", "admin", "Synthetic successful authentication after failures"),
        ("command_execution", "admin", "Synthetic suspicious command: wget payload.sh | sh"),
    ],
}
PIPELINE_KEYS = ["telemetry", "detection", "alert", "incident", "traceai", "mitre", "ai_analyst", "response_agent", "policy", "execution", "verification", "audit", "escalation"]


class RunRequest(BaseModel):
    asset_id: str
    scenario: str
    source_ip: str = "10.10.10.99"


def configured_assets() -> list[dict[str, str]]:
    if not settings.demo_lab_enabled:
        return []
    raw = (settings.demo_lab_assets or "").strip()
    if not raw or raw == "[]":
        return []
    try:
        assets = json.loads(raw)
    except json.JSONDecodeError as exc:
        if raw.startswith("[") or raw.startswith("{"):
            raise RuntimeError("DEMO_LAB_ASSETS is invalid JSON") from exc
        assets = [
            {
                "id": f"LAB-{index:02d}",
                "hostname": f"LAB-{index:02d}",
                "name": f"Lab Asset {index}",
                "ip": item.strip(),
                "address": item.strip(),
                "os": "Unknown",
                "type": "unknown",
            }
            for index, item in enumerate(raw.split(","), start=1)
            if item.strip()
        ]
    if isinstance(assets, dict):
        assets = [assets]
    valid = []
    for asset in assets:
        address_value = asset.get("ip") or asset.get("address")
        if not address_value:
            raise RuntimeError("Demo asset requires an ip or address field")
        address = ipaddress.ip_address(address_value)
        if not address.is_private or address.is_loopback or address.is_link_local:
            raise RuntimeError(f"Demo asset {asset.get('id')} must use a private lab address")
        identifier = asset.get("id") or asset.get("hostname") or str(address)
        hostname = asset.get("hostname") or asset.get("name") or identifier
        os_name = asset.get("os") or asset.get("type") or "Unknown"
        valid.append({
            **asset,
            "id": identifier,
            "name": asset.get("name") or hostname,
            "hostname": hostname,
            "ip": str(address),
            "address": str(address),
            "os": os_name,
            "type": asset.get("type") or os_name,
        })
    return valid


def serialize(run: DemoRun) -> dict[str, Any]:
    return {
        "id": run.id, "scenario": run.scenario, "asset_id": run.asset_id,
        "target_host": run.target_host, "target_ip": run.target_ip, "source_ip": run.source_ip,
        "status": run.status, "safety_mode": run.safety_mode, "stop_requested": run.stop_requested,
        "events_sent": run.events_sent, "alerts_created": run.alerts_created,
        "incident_id": run.incident_id, "pipeline": run.pipeline or {}, "log": run.log or [],
        "error": run.error, "created_at": utc_iso(run.created_at), "started_at": utc_iso(run.started_at),
        "completed_at": utc_iso(run.completed_at),
    }


def add_log(run: DemoRun, stage: str, message: str):
    run.log = [*(run.log or []), {"timestamp": utc_iso(utc_now()), "stage": stage, "message": message}]


async def publish(run: DemoRun):
    await manager.broadcast({"type": "demo_lab_update", "data": serialize(run)})


async def execute_run(run_id: str):
    db = SessionLocal()
    try:
        run = db.get(DemoRun, run_id)
        if run is None:
            return
        run.status, run.started_at = "running", utc_now()
        db.commit()
        await publish(run)
        events = SCENARIOS["full-attack" if run.scenario == "containment-failure" else run.scenario]
        if run.scenario == "containment-failure":
            events = [*events, *events]
        if len(events) > settings.demo_lab_max_events:
            raise RuntimeError("Scenario exceeds configured event limit")
        service = EventService(db)
        latest_result = None
        event_offset = timedelta(0)
        for event_index, (event_type, username, raw_event) in enumerate(events):
            if utc_now() - run.started_at > timedelta(seconds=settings.demo_lab_max_duration_seconds):
                raise TimeoutError("Demo scenario exceeded the configured duration limit")
            if run.scenario == "containment-failure" and event_index == len(SCENARIOS["full-attack"]):
                first_incident = db.get(Incident, run.incident_id)
                if first_incident is None:
                    raise RuntimeError("First containment scenario did not create an incident")
                first_outcome = ResponseService().process_incident(db, first_incident.id, automatic=True)
                first_execution = first_outcome.get("execution") or {}
                if not (first_execution.get("verification_result") or {}).get("verified") or first_execution.get("dry_run"):
                    raise RuntimeError("Containment failure simulation requires a verified non-dry-run response")
                first_incident.status = "resolved"
                db.commit()
                event_offset = timedelta(minutes=2)
                add_log(run, "VERIFIED", "First response verified; injecting controlled post-verification telemetry")
            db.refresh(run)
            if run.stop_requested:
                run.status, run.completed_at = "stopped", utc_now()
                add_log(run, "STOP", "Emergency stop acknowledged")
                db.commit()
                await publish(run)
                return
            latest_result = await asyncio.to_thread(service.process_event, EventCreate(
                timestamp=utc_now() + event_offset, host=run.target_host, source_ip=run.source_ip,
                event_type=event_type, username=username, severity="medium", raw_event=raw_event,
                normalized_data={"synthetic": True, "telemetry_source": "simulator", "demo_run_id": run.id, "asset_id": run.asset_id},
            ))
            run.events_sent += 1
            run.alerts_created += latest_result["alerts_created"]
            pipeline = dict(run.pipeline or {})
            pipeline["telemetry"] = "complete"
            if latest_result["alerts_created"]:
                pipeline["detection"] = pipeline["alert"] = "complete"
            if latest_result["incidents"]:
                pipeline["incident"] = "complete"
                run.incident_id = latest_result["incidents"][-1]["id"]
            if latest_result.get("escalations"):
                pipeline["escalation"] = "complete"
            run.pipeline = pipeline
            add_log(run, "EVENT", raw_event)
            db.commit()
            await publish(run)
            await asyncio.sleep(0.25)

        if not run.incident_id:
            run.status = "completed"
            run.completed_at = utc_now()
            db.commit()
            await publish(run)
            return
        incident = db.get(Incident, run.incident_id)
        trace = TraceAI(db).reconstruct_incident(run.incident_id)
        pipeline = dict(run.pipeline or {})
        pipeline["traceai"] = "complete" if trace.get("timeline") else "failed"
        pipeline["mitre"] = "complete" if trace.get("mitre_techniques") else "failed"
        analyst = AIAnalyst()
        analysis = await analyst.analyze_incident({
            "id": incident.id, "title": incident.title, "severity": getattr(incident.severity, "value", incident.severity),
            "confidence": incident.confidence, "source_entities": incident.source_entities,
            "target_entities": incident.target_entities, "attack_chain": incident.attack_chain,
            "mitre_techniques": incident.mitre_techniques, "events": trace.get("timeline", []),
        })
        pipeline["ai_analyst"] = "complete" if analysis else "failed"
        outcome = ResponseService().process_incident(db, incident.id, automatic=True)
        pipeline["response_agent"] = "complete" if outcome.get("proposal") else "failed"
        pipeline["policy"] = "complete" if outcome.get("policy") else "failed"
        execution = outcome.get("execution") or {}
        pipeline["execution"] = "complete" if execution else ("failed" if outcome.get("status") == "failed" else "pending")
        pipeline["verification"] = "complete" if (execution.get("verification_result") or {}).get("verified") else pipeline["execution"]
        pipeline["audit"] = "complete" if outcome.get("audit") else "pending"
        run.pipeline = pipeline
        run.status, run.completed_at = "completed", utc_now()
        add_log(run, "COMPLETE", "Scenario processed through the ThreatLens pipeline")
        db.commit()
        await publish(run)
    except Exception as exc:
        db.rollback()
        run = db.get(DemoRun, run_id)
        if run:
            run.status, run.error, run.completed_at = "failed", str(exc), utc_now()
            db.commit()
            await publish(run)
    finally:
        db.close()


@router.get("/assets")
def assets(db: Session = Depends(get_db)):
    agents = {agent.hostname: AgentService(db).serialize_agent(agent) for agent in db.query(EndpointAgent).all()}
    return [{**asset, "agent": agents.get(asset["hostname"])} for asset in configured_assets()]


@router.get("/status")
def status(db: Session = Depends(get_db)):
    configuration_error = None
    try:
        configured = configured_assets()
    except RuntimeError as exc:
        configured = []
        configuration_error = str(exc)
    assets = [
        {
            "id": asset["id"],
            "name": asset.get("name") or asset["hostname"],
            "address": asset["ip"],
            "type": asset.get("type") or asset.get("os") or "unknown",
            "hostname": asset["hostname"],
            "ip": asset["ip"],
            "os": asset.get("os") or "Unknown",
        }
        for asset in configured
    ]
    return {
        "enabled": settings.demo_lab_enabled,
        "configured": bool(assets),
        "assets": assets,
        "simulation_available": True,
        "configuration_error": configuration_error,
        "configuration": {
            "required": "DEMO_LAB_ASSETS",
            "example": "192.168.50.20,192.168.50.21",
            "restart_required": True,
        },
    }


@router.get("/scenarios")
def scenarios():
    return [{"id": key, "name": key.replace("-", " ").title(), "event_count": len(value), "synthetic": True} for key, value in SCENARIOS.items()] + [{"id": "containment-failure", "name": "Containment Failure Simulation", "event_count": 20, "synthetic": True}]


@router.post("/runs", status_code=202)
async def start_run(payload: RunRequest, db: Session = Depends(get_db)):
    assets_by_id = {asset["id"]: asset for asset in configured_assets()}
    asset = assets_by_id.get(payload.asset_id)
    if asset is None:
        raise HTTPException(status_code=400, detail="Target is not an allowed demo asset")
    if payload.scenario not in {*SCENARIOS, "containment-failure"}:
        raise HTTPException(status_code=400, detail="Unknown demo scenario")
    source = ipaddress.ip_address(payload.source_ip)
    if not source.is_private or source.is_loopback:
        raise HTTPException(status_code=400, detail="Demo source must be a private lab address")
    active = db.query(DemoRun).filter(DemoRun.status.in_(["queued", "running"])).count()
    if active >= settings.demo_lab_max_concurrent_runs:
        raise HTTPException(status_code=409, detail="Demo Lab already has the maximum number of active runs")
    run = DemoRun(
        scenario=payload.scenario, asset_id=asset["id"], target_host=asset["hostname"],
        target_ip=asset["ip"], source_ip=str(source), pipeline={key: "pending" for key in PIPELINE_KEYS},
        log=[{"timestamp": utc_iso(utc_now()), "stage": "QUEUED", "message": "Synthetic lab scenario queued"}],
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    asyncio.create_task(execute_run(run.id))
    return serialize(run)


@router.get("/runs/{run_id}")
def get_run(run_id: str, db: Session = Depends(get_db)):
    run = db.get(DemoRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Demo run not found")
    return serialize(run)


@router.post("/runs/{run_id}/stop")
def stop_run(run_id: str, db: Session = Depends(get_db)):
    run = db.get(DemoRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Demo run not found")
    if run.status not in {"queued", "running"}:
        return serialize(run)
    run.stop_requested = True
    add_log(run, "STOP", "Emergency stop requested by operator")
    db.commit()
    return serialize(run)
