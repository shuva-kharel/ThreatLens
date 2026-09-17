import hmac
import hashlib
import ipaddress
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.config import settings
from app.core.time import utc_iso, utc_now
from app.db.session import get_db
from app.models.database import AgentEventReceipt, AgentTask, EndpointAgent
from app.services.agent_service import AgentService
from app.services.event_service import EventService
from app.models.schemas import EventCreate


router = APIRouter()


def authenticate_agent(x_agent_token: str | None = Header(default=None)) -> None:
    expected = settings.agent_shared_secret
    if not expected or not x_agent_token or not hmac.compare_digest(x_agent_token, expected):
        raise HTTPException(status_code=401, detail="Invalid agent credentials")


class AgentRegistration(BaseModel):
    agent_id: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    hostname: str = Field(min_length=1, max_length=255)
    os: str = Field(min_length=1, max_length=100)
    ip_addresses: list[str] = Field(default_factory=list)
    version: str = Field(min_length=1, max_length=50)
    capabilities: list[str] = Field(default_factory=list)


class TaskResult(BaseModel):
    status: str
    result: dict[str, Any] = Field(default_factory=dict)
    verification_result: dict[str, Any] = Field(default_factory=dict)


TELEMETRY_SOURCES = {"sysmon", "windows_security", "windows_system", "syslog", "journald"}
EVENT_TYPES = {
    "process_creation", "process_termination", "network_connection", "dns_query",
    "file_create", "file_change", "login_success", "login_failed",
    "ssh_success", "ssh_failed_login", "account_created", "account_deleted",
    "account_group_changed", "service_installed", "service_state_change",
    "command_execution", "system_message",
}


class AgentTelemetryEvent(BaseModel):
    event_id: str = Field(min_length=1, max_length=255)
    timestamp: datetime
    telemetry_source: str
    event_type: str
    source_ip: str | None = None
    username: str | None = Field(default=None, max_length=255)
    severity: str | None = None
    message: str | None = Field(default=None, max_length=2000)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentTelemetryBatch(BaseModel):
    events: list[AgentTelemetryEvent] = Field(min_length=1, max_length=100)


@router.get("")
def list_agents(db: Session = Depends(get_db)):
    return [AgentService(db).serialize_agent(agent) for agent in db.query(EndpointAgent).all()]


@router.post("/register", dependencies=[Depends(authenticate_agent)])
def register_agent(payload: AgentRegistration, db: Session = Depends(get_db)):
    agent = db.get(EndpointAgent, payload.agent_id)
    if agent is None:
        agent = EndpointAgent(id=payload.agent_id, registered_at=utc_now())
        db.add(agent)
    for key, value in payload.model_dump(exclude={"agent_id"}).items():
        setattr(agent, key, value)
    agent.last_seen = utc_now()
    db.commit()
    db.refresh(agent)
    return AgentService(db).serialize_agent(agent)


@router.post("/{agent_id}/heartbeat", dependencies=[Depends(authenticate_agent)])
def heartbeat(agent_id: str, db: Session = Depends(get_db)):
    agent = db.get(EndpointAgent, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not registered")
    agent.last_seen = utc_now()
    db.commit()
    return {"status": "ONLINE", "last_seen": utc_iso(agent.last_seen)}


@router.get("/{agent_id}/tasks/next", dependencies=[Depends(authenticate_agent)])
def next_task(agent_id: str, db: Session = Depends(get_db)):
    agent = db.get(EndpointAgent, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not registered")
    agent.last_seen = utc_now()
    task = db.query(AgentTask).filter(AgentTask.agent_id == agent_id, AgentTask.status == "pending").order_by(AgentTask.created_at).first()
    if task is None:
        db.commit()
        return {"task": None}
    task.status = "claimed"
    task.claimed_at = utc_now()
    db.commit()
    return {"task": {"id": task.id, "action": task.action, "target": task.target, "managed_rule_id": task.managed_rule_id}}


@router.post("/{agent_id}/tasks/{task_id}/result", dependencies=[Depends(authenticate_agent)])
def report_task_result(agent_id: str, task_id: str, payload: TaskResult, db: Session = Depends(get_db)):
    task = db.get(AgentTask, task_id)
    if task is None or task.agent_id != agent_id:
        raise HTTPException(status_code=404, detail="Agent task not found")
    if task.status in {"completed", "failed"}:
        return {"status": task.status, "duplicate": True}
    verified = payload.verification_result.get("verified") is True
    task.status = "completed" if payload.status == "completed" and verified else "failed"
    task.result = payload.result
    task.verification_result = payload.verification_result
    task.completed_at = utc_now()
    agent = db.get(EndpointAgent, agent_id)
    if agent:
        agent.last_seen = utc_now()
    db.commit()
    return {"status": task.status, "duplicate": False}


@router.post("/{agent_id}/events/batch", dependencies=[Depends(authenticate_agent)])
def ingest_agent_events(agent_id: str, payload: AgentTelemetryBatch, db: Session = Depends(get_db)):
    agent = db.get(EndpointAgent, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not registered")
    accepted, duplicates, failed = [], [], []
    service = EventService(db)
    for item in payload.events:
        if item.telemetry_source not in TELEMETRY_SOURCES or item.event_type not in EVENT_TYPES:
            failed.append({"event_id": item.event_id, "error": "Unsupported telemetry source or event type"})
            continue
        if item.source_ip:
            try:
                ipaddress.ip_address(item.source_ip)
            except ValueError:
                failed.append({"event_id": item.event_id, "error": "Invalid source IP"})
                continue
        receipt_id = hashlib.sha256(f"{agent_id}:{item.event_id}".encode()).hexdigest()
        receipt = db.get(AgentEventReceipt, receipt_id)
        if receipt and receipt.status in {"processing", "completed"}:
            duplicates.append(item.event_id)
            continue
        if receipt is None:
            receipt = AgentEventReceipt(
                id=receipt_id, agent_id=agent_id, source_event_id=item.event_id,
                telemetry_source=item.telemetry_source, status="processing",
            )
            db.add(receipt)
            db.commit()
        else:
            receipt.status = "processing"
            db.commit()
        try:
            normalized = {
                **item.metadata,
                "agent_id": agent_id,
                "source_event_id": item.event_id,
                "telemetry_source": item.telemetry_source,
                "trusted_agent": True,
            }
            result = service.process_event(EventCreate(
                timestamp=item.timestamp,
                host=agent.hostname,
                source_ip=item.source_ip,
                event_type=item.event_type,
                username=item.username,
                severity=item.severity,
                raw_event=item.message,
                normalized_data=normalized,
            ))
            receipt.status = "completed"
            receipt.event_db_id = result["event"].id
            receipt.received_at = utc_now()
            agent.last_seen = utc_now()
            db.commit()
            accepted.append({
                "event_id": item.event_id, "database_id": result["event"].id,
                "alerts_created": result["alerts_created"], "incidents": result["incidents"],
            })
        except Exception as exc:
            db.rollback()
            receipt = db.get(AgentEventReceipt, receipt_id)
            if receipt:
                receipt.status = "failed"
                db.commit()
            failed.append({"event_id": item.event_id, "error": type(exc).__name__})
    return {"accepted": accepted, "duplicates": duplicates, "failed": failed}
