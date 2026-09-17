import hashlib
import ipaddress
import time
import uuid
from datetime import timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.config import settings
from app.core.time import utc_iso, utc_now
from app.models.database import AgentEventReceipt, AgentTask, EndpointAgent


CAPABILITY_BY_ACTION = {
    "block_source_ip": "firewall.block_ip",
    "unblock_source_ip": "firewall.unblock_ip",
}


def validate_block_target(value: str) -> str:
    address = ipaddress.ip_address(value)
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        raise ValueError("Target IP is protected and cannot be blocked")
    protected = {
        item.strip() for item in settings.protected_addresses.split(",") if item.strip()
    }
    if str(address) in protected:
        raise ValueError("Target IP is protected and cannot be blocked")
    return str(address)


def managed_rule_id(target: str) -> str:
    digest = hashlib.sha256(target.encode("ascii")).hexdigest()[:16]
    return f"ThreatLens-{digest}"


class AgentService:
    def __init__(self, db: Session):
        self.db = db

    def serialize_agent(self, agent: EndpointAgent) -> dict[str, Any]:
        online = agent.last_seen >= utc_now() - timedelta(seconds=settings.agent_offline_seconds)
        receipts = self.db.query(AgentEventReceipt).filter(AgentEventReceipt.agent_id == agent.id)
        events_received = receipts.filter(AgentEventReceipt.status == "completed").count()
        last_receipt = receipts.filter(AgentEventReceipt.status == "completed").order_by(AgentEventReceipt.received_at.desc()).first()
        sources = sorted({source for (source,) in receipts.with_entities(AgentEventReceipt.telemetry_source).distinct().all()})
        return {
            "id": agent.id,
            "hostname": agent.hostname,
            "os": agent.os,
            "ip_addresses": agent.ip_addresses or [],
            "version": agent.version,
            "capabilities": agent.capabilities or [],
            "last_seen": utc_iso(agent.last_seen),
            "registered_at": utc_iso(agent.registered_at),
            "status": "ONLINE" if online else "OFFLINE",
            "events_received": events_received,
            "last_event": utc_iso(last_receipt.received_at) if last_receipt else None,
            "telemetry_sources": sources,
        }

    def select_agent(self, endpoint: str | None, capability: str) -> EndpointAgent:
        cutoff = utc_now() - timedelta(seconds=settings.agent_offline_seconds)
        candidates = self.db.query(EndpointAgent).filter(EndpointAgent.last_seen >= cutoff).all()
        for agent in candidates:
            identity_match = endpoint is None or endpoint == agent.hostname or endpoint in (agent.ip_addresses or [])
            if identity_match and capability in (agent.capabilities or []):
                return agent
        raise RuntimeError("No online endpoint agent with the required capability")

    def dispatch_and_wait(
        self,
        *,
        execution_id: str,
        incident_id: str,
        endpoint: str | None,
        action: str,
        target: str,
    ) -> dict[str, Any]:
        target = validate_block_target(target)
        capability = CAPABILITY_BY_ACTION[action]
        agent = self.select_agent(endpoint, capability)
        existing = self.db.query(AgentTask).filter(AgentTask.execution_id == execution_id).first()
        if existing and existing.status in {"completed", "failed"}:
            return self._task_outcome(existing, agent)
        task = existing or AgentTask(
            id=str(uuid.uuid4()),
            agent_id=agent.id,
            incident_id=incident_id,
            execution_id=execution_id,
            action=action,
            target=target,
            managed_rule_id=managed_rule_id(target),
            status="pending",
        )
        if existing is None:
            self.db.add(task)
            self.db.commit()

        deadline = time.monotonic() + settings.agent_task_timeout_seconds
        while time.monotonic() < deadline:
            self.db.expire_all()
            task = self.db.get(AgentTask, task.id)
            if task and task.status in {"completed", "failed"}:
                return self._task_outcome(task, agent)
            time.sleep(0.1)
        task.status = "failed"
        task.completed_at = utc_now()
        task.result = {"error": "Endpoint agent task timed out"}
        self.db.commit()
        raise TimeoutError("Endpoint agent task timed out")

    @staticmethod
    def _task_outcome(task: AgentTask, agent: EndpointAgent) -> dict[str, Any]:
        verification = task.verification_result or {}
        if task.status != "completed" or verification.get("verified") is not True:
            raise RuntimeError((task.result or {}).get("error") or "Agent verification failed")
        return {
            "mode": "REAL EXECUTION",
            "agent_id": agent.id,
            "endpoint": agent.hostname,
            "agent_task_id": task.id,
            "managed_rule_id": task.managed_rule_id,
            "action": task.action,
            "target": task.target,
            "result": task.result or {},
            "verification": verification,
        }
