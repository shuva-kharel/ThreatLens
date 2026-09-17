from datetime import timedelta
import importlib.util
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.core.time import utc_now
from app.db.session import get_db
from app.main import app
from app.models.database import AgentTask, Base, EndpointAgent, Incident, Response
from app.models.response_models import ActionType
from app.services.agent_service import AgentService, managed_rule_id, validate_block_target
from app.services.response_service import ResponseService

agent_spec = importlib.util.spec_from_file_location(
    "threatlens_agent",
    Path(__file__).resolve().parent.parent / "agent" / "threatlens_agent.py",
)
assert agent_spec and agent_spec.loader
threatlens_agent = importlib.util.module_from_spec(agent_spec)
agent_spec.loader.exec_module(threatlens_agent)


@pytest.fixture
def agent_db(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'agents.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = session_factory()
    monkeypatch.setattr(settings, "agent_shared_secret", "test-agent-secret")
    monkeypatch.setattr(settings, "protected_addresses", "127.0.0.1,::1,10.0.0.1")
    monkeypatch.setattr(settings, "response_execution_mode", "real")
    ResponseService._instance = None

    def override_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    try:
        yield session
    finally:
        app.dependency_overrides.clear()
        session.close()
        engine.dispose()
        ResponseService._instance = None


def registration():
    return {
        "agent_id": "win-target-01",
        "hostname": "WIN-TARGET-01",
        "os": "Windows 11",
        "ip_addresses": ["192.168.56.20"],
        "version": "1.0.0",
        "capabilities": ["firewall.block_ip", "firewall.unblock_ip"],
    }


def agent_model():
    data = registration()
    data["id"] = data.pop("agent_id")
    return EndpointAgent(**data, last_seen=utc_now())


def test_registration_auth_heartbeat_and_online_offline(agent_db):
    with TestClient(app) as client:
        assert client.post("/api/v1/agents/register", json=registration()).status_code == 401
        registered = client.post("/api/v1/agents/register", json=registration(), headers={"X-Agent-Token": "test-agent-secret"})
        assert registered.status_code == 200
        assert registered.json()["status"] == "ONLINE"
        heartbeat = client.post("/api/v1/agents/win-target-01/heartbeat", headers={"X-Agent-Token": "test-agent-secret"})
        assert heartbeat.status_code == 200

    agent = agent_db.get(EndpointAgent, "win-target-01")
    agent.last_seen = utc_now() - timedelta(seconds=settings.agent_offline_seconds + 1)
    agent_db.commit()
    assert AgentService(agent_db).serialize_agent(agent)["status"] == "OFFLINE"
    with pytest.raises(RuntimeError, match="No online endpoint agent"):
        AgentService(agent_db).select_agent("WIN-TARGET-01", "firewall.block_ip")


def test_agent_task_result_verification_and_duplicate_reporting(agent_db):
    agent_db.add(agent_model())
    task = AgentTask(
        id="task-1", agent_id="win-target-01", incident_id="incident-1",
        execution_id="execution-1", action="block_source_ip", target="10.10.10.99",
        managed_rule_id=managed_rule_id("10.10.10.99"), status="claimed",
    )
    agent_db.add(task)
    agent_db.commit()
    payload = {"status": "completed", "result": {"created": True}, "verification_result": {"verified": True, "method": "firewall lookup"}}
    with TestClient(app) as client:
        first = client.post("/api/v1/agents/win-target-01/tasks/task-1/result", json=payload, headers={"X-Agent-Token": "test-agent-secret"})
        second = client.post("/api/v1/agents/win-target-01/tasks/task-1/result", json=payload, headers={"X-Agent-Token": "test-agent-secret"})
    assert first.json() == {"status": "completed", "duplicate": False}
    assert second.json() == {"status": "completed", "duplicate": True}

    failed = AgentTask(
        id="task-2", agent_id="win-target-01", incident_id="incident-1",
        execution_id="execution-2", action="block_source_ip", target="10.10.10.98",
        managed_rule_id=managed_rule_id("10.10.10.98"), status="failed",
        result={"error": "verification failed"}, verification_result={"verified": False},
    )
    with pytest.raises(RuntimeError, match="verification failed"):
        AgentService._task_outcome(failed, agent_db.get(EndpointAgent, "win-target-01"))


def test_agent_polling_round_trip_completes_waiting_dispatch(agent_db):
    agent_db.add(agent_model())
    agent_db.commit()
    factory = sessionmaker(bind=agent_db.get_bind(), autocommit=False, autoflush=False)

    def dispatch():
        db = factory()
        try:
            return AgentService(db).dispatch_and_wait(
                execution_id="roundtrip-exec", incident_id="roundtrip-incident",
                endpoint="WIN-TARGET-01", action="block_source_ip", target="10.10.10.77",
            )
        finally:
            db.close()

    with ThreadPoolExecutor(max_workers=1) as executor, TestClient(app) as client:
        future = executor.submit(dispatch)
        task = None
        for _ in range(20):
            response = client.get("/api/v1/agents/win-target-01/tasks/next", headers={"X-Agent-Token": "test-agent-secret"})
            task = response.json()["task"]
            if task:
                break
            time.sleep(0.02)
        assert task is not None
        report = client.post(
            f"/api/v1/agents/win-target-01/tasks/{task['id']}/result",
            headers={"X-Agent-Token": "test-agent-secret"},
            json={"status": "completed", "result": {"created": True}, "verification_result": {"verified": True, "method": "firewall lookup"}},
        )
        assert report.status_code == 200
        outcome = future.result(timeout=3)
    assert outcome["mode"] == "REAL EXECUTION"
    assert outcome["verification"]["verified"] is True


def test_real_execution_audit_idempotency_and_rollback(agent_db, monkeypatch):
    incident = Incident(
        id="incident-real", title="SSH brute force", severity="high", confidence=0.99,
        status="open", source_entities=["10.10.10.99"], target_entities=["WIN-TARGET-01"],
        attack_chain=[], mitre_techniques=["T1110"], first_seen=utc_now(), last_seen=utc_now(),
    )
    agent_db.add(incident)
    agent_db.commit()
    calls = []

    def dispatch(self, **kwargs):
        calls.append(kwargs)
        return {
            "mode": "REAL EXECUTION", "agent_id": "win-target-01", "endpoint": "WIN-TARGET-01",
            "agent_task_id": "task-real", "managed_rule_id": managed_rule_id(kwargs["target"]),
            "action": kwargs["action"], "target": kwargs["target"], "result": {"created": True},
            "verification": {"verified": True, "method": "Windows Firewall rule lookup"},
        }

    monkeypatch.setattr(AgentService, "dispatch_and_wait", dispatch)
    service = ResponseService()
    first = service.execute_action_once(
        agent_db, incident_id=incident.id, action=ActionType.BLOCK_IP,
        target="10.10.10.99", playbook_id="PB-BLOCK-IP", dry_run=False, approved_by="analyst",
    )
    second = service.execute_action_once(
        agent_db, incident_id=incident.id, action=ActionType.BLOCK_IP,
        target="10.10.10.99", playbook_id="PB-BLOCK-IP", dry_run=False, approved_by="analyst",
    )
    assert first.status.value == "verified"
    assert first.verification_result["verified"] is True
    assert first.result["mode"] == "REAL EXECUTION"
    assert second.execution_id == first.execution_id
    assert len(calls) == 1
    assert agent_db.query(Response).count() == 1
    assert len(service.audit_log) == 1

    rollback = service.rollback_action(first.execution_id, operator="analyst", db=agent_db)
    assert rollback["status"] == "success"
    assert calls[-1]["action"] == "unblock_source_ip"
    assert service.executions[first.execution_id].status.value == "rolled_back"


def test_invalid_protected_and_timeout_failures(agent_db, monkeypatch):
    for value in ["not-an-ip", "127.0.0.1", "10.0.0.1", "::1"]:
        with pytest.raises(ValueError):
            validate_block_target(value)

    agent_db.add(agent_model())
    agent_db.commit()
    monkeypatch.setattr(settings, "agent_task_timeout_seconds", 0)
    with pytest.raises(TimeoutError, match="timed out"):
        AgentService(agent_db).dispatch_and_wait(
            execution_id="timeout-exec", incident_id="incident-timeout",
            endpoint="WIN-TARGET-01", action="block_source_ip", target="10.10.10.88",
        )


def test_windows_firewall_adapter_executes_fixed_actions_and_verifies(monkeypatch):
    class Result:
        returncode = 0
        stderr = ""

        def __init__(self, stdout=""):
            self.stdout = stdout

    commands = []

    def successful_powershell(arguments):
        commands.append(arguments)
        return Result("managed-rule" if arguments[0] == "Get-NetFirewallRule" else "")

    monkeypatch.setattr(threatlens_agent, "powershell", successful_powershell)
    target = "10.10.10.99"
    rule = managed_rule_id(target)
    blocked = threatlens_agent.execute({"action": "block_source_ip", "target": target, "managed_rule_id": rule})
    assert blocked["status"] == "completed"
    assert blocked["verification_result"]["verified"] is True
    assert commands[0][0] == "New-NetFirewallRule"
    assert target in commands[0]

    def removal_powershell(arguments):
        commands.append(arguments)
        return Result("")

    monkeypatch.setattr(threatlens_agent, "powershell", removal_powershell)
    removed = threatlens_agent.execute({"action": "unblock_source_ip", "target": target, "managed_rule_id": rule})
    assert removed["status"] == "completed"
    assert removed["verification_result"]["verified"] is True
    assert commands[-2][0] == "Remove-NetFirewallRule"

    monkeypatch.setattr(threatlens_agent, "powershell", lambda arguments: Result(""))
    failed = threatlens_agent.execute({"action": "block_source_ip", "target": target, "managed_rule_id": rule})
    assert failed["status"] == "failed"
    assert failed["verification_result"]["verified"] is False

    class ExecutionFailure(Result):
        returncode = 1

    monkeypatch.setattr(threatlens_agent, "powershell", lambda arguments: ExecutionFailure(""))
    execution_failed = threatlens_agent.execute({"action": "block_source_ip", "target": target, "managed_rule_id": rule})
    assert execution_failed["status"] == "failed"
