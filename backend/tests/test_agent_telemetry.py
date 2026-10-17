import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.db.session import get_db
from app.main import app
from app.models.database import AgentEventReceipt, Alert, Base, EndpointAgent, Event, Incident


agent_spec = importlib.util.spec_from_file_location("telemetry_agent", Path(__file__).resolve().parent.parent / "agent" / "threatlens_agent.py")
assert agent_spec and agent_spec.loader
telemetry_agent = importlib.util.module_from_spec(agent_spec)
agent_spec.loader.exec_module(telemetry_agent)

SYSMON_PROCESS = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1</EventID><EventRecordID>101</EventRecordID><TimeCreated SystemTime="2026-09-18T01:00:00.0000000Z"/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-TARGET-01</Computer></System><EventData><Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data><Data Name="CommandLine">cmd.exe /c wget payload.sh</Data><Data Name="User">LAB\\analyst</Data><Data Name="ProcessId">1234</Data></EventData></Event>"""
WINDOWS_FAILURE = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4625</EventID><EventRecordID>202</EventRecordID><TimeCreated SystemTime="2026-09-18T01:01:00.0000000Z"/><Channel>Security</Channel><Computer>WIN-TARGET-01</Computer></System><EventData><Data Name="TargetUserName">admin</Data><Data Name="IpAddress">10.10.10.99</Data><Data Name="LogonType">3</Data></EventData></Event>"""


@pytest.fixture
def telemetry_db(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'telemetry.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = factory()
    monkeypatch.setattr(settings, "agent_shared_secret", "telemetry-secret")
    monkeypatch.setattr(settings, "automatic_response_enabled", False)

    def override_db():
        db = factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    session.add(EndpointAgent(
        id="win-agent", hostname="WIN-TARGET-01", os="Windows", ip_addresses=["192.168.56.20"],
        version="1.0.0", capabilities=["telemetry.sysmon", "telemetry.eventlog"],
    ))
    session.commit()
    try:
        yield session
    finally:
        app.dependency_overrides.clear()
        session.close()
        engine.dispose()


def test_sysmon_windows_security_and_syslog_normalization():
    sysmon = telemetry_agent.normalize_sysmon(SYSMON_PROCESS)
    assert sysmon["telemetry_source"] == "sysmon"
    assert sysmon["event_type"] == "process_creation"
    assert sysmon["metadata"]["process"].endswith("cmd.exe")
    assert "wget" in sysmon["message"]

    security = telemetry_agent.normalize_windows_event(WINDOWS_FAILURE)
    assert security["telemetry_source"] == "windows_security"
    assert security["event_type"] == "login_failed"
    assert security["source_ip"] == "10.10.10.99"
    assert security["username"] == "admin"

    syslog = telemetry_agent.normalize_linux_message(
        "Sep 18 07:00:00 linux-target sshd[123]: Failed password for admin from 10.10.10.99 port 5522 ssh2"
    )
    assert syslog["telemetry_source"] == "syslog"
    assert syslog["event_type"] == "ssh_failed_login"
    assert syslog["source_ip"] == "10.10.10.99"

    with pytest.raises(Exception):
        telemetry_agent.normalize_sysmon("not xml")


def test_authenticated_agent_batch_deduplicates(telemetry_db):
    event = telemetry_agent.normalize_sysmon(SYSMON_PROCESS)
    headers = {"X-Agent-Token": "telemetry-secret"}
    with TestClient(app) as client:
        assert client.post("/api/v1/agents/win-agent/events/batch", json={"events": [event]}).status_code == 401
        first = client.post("/api/v1/agents/win-agent/events/batch", json={"events": [event]}, headers=headers)
        second = client.post("/api/v1/agents/win-agent/events/batch", json={"events": [event]}, headers=headers)
        malformed = client.post("/api/v1/agents/win-agent/events/batch", json={"events": [{"timestamp": "bad"}]}, headers=headers)
    assert first.status_code == 200 and len(first.json()["accepted"]) == 1
    assert second.json()["duplicates"] == [event["event_id"]]
    assert malformed.status_code == 422
    assert telemetry_db.query(Event).count() == 1
    assert telemetry_db.query(AgentEventReceipt).count() == 1


def test_windows_login_events_flow_to_detection_and_incident(telemetry_db):
    base = datetime(2026, 9, 18, 1, 1, tzinfo=timezone.utc)
    events = []
    for index in range(5):
        event = telemetry_agent.normalize_windows_event(WINDOWS_FAILURE)
        event["event_id"] = f"Security:{202 + index}"
        event["timestamp"] = (base + timedelta(seconds=index)).isoformat()
        events.append(event)
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/agents/win-agent/events/batch", json={"events": events},
            headers={"X-Agent-Token": "telemetry-secret"},
        )
    assert response.status_code == 200
    assert len(response.json()["accepted"]) == 5
    assert telemetry_db.query(Event).count() == 5
    assert telemetry_db.query(Alert).filter(Alert.alert_type == "ssh_brute_force").count() == 1
    incident = telemetry_db.query(Incident).one()
    assert "10.10.10.99" in incident.source_entities


def test_offline_queue_retains_then_drains_after_reconnect(tmp_path, monkeypatch):
    queue = telemetry_agent.OfflineQueue(str(tmp_path / "queue.db"), limit=2)
    first = telemetry_agent.normalize_linux_message("Failed password for admin from 10.10.10.99")
    second = telemetry_agent.normalize_linux_message("Accepted password for admin from 10.10.10.99", event_id="second")
    third = telemetry_agent.normalize_linux_message("sudo: admin : COMMAND=/bin/id", event_id="third")
    queue.put(first)
    queue.put(second)
    queue.put(third)
    assert len(queue.batch()) == 2

    monkeypatch.setattr(telemetry_agent, "request", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("offline")))
    with pytest.raises(OSError):
        telemetry_agent.flush_events(queue)
    assert len(queue.batch()) == 2

    monkeypatch.setattr(telemetry_agent, "request", lambda *args, **kwargs: {
        "accepted": [{"event_id": item["event_id"]} for item in queue.batch()], "duplicates": [], "failed": []
    })
    telemetry_agent.flush_events(queue)
    assert queue.batch() == []
