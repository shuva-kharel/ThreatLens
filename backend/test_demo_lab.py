import asyncio
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api import demo_lab
from app.config import settings
from app.db.session import get_db
from app.main import app
from app.models.database import Alert, Base, DemoRun, Escalation, Event, Incident, Response
from app.services.response_service import ResponseService
from app.services.threat_map_service import ThreatMapService


ASSET = {"id": "WIN-TARGET-01", "hostname": "WIN-TARGET-01", "ip": "192.168.56.20", "os": "Windows"}


@pytest.fixture
def demo_db(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'demo.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = factory()
    monkeypatch.setattr(demo_lab, "SessionLocal", factory)
    monkeypatch.setattr(settings, "demo_lab_assets", json.dumps([ASSET]))
    monkeypatch.setattr(settings, "demo_lab_max_events", 30)
    monkeypatch.setattr(settings, "demo_lab_max_concurrent_runs", 1)
    monkeypatch.setattr(settings, "automatic_response_enabled", True)
    monkeypatch.setattr(settings, "automatic_response_dry_run", False)
    monkeypatch.setattr(settings, "response_execution_mode", "demo")
    monkeypatch.setattr(settings, "response_pipeline_version", "demo-lab-test")
    async def no_sleep(*_):
        return None

    monkeypatch.setattr(demo_lab.asyncio, "sleep", no_sleep)
    ResponseService._instance = None

    def override_db():
        db = factory()
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


def make_run(db, scenario):
    run = DemoRun(
        scenario=scenario, asset_id=ASSET["id"], target_host=ASSET["hostname"],
        target_ip=ASSET["ip"], source_ip="10.10.10.99",
        pipeline={key: "pending" for key in demo_lab.PIPELINE_KEYS}, log=[],
    )
    db.add(run)
    db.commit()
    return run.id


@pytest.mark.asyncio
@pytest.mark.parametrize("scenario", list(demo_lab.SCENARIOS))
async def test_every_demo_scenario_uses_real_ingestion(demo_db, scenario, monkeypatch):
    async def fallback(self, incident):
        return self._get_mock_response(incident)

    monkeypatch.setattr(demo_lab.AIAnalyst, "analyze_incident", fallback)
    run_id = make_run(demo_db, scenario)
    await demo_lab.execute_run(run_id)
    demo_db.expire_all()
    run = demo_db.get(DemoRun, run_id)
    assert run.status == "completed"
    assert run.events_sent == len(demo_lab.SCENARIOS[scenario])
    assert demo_db.query(Event).count() == run.events_sent
    assert all(event.normalized_data["synthetic"] is True for event in demo_db.query(Event).all())


@pytest.mark.asyncio
async def test_full_attack_visible_across_pipeline_and_threat_map(demo_db, monkeypatch):
    async def fallback(self, incident):
        return self._get_mock_response(incident)

    monkeypatch.setattr(demo_lab.AIAnalyst, "analyze_incident", fallback)
    run_id = make_run(demo_db, "full-attack")
    await demo_lab.execute_run(run_id)
    demo_db.expire_all()
    run = demo_db.get(DemoRun, run_id)
    assert demo_db.query(Event).count() == 10
    assert demo_db.query(Alert).count() >= 1
    assert demo_db.query(Incident).count() == 1
    assert demo_db.query(Response).count() == 1
    for stage in ["telemetry", "detection", "alert", "incident", "traceai", "mitre", "ai_analyst", "response_agent", "policy", "execution", "verification", "audit"]:
        assert run.pipeline[stage] == "complete", stage
    relationship = next(item for item in ThreatMapService(demo_db).aggregate()["relationships"] if item["source_ip"] == "10.10.10.99")
    assert run.incident_id in relationship["incident_ids"]


@pytest.mark.asyncio
async def test_containment_failure_uses_real_recurrence_pipeline(demo_db, monkeypatch):
    async def fallback(self, incident):
        return self._get_mock_response(incident)

    monkeypatch.setattr(demo_lab.AIAnalyst, "analyze_incident", fallback)
    run_id = make_run(demo_db, "containment-failure")
    await demo_lab.execute_run(run_id)
    demo_db.expire_all()
    run = demo_db.get(DemoRun, run_id)
    assert run.error is None, run.error
    escalations = demo_db.query(Escalation).all()
    assert escalations, {
        "incidents": [(item.id, str(item.status), item.first_seen) for item in demo_db.query(Incident).all()],
        "responses": [(item.incident_id, item.status, item.details) for item in demo_db.query(Response).all()],
    }
    escalation = escalations[0]
    assert run.status == "completed"
    assert run.pipeline["escalation"] == "complete"
    assert escalation.requires_human_review is True
    assert escalation.source_ip == "10.10.10.99"
    assert escalation.reason


@pytest.mark.asyncio
async def test_emergency_stop_is_cooperative(demo_db):
    run_id = make_run(demo_db, "traffic-load")
    run = demo_db.get(DemoRun, run_id)
    run.stop_requested = True
    demo_db.commit()
    await demo_lab.execute_run(run_id)
    demo_db.expire_all()
    assert demo_db.get(DemoRun, run_id).status == "stopped"
    assert demo_db.query(Event).count() == 0


def test_invalid_target_and_concurrency_are_rejected(demo_db, monkeypatch):
    monkeypatch.setattr(asyncio, "create_task", lambda coroutine: coroutine.close())
    with TestClient(app) as client:
        invalid = client.post("/api/v1/demo-lab/runs", json={"asset_id": "INTERNET", "scenario": "full-attack"})
        assert invalid.status_code == 400
        first = client.post("/api/v1/demo-lab/runs", json={"asset_id": ASSET["id"], "scenario": "full-attack"})
        assert first.status_code == 202
        second = client.post("/api/v1/demo-lab/runs", json={"asset_id": ASSET["id"], "scenario": "port-scan"})
        assert second.status_code == 409
