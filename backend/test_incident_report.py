from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.models.database import Alert, Base, Incident
from app.models.response_models import ActionType
from app.services.incident_report_service import IncidentReportService
from app.services.response_service import ResponseService


@pytest.fixture
def report_db(tmp_path, monkeypatch):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'report.db'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(autocommit=False, autoflush=False, bind=engine)()
    monkeypatch.setattr(settings, "response_pipeline_version", "report-tests")
    monkeypatch.setattr(settings, "response_execution_mode", "demo")
    ResponseService._instance = None
    try:
        yield session
    finally:
        session.close()
        engine.dispose()
        ResponseService._instance = None


def add_incident(db, *, title="SSH brute force", mitre=None, recommendations=None):
    start = datetime.fromisoformat("2026-09-18T01:00:00+00:00")
    incident = Incident(
        title=title,
        severity="high",
        confidence=0.91,
        status="open",
        source_entities=["10.10.10.99"],
        target_entities=["WIN-TARGET-01"],
        attack_chain=[],
        mitre_techniques=mitre or [],
        ai_summary="Observed repeated authentication failures.",
        recommendations=recommendations or [],
        first_seen=start,
        last_seen=start + timedelta(minutes=3),
    )
    db.add(incident)
    db.commit()
    return incident


def test_report_uses_complete_evidence_without_fabricating_verified_response(report_db):
    incident = add_incident(
        report_db,
        mitre=["T1110"],
        recommendations=["Review source IP reputation."],
    )
    alert = Alert(
        alert_type="ssh_brute_force",
        severity="high",
        mitre_technique="T1110",
        source_ip="10.10.10.99",
        target_host="WIN-TARGET-01",
        description="Five failed SSH login attempts observed.",
        evidence=["event-1", "event-2"],
        confidence=0.95,
        incident_id=incident.id,
        created_at=incident.first_seen + timedelta(seconds=20),
    )
    report_db.add(alert)
    report_db.commit()

    service = ResponseService()
    execution = service.execute_action_once(
        report_db,
        incident_id=incident.id,
        action=ActionType.BLOCK_IP,
        target="10.10.10.99",
        playbook_id="PB-BLOCK-IP",
        dry_run=False,
        approved_by="test",
    )

    report = IncidentReportService(report_db).build(incident.id)

    assert report["incident"]["id"] == incident.id
    assert report["mitre"][0]["id"] == "T1110"
    assert report["alerts"][0]["id"] == alert.id
    assert report["evidence_summary"]["event_ids"] == ["event-1", "event-2"]
    assert report["responses"][0]["execution_id"] == execution.execution_id
    assert report["responses"][0]["dry_run"] is False
    assert report["verification"][0]["verification_result"]["verified"] is True
    assert "T1110" in report["executive_summary"]


def test_report_handles_limited_incident_without_inventing_optional_sections(report_db):
    incident = add_incident(report_db, title="Limited telemetry incident")
    incident.ai_summary = None
    incident.recommendations = []
    report_db.commit()

    report = IncidentReportService(report_db).build(incident.id)

    assert report["alerts"] == []
    assert report["mitre"] == []
    assert report["responses"] == []
    assert report["verification"] == []
    assert report["human_escalation"] is None
    assert report["ai_assisted_analysis"] is None
    assert report["evidence_summary"]["event_ids"] == []


def test_report_preserves_dry_run_and_failed_response_statuses(report_db):
    incident = add_incident(report_db)
    dry_run = ResponseService().execute_action_once(
        report_db,
        incident_id=incident.id,
        action=ActionType.BLOCK_IP,
        target="10.10.10.99",
        playbook_id="PB-BLOCK-IP",
        dry_run=True,
        approved_by="test",
    )

    report = IncidentReportService(report_db).build(incident.id)

    assert report["responses"][0]["execution_id"] == dry_run.execution_id
    assert report["responses"][0]["dry_run"] is True
    assert report["responses"][0]["status"] == "executed"
    assert "dry-run" in report["executive_summary"]
