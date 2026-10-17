from datetime import timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.core.time import utc_now
from app.models.database import Alert, Base, Event, Incident, Response
from app.models.response_models import ActionType, ResponseProposal
from app.models.schemas import EventCreate, Severity
from app.services.event_service import EventService
from app.services.response_service import ResponseService


@pytest.fixture
def pipeline_db(tmp_path, monkeypatch):
    database_path = tmp_path / "response-pipeline.db"
    engine = create_engine(
        f"sqlite:///{database_path}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(autocommit=False, autoflush=False, bind=engine)()

    monkeypatch.setattr(settings, "automatic_response_enabled", True)
    monkeypatch.setattr(settings, "automatic_response_dry_run", True)
    monkeypatch.setattr(settings, "response_pipeline_version", "integration-v1")
    ResponseService._instance = None

    try:
        yield session
    finally:
        session.close()
        engine.dispose()
        ResponseService._instance = None


def submit_fresh_brute_force(db, source_ip="198.51.100.77"):
    service = EventService(db)
    base_time = utc_now()
    result = None

    for index in range(5):
        result = service.process_event(
            EventCreate(
                timestamp=base_time + timedelta(seconds=index),
                host="ssh-gateway-01",
                source_ip=source_ip,
                event_type="ssh_failed_login",
                username="admin",
                severity=Severity.HIGH,
                raw_event="Failed SSH password for admin",
            )
        )

    return result


def test_pending_incident_is_reevaluated_when_new_evidence_qualifies(pipeline_db):
    service = EventService(pipeline_db)
    base_time = utc_now()
    source_ip = "198.51.100.80"

    pending = None
    for index in range(3):
        pending = service.process_event(
            EventCreate(
                timestamp=base_time + timedelta(seconds=index),
                host="ssh-gateway-02",
                source_ip=source_ip,
                event_type="port_scan",
                severity=Severity.MEDIUM,
                raw_event=f"Port scan detected on port {20 + index}",
            )
        )

    assert pending["response_processing"][0]["status"] == "awaiting_approval"
    assert pipeline_db.query(Incident).count() == 1

    qualified = None
    for index in range(5):
        qualified = service.process_event(
            EventCreate(
                timestamp=base_time + timedelta(seconds=10 + index),
                host="ssh-gateway-02",
                source_ip=source_ip,
                event_type="ssh_failed_login",
                username="admin",
                severity=Severity.HIGH,
                raw_event="Failed SSH password for admin",
            )
        )

    outcome = qualified["response_processing"][0]
    assert outcome["status"] == "completed"
    assert outcome["policy"]["auto_execute"] is True
    assert outcome["execution"]["dry_run"] is True
    assert outcome["execution"]["verification_result"]["verified"] is True
    assert pipeline_db.query(Incident).count() == 1
    assert pipeline_db.query(Response).count() == 1


def test_fresh_telemetry_runs_complete_automatic_response_pipeline(pipeline_db):
    result = submit_fresh_brute_force(pipeline_db)

    assert pipeline_db.query(Event).count() == 5
    assert pipeline_db.query(Alert).count() == 1
    assert pipeline_db.query(Incident).count() == 1
    assert result["alerts_created"] == 1
    assert result["incidents_created"] == 1

    incident = pipeline_db.query(Incident).one()
    alert = pipeline_db.query(Alert).one()
    assert alert.incident_id == incident.id

    assert len(result["response_processing"]) == 1
    outcome = result["response_processing"][0]
    assert outcome["status"] == "completed"

    trace = outcome["trace"]
    evidence = outcome["evidence_package"]
    assert trace["incident_id"] == incident.id
    assert trace["timeline"]
    assert evidence["incident_id"] == incident.id
    assert evidence["alert_ids"] == [alert.id]

    proposal = ResponseProposal.model_validate(outcome["proposal"])
    assert proposal.incident_id == incident.id
    assert proposal.playbook_id == "PB-BLOCK-IP"
    assert proposal.recommended_action.value == "block_source_ip"

    assert outcome["policy"]["allowed"] is True
    assert outcome["policy"]["auto_execute"] is True
    assert outcome["policy"]["requires_approval"] is False
    assert outcome["playbook"]["id"] == "PB-BLOCK-IP"
    assert outcome["playbook"]["action_type"] == "block_source_ip"

    execution = outcome["execution"]
    assert execution["dry_run"] is True
    assert execution["result"]["no_changes_made"] is True
    assert execution["verification_result"]["verified"] is True
    assert outcome["audit"]["incident_id"] == incident.id
    assert outcome["audit"]["policy_decision"] == "Autonomous Policy Allowed"

    ledger = pipeline_db.query(Response).one()
    assert ledger.status == "completed"
    assert ledger.id == ResponseService._pipeline_record_id(incident.id)


def test_same_incident_is_not_executed_twice_even_after_service_restart(pipeline_db):
    result = submit_fresh_brute_force(pipeline_db, "198.51.100.78")
    outcome = result["response_processing"][0]
    incident = pipeline_db.query(Incident).one()
    first_execution_id = outcome["execution"]["execution_id"]

    service = ResponseService()
    repeated = service.process_incident(
        pipeline_db,
        incident.id,
        automatic=True,
    )
    assert repeated["execution"]["execution_id"] == first_execution_id
    assert len(service.executions) == 1
    assert pipeline_db.query(Response).count() == 1

    ResponseService._instance = None
    restarted_service = ResponseService()
    after_restart = restarted_service.process_incident(
        pipeline_db,
        incident.id,
        automatic=True,
    )
    assert after_restart["execution"]["execution_id"] == first_execution_id
    assert len(restarted_service.executions) == 1
    assert len(restarted_service.audit_log) == 1
    assert pipeline_db.query(Response).count() == 1

    duplicate_result = submit_fresh_brute_force(
        pipeline_db,
        "198.51.100.78",
    )
    assert pipeline_db.query(Incident).count() == 1
    assert pipeline_db.query(Response).count() == 1
    assert len(restarted_service.executions) == 1
    assert all(
        item["execution"]["execution_id"] == first_execution_id
        for item in duplicate_result["response_processing"]
    )


def test_response_agent_failure_does_not_lose_incident(
    pipeline_db,
    monkeypatch,
):
    def fail_response_agent(*args, **kwargs):
        raise RuntimeError("stubbed AI provider outage")

    monkeypatch.setattr(
        ResponseService,
        "formulate_proposal",
        fail_response_agent,
    )

    result = submit_fresh_brute_force(pipeline_db, "198.51.100.79")

    assert pipeline_db.query(Event).count() == 5
    assert pipeline_db.query(Alert).count() == 1
    assert pipeline_db.query(Incident).count() == 1
    assert result["incidents_created"] == 1

    outcome = result["response_processing"][0]
    assert outcome["status"] == "failed"
    assert outcome["failure"]["stage"] == "response_agent"
    assert "stubbed AI provider outage" in outcome["failure"]["message"]

    ledger = pipeline_db.query(Response).one()
    assert ledger.status == "failed"
    assert ledger.details["failure"]["stage"] == "response_agent"


def test_rollback_is_persisted_and_restored(pipeline_db):
    submit_fresh_brute_force(pipeline_db, "198.51.100.81")
    incident = pipeline_db.query(Incident).one()
    service = ResponseService()
    execution = service.execute_action_once(
        pipeline_db,
        incident_id=incident.id,
        action=ActionType.BLOCK_IP,
        target="198.51.100.81",
        playbook_id="PB-BLOCK-IP",
        dry_run=False,
        approved_by="test_operator",
    )

    result = service.rollback_action(execution.execution_id, db=pipeline_db)
    assert result["status"] == "success"

    ResponseService._instance = None
    restored = ResponseService()
    restored.load_persisted_outcomes(pipeline_db)
    record = restored.executions[execution.execution_id]
    assert record.status.value == "rolled_back"
    assert record.rollback_available is False
    assert any(entry.rollback for entry in restored.audit_log)
