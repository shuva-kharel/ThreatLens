from datetime import datetime, timedelta

import httpx
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.models.database import Base, Escalation, Incident, Response
from app.models.schemas import EventCreate, Severity
from app.services.event_service import EventService
from app.services.notification_service import NotificationService, SlackNotifier
from app.services.recurrence_service import RecurrenceService
from app.services.response_service import ResponseService


@pytest.fixture
def recurrence_db(tmp_path, monkeypatch):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'recurrence.db'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(autocommit=False, autoflush=False, bind=engine)()
    monkeypatch.setattr(settings, "automatic_response_enabled", True)
    monkeypatch.setattr(settings, "automatic_response_dry_run", False)
    monkeypatch.setattr(settings, "response_pipeline_version", "recurrence-v1")
    monkeypatch.setattr(settings, "slack_notifications_enabled", True)
    monkeypatch.setattr(settings, "slack_webhook_url", "https://hooks.slack.test/redacted")
    ResponseService._instance = None
    try:
        yield session
    finally:
        session.close()
        engine.dispose()
        ResponseService._instance = None


def submit_attack(db, source_ip, start):
    service = EventService(db)
    result = None
    for index in range(5):
        result = service.process_event(EventCreate(
            timestamp=start + timedelta(seconds=index),
            host="target-server",
            source_ip=source_ip,
            event_type="ssh_failed_login",
            username="admin",
            severity=Severity.HIGH,
            raw_event="Failed SSH password for admin",
        ))
    return result


def verified_first_attack(db, source_ip):
    first = submit_attack(
        db,
        source_ip,
        datetime.fromisoformat("2026-09-17T10:00:00+00:00"),
    )
    outcome = first["response_processing"][0]
    assert outcome["execution"]["dry_run"] is False
    assert outcome["execution"]["status"] == "verified"
    verification_at = datetime.fromisoformat(
        outcome["execution"]["verification_result"]["timestamp"]
    )
    incident = db.query(Incident).one()
    incident.status = "resolved"
    db.commit()
    return incident, outcome, verification_at


def test_repeat_attacker_escalates_and_notifies_slack_once(
    recurrence_db,
    monkeypatch,
):
    sent = []
    monkeypatch.setattr(
        SlackNotifier,
        "send_escalation",
        lambda self, payload: sent.append(payload),
    )
    source_ip = "10.10.10.99"
    previous, first_outcome, verified_at = verified_first_attack(
        recurrence_db, source_ip
    )

    second = submit_attack(
        recurrence_db,
        source_ip,
        verified_at + timedelta(minutes=2),
    )
    current = (
        recurrence_db.query(Incident)
        .filter(Incident.id != previous.id)
        .one()
    )
    escalation = recurrence_db.query(Escalation).one()

    assert second["escalations"][0]["id"] == escalation.id
    assert escalation.source_ip == source_ip
    assert escalation.current_incident_id == current.id
    assert escalation.previous_incident_id == previous.id
    assert escalation.previous_response_id == first_outcome["execution"]["execution_id"]
    assert escalation.previous_action == "block_source_ip"
    assert escalation.previous_response_status == "verified"
    assert escalation.previous_verification_at == verified_at
    assert escalation.last_activity_at > escalation.previous_verification_at
    assert escalation.recurrence_count == 2
    assert escalation.requires_human_review is True
    assert escalation.status == "ESCALATED"
    assert escalation.slack_notification_status == "SENT"
    assert len(sent) == 1

    repeated = RecurrenceService(recurrence_db).detect_and_escalate(current.id)
    assert repeated["id"] == escalation.id
    assert recurrence_db.query(Escalation).count() == 1
    assert len(sent) == 1

    audit = (
        recurrence_db.query(Response)
        .filter(Response.action == "human_escalation")
        .one()
    )
    event_types = [event["type"] for event in audit.details["events"]]
    assert event_types == [
        "repeat_threat_detected",
        "human_review_required",
        "slack_notification_sent",
    ]

    second_verification = datetime.fromisoformat(
        second["response_processing"][0]["execution"]["verification_result"]["timestamp"]
    )
    current.status = "resolved"
    recurrence_db.commit()
    third = submit_attack(
        recurrence_db,
        source_ip,
        second_verification + timedelta(minutes=2),
    )
    assert third["escalations"][0]["recurrence_count"] == 3
    assert recurrence_db.query(Escalation).count() == 2
    assert len(sent) == 2


def test_dry_run_different_ip_and_pre_verification_activity_do_not_escalate(
    recurrence_db,
    monkeypatch,
):
    monkeypatch.setattr(settings, "automatic_response_dry_run", True)
    monkeypatch.setattr(
        SlackNotifier,
        "send_escalation",
        lambda *args: pytest.fail("Slack must not be called"),
    )
    first = submit_attack(
        recurrence_db,
        "10.10.10.97",
        datetime.fromisoformat("2026-09-17T10:00:00+00:00"),
    )
    first_execution = first["response_processing"][0]["execution"]
    assert first_execution["dry_run"] is True
    verified_at = datetime.fromisoformat(
        first_execution["verification_result"]["timestamp"]
    )
    previous = recurrence_db.query(Incident).one()
    previous.status = "resolved"
    recurrence_db.commit()
    submit_attack(
        recurrence_db,
        "10.10.10.97",
        verified_at + timedelta(minutes=2),
    )
    assert recurrence_db.query(Escalation).count() == 0

    submit_attack(
        recurrence_db,
        "10.10.10.98",
        verified_at + timedelta(minutes=2),
    )
    assert recurrence_db.query(Escalation).count() == 0

    current = Incident(
        title="Historical malicious activity",
        severity="high",
        confidence=0.9,
        status="open",
        source_entities=["10.10.10.97"],
        target_entities=["target-server"],
        attack_chain=[],
        mitre_techniques=["T1110"],
        first_seen=verified_at - timedelta(seconds=1),
        last_seen=verified_at - timedelta(seconds=1),
    )
    recurrence_db.add(current)
    recurrence_db.commit()
    assert RecurrenceService(recurrence_db).detect_and_escalate(current.id) is None
    assert recurrence_db.query(Escalation).count() == 0


def test_failed_proposed_and_awaiting_responses_do_not_escalate(recurrence_db):
    source_ip = "10.10.10.96"
    previous = Incident(
        title="Prior attack",
        severity="high",
        confidence=0.9,
        status="resolved",
        source_entities=[source_ip],
        target_entities=["target-server"],
        attack_chain=[],
        mitre_techniques=["T1110"],
        first_seen=datetime.fromisoformat("2026-09-17T09:00:00+00:00"),
        last_seen=datetime.fromisoformat("2026-09-17T09:01:00+00:00"),
    )
    current = Incident(
        title="Current attack",
        severity="high",
        confidence=0.9,
        status="open",
        source_entities=[source_ip],
        target_entities=["target-server"],
        attack_chain=[],
        mitre_techniques=["T1110"],
        first_seen=datetime.fromisoformat("2026-09-17T11:00:00+00:00"),
        last_seen=datetime.fromisoformat("2026-09-17T11:01:00+00:00"),
    )
    recurrence_db.add_all([previous, current])
    recurrence_db.commit()

    for status in ["failed", "proposed", "awaiting_approval"]:
        recurrence_db.add(Response(
            incident_id=previous.id,
            action="block_source_ip",
            status=status,
            details={"status": status},
        ))
    recurrence_db.commit()

    assert RecurrenceService(recurrence_db).detect_and_escalate(current.id) is None
    assert recurrence_db.query(Escalation).count() == 0


def test_slack_failure_is_isolated_and_disabled_mode_makes_no_request(
    recurrence_db,
    monkeypatch,
):
    calls = []
    def timeout(self, payload):
        calls.append(payload)
        raise httpx.ReadTimeout("timeout")

    monkeypatch.setattr(SlackNotifier, "send_escalation", timeout)
    previous, _, verified_at = verified_first_attack(
        recurrence_db, "10.10.10.95"
    )
    second = submit_attack(
        recurrence_db,
        "10.10.10.95",
        verified_at + timedelta(minutes=2),
    )
    escalation = recurrence_db.query(Escalation).one()
    assert second["incidents_created"] >= 1
    assert escalation.requires_human_review is True
    assert escalation.slack_notification_status == "FAILED"
    assert escalation.slack_notification_error == "Slack request timed out"
    assert len(calls) == 1

    monkeypatch.setattr(settings, "slack_notifications_enabled", False)
    before = len(calls)
    disabled = NotificationService().notify_human_escalation({})
    assert disabled["status"] == "DISABLED"
    assert len(calls) == before

    monkeypatch.setattr(settings, "slack_notifications_enabled", True)
    monkeypatch.setattr(settings, "slack_webhook_url", None)
    missing = NotificationService().notify_human_escalation({})
    assert missing["status"] == "NOT_CONFIGURED"
    assert len(calls) == before


def test_slack_adapter_formats_kathmandu_time_and_handles_http_errors(
    recurrence_db,
    monkeypatch,
):
    payloads = []

    class SuccessfulResponse:
        status_code = 200

        def raise_for_status(self):
            return None

    def successful_post(url, json, timeout):
        payloads.append(json)
        return SuccessfulResponse()

    monkeypatch.setattr(httpx, "post", successful_post)
    SlackNotifier().send_escalation({
        "severity": "high",
        "source_ip": "10.10.10.99",
        "target": "target-server",
        "recurrence_count": 2,
        "current_incident_id": "incident-2",
        "previous_action": "block_source_ip",
        "previous_response_status": "verified",
        "last_activity_at": "2026-09-17T12:00:00+00:00",
        "reason": "Repeated malicious activity detected.",
    })
    assert len(payloads) == 1
    assert "2026-09-17 17:45:00 Asia/Kathmandu" in payloads[0]["text"]
    assert settings.slack_webhook_url not in payloads[0]["text"]

    request = httpx.Request("POST", "https://hooks.slack.test/redacted")
    response = httpx.Response(500, request=request)
    monkeypatch.setattr(
        SlackNotifier,
        "send_escalation",
        lambda *args: (_ for _ in ()).throw(
            httpx.HTTPStatusError("error", request=request, response=response)
        ),
    )
    failed = NotificationService().notify_human_escalation({})
    assert failed == {"status": "FAILED", "error": "Slack returned HTTP 500"}

    monkeypatch.setattr(
        SlackNotifier,
        "send_escalation",
        lambda *args: (_ for _ in ()).throw(httpx.ConnectError("dns")),
    )
    network = NotificationService().notify_human_escalation({})
    assert network == {"status": "FAILED", "error": "Slack network request failed"}
