from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.time import KATHMANDU, ensure_utc, to_kathmandu, utc_iso, utc_now
from app.core.trace_ai import TraceAI
from app.models.database import Base, Event
from app.models.response_models import ActionType
from app.models.schemas import Event as EventSchema, Incident as IncidentSchema
from app.services.response_service import ResponseService


def test_utc_generation_and_iso_serialization():
    current = utc_now()

    assert current.tzinfo is timezone.utc
    assert datetime.fromisoformat(utc_iso(current)).utcoffset() == timedelta(0)


def test_kathmandu_conversion_uses_forty_five_minute_offset():
    source = datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc)
    local = to_kathmandu(source)

    assert local.tzinfo == KATHMANDU
    assert local.utcoffset() == timedelta(hours=5, minutes=45)
    assert local.hour == 17 and local.minute == 45


def test_legacy_naive_timestamp_is_treated_as_utc():
    legacy = datetime(2026, 9, 17, 12, 0)

    assert ensure_utc(legacy) == datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc)


def test_database_round_trip_returns_aware_utc_for_legacy_input():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        event = Event(
            timestamp=datetime(2026, 9, 17, 12, 0),
            host="timestamp-test",
            event_type="test",
        )
        session.add(event)
        session.commit()
        session.expire_all()

        stored = session.query(Event).one()
        assert stored.timestamp.tzinfo is timezone.utc
        assert stored.created_at.tzinfo is timezone.utc
    finally:
        session.close()


def test_api_schema_serializes_utc_not_presentation_timezone():
    event = EventSchema(
        id="event-1",
        timestamp=datetime(2026, 9, 17, 12, 0),
        host="api-test",
        event_type="test",
    )

    assert event.model_dump()["timestamp"].endswith("+00:00")


def test_chronological_sorting_uses_instants_not_iso_text():
    values = [
        "2026-09-17T18:00:00+05:45",
        "2026-09-17T12:30:01+00:00",
        "2026-09-17T12:00:00Z",
    ]

    ordered = sorted(values, key=TraceAI._sort_timestamp)
    assert ordered == [values[2], values[0], values[1]]


def test_incident_timeline_duration_and_response_audit_are_aware_utc():
    incident = IncidentSchema(
        id="incident-1",
        title="Timestamp regression",
        severity="high",
        first_seen=datetime(2026, 9, 17, 12, 0),
        last_seen=datetime(2026, 9, 17, 12, 2, tzinfo=timezone.utc),
    )
    assert incident.duration_seconds == 120
    assert incident.model_dump()["first_seen"].endswith("+00:00")

    service = ResponseService()
    service.executions.clear()
    service.audit_log.clear()
    record = service.execute_action(
        incident_id="incident-1",
        action=ActionType.BLOCK_IP,
        target="198.51.100.10",
        dry_run=True,
    )

    assert record.started_at.utcoffset() == timedelta(0)
    assert record.completed_at.utcoffset() == timedelta(0)
    assert datetime.fromisoformat(record.verification_result["timestamp"]).utcoffset() == timedelta(0)
    assert service.audit_log[0].timestamp.utcoffset() == timedelta(0)
