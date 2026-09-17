from sqlalchemy import (
    create_engine,
    Column,
    String,
    Integer,
    Float,
    DateTime,
    Text,
    JSON,
    Enum,
    Index,
    TypeDecorator,
    Boolean,
)
from sqlalchemy.engine import Dialect
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import enum
import uuid

from app.core.time import UTC, ensure_utc, utc_now


Base = declarative_base()


# =============================================================================
# TIMEZONE / TIMESTAMP HELPERS
# =============================================================================

class UTCDateTime(TypeDecorator):
    """Store UTC compatibly and always expose timezone-aware values."""

    impl = DateTime
    cache_ok = True

    def load_dialect_impl(self, dialect: Dialect):
        return dialect.type_descriptor(DateTime(timezone=dialect.name != "sqlite"))

    def process_bind_param(self, value: datetime | None, dialect: Dialect):
        if value is None:
            return None
        value = ensure_utc(value)
        return value.replace(tzinfo=None) if dialect.name == "sqlite" else value

    def process_result_value(self, value: datetime | None, dialect: Dialect):
        return ensure_utc(value)


# =============================================================================
# ENUMS
# =============================================================================

class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


# =============================================================================
# EVENTS
# =============================================================================

class Event(Base):
    __tablename__ = "events"

    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    # Event occurrence time.
    # Stored as timezone-aware UTC.
    timestamp = Column(
        UTCDateTime(),
        nullable=False,
    )

    host = Column(
        String(255),
        nullable=False,
    )

    source_ip = Column(
        String(45),
        nullable=True,
    )

    event_type = Column(
        String(100),
        nullable=False,
    )

    username = Column(
        String(255),
        nullable=True,
    )

    severity = Column(
        String(20),
        nullable=True,
    )

    raw_event = Column(
        Text,
        nullable=True,
    )

    normalized_data = Column(
        JSON,
        nullable=True,
    )

    # Time ThreatLens received/created the event.
    created_at = Column(
        UTCDateTime(),
        default=utc_now,
        nullable=False,
    )

    __table_args__ = (
        Index(
            "idx_event_timestamp",
            "timestamp",
        ),
        Index(
            "idx_event_host",
            "host",
        ),
        Index(
            "idx_event_type",
            "event_type",
        ),
    )


# =============================================================================
# ALERTS
# =============================================================================

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    alert_type = Column(
        String(100),
        nullable=False,
    )

    severity = Column(
        Enum(Severity),
        nullable=False,
    )

    mitre_technique = Column(
        String(20),
        nullable=True,
    )

    source_ip = Column(
        String(45),
        nullable=True,
    )

    target_host = Column(
        String(255),
        nullable=True,
    )

    description = Column(
        Text,
        nullable=True,
    )

    # List of event IDs.
    evidence = Column(
        JSON,
        nullable=True,
    )

    confidence = Column(
        Float,
        default=1.0,
    )

    status = Column(
        String(20),
        default="open",
    )

    incident_id = Column(
        String(36),
        nullable=True,
    )

    created_at = Column(
        UTCDateTime(),
        default=utc_now,
        nullable=False,
    )

    __table_args__ = (
        Index(
            "idx_alert_severity",
            "severity",
        ),
        Index(
            "idx_alert_status",
            "status",
        ),
    )


# =============================================================================
# INCIDENTS
# =============================================================================

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    title = Column(
        String(255),
        nullable=False,
    )

    severity = Column(
        Enum(Severity),
        nullable=False,
    )

    confidence = Column(
        Float,
        default=0.0,
    )

    status = Column(
        Enum(IncidentStatus),
        default=IncidentStatus.OPEN,
    )

    # List of source IPs.
    source_entities = Column(
        JSON,
        nullable=True,
    )

    # List of target hosts.
    target_entities = Column(
        JSON,
        nullable=True,
    )

    # Ordered list of attack stages.
    attack_chain = Column(
        JSON,
        nullable=True,
    )

    # List of MITRE ATT&CK technique IDs.
    mitre_techniques = Column(
        JSON,
        nullable=True,
    )

    ai_summary = Column(
        Text,
        nullable=True,
    )

    recommendations = Column(
        JSON,
        nullable=True,
    )

    # -------------------------------------------------------------------------
    # Incident timeline
    # -------------------------------------------------------------------------

    # Timestamp of the first event belonging to this incident.
    first_seen = Column(
        UTCDateTime(),
        nullable=False,
    )

    # Timestamp of the most recent event belonging to this incident.
    last_seen = Column(
        UTCDateTime(),
        nullable=False,
    )

    # Timestamp when the incident was contained/resolved.
    resolved_at = Column(
        UTCDateTime(),
        nullable=True,
    )

    # Timestamp when ThreatLens created the incident.
    created_at = Column(
        UTCDateTime(),
        default=utc_now,
        nullable=False,
    )

    # Timestamp of the most recent modification.
    updated_at = Column(
        UTCDateTime(),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )

    __table_args__ = (
        Index(
            "idx_incident_severity",
            "severity",
        ),
        Index(
            "idx_incident_status",
            "status",
        ),
        Index(
            "idx_incident_last_seen",
            "last_seen",
        ),
    )


# =============================================================================
# RESPONSES
# =============================================================================

class Response(Base):
    __tablename__ = "responses"

    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    incident_id = Column(
        String(36),
        nullable=False,
    )

    action = Column(
        String(100),
        nullable=False,
    )

    status = Column(
        String(50),
        nullable=False,
    )

    performed_by = Column(
        String(100),
        default="analyst",
    )

    details = Column(
        JSON,
        nullable=True,
    )

    # Timestamp when the response action was recorded.
    created_at = Column(
        UTCDateTime(),
        default=utc_now,
        nullable=False,
    )

    __table_args__ = (
        Index(
            "idx_response_incident",
            "incident_id",
        ),
    )


class Escalation(Base):
    __tablename__ = "escalations"

    id = Column(String(36), primary_key=True)
    source_ip = Column(String(45), nullable=False)
    target = Column(String(255), nullable=True)
    severity = Column(String(20), nullable=False)
    current_incident_id = Column(String(36), nullable=False, unique=True)
    previous_incident_id = Column(String(36), nullable=False)
    previous_response_id = Column(String(36), nullable=False)
    previous_action = Column(String(100), nullable=False)
    previous_response_status = Column(String(50), nullable=False)
    previous_verification_at = Column(UTCDateTime(), nullable=False)
    last_activity_at = Column(UTCDateTime(), nullable=False)
    recurrence_count = Column(Integer, nullable=False, default=2)
    reason = Column(Text, nullable=False)
    requires_human_review = Column(Boolean, nullable=False, default=True)
    status = Column(String(30), nullable=False, default="ESCALATED")
    assigned_to = Column(String(100), nullable=True)
    slack_notification_status = Column(String(30), nullable=False, default="PENDING")
    slack_notification_attempted_at = Column(UTCDateTime(), nullable=True)
    slack_notification_error = Column(Text, nullable=True)
    created_at = Column(UTCDateTime(), default=utc_now, nullable=False)
    updated_at = Column(UTCDateTime(), default=utc_now, onupdate=utc_now, nullable=False)

    __table_args__ = (
        Index("idx_escalation_source", "source_ip"),
        Index("idx_escalation_status", "status"),
    )


class EndpointAgent(Base):
    __tablename__ = "endpoint_agents"

    id = Column(String(64), primary_key=True)
    hostname = Column(String(255), nullable=False, index=True)
    os = Column(String(100), nullable=False)
    ip_addresses = Column(JSON, nullable=False, default=list)
    version = Column(String(50), nullable=False)
    capabilities = Column(JSON, nullable=False, default=list)
    last_seen = Column(UTCDateTime(), nullable=False, default=utc_now, index=True)
    registered_at = Column(UTCDateTime(), nullable=False, default=utc_now)


class AgentTask(Base):
    __tablename__ = "agent_tasks"

    id = Column(String(64), primary_key=True)
    agent_id = Column(String(64), nullable=False, index=True)
    incident_id = Column(String(36), nullable=False, index=True)
    execution_id = Column(String(50), nullable=False, unique=True, index=True)
    action = Column(String(50), nullable=False)
    target = Column(String(45), nullable=False)
    managed_rule_id = Column(String(100), nullable=False)
    status = Column(String(30), nullable=False, default="pending", index=True)
    result = Column(JSON, nullable=True)
    verification_result = Column(JSON, nullable=True)
    created_at = Column(UTCDateTime(), nullable=False, default=utc_now)
    claimed_at = Column(UTCDateTime(), nullable=True)
    completed_at = Column(UTCDateTime(), nullable=True)


class DemoRun(Base):
    __tablename__ = "demo_runs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scenario = Column(String(50), nullable=False)
    asset_id = Column(String(64), nullable=False)
    target_host = Column(String(255), nullable=False)
    target_ip = Column(String(45), nullable=False)
    source_ip = Column(String(45), nullable=False)
    status = Column(String(30), nullable=False, default="queued", index=True)
    safety_mode = Column(String(30), nullable=False, default="synthetic_telemetry")
    stop_requested = Column(Boolean, nullable=False, default=False)
    events_sent = Column(Integer, nullable=False, default=0)
    alerts_created = Column(Integer, nullable=False, default=0)
    incident_id = Column(String(36), nullable=True)
    pipeline = Column(JSON, nullable=False, default=dict)
    log = Column(JSON, nullable=False, default=list)
    error = Column(Text, nullable=True)
    created_at = Column(UTCDateTime(), nullable=False, default=utc_now)
    started_at = Column(UTCDateTime(), nullable=True)
    completed_at = Column(UTCDateTime(), nullable=True)


class AgentEventReceipt(Base):
    __tablename__ = "agent_event_receipts"

    id = Column(String(64), primary_key=True)
    agent_id = Column(String(64), nullable=False, index=True)
    source_event_id = Column(String(255), nullable=False)
    telemetry_source = Column(String(50), nullable=False, index=True)
    event_db_id = Column(String(36), nullable=True)
    status = Column(String(20), nullable=False, default="processing")
    received_at = Column(UTCDateTime(), nullable=False, default=utc_now, index=True)

    __table_args__ = (
        Index("idx_agent_source_event", "agent_id", "source_event_id", unique=True),
    )
