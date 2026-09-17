from sqlalchemy import (
    create_engine, Column, String, Integer, Float,
    DateTime, Text, JSON, Enum, Index  # ← Added Index here
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import enum
import uuid

Base = declarative_base()

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

class Event(Base):
    __tablename__ = "events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, nullable=False)
    host = Column(String(255), nullable=False)
    source_ip = Column(String(45), nullable=True)
    event_type = Column(String(100), nullable=False)
    username = Column(String(255), nullable=True)
    severity = Column(String(20), nullable=True)
    raw_event = Column(Text, nullable=True)
    normalized_data = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Index for performance
    __table_args__ = (
        Index('idx_event_timestamp', 'timestamp'),
        Index('idx_event_host', 'host'),
        Index('idx_event_type', 'event_type'),
    )

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    alert_type = Column(String(100), nullable=False)
    severity = Column(Enum(Severity), nullable=False)
    mitre_technique = Column(String(20), nullable=True)
    source_ip = Column(String(45), nullable=True)
    target_host = Column(String(255), nullable=True)
    description = Column(Text, nullable=True)
    evidence = Column(JSON, nullable=True)  # List of event IDs
    confidence = Column(Float, default=1.0)
    status = Column(String(20), default="open")
    incident_id = Column(String(36), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index('idx_alert_severity', 'severity'),
        Index('idx_alert_status', 'status'),
    )

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(255), nullable=False)
    severity = Column(Enum(Severity), nullable=False)
    confidence = Column(Float, default=0.0)
    status = Column(Enum(IncidentStatus), default=IncidentStatus.OPEN)
    source_entities = Column(JSON, nullable=True)   # List of source IPs
    target_entities = Column(JSON, nullable=True)   # List of target hosts
    attack_chain = Column(JSON, nullable=True)      # Ordered list of stages
    mitre_techniques = Column(JSON, nullable=True)  # List of technique IDs
    ai_summary = Column(Text, nullable=True)
    recommendations = Column(JSON, nullable=True)
    first_seen = Column(DateTime, nullable=False)
    last_seen = Column(DateTime, nullable=False)
    resolved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        Index('idx_incident_severity', 'severity'),
        Index('idx_incident_status', 'status'),
        Index('idx_incident_last_seen', 'last_seen'),
    )

class Response(Base):
    __tablename__ = "responses"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = Column(String(36), nullable=False)
    action = Column(String(100), nullable=False)
    status = Column(String(50), nullable=False)
    performed_by = Column(String(100), default="analyst")
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index('idx_response_incident', 'incident_id'),
    )