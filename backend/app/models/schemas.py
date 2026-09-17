from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any

from pydantic import (
    BaseModel,
    Field,
    computed_field,
    field_serializer,
    ConfigDict,
)

from app.core.time import ensure_utc, utc_iso


# ============================================================
# ENUMS
# ============================================================

class Severity(str, Enum):
    """
    Severity levels used throughout ThreatLens.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, Enum):
    """
    Incident lifecycle states.
    """

    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"


class ResponseAction(str, Enum):
    """
    Automated response actions supported by ThreatLens.

    Keep these values aligned with ResponseService and the
    response API.
    """

    BLOCK_SOURCE_IP = "block_source_ip"
    DISABLE_ACCOUNT = "disable_account"
    FORCE_PASSWORD_RESET = "force_password_reset"
    TERMINATE_SESSION = "terminate_session"
    ISOLATE_ENDPOINT = "isolate_endpoint"
    DISABLE_SERVICE = "disable_service"
    APPLY_MITIGATION = "apply_mitigation"
    ROTATE_CREDENTIAL = "rotate_credential"
    COLLECT_EVIDENCE = "collect_evidence"


# ============================================================
# EVENT SCHEMAS
# ============================================================

class EventBase(BaseModel):
    timestamp: datetime
    host: str
    source_ip: Optional[str] = None
    event_type: str
    username: Optional[str] = None
    severity: Optional[str] = None
    raw_event: Optional[str] = None
    normalized_data: Optional[Dict[str, Any]] = None

    @field_serializer("timestamp")
    def serialize_timestamp(
        self,
        value: datetime,
    ) -> Optional[str]:
        """
        API representation is timezone-aware UTC.
        """
        return utc_iso(value)


class EventCreate(EventBase):
    pass


class Event(EventBase):
    model_config = ConfigDict(
        from_attributes=True
    )

    id: str

    created_at: Optional[datetime] = None

    @field_serializer("created_at")
    def serialize_created_at(
        self,
        value: Optional[datetime],
    ) -> Optional[str]:
        return utc_iso(value)


# ============================================================
# ALERT SCHEMAS
# ============================================================

class AlertBase(BaseModel):
    alert_type: str

    severity: str

    mitre_technique: Optional[str] = None

    source_ip: Optional[str] = None

    target_host: Optional[str] = None

    description: str

    evidence: List[str] = Field(
        default_factory=list
    )

    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )


class AlertCreate(AlertBase):
    pass


class Alert(AlertBase):
    model_config = ConfigDict(
        from_attributes=True
    )

    id: str

    incident_id: Optional[str] = None

    created_at: Optional[datetime] = None

    updated_at: Optional[datetime] = None

    @field_serializer("created_at", "updated_at")
    def serialize_timestamps(
        self,
        value: Optional[datetime],
    ) -> Optional[str]:
        return utc_iso(value)


# ============================================================
# ATTACK CHAIN
# ============================================================

class AttackStage(BaseModel):
    stage: str

    description: str

    timestamp: Optional[datetime] = None

    technique_id: Optional[str] = None

    @field_serializer("timestamp")
    def serialize_timestamp(
        self,
        value: Optional[datetime],
    ) -> Optional[str]:
        return utc_iso(value)


# ============================================================
# INCIDENT SCHEMAS
# ============================================================

class IncidentBase(BaseModel):
    title: str

    severity: str

    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    status: str = IncidentStatus.OPEN.value

    source_entities: List[str] = Field(
        default_factory=list
    )

    target_entities: List[str] = Field(
        default_factory=list
    )

    mitre_techniques: List[str] = Field(
        default_factory=list
    )

    attack_chain: List[Dict[str, Any]] = Field(
        default_factory=list
    )

    recommendations: List[str] = Field(
        default_factory=list
    )


class IncidentCreate(IncidentBase):
    first_seen: datetime

    last_seen: datetime

    @field_serializer("first_seen", "last_seen")
    def serialize_timestamps(
        self,
        value: datetime,
    ) -> Optional[str]:
        return utc_iso(value)


class IncidentUpdate(BaseModel):
    title: Optional[str] = None

    severity: Optional[str] = None

    confidence: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
    )

    status: Optional[str] = None

    source_entities: Optional[List[str]] = None

    target_entities: Optional[List[str]] = None

    mitre_techniques: Optional[List[str]] = None

    attack_chain: Optional[List[Dict[str, Any]]] = None

    recommendations: Optional[List[str]] = None


class Incident(IncidentBase):
    model_config = ConfigDict(
        from_attributes=True
    )

    id: str

    first_seen: datetime

    last_seen: datetime

    resolved_at: Optional[datetime] = None

    created_at: Optional[datetime] = None

    updated_at: Optional[datetime] = None

    @computed_field
    @property
    def duration_seconds(self) -> float:
        """
        Duration is calculated using the underlying UTC timestamps.

        Timezone conversion is presentation-only, so it must not
        affect duration calculations.
        """

        if not self.first_seen or not self.last_seen:
            return 0.0

        return max(
            0.0,
            (
                ensure_utc(self.last_seen) - ensure_utc(self.first_seen)
            ).total_seconds(),
        )

    @computed_field
    @property
    def duration_minutes(self) -> float:
        return round(
            self.duration_seconds / 60.0,
            2,
        )

    @field_serializer(
        "first_seen",
        "last_seen",
        "resolved_at",
        "created_at",
        "updated_at",
    )
    def serialize_timestamps(
        self,
        value: Optional[datetime],
    ) -> Optional[str]:
        return utc_iso(value)


# ============================================================
# RESPONSE RECORD
# ============================================================

class ResponseRecord(BaseModel):
    execution_id: str

    incident_id: str

    action: str

    target: str

    requested_by: str

    approved_by: Optional[str] = None

    created_at: datetime

    status: str

    dry_run: bool = True

    result: Optional[Dict[str, Any]] = None

    verification_result: Optional[Dict[str, Any]] = None

    @field_serializer("created_at")
    def serialize_created_at(
        self,
        value: datetime,
    ) -> Optional[str]:
        return utc_iso(value)


# ============================================================
# AI / INVESTIGATION SCHEMAS
# ============================================================

class AIAnalysisRequest(BaseModel):
    incident_id: str

    include_timeline: bool = True

    include_attack_graph: bool = True

    include_recommendations: bool = True


class AIAnalysisResponse(BaseModel):
    incident_id: str

    summary: str

    attack_narrative: str

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    findings: List[str] = Field(
        default_factory=list
    )

    recommendations: List[str] = Field(
        default_factory=list
    )

    mitre_techniques: List[str] = Field(
        default_factory=list
    )

    timeline: List[Dict[str, Any]] = Field(
        default_factory=list
    )

    attack_graph: Dict[str, Any] = Field(
        default_factory=dict
    )
