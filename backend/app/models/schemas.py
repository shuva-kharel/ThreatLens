from pydantic import BaseModel, Field, computed_field
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum

# ============ Enums ============
class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"

# ============ Event Schemas ============
class EventBase(BaseModel):
    timestamp: datetime
    host: str
    source_ip: Optional[str] = None
    event_type: str
    username: Optional[str] = None
    severity: Optional[Severity] = None
    raw_event: Optional[str] = None

class EventCreate(EventBase):
    pass

class Event(EventBase):
    id: str
    created_at: datetime
    normalized_data: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True

# ============ Alert Schemas ============
class AlertBase(BaseModel):
    alert_type: str
    severity: Severity
    mitre_technique: Optional[str] = None
    source_ip: Optional[str] = None
    target_host: Optional[str] = None
    description: str
    evidence: List[str] = []
    confidence: float = 1.0

class AlertCreate(AlertBase):
    pass

class Alert(AlertBase):
    id: str
    status: str
    incident_id: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True

# ============ Incident Schemas ============
class AttackStage(BaseModel):
    stage: str
    description: str
    timestamp: datetime
    technique_id: Optional[str] = None

class IncidentBase(BaseModel):
    title: str
    severity: Severity
    confidence: float = 0.0
    source_entities: List[str] = []
    target_entities: List[str] = []
    attack_chain: List[AttackStage] = []
    mitre_techniques: List[str] = []
    ai_summary: Optional[str] = None
    recommendations: Optional[List[str]] = None  # ← Allow None

class IncidentCreate(IncidentBase):
    first_seen: datetime
    last_seen: datetime

class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    severity: Optional[Severity] = None
    status: Optional[IncidentStatus] = None
    confidence: Optional[float] = None
    ai_summary: Optional[str] = None
    recommendations: Optional[List[str]] = None

class Incident(IncidentBase):
    id: str
    status: IncidentStatus
    first_seen: datetime
    last_seen: datetime
    resolved_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    recommendations: Optional[List[str]] = None  # ← Allow None

    @computed_field
    @property
    def duration_seconds(self) -> Optional[float]:
        if self.first_seen and self.last_seen:
            return round((self.last_seen - self.first_seen).total_seconds(), 3)
        return None

    @computed_field
    @property
    def duration_minutes(self) -> Optional[float]:
        secs = self.duration_seconds
        return round(secs / 60.0, 3) if secs is not None else None

    class Config:
        from_attributes = True

# ============ Response Schemas ============
class ResponseAction(BaseModel):
    action: str
    details: Optional[Dict[str, Any]] = None

class ResponseRecord(BaseModel):
    id: str
    incident_id: str
    action: str
    status: str
    performed_by: str
    details: Optional[Dict[str, Any]] = None
    created_at: datetime

# ============ AI Schemas ============
class AIAnalysisRequest(BaseModel):
    incident_id: str

class AIAnalysisResponse(BaseModel):
    summary: str
    attack_explanation: str
    evidence_list: List[str]        # OBSERVED — from events
    attack_progression: List[str]   # INFERRED — reconstructed
    mitre_explanation: str
    investigation_steps: List[str]
    containment_steps: List[str]
    # NEW FIELDS
    confidence: Optional[str] = "medium"
    likely_attack: Optional[str] = None
    observed_evidence: Optional[List[str]] = None
    inferences: Optional[List[str]] = None