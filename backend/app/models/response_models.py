from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import datetime

from pydantic import BaseModel, Field, field_serializer

from app.core.time import utc_iso


# ============================================================
# RESPONSE ACTIONS
# ============================================================

class ActionType(str, Enum):
    BLOCK_IP = "block_source_ip"
    DISABLE_ACCOUNT = "disable_account"
    FORCE_PASSWORD_RESET = "force_password_reset"
    TERMINATE_SESSION = "terminate_session"
    ISOLATE_ENDPOINT = "isolate_endpoint"
    DISABLE_SERVICE = "disable_service"
    APPLY_MITIGATION = "apply_mitigation"
    ROTATE_CREDENTIAL = "rotate_credential"
    COLLECT_EVIDENCE = "collect_evidence"


# ============================================================
# VULNERABILITY FINDINGS
# ============================================================

class VulnerabilityFinding(BaseModel):
    """
    Represents a vulnerability discovered during vulnerability
    assessment or security analysis.

    This model is intentionally flexible so it can accept findings
    from different scanners and analysis components.
    """

    id: Optional[str] = None

    title: str

    description: str

    severity: str = "medium"

    cve_id: Optional[str] = None

    cwe_id: Optional[str] = None

    affected_host: Optional[str] = None

    affected_service: Optional[str] = None

    affected_port: Optional[int] = None

    evidence: List[str] = Field(
        default_factory=list
    )

    remediation: Optional[str] = None

    references: List[str] = Field(
        default_factory=list
    )

    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    metadata: Dict[str, Any] = Field(
        default_factory=dict
    )


# ============================================================
# RISK
# ============================================================

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ============================================================
# EXECUTION STATUS
# ============================================================

class ExecutionStatus(str, Enum):
    PENDING_APPROVAL = "pending_approval"
    EXECUTED = "executed"
    VERIFIED = "verified"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


# ============================================================
# RESPONSE PLAYBOOK
# ============================================================

class ResponsePlaybook(BaseModel):
    id: str

    name: str

    description: str

    action_type: ActionType

    risk_level: RiskLevel

    supported_incident_types: List[str]

    supported_cves: List[str] = Field(
        default_factory=list
    )

    required_permissions: List[str] = Field(
        default_factory=list
    )

    auto_execute_allowed: bool = False

    verification_steps: List[str] = Field(
        default_factory=list
    )

    rollback_steps: List[str] = Field(
        default_factory=list
    )

    enabled: bool = True


# ============================================================
# RESPONSE POLICY
# ============================================================

class ResponsePolicy(BaseModel):
    action_type: ActionType

    enabled: bool = True

    auto_execute: bool = False

    minimum_confidence: float = Field(
        default=0.80,
        ge=0.0,
        le=1.0,
    )

    allowed_severities: List[str] = Field(
        default_factory=list
    )

    requires_approval: bool = True

    dry_run_default: bool = True


# ============================================================
# POLICY EVALUATION
# ============================================================

class PolicyEvaluationResult(BaseModel):
    allowed: bool

    requires_approval: bool

    reason: str

    policy_id: str

    auto_execute: bool


# ============================================================
# RESPONSE PROPOSAL
# ============================================================

class ResponseProposal(BaseModel):
    incident_id: str

    classification: str

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    recommended_action: ActionType

    playbook_id: str

    target: str

    reason: str

    evidence: List[str] = Field(
        default_factory=list
    )

    requires_approval: bool

    risk_level: RiskLevel

    verification_required: bool = True

    policy_evaluation: PolicyEvaluationResult

    dry_run_preview: Dict[str, Any] = Field(
        default_factory=dict
    )


# ============================================================
# RESPONSE EXECUTION
# ============================================================

class ResponseExecutionRecord(BaseModel):
    execution_id: str

    incident_id: str

    playbook_id: str

    action: ActionType

    target: str

    requested_by: str

    approved_by: Optional[str] = None

    started_at: datetime

    completed_at: Optional[datetime] = None

    status: ExecutionStatus

    dry_run: bool = True

    result: Dict[str, Any] = Field(
        default_factory=dict
    )

    verification_result: Optional[Dict[str, Any]] = None

    rollback_available: bool = False

    @field_serializer("started_at", "completed_at")
    def serialize_timestamps(
        self,
        value: Optional[datetime],
    ) -> Optional[str]:
        return utc_iso(value)


# ============================================================
# RESPONSE VERIFICATION
# ============================================================

class ResponseVerificationResult(BaseModel):
    verified: bool

    method: str

    details: Optional[str] = None

    timestamp: datetime

    evidence: List[str] = Field(
        default_factory=list
    )

    @field_serializer("timestamp")
    def serialize_timestamp(
        self,
        value: datetime,
    ) -> Optional[str]:
        return utc_iso(value)


# ============================================================
# RESPONSE AUDIT
# ============================================================

class ResponseAuditEntry(BaseModel):
    id: str

    timestamp: datetime

    incident_id: str

    agent: str

    action: ActionType

    policy_decision: str

    target: str

    operator: str

    execution_result: Dict[str, Any] = Field(
        default_factory=dict
    )

    verification: Dict[str, Any] = Field(
        default_factory=dict
    )

    rollback: Optional[Dict[str, Any]] = None

    dry_run: bool = True

    @field_serializer("timestamp")
    def serialize_timestamp(
        self,
        value: datetime,
    ) -> Optional[str]:
        return utc_iso(value)


# ============================================================
# EXECUTION REQUEST
# ============================================================

class ResponseExecutionRequest(BaseModel):
    incident_id: Optional[str] = None

    action: ActionType

    target: str

    playbook_id: Optional[str] = None

    dry_run: bool = True

    approved_by: str = "analyst"

    parameters: Dict[str, Any] = Field(
        default_factory=dict
    )


# ============================================================
# ROLLBACK REQUEST
# ============================================================

class ResponseRollbackRequest(BaseModel):
    execution_id: str

    operator: str = "analyst"
