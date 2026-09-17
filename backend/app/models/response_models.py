from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import datetime

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

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ExecutionStatus(str, Enum):
    PLANNED = "planned"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    EXECUTED = "executed"
    VERIFIED = "verified"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"

class ResponsePlaybook(BaseModel):
    id: str
    name: str
    description: str
    action_type: ActionType
    risk_level: RiskLevel
    supported_incident_types: List[str]
    supported_cves: List[str] = []
    required_permissions: List[str] = []
    auto_execute_allowed: bool = False
    verification_steps: List[str]
    rollback_steps: List[str]
    enabled: bool = True

class ResponsePolicy(BaseModel):
    action_type: ActionType
    enabled: bool = True
    auto_execute: bool = False
    minimum_confidence: float = 0.85
    allowed_severities: List[str] = ["medium", "high", "critical"]
    requires_approval: bool = True
    dry_run_default: bool = True

class PolicyEvaluationResult(BaseModel):
    allowed: bool
    requires_approval: bool
    reason: str
    policy_id: str
    auto_execute: bool

class ResponseProposal(BaseModel):
    incident_id: str
    classification: str
    confidence: float
    recommended_action: ActionType
    playbook_id: str
    target: str
    reason: str
    evidence: List[str] = []
    requires_approval: bool
    risk_level: RiskLevel
    verification_required: bool = True
    policy_evaluation: Optional[PolicyEvaluationResult] = None
    dry_run_preview: Optional[Dict[str, Any]] = None

class ResponseExecutionRequest(BaseModel):
    action: ActionType
    target: str
    playbook_id: Optional[str] = None
    dry_run: bool = True
    approved_by: Optional[str] = "analyst"
    parameters: Dict[str, Any] = Field(default_factory=dict)

class ResponseExecutionRecord(BaseModel):
    execution_id: str
    incident_id: str
    playbook_id: str
    action: ActionType
    target: str
    requested_by: str = "ai_agent"
    approved_by: Optional[str] = None
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: ExecutionStatus
    dry_run: bool
    result: Dict[str, Any] = Field(default_factory=dict)
    verification_result: Optional[Dict[str, Any]] = None
    rollback_available: bool = False

class ResponseVerificationResult(BaseModel):
    execution_id: str
    verified: bool
    method: str
    details: str
    timestamp: datetime

class VulnerabilityFinding(BaseModel):
    cve_id: str
    title: str
    affected_product: str
    affected_versions: str
    severity: str
    description: str
    detection_method: str
    remediation: str
    mitigation: str
    playbook_id: str
    auto_response_eligible: bool
    approval_required: bool
    verification_method: str
    references: List[str] = []
    affected_assets: List[str] = []

class ResponseAuditEntry(BaseModel):
    id: str
    timestamp: datetime
    incident_id: str
    agent: str
    action: ActionType
    policy_decision: str
    target: str
    operator: str
    execution_result: Dict[str, Any]
    verification: Optional[Dict[str, Any]] = None
    rollback: Optional[Dict[str, Any]] = None
    dry_run: bool = False
