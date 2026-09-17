from fastapi import APIRouter, HTTPException, Depends
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models.database import Incident as IncidentDB, Alert as AlertDB
from app.core.trace_ai import TraceAI
from app.models.response_models import (
    ActionType, ResponsePlaybook, ResponsePolicy,
    ResponseProposal, ResponseExecutionRequest,
    ResponseExecutionRecord, ResponseAuditEntry
)
from app.services.response_service import ResponseService

router = APIRouter()

def get_service() -> ResponseService:
    return ResponseService()

# -----------------------------------------------------------------------------
# 1. Playbooks
# -----------------------------------------------------------------------------
@router.get("/playbooks", response_model=List[ResponsePlaybook])
async def list_playbooks(service: ResponseService = Depends(get_service)):
    """List all registered defensive response playbooks."""
    return list(service.playbooks.values())

@router.get("/playbooks/{playbook_id}", response_model=ResponsePlaybook)
async def get_playbook(playbook_id: str, service: ResponseService = Depends(get_service)):
    """Retrieve details of a specific defensive response playbook."""
    pb = service.playbooks.get(playbook_id)
    if not pb:
        raise HTTPException(status_code=404, detail=f"Playbook {playbook_id} not found")
    return pb

# -----------------------------------------------------------------------------
# 2. Policies
# -----------------------------------------------------------------------------
@router.get("/policies", response_model=List[ResponsePolicy])
async def list_policies(service: ResponseService = Depends(get_service)):
    """List all response action security policies."""
    return list(service.policies.values())

@router.patch("/policies/{action_type}", response_model=ResponsePolicy)
async def update_policy(
    action_type: ActionType,
    update: Dict[str, Any],
    service: ResponseService = Depends(get_service)
):
    """Update auto-execute, confidence thresholds, or approval requirements for an action."""
    policy = service.policies.get(action_type)
    if not policy:
        raise HTTPException(status_code=404, detail=f"Policy for action {action_type} not found")

    if "auto_execute" in update:
        policy.auto_execute = bool(update["auto_execute"])
    if "requires_approval" in update:
        policy.requires_approval = bool(update["requires_approval"])
    if "minimum_confidence" in update:
        policy.minimum_confidence = float(update["minimum_confidence"])
    if "enabled" in update:
        policy.enabled = bool(update["enabled"])
    if "dry_run_default" in update:
        policy.dry_run_default = bool(update["dry_run_default"])

    return policy

# -----------------------------------------------------------------------------
# 3. Executions & Audit Log
# -----------------------------------------------------------------------------
@router.get("/executions", response_model=List[ResponseExecutionRecord])
async def list_executions(service: ResponseService = Depends(get_service)):
    """List all executed or active defensive response jobs."""
    return list(service.executions.values())

@router.get("/executions/{execution_id}", response_model=ResponseExecutionRecord)
async def get_execution(execution_id: str, service: ResponseService = Depends(get_service)):
    """Get single execution record with results and verification logs."""
    record = service.executions.get(execution_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Execution {execution_id} not found")
    return record

@router.get("/audit", response_model=List[ResponseAuditEntry])
async def get_audit_log(service: ResponseService = Depends(get_service)):
    """Retrieve append-only SOC response audit trail."""
    return service.audit_log

@router.get("/stats", response_model=Dict[str, Any])
async def get_response_stats(service: ResponseService = Depends(get_service)):
    """Retrieve aggregated stats for defensive response automation."""
    return service.get_stats()

@router.get("/proposals", response_model=List[ResponseProposal])
async def list_proposals(service: ResponseService = Depends(get_service)):
    """Retrieve all formulated AI response proposals."""
    return list(service.proposals.values())


# -----------------------------------------------------------------------------
# 4. Incident Response Integration Endpoints
# -----------------------------------------------------------------------------
@router.post("/incidents/{incident_id}/plan", response_model=ResponseProposal)
async def plan_incident_response(
    incident_id: str,
    db: Session = Depends(get_db),
    service: ResponseService = Depends(get_service)
):
    """AI Response Agent formulates a bounded, policy-checked defensive response plan."""
    incident = db.query(IncidentDB).filter(IncidentDB.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    alerts = db.query(AlertDB).filter(AlertDB.incident_id == incident_id).all()
    trace_ai = TraceAI(db)
    trace = trace_ai.reconstruct_incident(incident_id)

    proposal = service.formulate_proposal(incident, alerts, trace)
    return proposal

@router.post("/incidents/{incident_id}/execute", response_model=ResponseExecutionRecord)
async def execute_incident_response(
    incident_id: str,
    request: ResponseExecutionRequest,
    db: Session = Depends(get_db),
    service: ResponseService = Depends(get_service)
):
    """Execute defensive action in safe Demo Mode (or preview with dry_run)."""
    incident = db.query(IncidentDB).filter(IncidentDB.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    record = service.execute_action(
        incident_id=incident_id,
        action=request.action,
        target=request.target,
        playbook_id=request.playbook_id,
        dry_run=request.dry_run,
        approved_by=request.approved_by or "analyst",
        parameters=request.parameters
    )

    # If action succeeded and verified (and not dry run), update incident state to contained
    if not request.dry_run and record.status.value in ["executed", "verified"]:
        if record.verification_result and record.verification_result.get("verified"):
            from datetime import datetime
            incident.status = "contained"
            incident.resolved_at = datetime.utcnow()
            db.commit()

    return record

@router.post("/incidents/{incident_id}/rollback")
async def rollback_incident_response(
    incident_id: str,
    execution_id: str,
    operator: str = "analyst",
    db: Session = Depends(get_db),
    service: ResponseService = Depends(get_service)
):
    """Roll back previous defensive response action."""
    incident = db.query(IncidentDB).filter(IncidentDB.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    result = service.rollback_action(execution_id, operator=operator)
    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result.get("message"))

    # Reset status if rolling back containment
    incident.status = "investigating"
    db.commit()

    return result
