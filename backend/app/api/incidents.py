from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models.schemas import Incident as IncidentSchema, IncidentUpdate
from app.models.schemas import Alert as AlertSchema
from app.models.database import Incident as IncidentDB
from app.models.database import Alert as AlertDB
from app.core.ai_analyst import AIAnalyst
from app.core.trace_ai import TraceAI
from app.api.mitre import MITRE_TECHNIQUES
from datetime import datetime
import uuid
from typing import Optional, List

router = APIRouter()


# =============================================================================
# ROUTE ORDERING PRINCIPLE
# -----------------------------------------------------------------------------
# FastAPI/Starlette matches more specific paths first, but to keep the file
# readable and predictable, we list routes from MOST specific to LEAST specific.
# =============================================================================


# -----------------------------------------------------------------------------
# 1. Static / search routes (highest specificity)
# -----------------------------------------------------------------------------

@router.get("/search")
async def search_incidents(
    q: str = "",
    severity: Optional[str] = None,
    status: Optional[str] = None,
    source_ip: Optional[str] = None,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """Search incidents with filters."""
    query = db.query(IncidentDB)

    if q:
        query = query.filter(
            IncidentDB.title.ilike(f"%{q}%") |
            IncidentDB.id.ilike(f"%{q}%")
        )
    if severity:
        query = query.filter(IncidentDB.severity == severity)
    if status:
        query = query.filter(IncidentDB.status == status)
    if source_ip:
        query = query.filter(IncidentDB.source_entities.contains([source_ip]))

    incidents = query.order_by(IncidentDB.last_seen.desc()).limit(limit).all()
    return [IncidentSchema.model_validate(i) for i in incidents]


# -----------------------------------------------------------------------------
# 2. Sub-resource routes (2+ segments)
# -----------------------------------------------------------------------------

@router.get("/{incident_id}/mitre")
async def get_incident_mitre(incident_id: str, db: Session = Depends(get_db)):
    """Get MITRE ATT&CK techniques mapped for an incident."""
    incident = db.query(IncidentDB).filter(IncidentDB.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    techniques = []
    for tid in (incident.mitre_techniques or []):
        if tid in MITRE_TECHNIQUES:
            techniques.append({"id": tid, **MITRE_TECHNIQUES[tid]})
        else:
            techniques.append({
                "id": tid,
                "name": "Unknown",
                "tactic": "Unknown",
                "url": "",
            })

    return {
        "incident_id": incident_id,
        "title": incident.title,
        "total": len(techniques),
        "techniques": techniques,
    }


@router.get("/{incident_id}/trace")
async def trace_incident(incident_id: str, db: Session = Depends(get_db)):
    """Reconstruct attack timeline and attack graph for an incident."""
    trace_ai = TraceAI(db)
    result = trace_ai.reconstruct_incident(incident_id)

    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])

    return result


@router.post("/{incident_id}/analyze")
async def analyze_incident(incident_id: str, db: Session = Depends(get_db)):
    """Trigger AI analysis for an incident."""
    incident = db.query(IncidentDB).filter(IncidentDB.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    alerts = db.query(AlertDB).filter(AlertDB.incident_id == incident_id).all()

    incident_data = {
        "id": incident.id,
        "title": incident.title,
        "severity": incident.severity,
        "confidence": incident.confidence,
        "source_entities": incident.source_entities,
        "target_entities": incident.target_entities,
        "attack_chain": incident.attack_chain,
        "mitre_techniques": incident.mitre_techniques,
        "events": [
            {"id": a.id, "type": a.alert_type, "description": a.description}
            for a in alerts
        ],
    }

    analyst = AIAnalyst()
    result = await analyst.analyze_incident(incident_data)

    if result:
        incident.ai_summary = result.summary
        incident.recommendations = result.investigation_steps + result.containment_steps
        db.commit()
        db.refresh(incident)

    return {
        "status": "success",
        "incident_id": incident_id,
        "analysis": result.model_dump() if result else None,
    }


@router.post("/{incident_id}/response")
async def record_response(
    incident_id: str,
    action: dict,
    db: Session = Depends(get_db)
):
    """Record a simulated response action."""
    from app.models.database import Response

    incident = db.query(IncidentDB).filter(IncidentDB.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    response = Response(
        id=str(uuid.uuid4()),
        incident_id=incident_id,
        action=action.get("action", "unknown"),
        status="completed",
        performed_by="analyst",
        details=action.get("details", {}),
    )
    db.add(response)

    if action.get("action") in ["block_ip", "isolate_host", "disable_account"]:
        incident.status = "contained"
        incident.resolved_at = datetime.now()

    db.commit()

    return {
        "status": "success",
        "response_id": response.id,
        "incident_status": incident.status,
    }


# -----------------------------------------------------------------------------
# 3. Collection route (list)
# -----------------------------------------------------------------------------

@router.get("")
async def list_incidents(
    limit: int = 50,
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """List incidents."""
    query = db.query(IncidentDB)
    if status:
        query = query.filter(IncidentDB.status == status)
    incidents = query.order_by(IncidentDB.last_seen.desc()).limit(limit).all()
    return [IncidentSchema.model_validate(inc) for inc in incidents]


# -----------------------------------------------------------------------------
# 4. Single-resource routes (lowest specificity — MUST come last)
# -----------------------------------------------------------------------------

@router.get("/{incident_id}")
async def get_incident(incident_id: str, db: Session = Depends(get_db)):
    """Get incident details with timeline and alerts."""
    incident = db.query(IncidentDB).filter(IncidentDB.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    alerts = db.query(AlertDB).filter(AlertDB.incident_id == incident_id).all()

    return {
        "incident": IncidentSchema.model_validate(incident),
        "alerts": [AlertSchema.model_validate(a) for a in alerts],
        "alert_count": len(alerts),
    }


@router.patch("/{incident_id}")
async def update_incident(
    incident_id: str,
    update: IncidentUpdate,
    db: Session = Depends(get_db)
):
    """Update an incident."""
    incident = db.query(IncidentDB).filter(IncidentDB.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    for key, value in update.model_dump(exclude_unset=True).items():
        setattr(incident, key, value)

    if update.status and update.status in ["contained", "resolved", "false_positive"]:
        incident.resolved_at = datetime.now()

    db.commit()
    db.refresh(incident)
    return {"status": "success", "incident": IncidentSchema.model_validate(incident)}