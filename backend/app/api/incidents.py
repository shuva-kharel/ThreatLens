from typing import Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.mitre import MITRE_TECHNIQUES
from app.core.ai_analyst import AIAnalyst
from app.core.time import utc_iso, utc_now
from app.core.trace_ai import TraceAI
from app.db.session import get_db
from app.models.database import (
    Alert as AlertDB,
    Escalation,
    Incident as IncidentDB,
)
from app.services.recurrence_service import RecurrenceService
from app.models.schemas import (
    Alert as AlertSchema,
    Incident as IncidentSchema,
    IncidentUpdate,
    ResponseAction,
)


router = APIRouter()


# =============================================================================
# RESPONSE SERIALIZATION
# =============================================================================

def serialize_incident(incident: IncidentDB):
    """
    Serialize an Incident ORM object using the existing Pydantic schema.

    The Incident Pydantic schema emits timezone-aware UTC ISO 8601 strings.

    Database:
        UTC datetime

    API:
        ISO 8601 datetime with +00:00 offset
    """

    return (
        IncidentSchema
        .model_validate(incident)
        .model_dump(mode="python")
    )


def serialize_alert(alert: AlertDB):
    """
    Serialize an Alert ORM object using the existing Pydantic schema.

    Timestamp conversion is handled by AlertSchema.
    """

    return (
        AlertSchema
        .model_validate(alert)
        .model_dump(mode="python")
    )


# =============================================================================
# 1. SEARCH
# =============================================================================

@router.get("/search")
async def search_incidents(
    q: str = "",
    severity: Optional[str] = None,
    status: Optional[str] = None,
    source_ip: Optional[str] = None,
    limit: int = 50,
    db: Session = Depends(get_db),
):
    """Search incidents with filters."""

    query = db.query(IncidentDB)

    if q:
        query = query.filter(
            IncidentDB.title.ilike(f"%{q}%")
            | IncidentDB.id.ilike(f"%{q}%")
        )

    if severity:
        query = query.filter(
            IncidentDB.severity == severity
        )

    if status:
        query = query.filter(
            IncidentDB.status == status
        )

    if source_ip:
        query = query.filter(
            IncidentDB.source_entities.contains([source_ip])
        )

    incidents = (
        query
        .order_by(IncidentDB.last_seen.desc())
        .limit(limit)
        .all()
    )

    return [
        serialize_incident(incident)
        for incident in incidents
    ]


# =============================================================================
# 2. MITRE
# =============================================================================

@router.get("/{incident_id}/mitre")
async def get_incident_mitre(
    incident_id: str,
    db: Session = Depends(get_db),
):
    """Get MITRE ATT&CK techniques mapped for an incident."""

    incident = (
        db.query(IncidentDB)
        .filter(IncidentDB.id == incident_id)
        .first()
    )

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    techniques = []

    for technique_id in (incident.mitre_techniques or []):
        if technique_id in MITRE_TECHNIQUES:
            techniques.append(
                {
                    "id": technique_id,
                    **MITRE_TECHNIQUES[technique_id],
                }
            )
        else:
            techniques.append(
                {
                    "id": technique_id,
                    "name": "Unknown",
                    "tactic": "Unknown",
                    "url": "",
                }
            )

    return {
        "incident_id": incident_id,
        "title": incident.title,
        "total": len(techniques),
        "techniques": techniques,
    }


# =============================================================================
# 3. TRACE
# =============================================================================

@router.get("/{incident_id}/trace")
async def trace_incident(
    incident_id: str,
    db: Session = Depends(get_db),
):
    """Reconstruct attack timeline and attack graph."""

    trace_ai = TraceAI(db)

    result = trace_ai.reconstruct_incident(
        incident_id
    )

    if "error" in result:
        raise HTTPException(
            status_code=404,
            detail=result["error"],
        )

    return result


# =============================================================================
# 4. AI ANALYSIS
# =============================================================================

@router.post("/{incident_id}/analyze")
async def analyze_incident(
    incident_id: str,
    db: Session = Depends(get_db),
):
    """Trigger AI analysis for an incident."""

    incident = (
        db.query(IncidentDB)
        .filter(IncidentDB.id == incident_id)
        .first()
    )

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    alerts = (
        db.query(AlertDB)
        .filter(AlertDB.incident_id == incident_id)
        .all()
    )
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
            {
                "id": alert.id,
                "type": alert.alert_type,
                "description": alert.description,
            }
            for alert in alerts
        ],
    }

    analyst = AIAnalyst()

    result = await analyst.analyze_incident(
        incident_data
    )

    if result:
        incident.ai_summary = result.summary

        incident.recommendations = result.recommendations

        db.commit()
        db.refresh(incident)

    return {
        "status": "success",
        "incident_id": incident_id,
        "analysis": (
            result.model_dump()
            if result
            else None
        ),
    }


# =============================================================================
# 5. RESPONSE
# =============================================================================

@router.post("/{incident_id}/response")
async def record_response(
    incident_id: str,
    action: ResponseAction,
    db: Session = Depends(get_db),
):
    """Record a simulated response action."""

    from app.models.database import Response

    incident = (
        db.query(IncidentDB)
        .filter(IncidentDB.id == incident_id)
        .first()
    )

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    response = Response(
        id=str(uuid.uuid4()),
        incident_id=incident_id,
        action=action.action,
        status="completed",
        performed_by="analyst",
        details=action.details or {},
    )

    db.add(response)

    # Terminal response actions resolve/contain the incident.
    #
    # Terminal response actions record an aware UTC resolution time.
    if action.action in [
        "block_ip",
        "isolate_host",
        "disable_account",
    ]:
        incident.status = "contained"
        incident.resolved_at = utc_now()

    db.commit()
    db.refresh(incident)

    return {
        "status": "success",
        "response_id": response.id,
        "incident_status": incident.status,

        # The frontend converts this UTC value for presentation.
        "resolved_at": utc_iso(
            incident.resolved_at
        ),
    }


# =============================================================================
# 6. LIST
# =============================================================================

@router.get("")
async def list_incidents(
    limit: int = 50,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """List incidents."""

    query = db.query(IncidentDB)

    if status:
        query = query.filter(
            IncidentDB.status == status
        )

    incidents = (
        query
        .order_by(IncidentDB.last_seen.desc())
        .limit(limit)
        .all()
    )

    return [
        serialize_incident(incident)
        for incident in incidents
    ]


# =============================================================================
# 7. SINGLE INCIDENT
# =============================================================================

@router.get("/{incident_id}")
async def get_incident(
    incident_id: str,
    db: Session = Depends(get_db),
):
    """Get incident details with timeline and alerts."""

    incident = (
        db.query(IncidentDB)
        .filter(IncidentDB.id == incident_id)
        .first()
    )

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    alerts = (
        db.query(AlertDB)
        .filter(AlertDB.incident_id == incident_id)
        .order_by(AlertDB.created_at.asc())
        .all()
    )
    escalation = (
        db.query(Escalation)
        .filter(Escalation.current_incident_id == incident_id)
        .first()
    )

    return {
        "incident": serialize_incident(incident),
        "alerts": [
            serialize_alert(alert)
            for alert in alerts
        ],
        "alert_count": len(alerts),
        "escalation": (
            RecurrenceService.serialize(escalation)
            if escalation
            else None
        ),
    }


# =============================================================================
# 8. UPDATE
# =============================================================================

@router.patch("/{incident_id}")
async def update_incident(
    incident_id: str,
    update: IncidentUpdate,
    db: Session = Depends(get_db),
):
    """Update an incident."""

    incident = (
        db.query(IncidentDB)
        .filter(IncidentDB.id == incident_id)
        .first()
    )

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    # Apply requested changes.
    for key, value in update.model_dump(
        exclude_unset=True
    ).items():
        setattr(incident, key, value)

    # Terminal states get a resolution timestamp.
    if update.status and update.status in [
        "contained",
        "resolved",
        "false_positive",
    ]:
        incident.resolved_at = utc_now()

    db.commit()
    db.refresh(incident)

    return {
        "status": "success",
        "incident": serialize_incident(incident),
    }
