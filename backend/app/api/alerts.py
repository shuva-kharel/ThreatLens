from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_
from app.db.session import get_db
from app.models.schemas import Alert as AlertSchema
from app.models.database import Alert as AlertDB
from typing import Optional, List

router = APIRouter()

@router.get("")
async def list_alerts(
    limit: int = 100,
    offset: int = 0,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    alert_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    incident_id: Optional[str] = None,
    q: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """List alerts with filters."""
    query = db.query(AlertDB)

    if severity:
        query = query.filter(AlertDB.severity == severity)
    if status:
        query = query.filter(AlertDB.status == status)
    if alert_type:
        query = query.filter(AlertDB.alert_type == alert_type)
    if source_ip:
        query = query.filter(AlertDB.source_ip == source_ip)
    if incident_id:
        query = query.filter(AlertDB.incident_id == incident_id)
    if q:
        query = query.filter(
            or_(
                AlertDB.alert_type.ilike(f"%{q}%"),
                AlertDB.description.ilike(f"%{q}%"),
                AlertDB.source_ip.ilike(f"%{q}%"),
                AlertDB.target_host.ilike(f"%{q}%")
            )
        )

    total = query.count()
    alerts = query.order_by(AlertDB.created_at.desc()).offset(offset).limit(limit).all()

    return [AlertSchema.model_validate(a) for a in alerts]

@router.get("/stats")
async def get_alert_stats(db: Session = Depends(get_db)):
    """Get alert statistics."""
    from sqlalchemy import func

    total = db.query(AlertDB).count()

    severity_counts = db.query(
        AlertDB.severity,
        func.count(AlertDB.id).label('count')
    ).group_by(AlertDB.severity).all()

    type_counts = db.query(
        AlertDB.alert_type,
        func.count(AlertDB.id).label('count')
    ).group_by(AlertDB.alert_type).order_by(func.count(AlertDB.id).desc()).limit(10).all()

    return {
        "total": total,
        "by_severity": {s[0]: s[1] for s in severity_counts},
        "by_type": [{"type": t[0], "count": t[1]} for t in type_counts]
    }

@router.get("/{alert_id}")
async def get_alert(alert_id: str, db: Session = Depends(get_db)):
    """Get alert details."""
    alert = db.query(AlertDB).filter(AlertDB.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return AlertSchema.model_validate(alert)