from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, cast, Date
from app.db.session import get_db
from app.models.database import Incident, Alert, Event
from app.core.cleanup import DataCleanup
from datetime import datetime, timedelta

router = APIRouter()


@router.get("/stats/overview")
async def get_dashboard_stats(db: Session = Depends(get_db)):
    """Get dashboard statistics."""
    total_incidents = db.query(Incident).count()
    open_incidents = db.query(Incident).filter(Incident.status == "open").count()
    contained_incidents = db.query(Incident).filter(Incident.status == "contained").count()
    critical_incidents = db.query(Incident).filter(Incident.severity == "critical").count()

    yesterday = datetime.utcnow() - timedelta(days=1)
    incidents_24h = db.query(Incident).filter(Incident.created_at >= yesterday).count()
    alerts_24h = db.query(Alert).filter(Alert.created_at >= yesterday).count()

    top_alerts = db.query(
        Alert.alert_type,
        func.count(Alert.id).label('count')
    ).group_by(Alert.alert_type).order_by(func.count(Alert.id).desc()).limit(5).all()

    mitre_stats = db.query(
        Alert.mitre_technique,
        func.count(Alert.id).label('count')
    ).filter(Alert.mitre_technique.isnot(None)).group_by(
        Alert.mitre_technique
    ).order_by(func.count(Alert.id).desc()).limit(10).all()

    return {
        "total_incidents": total_incidents,
        "open_incidents": open_incidents,
        "contained_incidents": contained_incidents,
        "critical_incidents": critical_incidents,
        "incidents_24h": incidents_24h,
        "alerts_24h": alerts_24h,
        "top_attack_types": [{"type": a[0], "count": a[1]} for a in top_alerts],
        "mitre_distribution": [{"technique": m[0], "count": m[1]} for m in mitre_stats],
    }


@router.get("/stats/incidents/timeline")
async def get_incident_timeline(
    days: int = 7,
    db: Session = Depends(get_db)
):
    """Get incident timeline for charts (defensive implementation)."""
    try:
        start_date = datetime.utcnow() - timedelta(days=days)

        # Get incidents in the window
        incidents = db.query(Incident).filter(
            Incident.created_at >= start_date
        ).all()

        # Build timeline manually in Python (safer than SQL date functions)
        timeline = {}
        for inc in incidents:
            if not inc.created_at:
                continue

            # Get date string in YYYY-MM-DD format
            date_str = inc.created_at.strftime("%Y-%m-%d")

            if date_str not in timeline:
                timeline[date_str] = {"low": 0, "medium": 0, "high": 0, "critical": 0}

            severity = inc.severity or "medium"
            if severity in timeline[date_str]:
                timeline[date_str][severity] += 1

        # Convert to sorted list
        result = [
            {"date": date, **counts}
            for date, counts in sorted(timeline.items())
        ]

        # If empty, return a placeholder for the last N days
        if not result:
            result = [
                {
                    "date": (datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d"),
                    "low": 0,
                    "medium": 0,
                    "high": 0,
                    "critical": 0,
                }
                for i in range(days - 1, -1, -1)
            ]

        return result

    except Exception as e:
        print(f"[Stats] Timeline error: {e}")
        # Return empty timeline instead of 500 error
        return []


@router.get("/storage/stats")
async def get_storage_stats(db: Session = Depends(get_db)):
    """Get database storage statistics."""
    cleanup = DataCleanup(db)
    return cleanup.get_storage_stats()


@router.post("/cleanup/events")
async def cleanup_events(days: int = 30, db: Session = Depends(get_db)):
    """Clean up old events."""
    cleanup = DataCleanup(db)
    deleted = cleanup.cleanup_old_events(days)
    return {"deleted": deleted, "days": days}


@router.post("/cleanup/incidents")
async def cleanup_incidents(days: int = 90, db: Session = Depends(get_db)):
    """Clean up resolved incidents."""
    cleanup = DataCleanup(db)
    deleted = cleanup.cleanup_resolved_incidents(days)
    return {"deleted": deleted, "days": days}