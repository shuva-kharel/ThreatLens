from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.cleanup import DataCleanup
from app.core.time import KATHMANDU, ensure_utc, utc_now
from app.db.session import get_db
from app.models.database import Alert, EndpointAgent, Escalation, Event, Incident


router = APIRouter()


@router.get("/stats/overview")
async def get_dashboard_stats(
    db: Session = Depends(get_db),
):
    """Get dashboard statistics."""

    total_incidents = db.query(Incident).count()

    open_incidents = (
        db.query(Incident)
        .filter(Incident.status == "open")
        .count()
    )

    contained_incidents = (
        db.query(Incident)
        .filter(Incident.status == "contained")
        .count()
    )

    critical_incidents = (
        db.query(Incident)
        .filter(Incident.severity == "critical")
        .count()
    )

    # Database timestamps are stored as UTC.
    yesterday = utc_now() - timedelta(days=1)

    incidents_24h = (
        db.query(Incident)
        .filter(Incident.created_at >= yesterday)
        .count()
    )

    alerts_24h = (
        db.query(Alert)
        .filter(Alert.created_at >= yesterday)
        .count()
    )

    critical_alerts = (
        db.query(Alert)
        .filter(Alert.severity == "critical")
        .count()
    )
    events_ingested = db.query(Event).count()
    source_assets = {
        value for (value,) in db.query(Event.source_ip).distinct().all() if value
    }
    target_assets = {
        value for (value,) in db.query(Event.host).distinct().all() if value
    }
    observed_assets = len(source_assets | target_assets)
    repeat_threats = (
        db.query(Escalation)
        .filter(Escalation.recurrence_count > 1)
        .count()
    )
    human_escalations = (
        db.query(Escalation)
        .filter(Escalation.requires_human_review.is_(True))
        .count()
    )
    agents_online = (
        db.query(EndpointAgent)
        .filter(EndpointAgent.last_seen >= utc_now() - timedelta(minutes=2))
        .count()
    )

    # Most common alert/attack types.
    top_alerts = (
        db.query(
            Alert.alert_type,
            func.count(Alert.id).label("count"),
        )
        .group_by(Alert.alert_type)
        .order_by(func.count(Alert.id).desc())
        .limit(5)
        .all()
    )

    # MITRE ATT&CK technique distribution.
    mitre_stats = (
        db.query(
            Alert.mitre_technique,
            func.count(Alert.id).label("count"),
        )
        .filter(Alert.mitre_technique.isnot(None))
        .group_by(Alert.mitre_technique)
        .order_by(func.count(Alert.id).desc())
        .limit(10)
        .all()
    )

    return {
        "total_incidents": total_incidents,
        "open_incidents": open_incidents,
        "contained_incidents": contained_incidents,
        "critical_incidents": critical_incidents,
        "incidents_24h": incidents_24h,
        "alerts_24h": alerts_24h,
        "critical_alerts": critical_alerts,
        "events_ingested": events_ingested,
        "observed_assets": observed_assets,
        "repeat_threats": repeat_threats,
        "human_escalations": human_escalations,
        "agents_online": agents_online,
        "top_attack_types": [
            {
                "type": alert_type,
                "count": count,
            }
            for alert_type, count in top_alerts
        ],
        "mitre_distribution": [
            {
                "technique": technique,
                "count": count,
            }
            for technique, count in mitre_stats
        ],
        "timezone": "Asia/Kathmandu",
    }


@router.get("/stats/incidents/timeline")
async def get_incident_timeline(
    days: int = 7,
    db: Session = Depends(get_db),
):
    """
    Get incident timeline for charts.

    Database timestamps are stored as UTC.

    Timeline dates are grouped using Kathmandu local dates.
    """

    if days < 1:
        raise HTTPException(
            status_code=400,
            detail="days must be at least 1",
        )

    if days > 365:
        raise HTTPException(
            status_code=400,
            detail="days cannot exceed 365",
        )

    try:
        # Database timestamps are UTC.
        now_utc = utc_now()

        start_date = now_utc - timedelta(days=days)

        incidents = (
            db.query(Incident)
            .filter(Incident.created_at >= start_date)
            .all()
        )

        timeline = {}

        for incident in incidents:
            if not incident.created_at:
                continue

            # Convert the stored UTC timestamp to Kathmandu
            # before determining the calendar date.
            local_time = (
                ensure_utc(incident.created_at)
                .astimezone(KATHMANDU)
            )

            date_str = local_time.strftime("%Y-%m-%d")

            if date_str not in timeline:
                timeline[date_str] = {
                    "low": 0,
                    "medium": 0,
                    "high": 0,
                    "critical": 0,
                }

            severity = incident.severity or "medium"

            if severity in timeline[date_str]:
                timeline[date_str][severity] += 1

        result = [
            {
                "date": date,
                **counts,
            }
            for date, counts in sorted(timeline.items())
        ]

        # If there are no incidents, return zero-filled
        # Kathmandu dates for the requested period.
        if not result:
            local_now = (
                ensure_utc(now_utc)
                .astimezone(KATHMANDU)
            )

            result = []

            for i in range(days - 1, -1, -1):
                local_date = (
                    local_now - timedelta(days=i)
                ).strftime("%Y-%m-%d")

                result.append(
                    {
                        "date": local_date,
                        "low": 0,
                        "medium": 0,
                        "high": 0,
                        "critical": 0,
                    }
                )

        return {
            "days": days,
            "timezone": "Asia/Kathmandu",
            "timeline": result,
        }

    except Exception as e:
        print(f"[Stats] Timeline error: {e}")

        return {
            "days": days,
            "timezone": "Asia/Kathmandu",
            "timeline": [],
        }


@router.get("/storage/stats")
async def get_storage_stats(
    db: Session = Depends(get_db),
):
    """Get database storage statistics."""

    cleanup = DataCleanup(db)

    return cleanup.get_storage_stats()


@router.post("/cleanup/events")
async def cleanup_events(
    days: int = 30,
    db: Session = Depends(get_db),
):
    """Clean up old events."""

    if days < 1:
        raise HTTPException(
            status_code=400,
            detail="days must be at least 1",
        )

    cleanup = DataCleanup(db)

    deleted = cleanup.cleanup_old_events(days)

    return {
        "deleted": deleted,
        "days": days,
    }


@router.post("/cleanup/incidents")
async def cleanup_incidents(
    days: int = 90,
    db: Session = Depends(get_db),
):
    """Clean up resolved incidents."""

    if days < 1:
        raise HTTPException(
            status_code=400,
            detail="days must be at least 1",
        )

    cleanup = DataCleanup(db)

    deleted = cleanup.cleanup_resolved_incidents(days)

    return {
        "deleted": deleted,
        "days": days,
    }
