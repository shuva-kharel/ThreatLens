from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.db.session import get_db

from app.models.database import (
    Event,
    Alert,
    Incident,
)

from app.core.network_anomaly import NetworkAnomalyDetector
from app.services.threat_map_service import ThreatMapService

from app.core.time import (
    UTC,
    utc_now,
    utc_iso,
)


router = APIRouter()


@router.get("/network/threat-map")
async def get_threat_map(db: Session = Depends(get_db)):
    """Aggregate real stored telemetry into attack relationships."""
    return ThreatMapService(db).aggregate()


# =============================================================================
# NETWORK STATS
# =============================================================================

@router.get("/network/stats")
async def get_network_stats(
    db: Session = Depends(get_db),
):
    """Get network statistics."""

    total_events = db.query(Event).count()

    # IMPORTANT:
    # Database timestamps are UTC.
    hour_ago = (
        utc_now()
        - timedelta(hours=1)
    )

    recent_events = (
        db.query(Event)
        .filter(Event.timestamp >= hour_ago)
        .count()
    )

    unique_sources = (
        db.query(
            func.count(
                func.distinct(Event.source_ip)
            )
        )
        .scalar()
        or 0
    )

    unique_targets = (
        db.query(
            func.count(
                func.distinct(Event.host)
            )
        )
        .scalar()
        or 0
    )

    event_types = (
        db.query(
            Event.event_type,
            func.count(Event.id).label("count"),
        )
        .group_by(Event.event_type)
        .order_by(
            func.count(Event.id).desc()
        )
        .limit(10)
        .all()
    )

    top_sources = (
        db.query(
            Event.source_ip,
            func.count(Event.id).label("count"),
        )
        .filter(Event.source_ip.isnot(None))
        .group_by(Event.source_ip)
        .order_by(
            func.count(Event.id).desc()
        )
        .limit(10)
        .all()
    )

    return {
        "total_events": total_events,
        "recent_events": recent_events,
        "unique_sources": unique_sources,
        "unique_targets": unique_targets,

        "event_types": [
            {
                "type": event_type,
                "count": count,
            }
            for event_type, count in event_types
        ],

        "top_sources": [
            {
                "ip": source_ip,
                "count": count,
            }
            for source_ip, count in top_sources
        ],
    }


# =============================================================================
# NETWORK HOSTS
# =============================================================================

@router.get("/network/hosts")
async def get_network_hosts(
    db: Session = Depends(get_db),
):
    """Get all monitored hosts from events."""

    hosts = (
        db.query(
            Event.host,
            func.count(Event.id).label(
                "event_count"
            ),
            func.max(Event.timestamp).label(
                "last_seen"
            ),
        )
        .group_by(Event.host)
        .all()
    )

    result = []

    for host in hosts:

        alert_count = (
            db.query(Alert)
            .filter(
                Alert.target_host == host[0]
            )
            .count()
        )

        result.append({
            "hostname": host[0],
            "event_count": host[1],
            "alert_count": alert_count,

            # UTC -> Kathmandu
            "last_seen": utc_iso(
                host[2]
            ),
        })

    return result


# =============================================================================
# NETWORK CONNECTIONS
# =============================================================================

@router.get("/network/connections")
async def get_network_connections(
    limit: int = 100,
    db: Session = Depends(get_db),
):
    """Get recent network connections."""

    if limit < 1:
        raise HTTPException(
            status_code=400,
            detail="limit must be greater than 0",
        )

    if limit > 1000:
        limit = 1000

    events = (
        db.query(Event)
        .filter(Event.source_ip.isnot(None))
        .order_by(Event.timestamp.desc())
        .limit(limit)
        .all()
    )

    connections = []

    for event in events:
        connections.append({
            "id": event.id,

            # UTC -> Kathmandu
            "timestamp": utc_iso(
                event.timestamp
            ),

            "source_ip": event.source_ip,
            "target_host": event.host,
            "event_type": event.event_type,
            "severity": event.severity,
        })

    return connections


# =============================================================================
# NETWORK TIMELINE
# =============================================================================

@router.get("/network/timeline")
async def get_network_timeline(
    hours: int = 24,
    db: Session = Depends(get_db),
):
    """
    Get network activity timeline.

    Filtering happens in UTC.
    Returned timestamp buckets are timezone-aware UTC.
    """

    if hours < 1:
        raise HTTPException(
            status_code=400,
            detail="hours must be greater than 0",
        )

    if hours > 168:
        hours = 168

    start_time = (
        utc_now()
        - timedelta(hours=hours)
    )

    results = (
        db.query(
            func.strftime(
                "%Y-%m-%dT%H:00:00",
                Event.timestamp,
            ).label("hour"),

            func.count(Event.id).label("count"),
        )
        .filter(
            Event.timestamp >= start_time
        )
        .group_by("hour")
        .order_by("hour")
        .all()
    )

    timeline = []

    for hour, count in results:

        if hour:
            from datetime import datetime

            utc_hour = datetime.strptime(
                hour,
                "%Y-%m-%dT%H:00:00",
            ).replace(
                tzinfo=UTC
            )

            api_hour = utc_iso(utc_hour)

        else:
            api_hour = None

        timeline.append({
            "hour": api_hour,
            "count": count,
        })

    return {
        "hours": hours,
        "timezone": "UTC",
        "display_timezone": "Asia/Kathmandu",
        "timeline": timeline,
    }


# =============================================================================
# NETWORK ANOMALIES
# =============================================================================

@router.get("/network/anomalies")
async def get_network_anomalies(
    db: Session = Depends(get_db),
):
    """Get detected network anomalies."""

    detector = NetworkAnomalyDetector(db)

    anomalies = detector.run_all_detections()

    return {
        "total": len(anomalies),
        "anomalies": anomalies,
    }
