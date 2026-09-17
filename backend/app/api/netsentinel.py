from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.db.session import get_db
from app.models.database import Event, Alert, Incident
from app.core.network_anomaly import NetworkAnomalyDetector
from datetime import datetime, timedelta
from typing import Optional

router = APIRouter()


@router.get("/network/stats")
async def get_network_stats(db: Session = Depends(get_db)):
    """Get network statistics."""
    total_events = db.query(Event).count()

    hour_ago = datetime.utcnow() - timedelta(hours=1)
    recent_events = db.query(Event).filter(Event.timestamp >= hour_ago).count()

    unique_sources = db.query(func.count(func.distinct(Event.source_ip))).scalar() or 0
    unique_targets = db.query(func.count(func.distinct(Event.host))).scalar() or 0

    event_types = db.query(
        Event.event_type,
        func.count(Event.id).label('count')
    ).group_by(Event.event_type).order_by(func.count(Event.id).desc()).limit(10).all()

    top_sources = db.query(
        Event.source_ip,
        func.count(Event.id).label('count')
    ).filter(Event.source_ip.isnot(None)).group_by(
        Event.source_ip
    ).order_by(func.count(Event.id).desc()).limit(10).all()

    return {
        "total_events": total_events,
        "recent_events": recent_events,
        "unique_sources": unique_sources,
        "unique_targets": unique_targets,
        "event_types": [{"type": e[0], "count": e[1]} for e in event_types],
        "top_sources": [{"ip": s[0], "count": s[1]} for s in top_sources]
    }


@router.get("/network/hosts")
async def get_network_hosts(db: Session = Depends(get_db)):
    """Get all monitored hosts from events."""
    hosts = db.query(
        Event.host,
        func.count(Event.id).label('event_count'),
        func.max(Event.timestamp).label('last_seen')
    ).group_by(Event.host).all()

    result = []
    for host in hosts:
        alert_count = db.query(Alert).filter(Alert.target_host == host[0]).count()

        result.append({
            "hostname": host[0],
            "event_count": host[1],
            "alert_count": alert_count,
            "last_seen": host[2].isoformat() if host[2] else None
        })

    return result


@router.get("/network/connections")
async def get_network_connections(
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """Get recent network connections."""
    events = db.query(Event).filter(
        Event.source_ip.isnot(None)
    ).order_by(Event.timestamp.desc()).limit(limit).all()

    connections = []
    for event in events:
        connections.append({
            "id": event.id,
            "timestamp": event.timestamp.isoformat() if event.timestamp else None,
            "source_ip": event.source_ip,
            "target_host": event.host,
            "event_type": event.event_type,
            "severity": event.severity
        })

    return connections


@router.get("/network/timeline")
async def get_network_timeline(
    hours: int = 24,
    db: Session = Depends(get_db)
):
    """Get network activity timeline."""
    start_time = datetime.utcnow() - timedelta(hours=hours)

    results = db.query(
        func.strftime('%Y-%m-%dT%H:00:00', Event.timestamp).label('hour'),
        func.count(Event.id).label('count')
    ).filter(Event.timestamp >= start_time).group_by('hour').all()

    return [{"hour": r[0], "count": r[1]} for r in results]


@router.get("/network/anomalies")
async def get_network_anomalies(db: Session = Depends(get_db)):
    """Get detected network anomalies."""
    detector = NetworkAnomalyDetector(db)
    anomalies = detector.run_all_detections()

    return {
        "total": len(anomalies),
        "anomalies": anomalies
    }