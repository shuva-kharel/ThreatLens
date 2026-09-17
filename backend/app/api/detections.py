from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.db.session import get_db
from app.models.database import Alert, Incident, Event
from app.core.detection import DETECTION_RULES
from datetime import datetime, timedelta
from typing import Optional

router = APIRouter()


# Map rule IDs to their alert_type for stats lookup
RULE_TO_ALERT_TYPE = {
    "NET-001": "port_scanning",
    "AUTH-001": "ssh_brute_force",
    "AUTH-002": "successful_login_after_failures",
    "HOST-001": "suspicious_command",
}


@router.get("/rules")
async def list_rules(
    enabled_only: bool = False,
    category: Optional[str] = None,
):
    """List all detection rules."""
    rules = DETECTION_RULES

    if enabled_only:
        rules = [r for r in rules if r.get("enabled", True)]

    if category:
        rules = [r for r in rules if r.get("category") == category]

    return {
        "total": len(rules),
        "enabled": len([r for r in DETECTION_RULES if r.get("enabled", True)]),
        "rules": rules,
    }


@router.get("/rules/{rule_id}")
async def get_rule(rule_id: str):
    """Get details of a specific detection rule."""
    rule = next((r for r in DETECTION_RULES if r["id"] == rule_id), None)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@router.get("/stats")
async def get_detection_stats(db: Session = Depends(get_db)):
    """Get detection engine statistics — how many times each rule has fired."""

    # Count alerts by type
    alert_counts = db.query(
        Alert.alert_type,
        func.count(Alert.id).label('count')
    ).group_by(Alert.alert_type).all()

    alert_map = {a[0]: a[1] for a in alert_counts}

    # Enrich each rule with its trigger count
    rules_with_stats = []
    for rule in DETECTION_RULES:
        alert_type = RULE_TO_ALERT_TYPE.get(rule["id"], "")

        # Get last triggered timestamp
        last_alert = db.query(Alert).filter(
            Alert.alert_type == alert_type
        ).order_by(Alert.created_at.desc()).first() if alert_type else None

        rules_with_stats.append({
            **rule,
            "trigger_count": alert_map.get(alert_type, 0),
            "last_triggered": last_alert.created_at.isoformat() if last_alert else None,
        })

    # Sort by trigger count desc
    rules_with_stats.sort(key=lambda r: r["trigger_count"], reverse=True)

    # Summary
    total_alerts = sum(alert_map.values())

    return {
        "total_rules": len(DETECTION_RULES),
        "total_alerts_generated": total_alerts,
        "alert_type_distribution": alert_map,
        "rules": rules_with_stats,
        "categories": {
            "network": len([r for r in DETECTION_RULES if r.get("category") == "network"]),
            "authentication": len([r for r in DETECTION_RULES if r.get("category") == "authentication"]),
            "host": len([r for r in DETECTION_RULES if r.get("category") == "host"]),
        },
    }


@router.get("/timeline")
async def get_detection_timeline(
    hours: int = 24,
    db: Session = Depends(get_db),
):
    """Get detection activity over time."""
    start_time = datetime.utcnow() - timedelta(hours=hours)

    results = db.query(
        func.strftime('%Y-%m-%dT%H:00:00', Alert.created_at).label('hour'),
        func.count(Alert.id).label('count')
    ).filter(Alert.created_at >= start_time).group_by('hour').order_by('hour').all()

    return {
        "hours": hours,
        "timeline": [{"hour": r[0], "count": r[1]} for r in results],
    }


@router.get("/coverage")
async def get_detection_coverage(db: Session = Depends(get_db)):
    """Get MITRE ATT&CK coverage summary."""
    # Get all techniques from alerts
    techniques = db.query(
        Alert.mitre_technique,
        func.count(Alert.id).label('count')
    ).filter(Alert.mitre_technique.isnot(None)).group_by(
        Alert.mitre_technique
    ).order_by(func.count(Alert.id).desc()).all()

    return {
        "total_techniques_covered": len(techniques),
        "techniques": [
            {"id": t[0], "alert_count": t[1]}
            for t in techniques
        ],
    }