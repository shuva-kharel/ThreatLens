from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.db.session import get_db
from app.models.database import Alert, Incident
from typing import Optional

router = APIRouter()


# ===== MITRE ATT&CK Technique Registry =====
# Extend this as you add more detection rules
MITRE_TECHNIQUES = {
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts.",
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to gain access to accounts.",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "description": "Adversaries may obtain and abuse credentials of existing accounts.",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands.",
        "url": "https://attack.mitre.org/techniques/T1059/",
    },
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may circumvent mechanisms designed to control elevated privileges.",
        "url": "https://attack.mitre.org/techniques/T1548/",
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using OSI application layer protocols.",
        "url": "https://attack.mitre.org/techniques/T1071/",
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating it over an existing C2 channel.",
        "url": "https://attack.mitre.org/techniques/T1041/",
    },
}


@router.get("/techniques")
async def list_techniques(
    tactic: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """List all MITRE techniques with usage stats."""
    # Count alerts per technique
    technique_counts = db.query(
        Alert.mitre_technique,
        func.count(Alert.id).label('count')
    ).filter(Alert.mitre_technique.isnot(None)).group_by(
        Alert.mitre_technique
    ).all()

    count_map = {t[0]: t[1] for t in technique_counts}

    techniques = []
    for tid, info in MITRE_TECHNIQUES.items():
        if tactic and info["tactic"] != tactic:
            continue
        techniques.append({
            "id": tid,
            "name": info["name"],
            "tactic": info["tactic"],
            "description": info.get("description", ""),
            "url": info["url"],
            "alert_count": count_map.get(tid, 0),
        })

    # Sort by alert count desc
    techniques.sort(key=lambda t: t["alert_count"], reverse=True)

    return {
        "total": len(techniques),
        "techniques": techniques,
    }


@router.get("/techniques/{technique_id}")
async def get_technique(technique_id: str, db: Session = Depends(get_db)):
    """Get details of a specific MITRE technique."""
    if technique_id not in MITRE_TECHNIQUES:
        raise HTTPException(status_code=404, detail="Technique not found")

    info = MITRE_TECHNIQUES[technique_id]

    # Get recent alerts using this technique
    alerts = db.query(Alert).filter(
        Alert.mitre_technique == technique_id
    ).order_by(Alert.created_at.desc()).limit(10).all()

    # Count incidents using this technique
    incident_count = db.query(Incident).filter(
        Incident.mitre_techniques.contains([technique_id])
    ).count()

    return {
        "id": technique_id,
        **info,
        "alert_count": db.query(Alert).filter(Alert.mitre_technique == technique_id).count(),
        "incident_count": incident_count,
        "recent_alerts": [
            {
                "id": a.id,
                "alert_type": a.alert_type,
                "severity": a.severity,
                "source_ip": a.source_ip,
                "target_host": a.target_host,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in alerts
        ],
    }


@router.get("/tactics")
async def list_tactics(db: Session = Depends(get_db)):
    """List techniques grouped by MITRE tactic (kill chain phases)."""
    # Count alerts per technique
    technique_counts = db.query(
        Alert.mitre_technique,
        func.count(Alert.id).label('count')
    ).filter(Alert.mitre_technique.isnot(None)).group_by(
        Alert.mitre_technique
    ).all()

    count_map = {t[0]: t[1] for t in technique_counts}

    # Group by tactic
    tactics = {}
    for tid, info in MITRE_TECHNIQUES.items():
        tactic = info["tactic"]
        if tactic not in tactics:
            tactics[tactic] = {
                "tactic": tactic,
                "techniques": [],
                "total_alerts": 0,
            }
        alert_count = count_map.get(tid, 0)
        tactics[tactic]["techniques"].append({
            "id": tid,
            "name": info["name"],
            "alert_count": alert_count,
        })
        tactics[tactic]["total_alerts"] += alert_count

    # Order by kill-chain phase
    TACTIC_ORDER = [
        "Reconnaissance", "Resource Development", "Initial Access",
        "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery",
        "Lateral Movement", "Collection", "Command and Control",
        "Exfiltration", "Impact",
    ]

    ordered = sorted(
        tactics.values(),
        key=lambda t: TACTIC_ORDER.index(t["tactic"]) if t["tactic"] in TACTIC_ORDER else 99
    )

    return {
        "total_tactics": len(ordered),
        "tactics": ordered,
    }


@router.get("/techniques/{technique_id}/alerts")
async def get_technique_alerts(
    technique_id: str,
    limit: int = 50,
    db: Session = Depends(get_db),
):
    """Get all alerts that map to a specific technique."""
    if technique_id not in MITRE_TECHNIQUES:
        raise HTTPException(status_code=404, detail="Technique not found")

    alerts = db.query(Alert).filter(
        Alert.mitre_technique == technique_id
    ).order_by(Alert.created_at.desc()).limit(limit).all()

    return {
        "technique_id": technique_id,
        "total": len(alerts),
        "alerts": [
            {
                "id": a.id,
                "alert_type": a.alert_type,
                "severity": a.severity,
                "source_ip": a.source_ip,
                "target_host": a.target_host,
                "description": a.description,
                "confidence": a.confidence,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in alerts
        ],
    }