from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models.database import Incident as IncidentDB, Alert as AlertDB
from datetime import datetime
import csv
from io import StringIO

router = APIRouter()

# GET /api/v1/incidents/{incident_id}/export/csv
@router.get("/{incident_id}/export/csv")
async def export_incident_csv(incident_id: str, db: Session = Depends(get_db)):
    """Export incident details as CSV."""
    incident = db.query(IncidentDB).filter(IncidentDB.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    alerts = db.query(AlertDB).filter(AlertDB.incident_id == incident_id).all()

    output = StringIO()
    writer = csv.writer(output)

    writer.writerow(["=== INCIDENT REPORT ==="])
    writer.writerow([])
    writer.writerow(["Field", "Value"])
    writer.writerow(["Incident ID", incident.id])
    writer.writerow(["Title", incident.title])
    writer.writerow(["Severity", incident.severity])
    writer.writerow(["Status", incident.status])
    writer.writerow(["Confidence", f"{incident.confidence * 100:.1f}%"])
    writer.writerow(["First Seen", incident.first_seen])
    writer.writerow(["Last Seen", incident.last_seen])
    writer.writerow(["Source IPs", ", ".join(incident.source_entities or [])])
    writer.writerow(["Target Hosts", ", ".join(incident.target_entities or [])])
    writer.writerow(["MITRE Techniques", ", ".join(incident.mitre_techniques or [])])

    if incident.ai_summary:
        writer.writerow([])
        writer.writerow(["AI Summary", incident.ai_summary])

    if incident.recommendations:
        writer.writerow([])
        writer.writerow(["Recommendations"])
        for rec in incident.recommendations:
            writer.writerow(["-", rec])

    writer.writerow([])
    writer.writerow(["=== ALERTS ==="])
    writer.writerow([])
    writer.writerow(["Alert ID", "Type", "Severity", "MITRE", "Source IP", "Target", "Description"])

    for alert in alerts:
        writer.writerow([
            alert.id[:8] + "...",
            alert.alert_type,
            alert.severity,
            alert.mitre_technique or "N/A",
            alert.source_ip or "N/A",
            alert.target_host or "N/A",
            alert.description[:50] + "..." if len(alert.description) > 50 else alert.description
        ])

    output.seek(0)
    return StreamingResponse(
        output,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=incident_{incident_id}.csv"}
    )

# GET /api/v1/incidents/{incident_id}/export/json
@router.get("/{incident_id}/export/json")
async def export_incident_json(incident_id: str, db: Session = Depends(get_db)):
    """Export incident details as JSON."""
    incident = db.query(IncidentDB).filter(IncidentDB.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    alerts = db.query(AlertDB).filter(AlertDB.incident_id == incident_id).all()

    export_data = {
        "incident": {
            "id": incident.id,
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status,
            "confidence": incident.confidence,
            "first_seen": incident.first_seen.isoformat() if incident.first_seen else None,
            "last_seen": incident.last_seen.isoformat() if incident.last_seen else None,
            "source_entities": incident.source_entities,
            "target_entities": incident.target_entities,
            "attack_chain": incident.attack_chain,
            "mitre_techniques": incident.mitre_techniques,
            "ai_summary": incident.ai_summary,
            "recommendations": incident.recommendations,
            "created_at": incident.created_at.isoformat() if incident.created_at else None,
            "updated_at": incident.updated_at.isoformat() if incident.updated_at else None,
        },
        "alerts": [
            {
                "id": alert.id,
                "alert_type": alert.alert_type,
                "severity": alert.severity,
                "mitre_technique": alert.mitre_technique,
                "source_ip": alert.source_ip,
                "target_host": alert.target_host,
                "description": alert.description,
                "confidence": alert.confidence,
                "created_at": alert.created_at.isoformat() if alert.created_at else None,
            }
            for alert in alerts
        ],
        "alert_count": len(alerts),
        "exported_at": datetime.now().isoformat()
    }

    return JSONResponse(
        content=export_data,
        headers={"Content-Disposition": f"attachment; filename=incident_{incident_id}.json"}
    )

# GET /api/v1/incidents/export/all
@router.get("/export/all")
async def export_all_incidents(
    format: str = "json",
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """Export all incidents."""
    incidents = db.query(IncidentDB).order_by(IncidentDB.created_at.desc()).limit(limit).all()

    if format == "csv":
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(["ID", "Title", "Severity", "Status", "Confidence", "First Seen", "MITRE Techniques", "Alert Count"])

        for inc in incidents:
            alert_count = db.query(AlertDB).filter(AlertDB.incident_id == inc.id).count()
            writer.writerow([
                inc.id[:8] + "...",
                inc.title,
                inc.severity,
                inc.status,
                f"{inc.confidence * 100:.1f}%",
                inc.first_seen.strftime("%Y-%m-%d %H:%M") if inc.first_seen else "N/A",
                ", ".join(inc.mitre_techniques or []),
                alert_count
            ])

        output.seek(0)
        return StreamingResponse(
            output,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=all_incidents.csv"}
        )

    # Default: JSON
    data = []
    for inc in incidents:
        alert_count = db.query(AlertDB).filter(AlertDB.incident_id == inc.id).count()
        data.append({
            "id": inc.id,
            "title": inc.title,
            "severity": inc.severity,
            "status": inc.status,
            "confidence": inc.confidence,
            "first_seen": inc.first_seen.isoformat() if inc.first_seen else None,
            "last_seen": inc.last_seen.isoformat() if inc.last_seen else None,
            "mitre_techniques": inc.mitre_techniques,
            "alert_count": alert_count,
            "ai_summary": inc.ai_summary[:200] + "..." if inc.ai_summary and len(inc.ai_summary) > 200 else inc.ai_summary
        })

    return JSONResponse(
        content={
            "total": len(data),
            "exported_at": datetime.now().isoformat(),
            "incidents": data
        }
    )