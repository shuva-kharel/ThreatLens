from io import StringIO
import csv

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.database import Incident as IncidentDB, Alert as AlertDB
from app.core.time import kathmandu_iso, to_kathmandu, utc_now


router = APIRouter()


# GET /api/v1/incidents/{incident_id}/export/csv
@router.get("/{incident_id}/export/csv")
async def export_incident_csv(
    incident_id: str,
    db: Session = Depends(get_db),
):
    """Export incident details as CSV with timestamps in Kathmandu time."""

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

    output = StringIO()
    writer = csv.writer(output)

    writer.writerow(["=== INCIDENT REPORT ==="])
    writer.writerow([])

    writer.writerow(["Field", "Value"])
    writer.writerow(["Incident ID", incident.id])
    writer.writerow(["Title", incident.title])
    writer.writerow(["Severity", incident.severity])
    writer.writerow(["Status", incident.status])
    writer.writerow([
        "Confidence",
        f"{incident.confidence * 100:.1f}%"
        if incident.confidence is not None
        else "N/A",
    ])

    # Convert UTC database timestamps -> Kathmandu time
    writer.writerow([
        "First Seen",
        kathmandu_iso(incident.first_seen) or "N/A",
    ])
    writer.writerow([
        "Last Seen",
        kathmandu_iso(incident.last_seen) or "N/A",
    ])

    if incident.resolved_at:
        writer.writerow([
            "Resolved At",
            kathmandu_iso(incident.resolved_at),
        ])

    writer.writerow([
        "Source IPs",
        ", ".join(incident.source_entities or []),
    ])

    writer.writerow([
        "Target Hosts",
        ", ".join(incident.target_entities or []),
    ])

    writer.writerow([
        "MITRE Techniques",
        ", ".join(incident.mitre_techniques or []),
    ])

    if incident.ai_summary:
        writer.writerow([])
        writer.writerow(["AI Summary"])
        writer.writerow([incident.ai_summary])

    if incident.recommendations:
        writer.writerow([])
        writer.writerow(["Recommendations"])

        for rec in incident.recommendations:
            writer.writerow(["-", rec])

    writer.writerow([])
    writer.writerow(["=== ALERTS ==="])
    writer.writerow([])

    writer.writerow([
        "Alert ID",
        "Type",
        "Severity",
        "MITRE",
        "Source IP",
        "Target",
        "Created At",
        "Description",
    ])

    for alert in alerts:
        description = alert.description or ""

        writer.writerow([
            alert.id[:8] + "...",
            alert.alert_type,
            alert.severity,
            alert.mitre_technique or "N/A",
            alert.source_ip or "N/A",
            alert.target_host or "N/A",
            kathmandu_iso(alert.created_at) or "N/A",
            (
                description[:50] + "..."
                if len(description) > 50
                else description
            ),
        ])

    # Make sure StringIO is positioned at the beginning.
    output.seek(0)

    return StreamingResponse(
        output,
        media_type="text/csv",
        headers={
            "Content-Disposition": (
                f"attachment; filename=incident_{incident_id}.csv"
            )
        },
    )


# GET /api/v1/incidents/{incident_id}/export/json
@router.get("/{incident_id}/export/json")
async def export_incident_json(
    incident_id: str,
    db: Session = Depends(get_db),
):
    """Export incident details as JSON with Kathmandu timestamps."""

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

    export_data = {
        "incident": {
            "id": incident.id,
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status,
            "confidence": incident.confidence,

            # UTC -> Kathmandu
            "first_seen": kathmandu_iso(incident.first_seen),
            "last_seen": kathmandu_iso(incident.last_seen),
            "resolved_at": kathmandu_iso(incident.resolved_at),
            "created_at": kathmandu_iso(incident.created_at),
            "updated_at": kathmandu_iso(incident.updated_at),

            "source_entities": incident.source_entities,
            "target_entities": incident.target_entities,
            "attack_chain": incident.attack_chain,
            "mitre_techniques": incident.mitre_techniques,
            "ai_summary": incident.ai_summary,
            "recommendations": incident.recommendations,
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

                # UTC -> Kathmandu
                "created_at": kathmandu_iso(alert.created_at),
            }
            for alert in alerts
        ],

        "alert_count": len(alerts),

        # Current export time in Kathmandu
        "exported_at": kathmandu_iso(utc_now()),
    }

    return JSONResponse(
        content=export_data,
        headers={
            "Content-Disposition": (
                f"attachment; filename=incident_{incident_id}.json"
            )
        },
    )


# GET /api/v1/incidents/export/all
@router.get("/export/all")
async def export_all_incidents(
    format: str = "json",
    limit: int = 100,
    db: Session = Depends(get_db),
):
    """Export all incidents with Kathmandu timestamps."""

    # Basic validation
    format = format.lower()

    if format not in {"json", "csv"}:
        raise HTTPException(
            status_code=400,
            detail="Format must be either 'json' or 'csv'",
        )

    if limit < 1:
        raise HTTPException(
            status_code=400,
            detail="Limit must be greater than 0",
        )

    if limit > 1000:
        limit = 1000

    incidents = (
        db.query(IncidentDB)
        .order_by(IncidentDB.created_at.desc())
        .limit(limit)
        .all()
    )

    # ---------------------------------------------------------
    # CSV
    # ---------------------------------------------------------
    if format == "csv":
        output = StringIO()
        writer = csv.writer(output)

        writer.writerow([
            "ID",
            "Title",
            "Severity",
            "Status",
            "Confidence",
            "First Seen",
            "Last Seen",
            "Resolved At",
            "MITRE Techniques",
            "Alert Count",
        ])

        for inc in incidents:
            alert_count = (
                db.query(AlertDB)
                .filter(AlertDB.incident_id == inc.id)
                .count()
            )

            writer.writerow([
                inc.id[:8] + "...",
                inc.title,
                inc.severity,
                inc.status,

                (
                    f"{inc.confidence * 100:.1f}%"
                    if inc.confidence is not None
                    else "N/A"
                ),

                kathmandu_iso(inc.first_seen) or "N/A",
                kathmandu_iso(inc.last_seen) or "N/A",
                kathmandu_iso(inc.resolved_at) or "N/A",

                ", ".join(inc.mitre_techniques or []),

                alert_count,
            ])

        output.seek(0)

        return StreamingResponse(
            output,
            media_type="text/csv",
            headers={
                "Content-Disposition": (
                    "attachment; filename=all_incidents.csv"
                )
            },
        )

    # ---------------------------------------------------------
    # JSON
    # ---------------------------------------------------------
    data = []

    for inc in incidents:
        alert_count = (
            db.query(AlertDB)
            .filter(AlertDB.incident_id == inc.id)
            .count()
        )

        data.append({
            "id": inc.id,
            "title": inc.title,
            "severity": inc.severity,
            "status": inc.status,
            "confidence": inc.confidence,

            # UTC -> Kathmandu
            "first_seen": kathmandu_iso(inc.first_seen),
            "last_seen": kathmandu_iso(inc.last_seen),
            "resolved_at": kathmandu_iso(inc.resolved_at),
            "created_at": kathmandu_iso(inc.created_at),
            "updated_at": kathmandu_iso(inc.updated_at),

            "mitre_techniques": inc.mitre_techniques,
            "alert_count": alert_count,

            "ai_summary": (
                inc.ai_summary[:200] + "..."
                if inc.ai_summary and len(inc.ai_summary) > 200
                else inc.ai_summary
            ),
        })

    return JSONResponse(
        content={
            "total": len(data),

            # Current export time in Kathmandu
            "exported_at": kathmandu_iso(utc_now()),

            "incidents": data,
        }
    )
