from collections import defaultdict
from ipaddress import ip_address
from typing import Any, Dict

from sqlalchemy.orm import Session

from app.core.time import utc_iso
from app.models.database import Alert, Escalation, Event, Incident, Response


SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def classify_ip(value: str | None) -> Dict[str, Any]:
    if not value:
        return {"classification": "unknown", "network_label": "Unknown"}
    try:
        address = ip_address(value)
    except ValueError:
        return {"classification": "invalid", "network_label": "Unknown"}

    if address.is_loopback:
        classification = "loopback"
    elif address.is_link_local:
        classification = "link_local"
    elif address.is_private:
        classification = "private"
    elif address.is_global:
        classification = "public"
    else:
        classification = "reserved_internal"

    return {
        "classification": classification,
        "network_label": (
            "Public Internet" if classification == "public" else "Internal Network"
        ),
        "ip_version": address.version,
    }


class ThreatMapService:
    def __init__(self, db: Session):
        self.db = db

    def aggregate(self) -> Dict[str, Any]:
        groups: Dict[tuple[str, str, str], Dict[str, Any]] = {}
        alerts = self.db.query(Alert).order_by(Alert.created_at.asc()).all()

        for alert in alerts:
            source = alert.source_ip or "Unknown"
            target = alert.target_host or "Unknown"
            attack_type = alert.alert_type
            key = (source, target, attack_type)
            severity = getattr(alert.severity, "value", alert.severity) or "medium"
            item = groups.setdefault(key, {
                "source_ip": source,
                "target": target,
                "attack_type": attack_type,
                "severity": severity,
                "alert_count": 0,
                "event_ids": set(),
                "incident_ids": set(),
                "mitre_techniques": set(),
                "first_seen": alert.created_at,
                "last_seen": alert.created_at,
            })
            item["alert_count"] += 1
            if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(item["severity"], 0):
                item["severity"] = severity
            item["first_seen"] = min(item["first_seen"], alert.created_at)
            item["last_seen"] = max(item["last_seen"], alert.created_at)
            if alert.incident_id:
                item["incident_ids"].add(alert.incident_id)
            if alert.mitre_technique:
                item["mitre_techniques"].add(alert.mitre_technique)
            for evidence in alert.evidence or []:
                event_id = evidence.get("event_id") if isinstance(evidence, dict) else evidence
                if event_id:
                    item["event_ids"].add(event_id)

        response_by_incident = defaultdict(set)
        for response in self.db.query(Response).all():
            execution = (response.details or {}).get("execution") or {}
            status = execution.get("status") or response.status
            if response.action != "human_escalation":
                response_by_incident[response.incident_id].add(status)

        escalation_by_incident = {
            escalation.current_incident_id: escalation.status
            for escalation in self.db.query(Escalation).all()
        }

        relationships = []
        for item in groups.values():
            incident_ids = sorted(item.pop("incident_ids"))
            event_ids = item.pop("event_ids")
            if event_ids:
                event_count = len(event_ids)
            else:
                event_count = (
                    self.db.query(Event)
                    .filter(
                        Event.source_ip == item["source_ip"],
                        Event.host == item["target"],
                        Event.timestamp >= item["first_seen"],
                        Event.timestamp <= item["last_seen"],
                    )
                    .count()
                )

            response_statuses = sorted({
                status
                for incident_id in incident_ids
                for status in response_by_incident.get(incident_id, set())
            })
            escalation_statuses = sorted({
                escalation_by_incident[incident_id]
                for incident_id in incident_ids
                if incident_id in escalation_by_incident
            })
            source_meta = classify_ip(item["source_ip"])
            relationships.append({
                **item,
                "event_count": event_count,
                "incident_count": len(incident_ids),
                "incident_ids": incident_ids,
                "mitre_techniques": sorted(item["mitre_techniques"]),
                "first_seen": utc_iso(item["first_seen"]),
                "last_seen": utc_iso(item["last_seen"]),
                "response_status": response_statuses,
                "escalation_status": escalation_statuses,
                "source_classification": source_meta["classification"],
                "source_network": source_meta["network_label"],
                "ip_version": source_meta.get("ip_version"),
                "location": None,
                "coordinates": None,
            })

        relationships.sort(key=lambda item: item["last_seen"], reverse=True)
        return {
            "generated_from": "stored_threatlens_telemetry",
            "geolocation": {"enabled": False, "provider": None},
            "relationship_count": len(relationships),
            "relationships": relationships,
        }
