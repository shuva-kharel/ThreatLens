from datetime import datetime
from typing import List, Optional
from sqlalchemy.orm import Session
from app.models.database import Event, Alert, Incident
from app.models.schemas import EventCreate
from app.core.detection import DetectionEngine
from pydantic import BaseModel
import uuid
import asyncio

# Import WebSocket broadcast functions
from app.api.websocket import broadcast_new_alert, broadcast_new_incident


class EventBatch(BaseModel):
    """Schema for batch event submission."""
    events: List[EventCreate]


class EventService:
    def __init__(self, db: Session):
        self.db = db

    def create_event(self, event_data: EventCreate) -> Event:
        """Create a new event."""
        normalized_data = event_data.dict(exclude={'raw_event'})
        if 'timestamp' in normalized_data and isinstance(normalized_data['timestamp'], datetime):
            normalized_data['timestamp'] = normalized_data['timestamp'].isoformat()

        event = Event(
            id=str(uuid.uuid4()),
            timestamp=event_data.timestamp,
            host=event_data.host,
            source_ip=event_data.source_ip,
            event_type=event_data.event_type,
            username=event_data.username,
            severity=event_data.severity.value if event_data.severity else None,
            raw_event=event_data.raw_event,
            normalized_data=normalized_data
        )
        self.db.add(event)
        self.db.commit()
        self.db.refresh(event)
        return event

    def process_event(self, event_data: EventCreate) -> dict:
        """Process a single event through the full pipeline."""
        event = self.create_event(event_data)
        self.db.commit()

        # Run detection
        engine = DetectionEngine(self.db)
        alerts = engine.process_event(event)

        created_alerts = []
        incidents = []
        seen_incident_ids = set()

        for alert_data in alerts:
            alert = self._create_alert(alert_data)
            created_alerts.append(alert)
            self._broadcast_alert(alert)

        # Create incidents from alerts
        if created_alerts:
            for alert in created_alerts:
                incident = self._create_incident_from_alert(alert)
                if incident:
                    alert.incident_id = incident.id
                    self.db.commit()
                    self.db.refresh(alert)

                    if incident.id not in seen_incident_ids:
                        seen_incident_ids.add(incident.id)
                        self._broadcast_incident(incident)
                        incidents.append(self._serialize_incident(incident))

        return {
            "event": {
                "id": event.id,
                "timestamp": event.timestamp.isoformat(),
                "host": event.host,
                "source_ip": event.source_ip,
                "event_type": event.event_type,
                "username": event.username,
                "severity": event.severity,
            },
            "alerts_created": len(created_alerts),
            "incidents": incidents
        }

    def process_batch(self, batch: EventBatch) -> dict:
        """Process a batch of events through the full pipeline."""
        results = {
            "total": len(batch.events),
            "successful": 0,
            "failed": 0,
            "alerts_created": 0,
            "incidents_created": 0,
            "incident_ids": set(),
            "errors": []
        }

        for i, event_data in enumerate(batch.events):
            try:
                # Create event
                event = self.create_event(event_data)

                # Run detection
                engine = DetectionEngine(self.db)
                alerts = engine.process_event(event)

                # Create alerts
                for alert_data in alerts:
                    alert = self._create_alert(alert_data)
                    results["alerts_created"] += 1
                    self._broadcast_alert(alert)

                    # Create/update incident
                    incident = self._create_incident_from_alert(alert)
                    if incident:
                        alert.incident_id = incident.id
                        self.db.commit()
                        self.db.refresh(alert)

                        if incident.id not in results["incident_ids"]:
                            results["incident_ids"].add(incident.id)
                            self._broadcast_incident(incident)

                results["successful"] += 1

            except Exception as e:
                results["failed"] += 1
                results["errors"].append({
                    "index": i,
                    "error": str(e),
                    "event_type": event_data.event_type
                })

        # Convert set to list for JSON serialization
        results["incidents_created"] = len(results["incident_ids"])
        results["incident_ids"] = list(results["incident_ids"])
        results["status"] = "success" if results["failed"] == 0 else "partial"

        return results

    # ===== Private helper methods =====

    def _create_alert(self, alert_data) -> Alert:
        """Create and persist an alert."""
        alert = Alert(
            id=str(uuid.uuid4()),
            alert_type=alert_data.alert_type,
            severity=alert_data.severity.value,
            mitre_technique=alert_data.mitre_technique,
            source_ip=alert_data.source_ip,
            target_host=alert_data.target_host,
            description=alert_data.description,
            evidence=alert_data.evidence,
            confidence=alert_data.confidence
        )
        self.db.add(alert)
        self.db.commit()
        self.db.refresh(alert)
        return alert

    def _broadcast_alert(self, alert: Alert):
        """Broadcast alert via WebSocket."""
        try:
            alert_dict = {
                "id": alert.id,
                "alert_type": alert.alert_type,
                "severity": alert.severity,
                "mitre_technique": alert.mitre_technique,
                "source_ip": alert.source_ip,
                "target_host": alert.target_host,
                "description": alert.description,
                "confidence": alert.confidence,
                "created_at": alert.created_at.isoformat()
            }
            asyncio.create_task(broadcast_new_alert(alert_dict))
            print(f"[WebSocket] Broadcasted alert: {alert.alert_type}")
        except Exception as e:
            print(f"[WebSocket] Failed to broadcast alert: {e}")

    def _broadcast_incident(self, incident: Incident):
        """Broadcast incident via WebSocket."""
        try:
            incident_dict = {
                "id": incident.id,
                "title": incident.title,
                "severity": incident.severity,
                "confidence": incident.confidence,
                "status": incident.status,
                "source_entities": incident.source_entities,
                "target_entities": incident.target_entities,
                "mitre_techniques": incident.mitre_techniques,
                "first_seen": incident.first_seen.isoformat() if incident.first_seen else None,
                "last_seen": incident.last_seen.isoformat() if incident.last_seen else None,
                "alert_count": 1
            }
            asyncio.create_task(broadcast_new_incident(incident_dict))
            print(f"[WebSocket] Broadcasted incident: {incident.title}")
        except Exception as e:
            print(f"[WebSocket] Failed to broadcast incident: {e}")

    def _serialize_incident(self, incident: Incident) -> dict:
        """Serialize incident for API response."""
        return {
            "id": incident.id,
            "title": incident.title,
            "severity": incident.severity,
            "confidence": incident.confidence,
            "status": incident.status,
            "source_entities": incident.source_entities,
            "target_entities": incident.target_entities,
            "mitre_techniques": incident.mitre_techniques,
            "first_seen": incident.first_seen.isoformat() if incident.first_seen else None,
            "last_seen": incident.last_seen.isoformat() if incident.last_seen else None,
        }

    def _create_incident_from_alert(self, alert: Alert) -> Optional[Incident]:
        """Create or update an incident from a single alert."""
        # Look for existing open/investigating incident for this source IP
        existing = self.db.query(Incident).filter(
            Incident.status.in_(["open", "investigating"]),
            Incident.source_entities.contains([alert.source_ip])
        ).order_by(Incident.last_seen.desc()).first()

        if existing:
            return self._update_incident(existing, alert)

        return self._create_new_incident(alert)

    def _update_incident(self, incident: Incident, alert: Alert) -> Incident:
        """Update an existing incident with a new alert."""
        incident.last_seen = alert.created_at

        # Add MITRE technique if not already present
        if alert.mitre_technique:
            current_techniques = incident.mitre_techniques or []
            if alert.mitre_technique not in current_techniques:
                incident.mitre_techniques = current_techniques + [alert.mitre_technique]

        # Add attack chain entry if this stage doesn't exist
        current_chain = incident.attack_chain or []
        stage_name = self._get_stage_from_alert(alert)
        existing_stages = [s.get("stage") for s in current_chain]
        if stage_name not in existing_stages:
            current_chain.append({
                "stage": stage_name,
                "description": alert.description,
                "timestamp": alert.created_at.isoformat(),
                "technique_id": alert.mitre_technique
            })
            incident.attack_chain = current_chain

        # Escalate severity if needed
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        if severity_order.get(alert.severity, 0) > severity_order.get(incident.severity, 0):
            incident.severity = alert.severity

        # Update confidence (take max)
        if alert.confidence and alert.confidence > (incident.confidence or 0):
            incident.confidence = alert.confidence

        self.db.commit()
        self.db.refresh(incident)
        return incident

    def _create_new_incident(self, alert: Alert) -> Incident:
        """Create a new incident from an alert."""
        incident = Incident(
            id=str(uuid.uuid4()),
            title=f"{alert.alert_type.replace('_', ' ').title()} from {alert.source_ip}",
            severity=alert.severity,
            confidence=alert.confidence,
            status="open",
            source_entities=[alert.source_ip] if alert.source_ip else [],
            target_entities=[alert.target_host] if alert.target_host else [],
            attack_chain=[{
                "stage": self._get_stage_from_alert(alert),
                "description": alert.description,
                "timestamp": alert.created_at.isoformat(),
                "technique_id": alert.mitre_technique
            }],
            mitre_techniques=[alert.mitre_technique] if alert.mitre_technique else [],
            first_seen=alert.created_at,
            last_seen=alert.created_at,
            recommendations=[]
        )
        self.db.add(incident)
        self.db.commit()
        self.db.refresh(incident)
        return incident

    def _get_stage_from_alert(self, alert: Alert) -> str:
        """Determine attack stage from alert type."""
        alert_type = (alert.alert_type or "").lower()
        raw = (alert.description or "").lower()

        if "port_scan" in alert_type or "scan" in raw:
            return "Reconnaissance"
        elif "brute_force" in alert_type:
            return "Credential Access"
        elif "successful_login" in alert_type:
            return "Initial Access"
        elif "suspicious_command" in alert_type:
            return "Execution"
        elif "privilege" in alert_type or "escalation" in raw:
            return "Privilege Escalation"
        else:
            return "Unknown"