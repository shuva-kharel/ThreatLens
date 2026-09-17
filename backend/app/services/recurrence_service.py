from datetime import datetime
from typing import Any, Dict, Optional
import uuid

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.time import ensure_utc, utc_iso, utc_now
from app.models.database import Escalation, Incident, Response
from app.services.notification_service import NotificationService


class RecurrenceService:
    def __init__(
        self,
        db: Session,
        notifications: Optional[NotificationService] = None,
    ):
        self.db = db
        self.notifications = notifications or NotificationService()

    @staticmethod
    def _escalation_id(incident_id: str) -> str:
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"threatlens-escalation:{incident_id}"))

    @staticmethod
    def _parse(value: Any):
        if isinstance(value, datetime):
            return ensure_utc(value)
        if isinstance(value, str):
            try:
                return ensure_utc(datetime.fromisoformat(value))
            except ValueError:
                return None
        return None

    @staticmethod
    def serialize(escalation: Escalation) -> Dict[str, Any]:
        return {
            "id": escalation.id,
            "source_ip": escalation.source_ip,
            "target": escalation.target,
            "severity": escalation.severity,
            "current_incident_id": escalation.current_incident_id,
            "previous_incident_id": escalation.previous_incident_id,
            "previous_response_id": escalation.previous_response_id,
            "previous_action": escalation.previous_action,
            "previous_response_status": escalation.previous_response_status,
            "previous_verification_at": utc_iso(escalation.previous_verification_at),
            "last_activity_at": utc_iso(escalation.last_activity_at),
            "recurrence_count": escalation.recurrence_count,
            "reason": escalation.reason,
            "requires_human_review": escalation.requires_human_review,
            "status": escalation.status,
            "assigned_to": escalation.assigned_to,
            "slack_notification_status": escalation.slack_notification_status,
            "slack_notification_attempted_at": utc_iso(escalation.slack_notification_attempted_at),
            "slack_notification_error": escalation.slack_notification_error,
            "created_at": utc_iso(escalation.created_at),
            "updated_at": utc_iso(escalation.updated_at),
        }

    def detect_and_escalate(self, incident_id: str) -> Optional[Dict[str, Any]]:
        escalation_id = self._escalation_id(incident_id)
        existing = self.db.get(Escalation, escalation_id)
        if existing:
            return self.serialize(existing)

        current = self.db.get(Incident, incident_id)
        if current is None or not current.source_entities:
            return None

        current_activity = ensure_utc(current.first_seen)
        matches = []
        for source_ip in current.source_entities:
            responses = (
                self.db.query(Response)
                .filter(
                    Response.incident_id != incident_id,
                    Response.status == "completed",
                )
                .all()
            )
            for response in responses:
                details = response.details or {}
                execution = details.get("execution") or {}
                verification = execution.get("verification_result") or {}
                if execution.get("dry_run") is True:
                    continue
                if execution.get("status") != "verified":
                    continue
                if verification.get("verified") is not True:
                    continue
                if execution.get("target") != source_ip:
                    continue

                verified_at = self._parse(verification.get("timestamp"))
                if verified_at is None or current_activity <= verified_at:
                    continue

                previous = self.db.get(Incident, response.incident_id)
                if previous is None or source_ip not in (previous.source_entities or []):
                    continue
                matches.append((verified_at, source_ip, response, execution))

        if not matches:
            return None

        verified_at, source_ip, response, execution = max(matches, key=lambda item: item[0])
        recurrence_count = (
            self.db.query(Escalation)
            .filter(Escalation.source_ip == source_ip)
            .count()
            + 2
        )
        severity = getattr(current.severity, "value", current.severity) or "medium"
        target = (current.target_entities or [None])[0]
        reason = (
            f"Repeated malicious activity detected from {source_ip} after a "
            "previously verified defensive response."
        )
        escalation = Escalation(
            id=escalation_id,
            source_ip=source_ip,
            target=target,
            severity=severity,
            current_incident_id=incident_id,
            previous_incident_id=response.incident_id,
            previous_response_id=execution.get("execution_id") or response.id,
            previous_action=execution.get("action") or response.action,
            previous_response_status=execution.get("status") or response.status,
            previous_verification_at=verified_at,
            last_activity_at=current_activity,
            recurrence_count=recurrence_count,
            reason=reason,
            requires_human_review=True,
            status="ESCALATED",
            slack_notification_status="PENDING",
        )
        self.db.add(escalation)
        try:
            self.db.commit()
        except IntegrityError:
            self.db.rollback()
            return self.serialize(self.db.get(Escalation, escalation_id))

        audit_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"threatlens-escalation-audit:{escalation_id}"))
        audit = Response(
            id=audit_id,
            incident_id=incident_id,
            action="human_escalation",
            status="ESCALATED",
            performed_by="recurrence_engine",
            details={
                "escalation_id": escalation_id,
                "events": [{
                    "type": "repeat_threat_detected",
                    "timestamp": utc_iso(utc_now()),
                    "reason": reason,
                }, {
                    "type": "human_review_required",
                    "timestamp": utc_iso(utc_now()),
                }],
            },
        )
        self.db.add(audit)
        self.db.commit()

        outcome = self.notifications.notify_human_escalation(self.serialize(escalation))
        escalation.slack_notification_status = outcome["status"]
        escalation.slack_notification_attempted_at = utc_now()
        escalation.slack_notification_error = outcome["error"] or None
        audit.details = {
            **audit.details,
            "events": [
                *audit.details["events"],
                {
                    "type": (
                        "slack_notification_sent"
                        if outcome["status"] == "SENT"
                        else "slack_notification_failed"
                    ),
                    "timestamp": utc_iso(utc_now()),
                    "status": outcome["status"],
                },
            ],
        }
        self.db.commit()
        serialized = self.serialize(escalation)
        try:
            from app.api.websocket import manager
            manager.broadcast_sync({"type": "response_escalated", "data": serialized})
        except Exception as exc:
            print(f"[RecurrenceService] Escalation broadcast error: {exc}")
        return serialized
