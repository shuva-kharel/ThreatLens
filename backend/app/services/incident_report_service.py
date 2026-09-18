from typing import Any, Dict, List

from sqlalchemy.orm import Session

from app.api.mitre import MITRE_TECHNIQUES
from app.core.time import utc_iso, utc_now
from app.core.trace_ai import TraceAI
from app.models.database import Alert, Escalation, Incident, Response
from app.models.schemas import Alert as AlertSchema, Incident as IncidentSchema
from app.services.recurrence_service import RecurrenceService
from app.services.response_service import ResponseService


def _dump_incident(incident: Incident) -> Dict[str, Any]:
    return IncidentSchema.model_validate(incident).model_dump(mode="python")


def _dump_alert(alert: Alert) -> Dict[str, Any]:
    return AlertSchema.model_validate(alert).model_dump(mode="python")


def _clean(value: Any) -> Any:
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if any(secret in lowered for secret in ["key", "token", "secret", "webhook", "credential", "password"]):
                redacted[key] = "Redacted"
            else:
                redacted[key] = _clean(item)
        return redacted
    if isinstance(value, list):
        return [_clean(item) for item in value]
    return value


class IncidentReportService:
    report_version = "1.0"

    def __init__(self, db: Session):
        self.db = db

    def build(self, incident_id: str, generated_by: str = "ThreatLens Analyst") -> Dict[str, Any] | None:
        incident = self.db.get(Incident, incident_id)
        if incident is None:
            return None

        alerts = (
            self.db.query(Alert)
            .filter(Alert.incident_id == incident_id)
            .order_by(Alert.created_at.asc())
            .all()
        )
        trace = TraceAI(self.db).reconstruct_incident(incident_id) or {}
        response_service = ResponseService()
        response_service.load_persisted_outcomes(self.db)

        executions = [
            record.model_dump(mode="json")
            for record in response_service.executions.values()
            if record.incident_id == incident_id
        ]
        audits = [
            entry.model_dump(mode="json")
            for entry in response_service.audit_log
            if entry.incident_id == incident_id
        ]
        ledgers = (
            self.db.query(Response)
            .filter(Response.incident_id == incident_id)
            .order_by(Response.created_at.asc())
            .all()
        )
        escalation = (
            self.db.query(Escalation)
            .filter(Escalation.current_incident_id == incident_id)
            .first()
        )

        incident_data = _dump_incident(incident)
        alert_data = [_dump_alert(alert) for alert in alerts]
        mitre = self._mitre(incident.mitre_techniques or [])
        timeline = self._timeline(incident_data, trace, executions, audits, escalation)

        return _clean({
            "metadata": {
                "incident_id": incident.id,
                "generated_at": utc_iso(utc_now()),
                "generated_by": generated_by,
                "report_version": self.report_version,
                "display_timezone": "Asia/Kathmandu",
                "display_utc_offset": "UTC+05:45",
            },
            "incident": incident_data,
            "executive_summary": self._executive_summary(incident_data, trace, executions, escalation),
            "overview": self._overview(incident_data, trace, alert_data),
            "timeline": timeline,
            "attack_narrative": self._attack_narrative(trace),
            "entities": trace.get("entities") or {
                "source_ips": incident.source_entities or [],
                "target_hosts": incident.target_entities or [],
            },
            "mitre": mitre,
            "alerts": alert_data,
            "ai_assisted_analysis": self._ai_assisted_analysis(incident_data),
            "responses": executions,
            "verification": [item for item in executions if item.get("verification_result")],
            "human_escalation": RecurrenceService.serialize(escalation) if escalation else None,
            "recommendations": incident.recommendations or [],
            "evidence_summary": {
                "incident_id": incident.id,
                "alert_ids": [alert.id for alert in alerts],
                "event_ids": sorted({
                    event_id
                    for alert in alerts
                    for event_id in (alert.evidence or [])
                }),
                "execution_ids": [item["execution_id"] for item in executions],
                "escalation_id": escalation.id if escalation else None,
                "audit_ids": [item["id"] for item in audits],
                "response_ledger_ids": [ledger.id for ledger in ledgers],
            },
            "audit_history": audits,
        })

    def _mitre(self, technique_ids: List[str]) -> List[Dict[str, Any]]:
        mapped = []
        for technique_id in technique_ids:
            if technique_id in MITRE_TECHNIQUES:
                mapped.append({"id": technique_id, **MITRE_TECHNIQUES[technique_id]})
        return mapped

    def _timeline(
        self,
        incident: Dict[str, Any],
        trace: Dict[str, Any],
        executions: List[Dict[str, Any]],
        audits: List[Dict[str, Any]],
        escalation: Escalation | None,
    ) -> List[Dict[str, Any]]:
        items = []
        for item in trace.get("timeline") or []:
            if item.get("timestamp"):
                items.append({
                    "timestamp": item["timestamp"],
                    "type": item.get("type", "evidence"),
                    "title": item.get("event_type") or item.get("alert_type") or "Evidence",
                    "description": item.get("description") or "Observed telemetry",
                    "source": item.get("source_ip"),
                    "target": item.get("target_host") or item.get("host"),
                    "evidence_id": item.get("id"),
                })
        if incident.get("created_at"):
            items.append({"timestamp": incident["created_at"], "type": "incident", "title": "Incident Created", "description": incident["title"]})
        for execution in executions:
            if execution.get("started_at"):
                items.append({"timestamp": execution["started_at"], "type": "response", "title": execution["action"], "description": execution["status"], "evidence_id": execution["execution_id"]})
            verification = execution.get("verification_result") or {}
            if verification.get("timestamp"):
                items.append({"timestamp": verification["timestamp"], "type": "verification", "title": "Response Verification", "description": verification.get("details") or verification.get("method"), "evidence_id": execution["execution_id"]})
        for audit in audits:
            if audit.get("timestamp"):
                items.append({"timestamp": audit["timestamp"], "type": "audit", "title": audit["policy_decision"], "description": audit["action"], "evidence_id": audit["id"]})
        if escalation and escalation.created_at:
            items.append({"timestamp": utc_iso(escalation.created_at), "type": "escalation", "title": "Human Review Required", "description": escalation.reason, "evidence_id": escalation.id})
        return sorted(items, key=lambda item: item["timestamp"])

    def _executive_summary(
        self,
        incident: Dict[str, Any],
        trace: Dict[str, Any],
        executions: List[Dict[str, Any]],
        escalation: Escalation | None,
    ) -> str:
        source = ", ".join(incident.get("source_entities") or []) or "an unavailable source"
        target = ", ".join(incident.get("target_entities") or []) or "an unavailable target"
        severity = str(incident.get("severity") or "unknown").upper()
        status = str(incident.get("status") or "unknown").replace("_", " ").upper()
        mapped = ", ".join(trace.get("mitre_techniques") or incident.get("mitre_techniques") or [])
        response = " No response execution is recorded."
        if executions:
            latest = executions[-1]
            mode = "dry-run" if latest.get("dry_run") else "executed"
            response = f" The latest response action was {mode} with status {latest.get('status')}."
        escalation_text = " Human review is required." if escalation and escalation.requires_human_review else ""
        mitre_text = f" Mapped MITRE techniques: {mapped}." if mapped else ""
        return (
            f"ThreatLens correlated activity from {source} against {target} into a "
            f"{severity}-severity incident currently marked {status}.{mitre_text}"
            f"{response}{escalation_text}"
        )

    def _overview(self, incident: Dict[str, Any], trace: Dict[str, Any], alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        telemetry = sorted({
            item.get("telemetry_source")
            for item in trace.get("timeline") or []
            if item.get("telemetry_source")
        })
        return {
            "Incident ID": incident.get("id"),
            "Title": incident.get("title"),
            "Severity": incident.get("severity"),
            "Status": incident.get("status"),
            "Confidence": incident.get("confidence"),
            "Source": ", ".join(incident.get("source_entities") or []) or None,
            "Target": ", ".join(incident.get("target_entities") or []) or None,
            "First Seen": incident.get("first_seen"),
            "Last Seen": incident.get("last_seen"),
            "Duration": incident.get("duration_minutes"),
            "Detection Type": ", ".join(sorted({alert.get("alert_type") for alert in alerts if alert.get("alert_type")})) or None,
            "Telemetry Source": ", ".join(telemetry) or None,
        }

    def _attack_narrative(self, trace: Dict[str, Any]) -> Dict[str, Any]:
        stages = trace.get("stages") or []
        return {
            "observed_evidence": [
                stage.get("description")
                for stage in stages
                if stage.get("description")
            ],
            "interpretation": [
                f"{stage.get('stage')} observed from {stage.get('first_seen') or 'Not available'} to {stage.get('last_seen') or 'Not available'}."
                for stage in stages
                if stage.get("stage")
            ],
        }

    def _ai_assisted_analysis(self, incident: Dict[str, Any]) -> Dict[str, Any] | None:
        if not incident.get("ai_summary") and not incident.get("recommendations"):
            return None
        return {
            "summary": incident.get("ai_summary"),
            "recommendations": incident.get("recommendations") or [],
            "label": "AI-Assisted Analysis",
        }
