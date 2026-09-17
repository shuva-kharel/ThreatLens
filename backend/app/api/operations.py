from collections import defaultdict
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import String, cast, or_
from sqlalchemy.orm import Session

from app.api.mitre import MITRE_TECHNIQUES
from app.core.time import ensure_utc, utc_iso, utc_now
from app.db.session import get_db
from app.models.database import Alert, EndpointAgent, Escalation, Event, Incident, Response
from app.services.response_service import ResponseService
from app.services.vulnerability_service import VulnerabilityService


router = APIRouter()


def _value(value: Any) -> Any:
    return getattr(value, "value", value)


def _score(query: str, *values: Any) -> int:
    needle = query.casefold()
    texts = [str(value).casefold() for value in values if value is not None]
    if any(text == needle for text in texts):
        return 100
    if any(text.startswith(needle) for text in texts):
        return 70
    if any(needle in text for text in texts):
        return 40
    return 0


def _result(entity: str, identifier: str, label: str, detail: str, href: str, score: int, **extra: Any):
    return {
        "entity": entity,
        "id": identifier,
        "label": label,
        "detail": detail,
        "href": href,
        "score": score,
        **extra,
    }


@router.get("/search")
def search_threatlens(
    q: str = Query(min_length=1, max_length=100),
    limit: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
):
    """Search persisted ThreatLens entities and static defensive registries."""
    query = q.strip()
    pattern = f"%{query}%"
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)

    incidents = db.query(Incident).filter(or_(
        Incident.id.ilike(pattern), Incident.title.ilike(pattern),
        cast(Incident.source_entities, String).ilike(pattern),
        cast(Incident.target_entities, String).ilike(pattern),
        cast(Incident.mitre_techniques, String).ilike(pattern),
    )).limit(limit * 3).all()
    for item in incidents:
        score = _score(query, item.id, item.title, _value(item.severity), _value(item.status), *(item.source_entities or []), *(item.target_entities or []), *(item.mitre_techniques or []))
        if score:
            grouped["incidents"].append(_result("incident", item.id, item.title, f"{_value(item.severity)} - {_value(item.status)}", f"/incidents/{item.id}", score, severity=_value(item.severity), timestamp=utc_iso(item.last_seen)))

    alerts = db.query(Alert).filter(or_(
        Alert.id.ilike(pattern), Alert.alert_type.ilike(pattern), Alert.description.ilike(pattern),
        Alert.source_ip.ilike(pattern), Alert.target_host.ilike(pattern), Alert.mitre_technique.ilike(pattern),
    )).limit(limit * 3).all()
    for item in alerts:
        score = _score(query, item.id, item.alert_type, item.description, item.source_ip, item.target_host, item.mitre_technique, _value(item.severity))
        grouped["alerts"].append(_result("alert", item.id, item.alert_type, f"{item.source_ip or 'Unknown'} -> {item.target_host or 'Unknown'}", f"/incidents/{item.incident_id}" if item.incident_id else "/alerts", score, severity=_value(item.severity), timestamp=utc_iso(item.created_at)))

    events = db.query(Event).filter(or_(
        Event.id.ilike(pattern), Event.event_type.ilike(pattern), Event.host.ilike(pattern),
        Event.source_ip.ilike(pattern), Event.username.ilike(pattern), Event.raw_event.ilike(pattern),
        cast(Event.normalized_data, String).ilike(pattern),
    )).order_by(Event.timestamp.desc()).limit(limit * 4).all()
    source_counts: dict[str, dict[str, Any]] = {}
    host_counts: dict[str, dict[str, Any]] = {}
    for item in events:
        normalized = item.normalized_data or {}
        destination = normalized.get("destination_ip")
        score = _score(query, item.id, item.event_type, item.host, item.source_ip, item.username, item.raw_event, destination)
        if score:
            grouped["events"].append(_result("event", item.id, item.event_type, f"{item.source_ip or 'Local'} -> {item.host}", "/events", score, severity=item.severity, timestamp=utc_iso(item.timestamp)))
        for value, bucket, entity, href in (
            (item.source_ip, source_counts, "source", "/threat-map"),
            (destination, source_counts, "destination", "/network"),
            (item.host, host_counts, "host", "/network"),
        ):
            if value and _score(query, value):
                entry = bucket.setdefault(str(value), {"count": 0, "entity": entity, "href": href})
                entry["count"] += 1
    for value, data in source_counts.items():
        grouped["sources"].append(_result(data["entity"], value, value, f"{data['count']} matching events", data["href"], _score(query, value)))
    for value, data in host_counts.items():
        grouped["hosts"].append(_result("host", value, value, f"{data['count']} matching events", data["href"], _score(query, value)))

    for agent in db.query(EndpointAgent).filter(or_(
        EndpointAgent.id.ilike(pattern), EndpointAgent.hostname.ilike(pattern),
        EndpointAgent.os.ilike(pattern), cast(EndpointAgent.ip_addresses, String).ilike(pattern),
    )).limit(limit * 3).all():
        score = _score(query, agent.id, agent.hostname, agent.os, *(agent.ip_addresses or []))
        if score:
            online = ensure_utc(agent.last_seen) >= utc_now() - timedelta(minutes=2)
            grouped["agents"].append(_result("agent", agent.id, agent.hostname, f"{agent.os} - {'online' if online else 'offline'}", "/settings", score, timestamp=utc_iso(agent.last_seen)))

    for response in db.query(Response).filter(or_(
        Response.id.ilike(pattern), Response.incident_id.ilike(pattern),
        Response.action.ilike(pattern), Response.status.ilike(pattern),
        cast(Response.details, String).ilike(pattern),
    )).order_by(Response.created_at.desc()).limit(limit * 3).all():
        execution = (response.details or {}).get("execution") or {}
        execution_id = execution.get("execution_id")
        score = _score(query, response.id, response.incident_id, response.action, response.status, execution_id, execution.get("target"), execution.get("playbook_id"))
        if score:
            grouped["responses"].append(_result("response", execution_id or response.id, execution_id or response.action, f"{response.action} - {execution.get('status') or response.status}", "/response", score, timestamp=utc_iso(response.created_at)))

    for item in db.query(Escalation).filter(or_(
        Escalation.id.ilike(pattern), Escalation.source_ip.ilike(pattern),
        Escalation.target.ilike(pattern), Escalation.current_incident_id.ilike(pattern),
        Escalation.reason.ilike(pattern), Escalation.status.ilike(pattern),
    )).order_by(Escalation.last_activity_at.desc()).limit(limit * 3).all():
        score = _score(query, item.id, item.source_ip, item.target, item.current_incident_id, item.reason, item.status)
        if score:
            grouped["escalations"].append(_result("escalation", item.id, item.source_ip, f"{item.status} - {item.reason}", f"/incidents/{item.current_incident_id}", score, severity=item.severity, timestamp=utc_iso(item.last_activity_at)))

    for technique_id, info in MITRE_TECHNIQUES.items():
        score = _score(query, technique_id, info["name"], info["tactic"], info["description"])
        if score:
            grouped["mitre"].append(_result("mitre", technique_id, f"{technique_id} - {info['name']}", info["tactic"], f"/mitre?technique={technique_id}", score))

    for playbook in ResponseService().playbooks.values():
        score = _score(query, playbook.id, playbook.name, playbook.description, playbook.action_type.value)
        if score:
            grouped["playbooks"].append(_result("playbook", playbook.id, playbook.name, playbook.action_type.value, "/response", score))
    for finding in VulnerabilityService().list_vulnerabilities():
        score = _score(query, finding.cve_id, finding.title, finding.description, finding.severity, finding.affected_host, finding.affected_service, finding.remediation)
        if score:
            identifier = finding.cve_id or finding.id or finding.title
            grouped["vulnerabilities"].append(_result("vulnerability", identifier, f"{finding.cve_id or 'Finding'} - {finding.title}", finding.affected_host or finding.affected_service or finding.description, "/vulnerabilities", score, severity=finding.severity))

    ordered = {}
    for key, values in grouped.items():
        ordered[key] = sorted(values, key=lambda item: (-item["score"], item["label"].casefold()))[:limit]
    return {"query": query, "results": ordered, "total": sum(len(items) for items in ordered.values())}


@router.get("/activity")
def recent_activity(limit: int = Query(default=50, ge=1, le=200), db: Session = Depends(get_db)):
    """Build a chronological SOC feed from durable backend state."""
    activity: list[dict[str, Any]] = []
    for event in db.query(Event).order_by(Event.timestamp.desc()).limit(limit).all():
        activity.append({"id": f"event:{event.id}", "type": "event", "label": event.event_type, "detail": f"{event.source_ip or 'Local'} -> {event.host}", "timestamp": utc_iso(event.timestamp), "severity": event.severity, "href": "/events"})
    for alert in db.query(Alert).order_by(Alert.created_at.desc()).limit(limit).all():
        activity.append({"id": f"alert:{alert.id}", "type": "detection", "label": alert.alert_type, "detail": alert.description, "timestamp": utc_iso(alert.created_at), "severity": _value(alert.severity), "href": f"/incidents/{alert.incident_id}" if alert.incident_id else "/alerts", "stage": "detect"})
    for incident in db.query(Incident).order_by(Incident.updated_at.desc()).limit(limit).all():
        activity.append({"id": f"incident:{incident.id}:{utc_iso(incident.updated_at)}", "type": "incident", "label": incident.title, "detail": f"{incident.id} - {_value(incident.status)}", "timestamp": utc_iso(incident.updated_at), "severity": _value(incident.severity), "href": f"/incidents/{incident.id}", "stage": "correlate"})
        if incident.mitre_techniques:
            activity.append({"id": f"trace:{incident.id}:{utc_iso(incident.updated_at)}", "type": "traceai", "label": "Attack path reconstructed", "detail": ", ".join(incident.mitre_techniques), "timestamp": utc_iso(incident.updated_at), "severity": _value(incident.severity), "href": f"/incidents/{incident.id}", "stage": "trace"})
    for response in db.query(Response).order_by(Response.created_at.desc()).limit(limit).all():
        details = response.details or {}
        timestamp = details.get("completed_at") or utc_iso(response.created_at)
        proposal = details.get("proposal") or {}
        policy = details.get("policy") or {}
        execution = details.get("execution") or {}
        if proposal:
            activity.append({"id": f"proposal:{response.id}", "type": "ai_response", "label": f"{proposal.get('recommended_action', response.action)} proposed", "detail": proposal.get("reason"), "timestamp": timestamp, "href": "/response", "stage": "understand"})
        if policy:
            activity.append({"id": f"policy:{response.id}", "type": "policy", "label": "Auto-response approved" if policy.get("auto_execute") else "Human approval required", "detail": policy.get("reason"), "timestamp": timestamp, "href": "/response", "stage": "respond"})
        if execution:
            activity.append({"id": f"execution:{execution.get('execution_id', response.id)}", "type": "response", "label": f"{execution.get('playbook_id', response.action)} {execution.get('status', response.status)}", "detail": f"{execution.get('action', response.action)} -> {execution.get('target', 'Unknown')}", "timestamp": execution.get("completed_at") or timestamp, "href": "/response", "stage": "respond"})
            verification = execution.get("verification_result") or {}
            if verification:
                activity.append({"id": f"verification:{execution.get('execution_id', response.id)}", "type": "verified" if verification.get("verified") else "verification_failed", "label": verification.get("details") or "Response verification", "detail": verification.get("method"), "timestamp": verification.get("timestamp") or timestamp, "href": "/response", "stage": "verify"})
    for escalation in db.query(Escalation).order_by(Escalation.last_activity_at.desc()).limit(limit).all():
        activity.append({"id": f"escalation:{escalation.id}", "type": "escalation", "label": escalation.reason, "detail": f"{escalation.source_ip} -> {escalation.target or 'Unknown'}", "timestamp": utc_iso(escalation.last_activity_at), "severity": escalation.severity, "href": f"/incidents/{escalation.current_incident_id}", "stage": "verify"})
        if escalation.slack_notification_status != "PENDING":
            activity.append({"id": f"slack:{escalation.id}", "type": "slack", "label": f"Slack notification {escalation.slack_notification_status.lower()}", "detail": escalation.slack_notification_error, "timestamp": utc_iso(escalation.slack_notification_attempted_at or escalation.updated_at), "severity": "high" if escalation.slack_notification_status == "FAILED" else None, "href": "/response"})
    offline_cutoff = utc_now() - timedelta(minutes=2)
    for agent in db.query(EndpointAgent).filter(EndpointAgent.last_seen < offline_cutoff).order_by(EndpointAgent.last_seen.desc()).limit(limit).all():
        activity.append({"id": f"agent_offline:{agent.id}:{utc_iso(agent.last_seen)}", "type": "agent_offline", "label": f"{agent.hostname} is offline", "detail": agent.id, "timestamp": utc_iso(agent.last_seen), "severity": "high", "href": "/settings"})
    activity.sort(key=lambda item: item["timestamp"] or "", reverse=True)
    return {"activity": activity[:limit], "generated_at": utc_iso(utc_now())}
