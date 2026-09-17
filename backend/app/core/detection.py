from datetime import timedelta
from typing import List, Optional

from app.models.database import Event
from app.models.schemas import AlertCreate, Severity
from app.core.time import utc_now


# ===== MITRE ATT&CK Technique Mapping =====

MITRE_MAPPING = {
    "ssh_brute_force": "T1110",
    "port_scanning": "T1046",
    "successful_login_after_failures": "T1078",
    "suspicious_command": "T1059",
    "unusual_process": "T1059",
}


# ===== Detection Rule Registry =====

DETECTION_RULES = [
    {
        "id": "NET-001",
        "alert_type": "port_scanning",
        "name": "Port Scanning",
        "description": "Multiple connection attempts across ports in short window",
        "severity": "medium",
        "mitre_technique": "T1046",
        "mitre_name": "Network Service Discovery",
        "category": "network",
        "threshold": "3+ attempts in 30s",
        "window_seconds": 30,
        "enabled": True,
        "false_positives": "Vulnerability scanners, authorized pen tests",
    },
    {
        "id": "AUTH-001",
        "alert_type": "ssh_brute_force",
        "name": "SSH Brute Force",
        "description": "Multiple failed SSH logins from same source",
        "severity": "high",
        "mitre_technique": "T1110",
        "mitre_name": "Brute Force",
        "category": "authentication",
        "threshold": "5+ failures in 60s",
        "window_seconds": 60,
        "enabled": True,
        "false_positives": "Forgotten passwords, misconfigured automation",
    },
    {
        "id": "AUTH-002",
        "alert_type": "successful_login_after_failures",
        "name": "Successful Login After Failures",
        "description": "Successful login following multiple failed attempts",
        "severity": "high",
        "mitre_technique": "T1078",
        "mitre_name": "Valid Accounts",
        "category": "authentication",
        "threshold": "Success after 3+ failures in 5 min",
        "window_seconds": 300,
        "enabled": True,
        "false_positives": "User remembering password",
    },
    {
        "id": "HOST-001",
        "alert_type": "suspicious_command",
        "name": "Suspicious Command Execution",
        "description": "Risky commands executed on host",
        "severity": "critical",
        "mitre_technique": "T1059",
        "mitre_name": "Command and Scripting Interpreter",
        "category": "host",
        "threshold": "Known risky patterns",
        "window_seconds": None,
        "enabled": True,
        "false_positives": "Admin scripts, dev workflows",
    },
]


class DetectionEngine:
    """Deterministic detection engine for security events."""

    def __init__(self, db_session):
        self.db = db_session

    def process_event(self, event: Event) -> List[AlertCreate]:
        """Run all detection rules on a single event."""
        alerts = []

        rules = [
            self._check_ssh_brute_force,
            self._check_port_scanning,
            self._check_successful_login_after_failures,
            self._check_suspicious_command,
        ]

        for rule in rules:
            try:
                alert = rule(event)
                if alert:
                    alerts.append(alert)
            except Exception as e:
                print(f"[Detection] Rule {rule.__name__} failed: {e}")

        return alerts

    # ===== Individual Rules =====

    def _check_ssh_brute_force(
        self,
        event: Event,
    ) -> Optional[AlertCreate]:
        """
        Rule AUTH-001:
        5 or more failed SSH logins within 60 seconds
        from the same source IP and host.
        """
        if event.event_type not in {"ssh_failed_login", "login_failed"}:
            return None

        event_time = event.timestamp or utc_now()
        cutoff = event_time - timedelta(seconds=60)

        recent_failures = (
            self.db.query(Event)
            .filter(
                Event.event_type.in_(["ssh_failed_login", "login_failed"]),
                Event.source_ip == event.source_ip,
                Event.timestamp >= cutoff,
                Event.timestamp <= event_time,
                Event.host == event.host,
            )
            .count()
        )

        if recent_failures >= 5:
            evidence_events = (
                self.db.query(Event)
                .filter(
                    Event.event_type.in_(["ssh_failed_login", "login_failed"]),
                    Event.source_ip == event.source_ip,
                    Event.timestamp >= cutoff,
                    Event.timestamp <= event_time,
                    Event.host == event.host,
                )
                .all()
            )

            evidence_ids = [e.id for e in evidence_events]

            return AlertCreate(
                alert_type="ssh_brute_force",
                severity=Severity.HIGH,
                mitre_technique=MITRE_MAPPING["ssh_brute_force"],
                source_ip=event.source_ip,
                target_host=event.host,
                description=(
                    f"SSH brute force detected from {event.source_ip}"
                ),
                evidence=evidence_ids,
                confidence=0.9,
            )

        return None

    def _check_port_scanning(
        self,
        event: Event,
    ) -> Optional[AlertCreate]:
        """
        Rule NET-001:
        3 or more port-scan attempts within 30 seconds
        from the same source IP.
        """
        raw = (event.raw_event or "").lower()

        if event.event_type != "port_scan" and "port scan" not in raw:
            return None

        event_time = event.timestamp or utc_now()
        cutoff = event_time - timedelta(seconds=30)

        recent_attempts = (
            self.db.query(Event)
            .filter(
                (
                    (Event.event_type == "port_scan")
                    | (Event.raw_event.ilike("%port scan%"))
                ),
                Event.source_ip == event.source_ip,
                Event.timestamp >= cutoff,
                Event.timestamp <= event_time,
            )
            .count()
        )

        if recent_attempts >= 3:
            evidence_events = (
                self.db.query(Event)
                .filter(
                    (
                        (Event.event_type == "port_scan")
                        | (Event.raw_event.ilike("%port scan%"))
                    ),
                    Event.source_ip == event.source_ip,
                    Event.timestamp >= cutoff,
                    Event.timestamp <= event_time,
                )
                .all()
            )

            evidence_ids = (
                [e.id for e in evidence_events]
                if evidence_events
                else [event.id]
            )

            return AlertCreate(
                alert_type="port_scanning",
                severity=Severity.MEDIUM,
                mitre_technique=MITRE_MAPPING["port_scanning"],
                source_ip=event.source_ip,
                target_host=event.host,
                description=(
                    f"Port scanning detected from {event.source_ip}"
                ),
                evidence=evidence_ids,
                confidence=0.7,
            )

        return None

    def _check_successful_login_after_failures(
        self,
        event: Event,
    ) -> Optional[AlertCreate]:
        """
        Rule AUTH-002:
        Successful login following 3 or more failed logins
        from the same source and host within 5 minutes.
        """
        if event.event_type not in {"ssh_success", "login_success"}:
            return None

        event_time = event.timestamp or utc_now()
        cutoff = event_time - timedelta(minutes=5)

        prior_failures = (
            self.db.query(Event)
            .filter(
                Event.event_type.in_(["ssh_failed_login", "login_failed"]),
                Event.source_ip == event.source_ip,
                Event.timestamp >= cutoff,
                Event.timestamp <= event_time,
                Event.host == event.host,
            )
            .count()
        )

        if prior_failures >= 3:
            return AlertCreate(
                alert_type="successful_login_after_failures",
                severity=Severity.HIGH,
                mitre_technique=MITRE_MAPPING[
                    "successful_login_after_failures"
                ],
                source_ip=event.source_ip,
                target_host=event.host,
                description=(
                    f"Successful login after {prior_failures} "
                    f"failures from {event.source_ip}"
                ),
                evidence=[event.id],
                confidence=0.8,
            )

        return None

    def _check_suspicious_command(
        self,
        event: Event,
    ) -> Optional[AlertCreate]:
        """Rule HOST-001: Known suspicious command patterns."""
        if event.event_type not in {"command_execution", "process_creation"}:
            return None

        suspicious_patterns = [
            "wget",
            "curl",
            "nc ",
            "netcat",
            "ncat",
            "bash -c",
            "sh -c",
            "python -c",
            "perl -e",
            "chmod +x",
            "chown",
            "rm -rf",
            "dd if=",
            "mkfifo",
            "socat",
            "nmap",
            "masscan",
            "nc -e",
            "reverse shell",
            "base64 -d",
        ]

        raw = (event.raw_event or "").lower()

        if any(pattern in raw for pattern in suspicious_patterns):
            return AlertCreate(
                alert_type="suspicious_command",
                severity=Severity.CRITICAL,
                mitre_technique=MITRE_MAPPING["suspicious_command"],
                source_ip=event.source_ip,
                target_host=event.host,
                description=(
                    f"Suspicious command executed on {event.host}: "
                    f"{(event.raw_event or '')[:100]}"
                ),
                evidence=[event.id],
                confidence=0.85,
            )

        return None


# ===== Standalone batch detection function =====

def detect_alerts(
    db,
    events: List[Event],
) -> List[AlertCreate]:
    """Run detection on a batch of events."""
    engine = DetectionEngine(db)

    all_alerts = []

    for event in events:
        alerts = engine.process_event(event)
        all_alerts.extend(alerts)

    return all_alerts
