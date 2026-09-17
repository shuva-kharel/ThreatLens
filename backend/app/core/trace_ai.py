from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.database import Incident, Alert, Event
from app.core.time import ensure_utc, utc_iso


UTC_MAX = datetime.max.replace(tzinfo=timezone.utc)


class TraceAI:
    """
    Reconstructs an incident into a coherent attack narrative.

    Timestamp policy:
    - Database timestamps are treated as UTC.
    - Correlation, sorting, and duration calculations stay in UTC.
    - Timestamps returned to API consumers are converted to Asia/Kathmandu.
    """

    STAGE_ORDER = [
        "Reconnaissance",
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Command and Control",
        "Exfiltration",
        "Impact",
        "Unknown",
    ]

    MITRE_TO_STAGE = {
        "T1046": "Reconnaissance",
        "T1110": "Credential Access",
        "T1078": "Initial Access",
        "T1059": "Execution",
        "T1068": "Privilege Escalation",
        "T1548": "Privilege Escalation",
        "T1003": "Credential Access",
        "T1021": "Lateral Movement",
        "T1071": "Command and Control",
        "T1105": "Command and Control",
        "T1041": "Exfiltration",
        "T1486": "Impact",
    }

    STAGE_DESCRIPTIONS = {
        "Reconnaissance": "The attacker performed scanning or reconnaissance activity against the environment.",
        "Initial Access": "The attacker obtained or attempted to obtain an initial foothold.",
        "Execution": "Commands, scripts, or other executable activity was observed.",
        "Persistence": "Activity indicating an attempt to maintain access was observed.",
        "Privilege Escalation": "Activity indicating an attempt to obtain higher privileges was observed.",
        "Defense Evasion": "Activity suggesting attempts to avoid or bypass security controls was observed.",
        "Credential Access": "Activity targeting credentials or authentication mechanisms was observed.",
        "Discovery": "The attacker appeared to gather information about the environment.",
        "Lateral Movement": "Activity suggesting movement between systems was observed.",
        "Collection": "The attacker appeared to gather data from the environment.",
        "Command and Control": "Activity consistent with communication to an external controller was observed.",
        "Exfiltration": "Activity suggesting data transfer out of the environment was observed.",
        "Impact": "Activity indicating an attempt to disrupt, damage, or encrypt resources was observed.",
        "Unknown": "The activity could not be mapped confidently to a specific attack stage.",
    }

    def __init__(self, db: Session):
        self.db = db

    # ------------------------------------------------------------------
    # Timestamp helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_timestamp(value: Any) -> Optional[datetime]:
        """
        Convert a datetime or ISO timestamp into a timezone-aware UTC datetime.

        Naive timestamps are treated as UTC because ThreatLens stores
        database timestamps as UTC-naive values.
        """
        if value is None:
            return None

        if isinstance(value, datetime):
            return ensure_utc(value)

        if isinstance(value, str):
            try:
                return ensure_utc(datetime.fromisoformat(value))
            except ValueError:
                return None

        return None

    @staticmethod
    def _sort_timestamp(value: Any) -> datetime:
        parsed = TraceAI._parse_timestamp(value)
        return parsed if parsed else UTC_MAX

    # ------------------------------------------------------------------
    # Main reconstruction
    # ------------------------------------------------------------------

    def reconstruct_incident(
        self,
        incident_id: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Reconstruct an incident into:
        - timeline
        - attack graph
        - attack stages
        - entities
        - duration
        - MITRE mapping
        """

        incident = (
            self.db.query(Incident)
            .filter(Incident.id == incident_id)
            .first()
        )

        if not incident:
            return None

        alerts = self._get_incident_alerts(incident)
        events = self._get_incident_events(incident, alerts)

        alerts = sorted(
            alerts,
            key=lambda a: self._sort_timestamp(a.created_at),
        )

        events = sorted(
            events,
            key=lambda e: self._sort_timestamp(e.timestamp),
        )

        timeline = self._build_timeline(events, alerts)
        attack_graph = self._build_attack_graph(
            incident,
            events,
            alerts,
        )
        stages = self._identify_stages(
            incident,
            events,
            alerts,
        )
        entities = self._extract_entities(
            incident,
            events,
            alerts,
        )
        duration = self._calculate_durations(
            incident,
            events,
            alerts,
        )

        return {
            "incident_id": incident.id,
            "title": incident.title,
            "severity": incident.severity,
            "confidence": incident.confidence,
            "status": incident.status,

            "first_seen": utc_iso(incident.first_seen),
            "last_seen": utc_iso(incident.last_seen),

            "duration_seconds": duration,

            "source_entities": incident.source_entities or [],
            "target_entities": incident.target_entities or [],
            "mitre_techniques": incident.mitre_techniques or [],

            "entities": entities,
            "timeline": timeline,
            "stages": stages,
            "attack_graph": attack_graph,

            "alert_count": len(alerts),
            "event_count": len(events),

            "attack_chain": incident.attack_chain or [],
        }

    # ------------------------------------------------------------------
    # Data retrieval
    # ------------------------------------------------------------------

    def _get_incident_alerts(
        self,
        incident: Incident,
    ) -> List[Alert]:
        """
        Retrieve alerts directly associated with the incident.

        Falls back to source-IP/timeline correlation for older incidents
        that may not have incident_id populated on their alerts.
        """

        alerts = (
            self.db.query(Alert)
            .filter(Alert.incident_id == incident.id)
            .all()
        )

        if alerts:
            return alerts

        source_ips = incident.source_entities or []

        if not source_ips:
            return []

        query = self.db.query(Alert).filter(
            Alert.source_ip.in_(source_ips)
        )

        if incident.first_seen and incident.last_seen:
            query = query.filter(
                Alert.created_at >= incident.first_seen,
                Alert.created_at <= incident.last_seen,
            )

        return query.all()

    def _get_incident_events(
        self,
        incident: Incident,
        alerts: List[Alert],
    ) -> List[Event]:
        """
        Retrieve events that contributed to the incident alerts.

        Falls back to source-IP/timeline matching if alert evidence
        is unavailable.
        """

        evidence_ids = set()

        for alert in alerts:
            if alert.evidence:
                evidence_ids.update(alert.evidence)

        if evidence_ids:
            events = (
                self.db.query(Event)
                .filter(Event.id.in_(list(evidence_ids)))
                .all()
            )

            if events:
                return events

        source_ips = incident.source_entities or []

        if not source_ips:
            return []

        query = self.db.query(Event).filter(
            Event.source_ip.in_(source_ips)
        )

        if incident.first_seen and incident.last_seen:
            query = query.filter(
                Event.timestamp >= incident.first_seen,
                Event.timestamp <= incident.last_seen,
            )

        return query.all()

    # ------------------------------------------------------------------
    # Timeline
    # ------------------------------------------------------------------

    def _build_timeline(
        self,
        events: List[Event],
        alerts: List[Alert],
    ) -> List[Dict[str, Any]]:
        timeline = []

        for event in events:
            timestamp = self._parse_timestamp(event.timestamp)

            timeline.append(
                {
                    "type": "event",
                    "id": event.id,
                    "timestamp": utc_iso(event.timestamp),
                    "host": event.host,
                    "source_ip": event.source_ip,
                    "event_type": event.event_type,
                    "username": event.username,
                    "severity": event.severity,
                    "telemetry_source": (event.normalized_data or {}).get("telemetry_source"),
                    "agent_id": (event.normalized_data or {}).get("agent_id"),
                    "description": (
                        event.normalized_data.get("description")
                        if isinstance(event.normalized_data, dict)
                        else None
                    ),
                    "_sort_timestamp": timestamp,
                }
            )

        for alert in alerts:
            timestamp = self._parse_timestamp(alert.created_at)

            timeline.append(
                {
                    "type": "alert",
                    "id": alert.id,
                    "timestamp": utc_iso(alert.created_at),
                    "alert_type": alert.alert_type,
                    "severity": alert.severity,
                    "mitre_technique": alert.mitre_technique,
                    "source_ip": alert.source_ip,
                    "target_host": alert.target_host,
                    "description": alert.description,
                    "confidence": alert.confidence,
                    "_sort_timestamp": timestamp,
                }
            )

        timeline.sort(
            key=lambda item: item["_sort_timestamp"] or UTC_MAX
        )

        for item in timeline:
            item.pop("_sort_timestamp", None)

        return timeline

    # ------------------------------------------------------------------
    # Attack graph
    # ------------------------------------------------------------------

    def _build_attack_graph(
        self,
        incident: Incident,
        events: List[Event],
        alerts: List[Alert],
    ) -> Dict[str, Any]:

        nodes = []
        edges = []

        node_ids = set()

        def add_node(
            node_id: str,
            node_type: str,
            label: str,
            metadata: Optional[Dict[str, Any]] = None,
        ):
            if node_id in node_ids:
                return

            node_ids.add(node_id)

            nodes.append(
                {
                    "id": node_id,
                    "type": node_type,
                    "label": label,
                    "metadata": metadata or {},
                }
            )

        def add_edge(
            source: str,
            target: str,
            relationship: str,
        ):
            edges.append(
                {
                    "source": source,
                    "target": target,
                    "relationship": relationship,
                }
            )

        source_entities = incident.source_entities or []
        target_entities = incident.target_entities or []

        for source in source_entities:
            source_id = f"source:{source}"

            add_node(
                source_id,
                "attacker",
                source,
            )

        for target in target_entities:
            target_id = f"target:{target}"

            add_node(
                target_id,
                "target",
                target,
            )

            for source in source_entities:
                add_edge(
                    f"source:{source}",
                    target_id,
                    "targets",
                )

        stage_first_seen: Dict[str, datetime] = {}

        for alert in alerts:
            stage = self._get_stage_from_alert(alert)

            timestamp = self._parse_timestamp(alert.created_at)

            if timestamp:
                current = stage_first_seen.get(stage)

                if current is None or timestamp < current:
                    stage_first_seen[stage] = timestamp

            stage_id = f"stage:{stage}"

            add_node(
                stage_id,
                "stage",
                stage,
                {
                    "description": self.STAGE_DESCRIPTIONS.get(
                        stage,
                        "",
                    ),
                    "mitre_technique": alert.mitre_technique,
                },
            )

            if alert.source_ip:
                add_edge(
                    f"source:{alert.source_ip}",
                    stage_id,
                    "performs",
                )

            if alert.target_host:
                add_edge(
                    stage_id,
                    f"target:{alert.target_host}",
                    "affects",
                )

            usernames = {
                event.username
                for event in events
                if (
                    event.username
                    and event.source_ip == alert.source_ip
                    and event.host == alert.target_host
                )
            }

            for username in usernames:
                user_id = f"user:{username}"

                add_node(
                    user_id,
                    "user",
                    username,
                )

                add_edge(
                    stage_id,
                    user_id,
                    "targets_account",
                )

        ordered_stages = sorted(
            stage_first_seen.keys(),
            key=lambda stage: (
                stage_first_seen.get(stage, UTC_MAX),
                self.STAGE_ORDER.index(stage)
                if stage in self.STAGE_ORDER
                else len(self.STAGE_ORDER),
            ),
        )

        for first_stage, second_stage in zip(
            ordered_stages,
            ordered_stages[1:],
        ):
            add_edge(
                f"stage:{first_stage}",
                f"stage:{second_stage}",
                "follows",
            )

        return {
            "nodes": nodes,
            "edges": edges,
        }

    # ------------------------------------------------------------------
    # Attack stages
    # ------------------------------------------------------------------

    def _identify_stages(
        self,
        incident: Incident,
        events: List[Event],
        alerts: List[Alert],
    ) -> List[Dict[str, Any]]:

        stage_data: Dict[str, Dict[str, Any]] = {}

        def ensure_stage(stage: str):
            if stage not in stage_data:
                stage_data[stage] = {
                    "stage": stage,
                    "description": self.STAGE_DESCRIPTIONS.get(
                        stage,
                        "",
                    ),
                    "mitre_techniques": [],
                    "_first_seen_dt": None,
                    "_last_seen_dt": None,
                }

        def update_stage(
            stage: str,
            timestamp: Any,
            mitre: Optional[str] = None,
        ):
            ensure_stage(stage)

            parsed = self._parse_timestamp(timestamp)

            if parsed:
                current_first = stage_data[stage]["_first_seen_dt"]
                current_last = stage_data[stage]["_last_seen_dt"]

                if current_first is None or parsed < current_first:
                    stage_data[stage]["_first_seen_dt"] = parsed

                if current_last is None or parsed > current_last:
                    stage_data[stage]["_last_seen_dt"] = parsed

            if mitre:
                if mitre not in stage_data[stage]["mitre_techniques"]:
                    stage_data[stage]["mitre_techniques"].append(mitre)

        for alert in alerts:
            stage = self._get_stage_from_alert(alert)

            update_stage(
                stage,
                alert.created_at,
                alert.mitre_technique,
            )

        for event in events:
            stage = self._get_stage_from_event(event)

            update_stage(
                stage,
                event.timestamp,
                self._get_mitre_from_event(event),
            )

        # Existing attack-chain data is used as an additional source.
        for chain_item in incident.attack_chain or []:
            if not isinstance(chain_item, dict):
                continue

            stage = chain_item.get("stage") or "Unknown"

            update_stage(
                stage,
                chain_item.get("timestamp"),
                chain_item.get("technique_id"),
            )

        stages = list(stage_data.values())

        stages.sort(
            key=lambda stage: (
                stage["_first_seen_dt"] or UTC_MAX,
                self.STAGE_ORDER.index(stage["stage"])
                if stage["stage"] in self.STAGE_ORDER
                else len(self.STAGE_ORDER),
            )
        )

        result = []

        for index, stage in enumerate(stages, start=1):
            first_seen = stage.pop("_first_seen_dt", None)
            last_seen = stage.pop("_last_seen_dt", None)

            stage["order"] = index

            stage["first_seen"] = utc_iso(first_seen)
            stage["last_seen"] = utc_iso(last_seen)

            result.append(stage)

        return result

    # ------------------------------------------------------------------
    # Entity extraction
    # ------------------------------------------------------------------

    def _extract_entities(
        self,
        incident: Incident,
        events: List[Event],
        alerts: List[Alert],
    ) -> Dict[str, List[str]]:

        source_ips = set(incident.source_entities or [])
        target_hosts = set(incident.target_entities or [])
        usernames = set()

        for event in events:
            if event.source_ip:
                source_ips.add(event.source_ip)

            if event.host:
                target_hosts.add(event.host)

            if event.username:
                usernames.add(event.username)

        for alert in alerts:
            if alert.source_ip:
                source_ips.add(alert.source_ip)

            if alert.target_host:
                target_hosts.add(alert.target_host)

        return {
            "source_ips": sorted(source_ips),
            "target_hosts": sorted(target_hosts),
            "usernames": sorted(usernames),
        }

    # ------------------------------------------------------------------
    # Stage classification
    # ------------------------------------------------------------------

    def _get_stage_from_event(self, event: Event) -> str:
        event_type = (event.event_type or "").lower()

        normalized = event.normalized_data or {}

        text_parts = [
            event_type,
            event.raw_event or "",
        ]

        if isinstance(normalized, dict):
            text_parts.extend(
                str(value)
                for value in normalized.values()
            )

        text = " ".join(text_parts).lower()

        if any(
            value in text
            for value in [
                "port_scan",
                "port scan",
                "network_scan",
                "network scan",
                "scan",
            ]
        ):
            return "Reconnaissance"

        if any(
            value in text
            for value in [
                "failed_login",
                "failed login",
                "authentication_failure",
                "auth failure",
                "brute_force",
                "brute force",
            ]
        ):
            return "Credential Access"

        if any(
            value in text
            for value in [
                "successful_login",
                "successful login",
                "login_success",
                "login success",
            ]
        ):
            return "Initial Access"

        if any(
            value in text
            for value in [
                "privilege_escalation",
                "privilege escalation",
                "sudo",
                "root",
            ]
        ):
            return "Privilege Escalation"

        if any(
            value in text
            for value in [
                "credential_dump",
                "credential dumping",
                "password_dump",
                "lsass",
            ]
        ):
            return "Credential Access"

        if any(
            value in text
            for value in [
                "c2",
                "command_and_control",
                "beacon",
                "beaconing",
            ]
        ):
            return "Command and Control"

        if any(
            value in text
            for value in [
                "command",
                "powershell",
                "shell",
                "exec",
                "execution",
            ]
        ):
            return "Execution"

        return "Unknown"

    def _get_stage_from_alert(self, alert: Alert) -> str:
        alert_type = (alert.alert_type or "").lower()
        description = (alert.description or "").lower()

        if alert.mitre_technique:
            mitre_stage = self.MITRE_TO_STAGE.get(
                alert.mitre_technique
            )

            if mitre_stage:
                return mitre_stage

        if "port_scan" in alert_type:
            return "Reconnaissance"

        if "scan" in description:
            return "Reconnaissance"

        if "brute_force" in alert_type:
            return "Credential Access"

        if "successful_login" in alert_type:
            return "Initial Access"

        if "suspicious_command" in alert_type:
            return "Execution"

        if "privilege" in alert_type:
            return "Privilege Escalation"

        if "escalation" in description:
            return "Privilege Escalation"

        if "credential" in alert_type:
            return "Credential Access"

        if "c2" in alert_type or "beacon" in alert_type:
            return "Command and Control"

        return "Unknown"

    # ------------------------------------------------------------------
    # MITRE
    # ------------------------------------------------------------------

    def _get_mitre_from_event(
        self,
        event: Event,
    ) -> Optional[str]:

        text = " ".join(
            [
                event.event_type or "",
                event.raw_event or "",
            ]
        ).lower()

        if isinstance(event.normalized_data, dict):
            text += " " + " ".join(
                str(value)
                for value in event.normalized_data.values()
            ).lower()

        if "scan" in text:
            return "T1046"

        if (
            "failed_login" in text
            or "brute_force" in text
            or "brute force" in text
        ):
            return "T1110"

        if (
            "successful_login" in text
            or "login_success" in text
        ):
            return "T1078"

        if (
            "powershell" in text
            or "command" in text
            or "shell" in text
        ):
            return "T1059"

        if (
            "privilege" in text
            or "sudo" in text
        ):
            return "T1068"

        if (
            "credential_dump" in text
            or "credential dumping" in text
            or "lsass" in text
        ):
            return "T1003"

        return None

    # ------------------------------------------------------------------
    # Duration
    # ------------------------------------------------------------------

    def _calculate_durations(
        self,
        incident: Incident,
        events: List[Event],
        alerts: List[Alert],
    ) -> float:

        timestamps: List[datetime] = []

        if incident.first_seen:
            first = self._parse_timestamp(incident.first_seen)

            if first:
                timestamps.append(first)

        if incident.last_seen:
            last = self._parse_timestamp(incident.last_seen)

            if last:
                timestamps.append(last)

        for event in events:
            timestamp = self._parse_timestamp(event.timestamp)

            if timestamp:
                timestamps.append(timestamp)

        for alert in alerts:
            timestamp = self._parse_timestamp(alert.created_at)

            if timestamp:
                timestamps.append(timestamp)

        if len(timestamps) < 2:
            return 0.0

        return max(
            0.0,
            (
                max(timestamps) - min(timestamps)
            ).total_seconds(),
        )
