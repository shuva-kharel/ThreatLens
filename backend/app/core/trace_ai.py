from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_
from app.models.database import Incident, Alert, Event


class TraceAI:
    """Reconstructs attack timelines, builds attack graphs, and identifies attack stages."""

    # Attack stage ordering (higher = later in kill chain)
    STAGE_ORDER = {
        "Unknown": 0,
        "Reconnaissance": 1,
        "Port Scanning": 1,
        "Weaponization": 2,
        "Credential Access": 2,
        "SSH Brute Force": 2,
        "Initial Access": 3,
        "Successful Login": 3,
        "Execution": 4,
        "Command Execution": 4,
        "Persistence": 5,
        "Privilege Escalation": 5,
        "Defense Evasion": 6,
        "Credential Dumping": 6,
        "Discovery": 7,
        "Lateral Movement": 8,
        "Collection": 9,
        "Command & Control": 10,
        "Exfiltration": 11,
        "Impact": 12
    }

    # MITRE technique to kill chain stage
    MITRE_TO_STAGE = {
        "T1046": "Reconnaissance",
        "T1595": "Reconnaissance",
        "T1110": "Credential Access",
        "T1078": "Initial Access",
        "T1190": "Initial Access",
        "T1059": "Execution",
        "T1053": "Persistence",
        "T1548": "Privilege Escalation",
        "T1068": "Privilege Escalation",
        "T1003": "Credential Dumping",
        "T1087": "Discovery",
        "T1021": "Lateral Movement",
        "T1071": "Command & Control",
        "T1041": "Exfiltration",
        "T1486": "Impact"
    }

    # Stage descriptions for timeline
    STAGE_DESCRIPTIONS = {
        "Reconnaissance": "Attacker gathers information about the target",
        "Credential Access": "Attacker attempts to obtain credentials",
        "Initial Access": "Attacker gains first foothold in the environment",
        "Execution": "Attacker executes malicious code",
        "Persistence": "Attacker establishes persistence mechanisms",
        "Privilege Escalation": "Attacker attempts to gain higher privileges",
        "Defense Evasion": "Attacker attempts to avoid detection",
        "Credential Dumping": "Attacker extracts credentials from the system",
        "Discovery": "Attacker explores the environment",
        "Lateral Movement": "Attacker moves to other systems",
        "Collection": "Attacker collects data of interest",
        "Command & Control": "Attacker communicates with compromised system",
        "Exfiltration": "Attacker extracts data from the environment",
        "Impact": "Attacker disrupts or destroys systems"
    }

    def __init__(self, db: Session):
        self.db = db

    def reconstruct_incident(self, incident_id: str) -> Dict[str, Any]:
        """Reconstruct the full attack timeline for an incident."""
        incident = self.db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            return {"error": "Incident not found"}

        # Filter alerts belonging to incident within incident timeline
        alerts = self._get_incident_alerts(incident)

        # Filter events belonging to incident strictly within incident timeline
        events = self._get_incident_events(incident, alerts)

        # Sort by timestamp
        events.sort(key=lambda e: e.timestamp or datetime.min)
        alerts.sort(key=lambda a: a.created_at or datetime.min)

        # Build components
        timeline = self._build_timeline(events, alerts)
        attack_graph = self._build_attack_graph(events, alerts, incident)
        stages = self._identify_stages(events, alerts, incident)
        entities = self._extract_entities(events, alerts, incident)

        durations = self._calculate_durations(incident)

        return {
            "incident_id": incident_id,
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status,
            "confidence": incident.confidence,
            "timeline": timeline,
            "attack_graph": attack_graph,
            "stages": stages,
            "entities": entities,
            "mitre_techniques": incident.mitre_techniques or [],
            "event_count": len(events),
            "alert_count": len(alerts),
            "first_seen": incident.first_seen.isoformat() if incident.first_seen else None,
            "last_seen": incident.last_seen.isoformat() if incident.last_seen else None,
            "duration_seconds": durations["duration_seconds"],
            "duration_minutes": durations["duration_minutes"]
        }

    def _get_incident_alerts(self, incident: Incident) -> List[Alert]:
        """Get all alerts for an incident strictly within its timeline."""
        # Primary: Get alerts linked via incident_id
        alerts = self.db.query(Alert).filter(
            Alert.incident_id == incident.id
        ).all()

        # Fallback: Get alerts by matching source IP within incident timeline
        if not alerts and incident.source_entities:
            for source_ip in incident.source_entities:
                query = self.db.query(Alert).filter(Alert.source_ip == source_ip)
                if incident.first_seen:
                    query = query.filter(Alert.created_at >= incident.first_seen)
                if incident.last_seen:
                    query = query.filter(Alert.created_at <= incident.last_seen)
                fallback_alerts = query.all()
                alerts.extend(fallback_alerts)

        # Enforce boundary: alert must be within [first_seen, last_seen] if set
        filtered_alerts = []
        for a in alerts:
            if a.created_at:
                if incident.first_seen and a.created_at < incident.first_seen:
                    continue
                if incident.last_seen and a.created_at > incident.last_seen:
                    continue
            filtered_alerts.append(a)

        return list({a.id: a for a in filtered_alerts}.values())

    def _get_incident_events(self, incident: Incident, alerts: List[Alert]) -> List[Event]:
        """Get all events related to an incident strictly within its timeline [first_seen, last_seen]."""
        events = []
        event_ids = set()

        # Primary: Get events via alert evidence
        for alert in alerts:
            if alert.evidence:
                for event_id in alert.evidence:
                    if event_id not in event_ids:
                        event = self.db.query(Event).filter(Event.id == event_id).first()
                        if event:
                            events.append(event)
                            event_ids.add(event_id)

        # Fallback / Correlated: Get events by source IP within incident timeline
        if incident.source_entities:
            for source_ip in incident.source_entities:
                query = self.db.query(Event).filter(Event.source_ip == source_ip)
                if incident.first_seen:
                    query = query.filter(Event.timestamp >= incident.first_seen)
                if incident.last_seen:
                    query = query.filter(Event.timestamp <= incident.last_seen)
                correlated_events = query.all()
                for e in correlated_events:
                    if e.id not in event_ids:
                        events.append(e)
                        event_ids.add(e.id)

        # Enforce strict boundary: event.timestamp >= first_seen and <= last_seen
        filtered_events = []
        for e in events:
            if e.timestamp:
                if incident.first_seen and e.timestamp < incident.first_seen:
                    continue
                if incident.last_seen and e.timestamp > incident.last_seen:
                    continue
            filtered_events.append(e)

        return list({e.id: e for e in filtered_events}.values())

    def _build_timeline(self, events: List[Event], alerts: List[Alert]) -> List[Dict]:
        """Build chronological timeline of the attack."""
        timeline = []

        for event in events:
            stage = self._get_stage_from_event(event)
            timeline.append({
                "id": event.id,
                "type": "event",
                "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                "event_type": event.event_type,
                "stage": stage,
                "source_ip": event.source_ip,
                "target_host": event.host,
                "username": event.username,
                "description": (event.raw_event or "")[:200],
                "severity": event.severity,
                "mitre_technique": self._get_mitre_from_event(event)
            })

        for alert in alerts:
            timeline.append({
                "id": alert.id,
                "type": "alert",
                "timestamp": alert.created_at.isoformat() if alert.created_at else None,
                "event_type": alert.alert_type,
                "stage": self._get_stage_from_alert(alert),
                "source_ip": alert.source_ip,
                "target_host": alert.target_host,
                "description": alert.description,
                "severity": alert.severity,
                "confidence": alert.confidence,
                "mitre_technique": alert.mitre_technique
            })

        timeline.sort(key=lambda x: x["timestamp"] or "")
        return timeline

    def _build_attack_graph(
        self,
        events: List[Event],
        alerts: List[Alert],
        incident: Incident
    ) -> Dict[str, Any]:
        """Build attack graph with nodes and edges."""
        nodes = []
        edges = []

        seen_nodes = set()
        seen_edges = set()

        # Attacker node(s)
        for ip in (incident.source_entities or []):
            node_id = f"attacker-{ip}"
            if node_id not in seen_nodes:
                nodes.append({
                    "id": node_id,
                    "type": "attacker",
                    "label": ip,
                    "data": {"ip": ip, "role": "attacker"}
                })
                seen_nodes.add(node_id)

        # Target node(s)
        for host in (incident.target_entities or []):
            node_id = f"target-{host}"
            if node_id not in seen_nodes:
                nodes.append({
                    "id": node_id,
                    "type": "target",
                    "label": host,
                    "data": {"host": host, "role": "target"}
                })
                seen_nodes.add(node_id)

        # Stage nodes - from alerts and correlated events
        stage_mitre_map = {}
        stage_first_seen_map = {}
        for alert in alerts:
            st = self._get_stage_from_alert(alert)
            if st and st != "Unknown":
                stage_mitre_map[st] = alert.mitre_technique
                ts = alert.created_at.isoformat() if alert.created_at else "9999"
                if st not in stage_first_seen_map or ts < stage_first_seen_map[st]:
                    stage_first_seen_map[st] = ts
        for event in events:
            st = self._get_stage_from_event(event)
            if st and st != "Unknown":
                if st not in stage_mitre_map:
                    stage_mitre_map[st] = self._get_mitre_from_event(event)
                ts = event.timestamp.isoformat() if event.timestamp else "9999"
                if st not in stage_first_seen_map or ts < stage_first_seen_map[st]:
                    stage_first_seen_map[st] = ts

        for stage, mitre_tech in stage_mitre_map.items():
            stage_id = f"stage-{stage.lower().replace(' ', '-')}"
            if stage_id not in seen_nodes:
                nodes.append({
                    "id": stage_id,
                    "type": "stage",
                    "label": stage,
                    "data": {
                        "stage": stage,
                        "mitre_technique": mitre_tech
                    }
                })
                seen_nodes.add(stage_id)

        # User nodes
        usernames = set(e.username for e in events if e.username)
        for username in usernames:
            node_id = f"user-{username}"
            if node_id not in seen_nodes:
                nodes.append({
                    "id": node_id,
                    "type": "user",
                    "label": username,
                    "data": {"username": username, "role": "user"}
                })
                seen_nodes.add(node_id)

        # Edges from attacker to targets
        for ip in (incident.source_entities or []):
            for host in (incident.target_entities or []):
                edge_id = f"edge-{ip}-{host}"
                if edge_id not in seen_edges:
                    edges.append({
                        "id": edge_id,
                        "source": f"attacker-{ip}",
                        "target": f"target-{host}",
                        "label": "attacked"
                    })
                    seen_edges.add(edge_id)

        # Edges from attacker to stages (in chronological order)
        stages_in_order = sorted(
            list(stage_mitre_map.keys()),
            key=lambda s: (stage_first_seen_map.get(s, "9999"), self.STAGE_ORDER.get(s, 99))
        )

        for ip in (incident.source_entities or []):
            for i, stage in enumerate(stages_in_order):
                stage_id = f"stage-{stage.lower().replace(' ', '-')}"
                edge_id = f"edge-{ip}-{stage}"
                if edge_id not in seen_edges:
                    edges.append({
                        "id": edge_id,
                        "source": f"attacker-{ip}",
                        "target": stage_id,
                        "label": f"stage-{i+1}"
                    })
                    seen_edges.add(edge_id)

        return {
            "nodes": nodes,
            "edges": edges,
            "node_count": len(nodes),
            "edge_count": len(edges)
        }

    def _identify_stages(
        self,
        events: List[Event],
        alerts: List[Alert],
        incident: Incident
    ) -> List[Dict]:
        """Identify attack stages with timing."""
        stage_data = {}

        # From alerts
        for alert in alerts:
            stage = self._get_stage_from_alert(alert)
            if stage and stage != "Unknown":
                if stage not in stage_data:
                    stage_data[stage] = {
                        "stage": stage,
                        "order": self.STAGE_ORDER.get(stage, 99),
                        "first_seen": alert.created_at.isoformat() if alert.created_at else None,
                        "last_seen": alert.created_at.isoformat() if alert.created_at else None,
                        "alert_types": [],
                        "mitre_techniques": [],
                        "event_count": 0
                    }
                stage_data[stage]["alert_types"].append(alert.alert_type)
                if alert.mitre_technique and alert.mitre_technique not in stage_data[stage]["mitre_techniques"]:
                    stage_data[stage]["mitre_techniques"].append(alert.mitre_technique)

        # From events
        for event in events:
            stage = self._get_stage_from_event(event)
            if stage and stage != "Unknown":
                if stage not in stage_data:
                    stage_data[stage] = {
                        "stage": stage,
                        "order": self.STAGE_ORDER.get(stage, 99),
                        "first_seen": event.timestamp.isoformat() if event.timestamp else None,
                        "last_seen": event.timestamp.isoformat() if event.timestamp else None,
                        "alert_types": [],
                        "mitre_techniques": [],
                        "event_count": 0
                    }
                stage_data[stage]["event_count"] += 1
                if event.timestamp:
                    ts = event.timestamp.isoformat()
                    if not stage_data[stage]["first_seen"] or ts < stage_data[stage]["first_seen"]:
                        stage_data[stage]["first_seen"] = ts
                    if not stage_data[stage]["last_seen"] or ts > stage_data[stage]["last_seen"]:
                        stage_data[stage]["last_seen"] = ts

        # From incident attack chain
        for chain_item in (incident.attack_chain or []):
            stage = chain_item.get("stage", "Unknown")
            if stage != "Unknown" and stage not in stage_data:
                stage_data[stage] = {
                    "stage": stage,
                    "order": self.STAGE_ORDER.get(stage, 99),
                    "first_seen": chain_item.get("timestamp"),
                    "last_seen": chain_item.get("timestamp"),
                    "alert_types": [],
                    "mitre_techniques": [chain_item.get("technique_id")] if chain_item.get("technique_id") else [],
                    "event_count": 0,
                    "description": self.STAGE_DESCRIPTIONS.get(stage, "")
                }

        # Convert to list and sort chronologically by first_seen, falling back to STAGE_ORDER
        stages = list(stage_data.values())
        stages.sort(key=lambda s: (s["first_seen"] or "9999", s.get("order", 99)))

        # Assign contiguous 1-based chronological order (1, 2, 3...)
        for idx, stage in enumerate(stages, start=1):
            stage["order"] = idx
            if "description" not in stage or not stage["description"]:
                stage["description"] = self.STAGE_DESCRIPTIONS.get(stage["stage"], "")

        return stages

    def _extract_entities(
        self,
        events: List[Event],
        alerts: List[Alert],
        incident: Incident
    ) -> Dict[str, List]:
        """Extract all entities from an incident."""
        entities = {
            "source_ips": set(incident.source_entities or []),
            "target_hosts": set(incident.target_entities or []),
            "usernames": set(),
            "event_types": set(),
            "alert_types": set(),
            "mitre_techniques": set(incident.mitre_techniques or [])
        }

        for event in events:
            if event.source_ip:
                entities["source_ips"].add(event.source_ip)
            if event.host:
                entities["target_hosts"].add(event.host)
            if event.username:
                entities["usernames"].add(event.username)
            if event.event_type:
                entities["event_types"].add(event.event_type)

        for alert in alerts:
            if alert.source_ip:
                entities["source_ips"].add(alert.source_ip)
            if alert.target_host:
                entities["target_hosts"].add(alert.target_host)
            if alert.alert_type:
                entities["alert_types"].add(alert.alert_type)
            if alert.mitre_technique:
                entities["mitre_techniques"].add(alert.mitre_technique)

        return {
            "source_ips": sorted(list(entities["source_ips"])),
            "target_hosts": sorted(list(entities["target_hosts"])),
            "usernames": sorted(list(entities["usernames"])),
            "event_types": sorted(list(entities["event_types"])),
            "alert_types": sorted(list(entities["alert_types"])),
            "mitre_techniques": sorted(list(entities["mitre_techniques"]))
        }

    def _get_stage_from_event(self, event: Event) -> str:
        """Determine attack stage from a single event."""
        event_type = (event.event_type or "").lower()
        raw = (event.raw_event or "").lower()

        # Port scanning / reconnaissance (T1046) - check event_type first
        if event_type == "port_scan" or "port scan" in raw or "syn sweep" in raw:
            return "Reconnaissance"

        # Failed authentication / brute force (T1110)
        if event_type == "ssh_failed_login" or "failed password" in raw or ("failed" in event_type and "ssh" in event_type):
            return "Credential Access"

        # Successful login (T1078)
        if event_type == "ssh_success" or "accepted password" in raw or ("success" in event_type and "ssh" in event_type):
            return "Initial Access"

        # Privilege escalation (T1548 / T1068)
        if "sudo" in raw or "privilege" in raw or "su -" in raw or "su " in raw:
            return "Privilege Escalation"

        # Credential dumping (T1003)
        if "shadow" in raw or "passwd" in raw or "mimikatz" in raw:
            return "Credential Dumping"

        # C2 (T1071)
        if "reverse shell" in raw or ("nc " in raw and "-e" in raw) or "malicious.com 4444" in raw:
            return "Command & Control"

        # General command execution (T1059)
        if event_type == "command_execution" or "wget" in raw or "curl" in raw or "bash" in raw or "sh" in raw:
            return "Execution"

        # Other generic checks
        if "scan" in raw or "probe" in raw:
            return "Reconnaissance"
        if "failed" in event_type or "failed" in raw:
            return "Credential Access"
        if "success" in event_type or "accepted" in raw:
            return "Initial Access"

        return "Unknown"

    def _get_stage_from_alert(self, alert: Alert) -> str:
        """Determine attack stage from an alert."""
        alert_type = (alert.alert_type or "").lower()

        # Try MITRE first
        if alert.mitre_technique:
            if alert.mitre_technique in self.MITRE_TO_STAGE:
                return self.MITRE_TO_STAGE[alert.mitre_technique]

        # Fall back to alert type
        if "port_scan" in alert_type:
            return "Reconnaissance"
        elif "brute_force" in alert_type:
            return "Credential Access"
        elif "successful_login" in alert_type:
            return "Initial Access"
        elif "suspicious_command" in alert_type:
            return "Execution"
        elif "privilege" in alert_type:
            return "Privilege Escalation"
        elif "exfiltration" in alert_type:
            return "Exfiltration"

        return "Unknown"

    def _get_mitre_from_event(self, event: Event) -> Optional[str]:
        """Get MITRE technique from an event."""
        event_type = (event.event_type or "").lower()
        if event_type == "port_scan":
            return "T1046"
        elif event_type == "ssh_failed_login":
            return "T1110"
        elif event_type == "ssh_success":
            return "T1078"
        elif event_type == "command_execution":
            stage = self._get_stage_from_event(event)
            if stage == "Privilege Escalation":
                return "T1548"
            elif stage == "Credential Dumping":
                return "T1003"
            elif stage == "Command & Control":
                return "T1071"
            return "T1059"

        stage = self._get_stage_from_event(event)
        for technique, mapped_stage in self.MITRE_TO_STAGE.items():
            if mapped_stage == stage:
                return technique
        return None

    def _calculate_durations(self, incident: Incident) -> Dict[str, Optional[float]]:
        """Calculate incident duration in seconds and minutes."""
        if incident.first_seen and incident.last_seen:
            delta = incident.last_seen - incident.first_seen
            seconds = round(delta.total_seconds(), 3)
            minutes = round(seconds / 60.0, 3)
            return {
                "duration_seconds": seconds,
                "duration_minutes": minutes
            }
        return {
            "duration_seconds": None,
            "duration_minutes": None
        }