from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from app.models.database import Alert, Incident, Severity, IncidentStatus
from app.models.schemas import IncidentCreate, AttackStage
import uuid

class CorrelationEngine:
    def __init__(self, db_session):
        self.db = db_session
        self.CORRELATION_WINDOW = 600  # 10 minutes
        self.ATTACK_STAGES = {
            "port_scanning": {"stage": "Reconnaissance", "order": 1},
            "ssh_brute_force": {"stage": "Credential Access", "order": 2},
            "successful_login_after_failures": {"stage": "Initial Access", "order": 3},
            "suspicious_command": {"stage": "Execution", "order": 4},
            "unusual_process": {"stage": "Execution", "order": 5},
        }

    def correlate_alerts(self, alerts: List[Alert]) -> List[Incident]:
        """Correlate alerts into incidents."""
        if not alerts:
            return []

        incidents = []

        # Group alerts by (source_ip, target_host)
        groups = self._group_alerts(alerts)

        for group_key, group_alerts in groups.items():
            source, target = group_key

            # Sort by timestamp
            sorted_alerts = sorted(group_alerts, key=lambda a: a.created_at)

            # Check if alerts form a coherent sequence
            if self._is_coherent_sequence(sorted_alerts):
                incident = self._create_incident(source, target, sorted_alerts)
                incidents.append(incident)
            else:
                # Create separate incidents for unrelated alerts
                for alert in sorted_alerts:
                    incident = self._create_single_incident(alert)
                    incidents.append(incident)

        return incidents

    def _group_alerts(self, alerts: List[Alert]) -> Dict:
        """Group alerts by (source_ip, target_host)."""
        groups = {}
        for alert in alerts:
            key = (alert.source_ip, alert.target_host)
            if key not in groups:
                groups[key] = []
            groups[key].append(alert)
        return groups

    def _is_coherent_sequence(self, alerts: List[Alert]) -> bool:
        """Check if alerts form a logical attack sequence."""
        if len(alerts) < 2:
            return False

        # Check time proximity
        time_span = (alerts[-1].created_at - alerts[0].created_at).total_seconds()
        if time_span > self.CORRELATION_WINDOW:
            return False

        # Check if alert types follow a logical order
        alert_types = [a.alert_type for a in alerts]

        # Look for expected sequences (recon -> credential -> execution)
        stage_order = []
        for alert_type in alert_types:
            if alert_type in self.ATTACK_STAGES:
                stage_order.append(self.ATTACK_STAGES[alert_type]["order"])

        # Check if stages are generally increasing
        return all(stage_order[i] <= stage_order[i+1] for i in range(len(stage_order)-1))

    def _create_incident(self, source: str, target: str, alerts: List[Alert]) -> Incident:
        """Create an incident from a group of correlated alerts."""
        # Determine severity (max of alerts)
        severity = max([a.severity for a in alerts], key=lambda s: ["low","medium","high","critical"].index(s.value))

        # Build attack chain
        attack_chain = []
        seen_stages = set()
        for alert in alerts:
            if alert.alert_type in self.ATTACK_STAGES:
                stage_info = self.ATTACK_STAGES[alert.alert_type]
                if stage_info["stage"] not in seen_stages:
                    attack_chain.append(AttackStage(
                        stage=stage_info["stage"],
                        description=f"{alert.alert_type.replace('_', ' ').title()} from {alert.source_ip}",
                        timestamp=alert.created_at,
                        technique_id=alert.mitre_technique
                    ))
                    seen_stages.add(stage_info["stage"])

        # Calculate confidence
        confidence = self._calculate_confidence(alerts, attack_chain)

        # Collect MITRE techniques
        mitre_techniques = list(set([a.mitre_technique for a in alerts if a.mitre_technique]))

        return IncidentCreate(
            title=f"Attack from {source} to {target}",
            severity=Severity(severity),
            confidence=confidence,
            source_entities=[source],
            target_entities=[target],
            attack_chain=attack_chain,
            mitre_techniques=mitre_techniques,
            first_seen=alerts[0].created_at,
            last_seen=alerts[-1].created_at
        )

    def _create_single_incident(self, alert: Alert) -> Incident:
        """Create an incident from a single alert."""
        return IncidentCreate(
            title=f"{alert.alert_type.replace('_', ' ').title()} from {alert.source_ip}",
            severity=Severity(alert.severity),
            confidence=alert.confidence,
            source_entities=[alert.source_ip] if alert.source_ip else [],
            target_entities=[alert.target_host] if alert.target_host else [],
            attack_chain=[AttackStage(
                stage="Unknown",
                description=alert.description,
                timestamp=alert.created_at,
                technique_id=alert.mitre_technique
            )],
            mitre_techniques=[alert.mitre_technique] if alert.mitre_technique else [],
            first_seen=alert.created_at,
            last_seen=alert.created_at
        )

    def _calculate_confidence(self, alerts: List[Alert], attack_chain: List[AttackStage]) -> float:
        """Calculate confidence score for an incident."""
        confidence = 0.0

        # Factor 1: Number of alerts
        confidence += min(len(alerts) * 0.1, 0.4)

        # Factor 2: Completeness of attack chain
        if attack_chain:
            confidence += min(len(attack_chain) * 0.12, 0.5)

        # Factor 3: High severity alerts
        high_severity_count = sum(1 for a in alerts if a.severity in [Severity.HIGH, Severity.CRITICAL])
        confidence += min(high_severity_count * 0.05, 0.2)

        return min(confidence, 1.0)