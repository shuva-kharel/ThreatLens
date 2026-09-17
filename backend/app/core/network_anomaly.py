from typing import List, Dict, Optional
from datetime import timedelta

from sqlalchemy.orm import Session

from app.models.database import Event
from app.core.time import utc_now


class NetworkAnomalyDetector:
    """Detects network anomalies from event data."""

    def __init__(self, db: Session):
        self.db = db

    def detect_port_scan(
        self,
        source_ip: str,
        window_seconds: int = 60,
    ) -> Optional[Dict]:
        """Detect port scanning activity."""
        cutoff = utc_now() - timedelta(seconds=window_seconds)

        events = (
            self.db.query(Event)
            .filter(
                Event.source_ip == source_ip,
                Event.timestamp >= cutoff,
            )
            .all()
        )

        if len(events) >= 10:
            targets = {e.host for e in events if e.host}

            return {
                "type": "port_scan",
                "source_ip": source_ip,
                "event_count": len(events),
                "unique_targets": len(targets),
                "targets": list(targets),
                "severity": "high" if len(events) > 50 else "medium",
                "mitre_technique": "T1046",
            }

        return None

    def detect_brute_force(
        self,
        source_ip: str,
        window_seconds: int = 60,
    ) -> Optional[Dict]:
        """Detect brute force authentication attempts."""
        cutoff = utc_now() - timedelta(seconds=window_seconds)

        events = (
            self.db.query(Event)
            .filter(
                Event.source_ip == source_ip,
                Event.timestamp >= cutoff,
                Event.event_type.like("%failed%"),
            )
            .all()
        )

        if len(events) >= 5:
            usernames = {
                e.username
                for e in events
                if e.username
            }

            return {
                "type": "brute_force",
                "source_ip": source_ip,
                "attempt_count": len(events),
                "targeted_users": list(usernames),
                "severity": (
                    "critical"
                    if len(events) > 20
                    else "high"
                ),
                "mitre_technique": "T1110",
            }

        return None

    def detect_beaconing(
        self,
        source_ip: str,
    ) -> Optional[Dict]:
        """Detect beaconing (regular callbacks to C2)."""
        cutoff = utc_now() - timedelta(hours=1)

        events = (
            self.db.query(Event)
            .filter(
                Event.source_ip == source_ip,
                Event.timestamp >= cutoff,
            )
            .order_by(Event.timestamp)
            .all()
        )

        if len(events) < 5:
            return None

        intervals = []

        for i in range(1, len(events)):
            delta = (
                events[i].timestamp
                - events[i - 1].timestamp
            ).total_seconds()

            intervals.append(delta)

        if not intervals:
            return None

        avg_interval = sum(intervals) / len(intervals)

        variance = (
            sum(
                (interval - avg_interval) ** 2
                for interval in intervals
            )
            / len(intervals)
        )

        if variance < 100 and 30 <= avg_interval <= 300:
            return {
                "type": "beaconing",
                "source_ip": source_ip,
                "avg_interval_seconds": avg_interval,
                "connection_count": len(events),
                "severity": "high",
                "mitre_technique": "T1071",
            }

        return None

    def detect_exfiltration(
        self,
        source_ip: str,
    ) -> Optional[Dict]:
        """Detect possible data exfiltration."""
        cutoff = utc_now() - timedelta(hours=1)

        events = (
            self.db.query(Event)
            .filter(
                Event.source_ip == source_ip,
                Event.timestamp >= cutoff,
                Event.event_type.like("%outbound%"),
            )
            .all()
        )

        if len(events) >= 10:
            return {
                "type": "possible_exfiltration",
                "source_ip": source_ip,
                "outbound_connections": len(events),
                "severity": "critical",
                "mitre_technique": "T1041",
            }

        return None

    def run_all_detections(self) -> List[Dict]:
        """Run all anomaly detections."""
        cutoff = utc_now() - timedelta(hours=1)

        sources = (
            self.db.query(Event.source_ip)
            .filter(
                Event.timestamp >= cutoff,
                Event.source_ip.isnot(None),
            )
            .distinct()
            .all()
        )

        anomalies = []

        detectors = [
            self.detect_port_scan,
            self.detect_brute_force,
            self.detect_beaconing,
            self.detect_exfiltration,
        ]

        for (source_ip,) in sources:
            if not source_ip:
                continue

            for detector in detectors:
                result = detector(source_ip)

                if result:
                    anomalies.append(result)

        return anomalies
