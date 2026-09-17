from typing import List

from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.config import settings
from app.core.detection import DetectionEngine
from app.core.time import ensure_utc, utc_iso, utc_now
from app.models.database import Event, Alert, Incident
from app.models.schemas import EventCreate
from app.services.response_service import ResponseService
from app.services.recurrence_service import RecurrenceService


class EventBatch(BaseModel):
    events: List[EventCreate]


class EventService:
    """
    Main event ingestion and processing service.

    Flow:

        Event
          ↓
        Detection
          ↓
        Alert
          ↓
        Correlation
          ↓
        Incident
          ↓
        WebSocket broadcast
    """

    def __init__(self, db: Session):
        self.db = db

        # DetectionEngine requires the database session.
        self.detection_engine = DetectionEngine(db)

    # =========================================================================
    # HELPERS
    # =========================================================================

    @staticmethod
    def _enum_or_value(value):
        """
        Safely handle both Enum instances and plain strings.

        Examples:

            Severity.HIGH -> "high"
            "high"        -> "high"
            None          -> None
        """

        if value is None:
            return None

        return getattr(value, "value", value)

    # =========================================================================
    # EVENT CREATION
    # =========================================================================

    def create_event(
        self,
        event_data: EventCreate,
    ) -> Event:
        """
        Create a database Event from EventCreate.

        Legacy naive input timestamps are interpreted as UTC.
        """

        severity = self._enum_or_value(
            event_data.severity
        )

        event = Event(
            timestamp=ensure_utc(event_data.timestamp),
            host=event_data.host,
            source_ip=event_data.source_ip,
            event_type=event_data.event_type,
            username=event_data.username,
            severity=severity,
            raw_event=event_data.raw_event,
            normalized_data=event_data.normalized_data,
        )

        self.db.add(event)
        self.db.commit()
        self.db.refresh(event)

        return event

    # =========================================================================
    # SINGLE EVENT PROCESSING
    # =========================================================================

    def process_event(
        self,
        event_data: EventCreate,
    ):
        """
        Process a single event through detection and correlation.
        """

        event = self.create_event(event_data)
        self._broadcast_event(event)

        # ---------------------------------------------------------------------
        # Detection
        # ---------------------------------------------------------------------

        alerts = self.detection_engine.process_event(event)

        created_alerts = []
        correlated_incidents = []

        for alert_data in alerts:

            alert = self._create_alert(
                event=event,
                alert_data=alert_data,
            )

            created_alerts.append(alert)

            self._broadcast_alert(alert)

            # -----------------------------------------------------------------
            # Incident correlation
            # -----------------------------------------------------------------

            incident = self._create_incident_from_alert(
                alert=alert,
                event=event,
            )

            if incident:
                correlated_incidents.append(incident)
                self._broadcast_incident(incident)

        self.db.commit()

        escalations = []
        for incident_id in dict.fromkeys(
            incident.id for incident in correlated_incidents
        ):
            try:
                escalation = RecurrenceService(self.db).detect_and_escalate(
                    incident_id
                )
                if escalation:
                    escalations.append(escalation)
            except Exception as exc:
                print(
                    "[Recurrence] Escalation processing failed: "
                    f"{type(exc).__name__}: {exc}"
                )

        response_processing = []
        if settings.automatic_response_enabled:
            for incident_id in dict.fromkeys(
                incident.id for incident in correlated_incidents
            ):
                try:
                    outcome = ResponseService().process_incident(
                        self.db,
                        incident_id,
                        automatic=True,
                    )
                    response_processing.append(outcome)
                except Exception as exc:
                    # Response automation is deliberately isolated from the
                    # telemetry/detection/correlation transaction.
                    response_processing.append({
                        "incident_id": incident_id,
                        "status": "failed",
                        "failure": {
                            "stage": "orchestration",
                            "type": type(exc).__name__,
                            "message": str(exc),
                        },
                    })

        return {
            "event": event,
            "alerts": created_alerts,
            "alerts_created": len(created_alerts),
            "incidents": [
                self._serialize_incident(incident)
                for incident in correlated_incidents
            ],
            "incidents_created": len(correlated_incidents),
            "response_processing": response_processing,
            "escalations": escalations,
        }

    # =========================================================================
    # BATCH PROCESSING
    # =========================================================================

    def process_batch(
        self,
        batch: EventBatch,
    ):
        """
        Process multiple events.
        """

        results = []

        for event_data in batch.events:
            result = self.process_event(
                event_data
            )
            results.append(result)

        return results

    # =========================================================================
    # ALERT CREATION
    # =========================================================================

    def _create_alert(
        self,
        event: Event,
        alert_data,
    ):
        """
        Create an Alert from detection output.

        Alert timestamps are stored as UTC.
        """

        alert_created_at = utc_now()

        # ---------------------------------------------------------------------
        # Determine timestamp from evidence when available.
        # ---------------------------------------------------------------------

        evidence = getattr(
            alert_data,
            "evidence",
            None,
        )

        if evidence:

            evidence_ids = []

            for evidence_item in evidence:

                if isinstance(
                    evidence_item,
                    dict,
                ):

                    event_id = evidence_item.get(
                        "event_id"
                    )

                    if event_id:
                        evidence_ids.append(
                            event_id
                        )

                elif isinstance(
                    evidence_item,
                    str,
                ):

                    evidence_ids.append(
                        evidence_item
                    )

            if evidence_ids:

                evidence_events = (
                    self.db.query(Event)
                    .filter(
                        Event.id.in_(evidence_ids)
                    )
                    .all()
                )

                timestamps = [
                    ev.timestamp
                    for ev in evidence_events
                    if ev.timestamp
                ]

                if timestamps:
                    alert_created_at = min(
                        timestamps
                    )

        severity = self._enum_or_value(
            getattr(
                alert_data,
                "severity",
                None,
            )
        )

        alert = Alert(
            alert_type=alert_data.alert_type,
            description=alert_data.description,
            severity=severity,
            confidence=alert_data.confidence,
            mitre_technique=getattr(
                alert_data,
                "mitre_technique",
                None,
            ),
            evidence=evidence,
            source_ip=event.source_ip,
            target_host=event.host,
            incident_id=None,
            created_at=alert_created_at,
        )

        self.db.add(alert)
        self.db.flush()

        return alert

    # =========================================================================
    # INCIDENT CORRELATION
    # =========================================================================

    def _create_incident_from_alert(
        self,
        alert: Alert,
        event: Event,
    ):
        """
        Correlate an alert with an existing incident.

        If no suitable incident exists, create a new one.
        """

        alert_time = (
            alert.created_at
            or utc_now()
        )

        window_seconds = getattr(
            settings,
            "incident_correlation_window_seconds",
            300,
        )

        existing = None

        # ---------------------------------------------------------------------
        # Find active incident from same source IP.
        # ---------------------------------------------------------------------

        if event.source_ip:

            candidates = (
                self.db.query(Incident)
                .filter(
                    Incident.status.in_(
                        [
                            "open",
                            "investigating",
                            "contained",
                        ]
                    )
                )
                .order_by(
                    Incident.last_seen.desc()
                )
                .all()
            )

            for candidate in candidates:

                if not candidate.source_entities:
                    continue

                if (
                    event.source_ip
                    not in candidate.source_entities
                ):
                    continue

                if not candidate.last_seen:
                    continue

                gap = (
                    alert_time
                    - candidate.last_seen
                ).total_seconds()

                # Duplicate or delayed telemetry can produce an alert whose
                # evidence timestamp falls inside the incident interval.
                if (
                    candidate.first_seen
                    and candidate.first_seen
                    <= alert_time
                    <= candidate.last_seen
                ):
                    existing = candidate
                    break

                # Normal forward correlation.
                if (
                    0
                    <= gap
                    <= window_seconds
                ):
                    existing = candidate
                    break

                # Event has an earlier timestamp.
                if gap < 0:

                    if not candidate.first_seen:
                        continue

                    reverse_gap = (
                        candidate.first_seen
                        - alert_time
                    ).total_seconds()

                    if (
                        0
                        <= reverse_gap
                        <= window_seconds
                    ):
                        existing = candidate
                        break

        # ---------------------------------------------------------------------
        # Existing incident.
        # ---------------------------------------------------------------------

        if existing:

            self._update_incident(
                incident=existing,
                alert=alert,
                event=event,
            )

            alert.incident_id = existing.id

            self.db.flush()

            return existing

        # ---------------------------------------------------------------------
        # New incident.
        # ---------------------------------------------------------------------

        return self._create_new_incident(
            alert=alert,
            event=event,
        )

    # =========================================================================
    # UPDATE INCIDENT
    # =========================================================================

    def _update_incident(
        self,
        incident: Incident,
        alert: Alert,
        event: Event,
    ):
        """
        Add an alert/event to an existing incident.
        """

        alert_time = (
            alert.created_at
            or event.timestamp
            or utc_now()
        )

        # ---------------------------------------------------------------------
        # First / last seen
        # ---------------------------------------------------------------------

        if incident.first_seen is None:
            incident.first_seen = alert_time

        if incident.last_seen is None:
            incident.last_seen = alert_time

        else:

            if alert_time > incident.last_seen:
                incident.last_seen = alert_time

            if alert_time < incident.first_seen:
                incident.first_seen = alert_time

        # ---------------------------------------------------------------------
        # Source entities
        # ---------------------------------------------------------------------

        source_entities = list(
            incident.source_entities or []
        )

        if event.source_ip:

            if (
                event.source_ip
                not in source_entities
            ):
                source_entities.append(
                    event.source_ip
                )

        incident.source_entities = source_entities

        # ---------------------------------------------------------------------
        # Target entities
        # ---------------------------------------------------------------------

        target_entities = list(
            incident.target_entities or []
        )

        if event.host:

            if event.host not in target_entities:
                target_entities.append(
                    event.host
                )

        incident.target_entities = target_entities

        # ---------------------------------------------------------------------
        # MITRE ATT&CK
        # ---------------------------------------------------------------------

        mitre_techniques = list(
            incident.mitre_techniques or []
        )

        if alert.mitre_technique:

            if (
                alert.mitre_technique
                not in mitre_techniques
            ):
                mitre_techniques.append(
                    alert.mitre_technique
                )

        incident.mitre_techniques = (
            mitre_techniques
        )

        # ---------------------------------------------------------------------
        # Attack chain
        #
        # Stored timestamps remain UTC.
        # ---------------------------------------------------------------------

        attack_chain = list(
            incident.attack_chain or []
        )

        attack_chain.append(
            {
                "alert_id": alert.id,
                "alert_type": alert.alert_type,
                "timestamp": (
                    alert_time.isoformat()
                    if alert_time
                    else None
                ),
                "mitre_technique": (
                    alert.mitre_technique
                ),
            }
        )

        incident.attack_chain = attack_chain

        # ---------------------------------------------------------------------
        # Severity escalation
        # ---------------------------------------------------------------------

        severity_order = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }

        current_severity = (
            self._enum_or_value(
                incident.severity
            )
            or "medium"
        )

        alert_severity = (
            self._enum_or_value(
                alert.severity
            )
            or "medium"
        )

        if (
            severity_order.get(
                alert_severity,
                0,
            )
            > severity_order.get(
                current_severity,
                0,
            )
        ):
            incident.severity = alert_severity

        # ---------------------------------------------------------------------
        # Confidence
        # ---------------------------------------------------------------------

        if alert.confidence is not None:

            current_confidence = (
                incident.confidence
                or 0.0
            )

            incident.confidence = max(
                current_confidence,
                alert.confidence,
            )

        self.db.flush()

    # =========================================================================
    # CREATE NEW INCIDENT
    # =========================================================================

    def _create_new_incident(
        self,
        alert: Alert,
        event: Event,
    ):
        """
        Create a new incident from an alert.
        """

        alert_time = (
            alert.created_at
            or event.timestamp
            or utc_now()
        )

        severity = (
            self._enum_or_value(
                alert.severity
            )
            or "medium"
        )

        confidence = (
            alert.confidence
            if alert.confidence is not None
            else 0.0
        )

        # ---------------------------------------------------------------------
        # Source entities
        # ---------------------------------------------------------------------

        source_entities = []

        if event.source_ip:
            source_entities.append(
                event.source_ip
            )

        # ---------------------------------------------------------------------
        # Target entities
        # ---------------------------------------------------------------------

        target_entities = []

        if event.host:
            target_entities.append(
                event.host
            )

        # ---------------------------------------------------------------------
        # MITRE techniques
        # ---------------------------------------------------------------------

        mitre_techniques = []

        if alert.mitre_technique:
            mitre_techniques.append(
                alert.mitre_technique
            )

        # ---------------------------------------------------------------------
        # Attack chain
        # ---------------------------------------------------------------------

        attack_chain = [
            {
                "alert_id": alert.id,
                "alert_type": alert.alert_type,
                "timestamp": (
                    alert_time.isoformat()
                    if alert_time
                    else None
                ),
                "mitre_technique": (
                    alert.mitre_technique
                ),
            }
        ]

        incident = Incident(
            title=(
                f"{alert.alert_type} "
                f"detected on {event.host}"
            ),
            severity=severity,
            status="open",
            confidence=confidence,
            source_entities=source_entities,
            target_entities=target_entities,
            attack_chain=attack_chain,
            mitre_techniques=mitre_techniques,
            first_seen=alert_time,
            last_seen=alert_time,
            resolved_at=None,
            ai_summary=None,
            recommendations=[],
        )

        self.db.add(incident)
        self.db.flush()

        # Associate alert with incident.
        alert.incident_id = incident.id

        self.db.flush()

        return incident

    # =========================================================================
    # BROADCAST EVENT
    # =========================================================================

    def _broadcast_event(self, event: Event):
        try:
            from app.api.websocket import manager
            manager.broadcast_sync({
                "type": "event",
                "data": {
                    "id": event.id,
                    "event_type": event.event_type,
                    "source_ip": event.source_ip,
                    "host": event.host,
                    "severity": event.severity,
                    "timestamp": utc_iso(event.timestamp),
                },
            })
        except Exception as exc:
            print(f"[EventService] Event broadcast error: {exc}")

    # =========================================================================
    # BROADCAST ALERT
    # =========================================================================

    def _broadcast_alert(
        self,
        alert: Alert,
    ):
        """
        Broadcast alert to connected WebSocket clients.
        """

        try:

            from app.api.websocket import manager

            payload = {
                "type": "alert",
                "data": {
                    "id": alert.id,
                    "alert_type": alert.alert_type,
                    "description": alert.description,

                    "severity": self._enum_or_value(
                        alert.severity
                    ),

                    "confidence": alert.confidence,

                    "mitre_technique": (
                        alert.mitre_technique
                    ),

                    "source_ip": alert.source_ip,
                    "target_host": alert.target_host,
                    "incident_id": alert.incident_id,

                    "created_at": utc_iso(
                        alert.created_at
                    ),
                },
            }

            manager.broadcast_sync(
                payload
            )

        except Exception as e:

            print(
                "[EventService] "
                f"Alert broadcast error: {e}"
            )

    # =========================================================================
    # BROADCAST INCIDENT
    # =========================================================================

    def _broadcast_incident(
        self,
        incident: Incident,
    ):
        """
        Broadcast incident update to connected clients.
        """

        try:

            from app.api.websocket import manager

            payload = {
                "type": "incident",
                "data": self._serialize_incident(
                    incident
                ),
            }

            manager.broadcast_sync(
                payload
            )

        except Exception as e:

            print(
                "[EventService] "
                f"Incident broadcast error: {e}"
            )

    # =========================================================================
    # INCIDENT SERIALIZATION
    # =========================================================================

    def _serialize_incident(
        self,
        incident: Incident,
    ):
        """
        Serialize incident for WebSocket/API consumers.

        API consumers receive timezone-aware UTC and localize for display.
        """

        return {
            "id": incident.id,
            "title": incident.title,
            "description": getattr(
                incident,
                "description",
                incident.title,
            ),

            "severity": self._enum_or_value(
                incident.severity
            ),

            "status": self._enum_or_value(
                incident.status
            ),

            "confidence": incident.confidence,

            "source_entities": (
                incident.source_entities
                or []
            ),

            "target_entities": (
                incident.target_entities
                or []
            ),

            "attack_chain": (
                incident.attack_chain
                or []
            ),

            "mitre_techniques": (
                incident.mitre_techniques
                or []
            ),

            "first_seen": utc_iso(
                incident.first_seen
            ),

            "last_seen": utc_iso(
                incident.last_seen
            ),

            "resolved_at": utc_iso(
                incident.resolved_at
            ),
        }
