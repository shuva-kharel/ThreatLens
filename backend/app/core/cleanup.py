from datetime import timedelta

from sqlalchemy.orm import Session

from app.models.database import Event, Alert, Incident
from app.core.time import utc_now


class DataCleanup:
    """Data retention and cleanup utilities."""

    def __init__(self, db: Session):
        self.db = db

    def cleanup_old_events(self, days: int = 30) -> int:
        """Delete events older than N days."""

        cutoff = utc_now() - timedelta(days=days)

        deleted = (
            self.db.query(Event)
            .filter(Event.timestamp < cutoff)
            .delete()
        )

        self.db.commit()

        return deleted

    def cleanup_resolved_incidents(
        self,
        days: int = 90,
    ) -> int:
        """Delete resolved incidents older than N days."""

        cutoff = utc_now() - timedelta(days=days)

        deleted = (
            self.db.query(Incident)
            .filter(
                Incident.status.in_(
                    ["resolved", "false_positive"]
                ),
                Incident.resolved_at < cutoff,
            )
            .delete()
        )

        self.db.commit()

        return deleted

    def get_storage_stats(self) -> dict:
        """Get database storage statistics."""

        return {
            "events": self.db.query(Event).count(),
            "alerts": self.db.query(Alert).count(),
            "incidents": self.db.query(Incident).count(),
        }
