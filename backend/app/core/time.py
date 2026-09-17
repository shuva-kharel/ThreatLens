from datetime import datetime, timezone
from zoneinfo import ZoneInfo


UTC = timezone.utc
KATHMANDU = ZoneInfo("Asia/Kathmandu")


def utc_now() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)


def ensure_utc(dt: datetime | None) -> datetime | None:
    """
    Treat naive datetimes as UTC and convert aware datetimes to UTC.
    """
    if dt is None:
        return None

    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)

    return dt.astimezone(UTC)


def to_kathmandu(dt: datetime | None) -> datetime | None:
    """Convert a datetime from UTC to Asia/Kathmandu."""
    if dt is None:
        return None

    utc_dt = ensure_utc(dt)

    return utc_dt.astimezone(KATHMANDU)


def kathmandu_iso(dt: datetime | None) -> str | None:
    """
    Convert a datetime to Kathmandu time and return ISO 8601.

    Example:
    2026-09-17T19:30:00+05:45
    """
    converted = to_kathmandu(dt)

    if converted is None:
        return None

    return converted.isoformat()


def utc_iso(dt: datetime | None) -> str | None:
    """Serialize a datetime as an ISO-8601 UTC timestamp."""
    converted = ensure_utc(dt)
    return converted.isoformat() if converted is not None else None
