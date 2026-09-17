from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models.database import Event, Alert, Incident
from datetime import datetime, timedelta
import psutil
import os

router = APIRouter()

@router.get("/health/detailed")
async def detailed_health(db: Session = Depends(get_db)):
    """Detailed health check with system metrics."""
    total_events = db.query(Event).count()
    total_alerts = db.query(Alert).count()
    total_incidents = db.query(Incident).count()

    # System metrics
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')

    return {
        "status": "healthy",
        "database": {
            "events": total_events,
            "alerts": total_alerts,
            "incidents": total_incidents,
        },
        "system": {
            "cpu_percent": cpu_percent,
            "memory_used": f"{memory.used / (1024**3):.2f} GB",
            "memory_total": f"{memory.total / (1024**3):.2f} GB",
            "memory_percent": memory.percent,
            "disk_used": f"{disk.used / (1024**3):.2f} GB",
            "disk_free": f"{disk.free / (1024**3):.2f} GB",
            "disk_percent": disk.percent,
        },
        "uptime": "system uptime not available",
    }

@router.get("/health/readiness")
async def readiness(db: Session = Depends(get_db)):
    """Readiness probe for orchestration."""
    try:
        # Check database connection
        db.execute("SELECT 1")
        db_healthy = True
    except:
        db_healthy = False

    return {
        "ready": db_healthy,
        "database": db_healthy,
        "api": True,
    }