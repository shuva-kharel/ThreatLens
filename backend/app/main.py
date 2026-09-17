from fastapi import FastAPI, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from sqlalchemy.orm import Session

import uvicorn
import traceback
import sys

from app.api import (
    events,
    alerts,
    incidents,
    websocket,
    export,
    stats,
    simulator,
    netsentinel,
    detections,
    mitre,
    response,
    vulnerabilities,
    health,
)

from app.db.session import engine, get_db

from app.models.database import (
    Base,
    Event,
    Incident,
    Alert,
    utc_now,
)

from app.config import settings


# =============================================================================
# WINDOWS UTF-8 CONSOLE SUPPORT
# =============================================================================

try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(
            encoding="utf-8",
            errors="replace",
        )

    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(
            encoding="utf-8",
            errors="replace",
        )

except Exception:
    pass


# =============================================================================
# DATABASE
# =============================================================================

Base.metadata.create_all(bind=engine)


# =============================================================================
# APPLICATION
# =============================================================================

app = FastAPI(
    title="MiniSOC ThreatLens API",
    description="AI-assisted security analyst layer",
    version="1.0.0",
)


# =============================================================================
# CORS
# =============================================================================

app.add_middleware(
    CORSMiddleware,

    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3001",
        "http://192.168.43.1:3000",
        "*",
    ],

    allow_credentials=False,

    allow_methods=["*"],

    allow_headers=["*"],

    expose_headers=["*"],
)


# =============================================================================
# GLOBAL EXCEPTION HANDLER
# =============================================================================

@app.exception_handler(Exception)
async def global_exception_handler(
    request: Request,
    exc: Exception,
):
    """Ensure CORS headers are present on unexpected errors."""

    print(
        f"\n[ERROR] "
        f"{request.method} "
        f"{request.url.path}"
    )

    print(
        f"[ERROR] "
        f"{type(exc).__name__}: "
        f"{exc}"
    )

    traceback.print_exc()

    return JSONResponse(
        status_code=500,

        content={
            "detail": str(exc),
            "type": type(exc).__name__,
            "path": str(request.url.path),
        },

        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "*",
            "Access-Control-Allow-Headers": "*",
        },
    )


# =============================================================================
# ROUTERS
# =============================================================================

app.include_router(
    mitre.router,
    prefix="/api/v1/mitre",
    tags=["mitre"],
)

app.include_router(
    detections.router,
    prefix="/api/v1/detections",
    tags=["detections"],
)

app.include_router(
    netsentinel.router,
    prefix="/api/v1",
    tags=["netsentinel"],
)

app.include_router(
    simulator.router,
    prefix="/api/v1",
    tags=["simulator"],
)

app.include_router(
    stats.router,
    prefix="/api/v1",
    tags=["stats"],
)

app.include_router(
    export.router,
    prefix="/api/v1/incidents/export",
    tags=["export"],
)

app.include_router(
    events.router,
    prefix="/api/v1/events",
    tags=["events"],
)

app.include_router(
    alerts.router,
    prefix="/api/v1/alerts",
    tags=["alerts"],
)

app.include_router(
    incidents.router,
    prefix="/api/v1/incidents",
    tags=["incidents"],
)

app.include_router(
    response.router,
    prefix="/api/v1/response",
    tags=["response"],
)

app.include_router(
    vulnerabilities.router,
    prefix="/api/v1/vulnerabilities",
    tags=["vulnerabilities"],
)

app.include_router(
    health.router,
    prefix="/api/v1",
    tags=["health"],
)

app.include_router(
    websocket.router,
    prefix="/api/v1/ws",
    tags=["websocket"],
)


# =============================================================================
# ROOT
# =============================================================================

@app.get("/")
async def root():

    return {
        "service": "MiniSOC ThreatLens",
        "version": "1.0.0",
        "status": "operational",

        "endpoints": [
            "/api/v1/events",
            "/api/v1/events/batch",
            "/api/v1/alerts",
            "/api/v1/incidents",
            "/api/v1/stats/overview",
            "/api/v1/stats/incidents/timeline",
            "/api/v1/storage/stats",
            "/api/v1/network/stats",
            "/api/v1/network/anomalies",
            "/api/v1/detections/rules",
            "/api/v1/mitre/techniques",
            "/api/v1/simulate/full-attack",
            "/api/v1/ws/events",
        ],
    }


# =============================================================================
# HEALTH CHECK
# =============================================================================

@app.get("/health")
async def health_check(
    db: Session = Depends(get_db),
):
    """
    Detailed health check with database and AI provider status.
    """

    health = {
        "status": "healthy",

        # Always timezone-aware UTC.
        "timestamp": utc_now().isoformat(),

        "database": "unknown",

        "ai_providers": [],

        "stats": {},
    }

    try:

        event_count = (
            db.query(Event)
            .count()
        )

        incident_count = (
            db.query(Incident)
            .count()
        )

        alert_count = (
            db.query(Alert)
            .count()
        )

        health["database"] = "healthy"

        health["stats"] = {
            "events": event_count,
            "alerts": alert_count,
            "incidents": incident_count,
        }

    except Exception as e:

        health["database"] = f"error: {e}"

        health["status"] = "degraded"

    if settings.groq_api_key:
        health["ai_providers"].append("groq")

    if settings.gemini_api_key:
        health["ai_providers"].append("gemini")

    if settings.openrouter_api_key:
        health["ai_providers"].append("openrouter")

    return health


# =============================================================================
# RUN
# =============================================================================

if __name__ == "__main__":

    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=True,
    )
