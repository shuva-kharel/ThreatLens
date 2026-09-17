from fastapi import FastAPI, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from datetime import datetime
import uvicorn
import traceback

from app.api import (
    events, alerts, detections, websocket, incidents, stats, health
)
from app.db.session import engine, get_db
from app.models.database import Base
from app.config import settings

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="ThreatLens API",
    description="AI-assisted security analyst layer",
    version="1.0.0"
)

# ===== CORS MIDDLEWARE (MUST BE FIRST) =====
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3001",
        "http://192.168.43.1:3000",
        "*",  # ← Keep for dev; remove for production
    ],
    allow_credentials=False,  # Must be False if allow_origins=["*"]
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)


# ===== GLOBAL EXCEPTION HANDLER (ensures CORS on errors) =====
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Ensure CORS headers are present even on unexpected errors."""
    print(f"\n[ERROR] {request.method} {request.url.path}")
    print(f"[ERROR] {type(exc).__name__}: {exc}")
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
        }
    )


# ===== REGISTER ROUTERS =====
app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["alerts"])
app.include_router(detections.router, prefix="/api/v1/detections", tags=["detections"])
app.include_router(websocket.router, prefix="/api/v1/ws", tags=["websocket"])
app.include_router(incidents.router, prefix="/api/v1/incidents", tags=["incidents"])
app.include_router(stats.router, prefix="/api/v1/stats", tags=["stats"])
app.include_router(health.router, prefix="/api/v1/health", tags=["health"])

@app.get("/")
async def root():
    return {
        "service": "MiniSOC ThreatLens",
        "version": "1.0.0",
        "status": "operational",
        "endpoints": [
            "/api/v1/events",
            "/api/v1/alerts",
            "/api/v1/ws/events",
        ]
    }