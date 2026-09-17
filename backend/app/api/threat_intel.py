from fastapi import APIRouter
from typing import List, Optional

router = APIRouter()

# Mock threat intelligence data
THREAT_INTEL = [
    {"ip": "10.10.10.20", "threat_level": "high", "category": "Brute Force", "last_seen": "2026-09-09T10:00:00Z"},
    {"ip": "192.168.1.100", "threat_level": "medium", "category": "Port Scan", "last_seen": "2026-09-09T09:30:00Z"},
    {"ip": "203.0.113.45", "threat_level": "critical", "category": "Malware C2", "last_seen": "2026-09-09T08:00:00Z"},
]

@router.get("/threat-intel/ip/{ip}")
async def check_ip(ip: str):
    """Check IP against threat intelligence."""
    result = next((t for t in THREAT_INTEL if t["ip"] == ip), None)
    if result:
        return {"ip": ip, **result}
    return {"ip": ip, "threat_level": "unknown", "category": "No known threats"}

@router.get("/threat-intel/recent")
async def get_recent_threats(limit: int = 10):
    """Get recent threat intelligence."""
    return THREAT_INTEL[:limit]

@router.post("/threat-intel")
async def add_threat(data: dict):
    """Add a threat intelligence entry (for demo)."""
    THREAT_INTEL.append(data)
    return {"status": "added", "data": data}