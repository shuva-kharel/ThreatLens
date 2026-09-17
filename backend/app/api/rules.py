from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.session import get_db
from pydantic import BaseModel
from typing import Optional, List

router = APIRouter()

class Rule(BaseModel):
    id: str
    name: str
    description: str
    severity: str
    mitre_technique: str
    enabled: bool = True
    conditions: dict

# In-memory rules (in production, store in DB)
RULES = [
    {
        "id": "rule_001",
        "name": "SSH Brute Force",
        "description": "Detects multiple failed SSH logins from same source",
        "severity": "high",
        "mitre_technique": "T1110",
        "enabled": True,
        "conditions": {"event_type": "ssh_failed_login", "threshold": 5, "window": 60}
    },
    {
        "id": "rule_002",
        "name": "Port Scanning",
        "description": "Detects port scanning activity",
        "severity": "medium",
        "mitre_technique": "T1046",
        "enabled": True,
        "conditions": {"event_type": "ssh_failed_login", "threshold": 4, "window": 30}
    },
]

@router.get("/rules")
async def list_rules():
    """List all detection rules."""
    return RULES

@router.get("/rules/{rule_id}")
async def get_rule(rule_id: str):
    """Get a specific rule."""
    rule = next((r for r in RULES if r["id"] == rule_id), None)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule

@router.post("/rules")
async def create_rule(rule: dict):
    """Create a new detection rule."""
    rule["id"] = f"rule_{len(RULES) + 1:03d}"
    RULES.append(rule)
    return rule

@router.put("/rules/{rule_id}/toggle")
async def toggle_rule(rule_id: str):
    """Enable/disable a rule."""
    rule = next((r for r in RULES if r["id"] == rule_id), None)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule["enabled"] = not rule["enabled"]
    return rule