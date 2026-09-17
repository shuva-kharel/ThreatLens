from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.time import utc_now
from app.db.session import get_db
from app.main import app
from app.models.database import Alert, Base, EndpointAgent, Event, Incident, Response, Severity


def test_ranked_search_and_activity_use_persisted_data(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'operations.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    db = session_factory()
    now = utc_now()
    incident = Incident(
        id="INC-A31F", title="SSH brute force", severity=Severity.HIGH, status="open",
        source_entities=["10.10.10.99"], target_entities=["WIN-TARGET-01"],
        mitre_techniques=["T1110"], first_seen=now, last_seen=now,
    )
    event = Event(id="EVT-1", timestamp=now, host="WIN-TARGET-01", source_ip="10.10.10.99", event_type="ssh_failed_login", severity="high", normalized_data={"destination_ip": "10.10.10.10"})
    alert = Alert(id="ALT-1", alert_type="ssh_brute_force", severity=Severity.HIGH, mitre_technique="T1110", source_ip="10.10.10.99", target_host="WIN-TARGET-01", description="Brute-force threshold reached", incident_id=incident.id, created_at=now)
    response = Response(id="RESP-1", incident_id=incident.id, action="block_source_ip", status="completed", details={"completed_at": now.isoformat(), "execution": {"execution_id": "EXEC-16BCB1F0", "playbook_id": "PB-BLOCK-IP", "action": "block_source_ip", "target": "10.10.10.99", "status": "verified", "completed_at": now.isoformat(), "verification_result": {"verified": True, "method": "firewall", "details": "Source blocked", "timestamp": now.isoformat()}}})
    agent = EndpointAgent(id="agent-win-01", hostname="WIN-TARGET-01", os="Windows", ip_addresses=["10.10.10.10"], version="1.0", capabilities=["telemetry"], last_seen=now - timedelta(seconds=10))
    db.add_all([incident, event, alert, response, agent])
    db.commit()

    def override_db():
        yield db

    app.dependency_overrides[get_db] = override_db
    try:
        with TestClient(app) as client:
            exact_ip = client.get("/api/v1/search", params={"q": "10.10.10.99"}).json()
            assert exact_ip["results"]["sources"][0]["label"] == "10.10.10.99"
            assert exact_ip["results"]["sources"][0]["score"] == 100
            assert any(item["id"] == "INC-A31F" for item in exact_ip["results"]["incidents"])

            assert client.get("/api/v1/search", params={"q": "10.10"}).json()["total"] > 0
            assert client.get("/api/v1/search", params={"q": "INC-A31F"}).json()["results"]["incidents"][0]["id"] == "INC-A31F"
            assert client.get("/api/v1/search", params={"q": "EXEC-16BCB1F0"}).json()["results"]["responses"][0]["id"] == "EXEC-16BCB1F0"
            assert client.get("/api/v1/search", params={"q": "T1110"}).json()["results"]["mitre"][0]["id"] == "T1110"
            assert client.get("/api/v1/search", params={"q": "WIN-TARGET"}).json()["results"]["hosts"]
            assert client.get("/api/v1/search", params={"q": "not-a-real-record"}).json()["total"] == 0

            activity = client.get("/api/v1/activity", params={"limit": 20}).json()["activity"]
            assert any(item["type"] == "event" for item in activity)
            assert any(item["type"] == "detection" for item in activity)
            assert any(item["type"] == "response" for item in activity)
            assert any(item["type"] == "verified" for item in activity)
    finally:
        app.dependency_overrides.clear()
        db.close()
        engine.dispose()
