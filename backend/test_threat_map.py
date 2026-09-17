from unittest.mock import AsyncMock

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api import simulator
from app.config import settings
from app.models.database import Base
from app.services.response_service import ResponseService
from app.services.threat_map_service import ThreatMapService, classify_ip


def test_ip_classification_has_no_fake_geography():
    assert classify_ip("10.10.10.99")["classification"] == "private"
    assert classify_ip("172.16.2.3")["network_label"] == "Internal Network"
    assert classify_ip("192.168.1.5")["classification"] == "private"
    assert classify_ip("127.0.0.1")["classification"] == "loopback"
    assert classify_ip("169.254.1.1")["classification"] == "link_local"
    assert classify_ip("8.8.8.8")["classification"] == "public"
    assert classify_ip("2606:4700:4700::1111")["classification"] == "public"
    assert classify_ip("::1")["classification"] == "loopback"


@pytest.mark.asyncio
async def test_simulator_telemetry_appears_in_threat_map(tmp_path, monkeypatch):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'threat-map.db'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    db = sessionmaker(autocommit=False, autoflush=False, bind=engine)()
    monkeypatch.setattr(settings, "automatic_response_enabled", False)
    monkeypatch.setattr(simulator.asyncio, "sleep", AsyncMock())
    ResponseService._instance = None
    try:
        result = await simulator.simulate_full_attack(
            target_ip="target-map-server",
            attacker_ip="10.10.10.99",
            db=db,
        )
        threat_map = ThreatMapService(db).aggregate()
        relationships = threat_map["relationships"]

        assert result["events_sent"] == 10
        assert relationships
        assert all(item["source_ip"] == "10.10.10.99" for item in relationships)
        assert all(item["target"] != "Unknown" for item in relationships)
        assert all(item["source_classification"] == "private" for item in relationships)
        assert all(item["source_network"] == "Internal Network" for item in relationships)
        assert all(item["location"] is None for item in relationships)
        assert all(item["coordinates"] is None for item in relationships)
        assert sum(item["event_count"] for item in relationships) >= 4
        assert any(item["severity"] == "critical" for item in relationships)
        assert any("T1110" in item["mitre_techniques"] for item in relationships)
        assert any("simulator" in item["telemetry_sources"] for item in relationships)
        assert all(item["first_seen"] <= item["last_seen"] for item in relationships)
        assert any(item["incident_ids"] for item in relationships)
    finally:
        db.close()
        engine.dispose()
        ResponseService._instance = None
