from fastapi.testclient import TestClient

from app.main import app


def test_frontend_read_contracts_are_mounted_and_shaped():
    with TestClient(app) as client:
        overview = client.get("/api/v1/stats/overview")
        assert overview.status_code == 200
        assert {
            "total_incidents",
            "open_incidents",
            "contained_incidents",
            "critical_incidents",
            "alerts_24h",
            "critical_alerts",
            "events_ingested",
            "observed_assets",
            "repeat_threats",
            "human_escalations",
            "mitre_distribution",
            "top_attack_types",
        } <= overview.json().keys()

        incident_timeline = client.get("/api/v1/stats/incidents/timeline")
        assert incident_timeline.status_code == 200
        assert isinstance(incident_timeline.json()["timeline"], list)

        network_timeline = client.get("/api/v1/network/timeline")
        assert network_timeline.status_code == 200
        assert isinstance(network_timeline.json()["timeline"], list)

        health = client.get("/api/v1/health/detailed")
        assert health.status_code == 200
        assert {"database", "system", "timestamp"} <= health.json().keys()


def test_incident_update_contract_uses_patch_json():
    with TestClient(app) as client:
        response = client.patch(
            "/api/v1/incidents/nonexistent-contract-check",
            json={"status": "open"},
        )
    assert response.status_code == 404
    assert response.json()["detail"] == "Incident not found"
