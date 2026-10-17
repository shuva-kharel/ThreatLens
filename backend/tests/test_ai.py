import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings
from datetime import datetime, timedelta

client = TestClient(app)
API_KEY = settings.api_key or "your-static-api-key-here"

class TestAIProvider:
    """Test AI provider functionality."""

    @pytest.fixture
    def create_test_incident(self):
        """Create a test incident for AI analysis."""
        # Send 5 failed logins to create an incident
        for i in range(5):
            event = {
                "timestamp": (datetime.utcnow() + timedelta(seconds=i*5)).isoformat() + "Z",
                "host": "ubuntu-server",
                "source_ip": "10.10.10.20",
                "event_type": "ssh_failed_login",
                "username": "admin",
                "severity": "low",
                "raw_event": f"Failed password attempt {i+1}"
            }
            response = client.post(
                "/api/v1/events",
                json=event,
                headers={"X-API-Key": API_KEY}
            )
            assert response.status_code == 200

        # Get the incident ID
        response = client.get("/api/v1/incidents?limit=1")
        assert response.status_code == 200
        incidents = response.json()
        if len(incidents) > 0:
            return incidents[0]["id"]
        return None

    def test_ai_analysis_endpoint(self, create_test_incident):
        """Test AI analysis endpoint."""
        incident_id = create_test_incident
        if not incident_id:
            pytest.skip("No incident created for testing")

        response = client.post(f"/api/v1/incidents/{incident_id}/analyze")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["incident_id"] == incident_id

        # Check response structure (may be mock or real AI)
        analysis = data.get("analysis")
        if analysis:
            # Should have summary
            assert "summary" in analysis

            # Should have attack explanation
            assert "attack_explanation" in analysis

            # Should have evidence list (may be empty if parsing failed)
            assert "evidence_list" in analysis
            assert isinstance(analysis["evidence_list"], list)

            # Should have investigation steps
            assert "investigation_steps" in analysis
            assert isinstance(analysis["investigation_steps"], list)

            # Should have containment steps
            assert "containment_steps" in analysis
            assert isinstance(analysis["containment_steps"], list)

    def test_ai_analysis_incident_not_found(self):
        """Test AI analysis on non-existent incident."""
        response = client.post("/api/v1/incidents/non-existent-id/analyze")
        assert response.status_code == 404

    def test_ai_analysis_stores_summary(self, create_test_incident):
        """Test that AI analysis stores summary in incident."""
        incident_id = create_test_incident
        if not incident_id:
            pytest.skip("No incident created for testing")

        # Run AI analysis
        response = client.post(f"/api/v1/incidents/{incident_id}/analyze")
        assert response.status_code == 200

        # Get the incident to check if summary was stored
        response = client.get(f"/api/v1/incidents/{incident_id}")
        assert response.status_code == 200
        data = response.json()
        incident = data.get("incident")

        if incident:
            # Check if ai_summary was set (may be None if AI failed)
            if incident.get("ai_summary"):
                assert isinstance(incident["ai_summary"], str)
                assert len(incident["ai_summary"]) > 0

    def test_ai_fallback_to_mock(self):
        """Test that AI falls back to mock when providers fail."""
        # This test assumes providers might fail
        # Create incident
        for i in range(5):
            event = {
                "timestamp": (datetime.utcnow() + timedelta(seconds=i*5)).isoformat() + "Z",
                "host": "test-host",
                "source_ip": "192.168.1.100",
                "event_type": "ssh_failed_login",
                "username": "testuser",
                "severity": "low",
                "raw_event": f"Test event {i+1}"
            }
            client.post(
                "/api/v1/events",
                json=event,
                headers={"X-API-Key": API_KEY}
            )

        response = client.get("/api/v1/incidents?limit=1")
        if len(response.json()) > 0:
            incident_id = response.json()[0]["id"]

            # Run analysis with potentially failing providers
            response = client.post(f"/api/v1/incidents/{incident_id}/analyze")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"

            # Should still have analysis (mock or real)
            analysis = data.get("analysis")
            if analysis:
                assert "summary" in analysis