from typing import Any, Dict, Optional
from datetime import datetime

import httpx

from app.config import settings
from app.core.time import to_kathmandu


class SlackNotifier:
    def send_escalation(self, escalation: Dict[str, Any]) -> None:
        if not settings.slack_webhook_url:
            raise ValueError("Slack webhook is not configured")

        activity = escalation["last_activity_at"]
        if isinstance(activity, str):
            activity = datetime.fromisoformat(activity)
        local_time = to_kathmandu(activity)
        timestamp = local_time.strftime("%Y-%m-%d %H:%M:%S Asia/Kathmandu")
        lines = [
            "ThreatLens - HUMAN REVIEW REQUIRED",
            "",
            "Repeated malicious activity followed a verified defensive response.",
            f"Severity: {escalation['severity'].upper()}",
            f"Source: {escalation['source_ip']}",
            f"Target: {escalation.get('target') or 'Unknown'}",
            f"Recurrence Count: {escalation['recurrence_count']}",
            f"Current Incident: {escalation['current_incident_id']}",
            f"Previous Response: {escalation['previous_action']}",
            f"Previous Response Status: {escalation['previous_response_status'].upper()}",
            f"Last Activity: {timestamp}",
            "",
            f"Reason: {escalation['reason']}",
            "Human investigation is required.",
        ]
        if settings.frontend_base_url:
            base_url = settings.frontend_base_url.rstrip("/")
            lines.append(
                f"Open Incident Investigation: {base_url}/incidents/"
                f"{escalation['current_incident_id']}"
            )

        response = httpx.post(
            settings.slack_webhook_url,
            json={"text": "\n".join(lines)},
            timeout=5.0,
        )
        response.raise_for_status()


class NotificationService:
    def __init__(self, slack: Optional[SlackNotifier] = None):
        self.slack = slack or SlackNotifier()

    def notify_human_escalation(self, escalation: Dict[str, Any]) -> Dict[str, str]:
        if not settings.slack_notifications_enabled:
            return {"status": "DISABLED", "error": ""}
        if not settings.slack_webhook_url:
            return {"status": "NOT_CONFIGURED", "error": "Slack webhook is not configured"}

        try:
            self.slack.send_escalation(escalation)
            return {"status": "SENT", "error": ""}
        except httpx.TimeoutException:
            return {"status": "FAILED", "error": "Slack request timed out"}
        except httpx.HTTPStatusError as exc:
            return {
                "status": "FAILED",
                "error": f"Slack returned HTTP {exc.response.status_code}",
            }
        except httpx.RequestError:
            return {"status": "FAILED", "error": "Slack network request failed"}
        except Exception as exc:
            return {"status": "FAILED", "error": f"Slack notification failed: {type(exc).__name__}"}
