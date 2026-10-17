import pytest

from app.core.ai_analyst import AIAnalyst


class FailingProvider:
    name = "failing-test-provider"

    async def analyze(self, prompt):
        raise RuntimeError("provider unavailable")


@pytest.mark.asyncio
async def test_ai_provider_failure_returns_schema_valid_fallback(monkeypatch):
    analyst = AIAnalyst()
    analyst.available_providers = [FailingProvider()]
    incident = {
        "id": "incident-ai-failure",
        "title": "Multi-stage attack",
        "source_entities": ["10.10.10.99"],
        "target_entities": ["target-server"],
        "confidence": 0.92,
        "mitre_techniques": ["T1046", "T1110"],
        "attack_chain": [{"stage": "Reconnaissance"}],
    }

    result = await analyst.analyze_incident(incident)

    assert result.incident_id == incident["id"]
    assert result.confidence == 0.92
    assert result.summary
    assert result.attack_narrative
    assert result.findings
    assert result.recommendations
    assert result.mitre_techniques == ["T1046", "T1110"]
    assert result.timeline == incident["attack_chain"]
