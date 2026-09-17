import json
import re
from typing import Optional, Dict, Any, List
from app.models.schemas import AIAnalysisResponse
from app.core.ai_providers import GroqProvider, GeminiProvider, OpenRouterProvider


class AIAnalyst:
    def __init__(self):
        print("\n[AI] Initializing AI Analyst...")
        print("-" * 40)

        self.providers = [
            GroqProvider(),
            GeminiProvider(),
            OpenRouterProvider()
        ]

        self.available_providers = [p for p in self.providers if p.is_available()]

        provider_names = [p.name for p in self.available_providers]
        print(f"\n[AI] [OK] Available providers: {provider_names}")

        if not self.available_providers:
            print("[AI] [WARN] WARNING: No AI providers available! Using mock responses.")
        else:
            print(f"[AI] [*] Using primary provider: {self.available_providers[0].name}")
        print("-" * 40 + "\n")

    async def analyze_incident(self, incident_data: Dict[str, Any]) -> Optional[AIAnalysisResponse]:
        print("[AI] Starting incident analysis...")

        prompt = self._build_prompt(incident_data)

        for provider in self.available_providers:
            print(f"\n[AI] [*] Trying provider: {provider.name}")

            try:
                response_text = await provider.analyze(prompt)

                if response_text:
                    print(f"[AI] [OK] {provider.name} succeeded!")
                    parsed_response = self._parse_response(response_text, incident_data)
                    print("[AI] Analysis complete!\n")
                    return parsed_response
                else:
                    print(f"[AI] [FAIL] {provider.name} returned empty response, trying next...")

            except Exception as e:
                print(f"[AI] [FAIL] {provider.name} failed: {str(e)}, trying next...")
                continue

        print("\n[AI] [FAIL] All providers failed - using mock response")
        return self._get_mock_response(incident_data)

    def _build_prompt(self, incident_data: Dict[str, Any]) -> str:
        return f"""
        Incident Type: {incident_data.get('title', 'Unknown')}
        Source: {incident_data.get('source_entities', ['Unknown'])[0]}
        Target: {incident_data.get('target_entities', ['Unknown'])[0]}
        Severity: {incident_data.get('severity', 'unknown')}
        Confidence: {incident_data.get('confidence', 0)}
        MITRE Techniques: {', '.join(incident_data.get('mitre_techniques', []))}
        Attack Chain: {json.dumps(incident_data.get('attack_chain', []), indent=2)}
        Events: {json.dumps(incident_data.get('events', []), indent=2)}
        """

    def _parse_response(self, content: str, incident_data: Dict[str, Any]) -> AIAnalysisResponse:
        """Parse the AI response into structured format."""

        # Clean up the response - remove thinking tags
        content = re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL)
        content = re.sub(r'<thinking>.*?</thinking>', '', content, flags=re.DOTALL)

        lines = [line.strip() for line in content.split('\n') if line.strip()]

        response = {
            "summary": "",
            "attack_explanation": "",
            "evidence_list": [],
            "attack_progression": [],
            "mitre_explanation": "",
            "investigation_steps": [],
            "containment_steps": []
        }

        current_section = None
        summary_lines = []
        attack_lines = []
        mitre_lines = []

        for line in lines:
            lower_line = line.lower()

            # Detect section headers
            if "summary" in lower_line and len(line) < 50:
                current_section = "summary"
                continue
            elif "attack explanation" in lower_line and len(line) < 50:
                current_section = "attack_explanation"
                continue
            elif "evidence" in lower_line and len(line) < 40:
                current_section = "evidence"
                continue
            elif "attack progression" in lower_line or "progression" in lower_line:
                current_section = "progression"
                continue
            elif "mitre" in lower_line and len(line) < 50:
                current_section = "mitre"
                continue
            elif "investigation" in lower_line and len(line) < 40:
                current_section = "investigation"
                continue
            elif "containment" in lower_line and len(line) < 40:
                current_section = "containment"
                continue

            # Handle bullet points
            if line.startswith('-') or line.startswith('*') or line.startswith('\u2022'):
                clean_line = line.lstrip('-*\u2022 ').strip()
                if current_section == "evidence":
                    response["evidence_list"].append(clean_line)
                elif current_section == "progression":
                    response["attack_progression"].append(clean_line)
                elif current_section == "investigation":
                    response["investigation_steps"].append(clean_line)
                elif current_section == "containment":
                    response["containment_steps"].append(clean_line)
            else:
                # Handle regular text
                if current_section == "summary":
                    summary_lines.append(line)
                elif current_section == "attack_explanation":
                    attack_lines.append(line)
                elif current_section == "mitre":
                    mitre_lines.append(line)

        # Join the collected text
        if summary_lines:
            response["summary"] = " ".join(summary_lines)[:300]
        else:
            response["summary"] = f"Attack detected from {incident_data.get('source_entities', ['Unknown'])[0]} targeting {incident_data.get('target_entities', ['Unknown'])[0]}."

        if attack_lines:
            response["attack_explanation"] = " ".join(attack_lines)[:500]
        else:
            response["attack_explanation"] = "Suspicious activity consistent with a multi-stage attack."

        if mitre_lines:
            response["mitre_explanation"] = " ".join(mitre_lines)[:300]
        elif incident_data.get('mitre_techniques'):
            response["mitre_explanation"] = f"MITRE techniques detected: {', '.join(incident_data.get('mitre_techniques', []))}"

        # Ensure we have at least some recommendations
        if not response["investigation_steps"]:
            response["investigation_steps"] = [
                f"Review all activities from source {incident_data.get('source_entities', ['Unknown'])[0]}",
                f"Check for successful privilege escalation on {incident_data.get('target_entities', ['Unknown'])[0]}",
                "Review system logs for additional suspicious activities"
            ]

        if not response["containment_steps"]:
            response["containment_steps"] = [
                f"Consider blocking IP {incident_data.get('source_entities', ['Unknown'])[0]}",
                f"Isolate host {incident_data.get('target_entities', ['Unknown'])[0]} for further investigation",
                "Reset credentials for affected accounts"
            ]

        return AIAnalysisResponse(
            incident_id=incident_data.get("id", "unknown"),
            summary=response["summary"],
            attack_narrative=response["attack_explanation"],
            confidence=float(incident_data.get("confidence") or 0.0),
            findings=[
                *response["evidence_list"],
                *response["attack_progression"],
                *([response["mitre_explanation"]] if response["mitre_explanation"] else []),
            ],
            recommendations=[
                *response["investigation_steps"],
                *response["containment_steps"],
            ],
            mitre_techniques=incident_data.get("mitre_techniques", []),
            timeline=incident_data.get("attack_chain", []),
            attack_graph={},
        )

    def _get_mock_response(self, incident_data: Dict[str, Any]) -> AIAnalysisResponse:
        source = incident_data.get('source_entities', ['Unknown'])[0]
        target = incident_data.get('target_entities', ['Unknown'])[0]

        print("[Mock] Generating mock response...")

        return AIAnalysisResponse(
            incident_id=incident_data.get("id", "unknown"),
            summary=f"Potential attack detected from {source} targeting {target}.",
            attack_narrative=f"Analysis shows suspicious activity originating from {source} against {target}. The pattern is consistent with a multi-stage attack.",
            confidence=float(incident_data.get("confidence") or 0.0),
            findings=["Port scanning detected", "Multiple failed login attempts", "Successful authentication"],
            recommendations=[
                f"Review all activities from source {source}",
                f"Check for successful privilege escalation on {target}",
                "Review system logs for additional suspicious activities",
                f"Consider blocking IP {source}",
                f"Isolate host {target} for further investigation",
                "Reset credentials for affected accounts",
            ],
            mitre_techniques=incident_data.get("mitre_techniques", []),
            timeline=incident_data.get("attack_chain", []),
            attack_graph={},
        )
