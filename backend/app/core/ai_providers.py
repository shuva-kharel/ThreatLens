import json
import httpx
from typing import Optional, Dict, Any, List
from abc import ABC, abstractmethod
from app.config import settings


class AIProvider(ABC):
    """Base class for AI providers."""

    def __init__(self):
        self.client = httpx.AsyncClient(timeout=30.0)

    @abstractmethod
    def is_available(self) -> bool:
        pass

    @abstractmethod
    async def analyze(self, prompt: str) -> Optional[str]:
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    def _get_system_prompt(self) -> str:
        return """You are a security analyst assistant.
        Analyze the incident data provided and produce:
        1. Executive summary (2-3 sentences)
        2. Attack explanation in plain language
        3. Evidence list (restated from input)
        4. Likely attack progression
        5. MITRE technique explanation
        6. Recommended investigation steps
        7. Recommended containment steps

        DO NOT invent events not present in the input.
        Clearly distinguish evidence from recommendations.
        Be concise and actionable."""


class GroqProvider(AIProvider):
    """Groq AI Provider - Primary (Fastest)."""

    def __init__(self):
        super().__init__()
        self.api_key = settings.groq_api_key
        self.model = settings.groq_model
        self.base_url = settings.groq_base_url
        print(f"[Groq] Initialized with model: {self.model}")
        print(f"[Groq] Base URL: {self.base_url}")

    def is_available(self) -> bool:
        is_avail = self.api_key is not None and len(self.api_key) > 10
        print(f"[Groq] Available: {is_avail}")
        return is_avail

    @property
    def name(self) -> str:
        return "Groq"

    async def analyze(self, prompt: str) -> Optional[str]:
        print(f"[Groq] Sending request...")
        try:
            response = await self.client.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": self._get_system_prompt()},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.3,
                    "max_tokens": 600
                }
            )

            if response.status_code == 200:
                result = response.json()
                content = result["choices"][0]["message"]["content"]
                print(f"[Groq] [OK] Success! Response length: {len(content)}")
                return content
            else:
                print(f"[Groq] [FAIL] Error: Status {response.status_code}")
                print(f"[Groq] Response: {response.text[:200]}")
                return None
        except Exception as e:
            print(f"[Groq] [FAIL] Exception: {str(e)}")
            return None


class GeminiProvider(AIProvider):
    """Google Gemini AI Provider - Fallback 1 (Smart)."""

    def __init__(self):
        super().__init__()
        self.api_key = settings.gemini_api_key
        self.model = settings.gemini_model
        self.base_url = settings.gemini_base_url
        print(f"[Gemini] Initialized with model: {self.model}")
        print(f"[Gemini] Base URL: {self.base_url}")

    def is_available(self) -> bool:
        is_avail = self.api_key is not None and len(self.api_key) > 10
        print(f"[Gemini] Available: {is_avail}")
        return is_avail

    @property
    def name(self) -> str:
        return "Gemini"

    async def analyze(self, prompt: str) -> Optional[str]:
        print(f"[Gemini] Sending request...")
        try:
            # Gemini needs the model path format
            model_name = self.model
            if not model_name.startswith("models/"):
                model_name = f"models/{model_name}"

            response = await self.client.post(
                f"{self.base_url}/{model_name}:generateContent",
                params={"key": self.api_key},
                json={
                    "contents": [{
                        "parts": [{
                            "text": f"{self._get_system_prompt()}\n\nIncident Data:\n{prompt}"
                        }]
                    }],
                    "generationConfig": {
                        "temperature": 0.3,
                        "maxOutputTokens": 600
                    }
                }
            )

            if response.status_code == 200:
                data = response.json()
                if "candidates" in data and len(data["candidates"]) > 0:
                    content = data["candidates"][0]["content"]["parts"][0]["text"]
                    print(f"[Gemini] [OK] Success! Response length: {len(content)}")
                    return content
                else:
                    print(f"[Gemini] [FAIL] No candidates in response")
                    return None
            else:
                print(f"[Gemini] [FAIL] Error: Status {response.status_code}")
                print(f"[Gemini] Response: {response.text[:200]}")
                return None
        except Exception as e:
            print(f"[Gemini] [FAIL] Exception: {str(e)}")
            return None


class OpenRouterProvider(AIProvider):
    """OpenRouter AI Provider - Fallback 2 (Access to many free models)."""

    def __init__(self):
        super().__init__()
        self.api_key = settings.openrouter_api_key
        self.model = settings.openrouter_model
        self.base_url = settings.openrouter_base_url
        print(f"[OpenRouter] Initialized with model: {self.model}")
        print(f"[OpenRouter] Base URL: {self.base_url}")

    def is_available(self) -> bool:
        is_avail = self.api_key is not None and len(self.api_key) > 10
        print(f"[OpenRouter] Available: {is_avail}")
        return is_avail

    @property
    def name(self) -> str:
        return "OpenRouter"

    async def analyze(self, prompt: str) -> Optional[str]:
        print(f"[OpenRouter] Sending request...")
        try:
            response = await self.client.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": self._get_system_prompt()},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.3,
                    "max_tokens": 600
                }
            )

            if response.status_code == 200:
                result = response.json()
                content = result["choices"][0]["message"]["content"]
                print(f"[OpenRouter] [OK] Success! Response length: {len(content)}")
                return content
            else:
                print(f"[OpenRouter] [FAIL] Error: Status {response.status_code}")
                print(f"[OpenRouter] Response: {response.text[:200]}")
                return None
        except Exception as e:
            print(f"[OpenRouter] [FAIL] Exception: {str(e)}")
            return None