import os
from typing import Optional

from dotenv import load_dotenv
from pydantic_settings import BaseSettings

# Load .env file explicitly
load_dotenv()

class Settings(BaseSettings):
    # ===== API Configuration =====
    api_key: str = os.getenv("API_KEY", "your-static-api-key-here")
    secret_key: str = os.getenv("SECRET_KEY", "your-secret-key")

    # ===== Database =====
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./minisoc.db")

    # ===== Server =====
    host: str = os.getenv("HOST", "0.0.0.0")
    port: int = int(os.getenv("PORT", "8000"))

    # ===== Incident Correlation =====
    # Inactivity gap threshold (seconds) before starting a new incident for the same source/target
    incident_correlation_window_seconds: int = int(os.getenv("INCIDENT_CORRELATION_WINDOW_SECONDS", "300"))

    # ===== Automated Response Orchestration =====
    automatic_response_enabled: bool = os.getenv(
        "AUTOMATIC_RESPONSE_ENABLED", "false"
    ).lower() in {"1", "true", "yes", "on"}
    automatic_response_dry_run: bool = os.getenv(
        "AUTOMATIC_RESPONSE_DRY_RUN", "true"
    ).lower() in {"1", "true", "yes", "on"}
    response_pipeline_version: str = os.getenv(
        "RESPONSE_PIPELINE_VERSION", "v1"
    )
    slack_notifications_enabled: bool = os.getenv(
        "SLACK_NOTIFICATIONS_ENABLED", "false"
    ).lower() in {"1", "true", "yes", "on"}
    slack_webhook_url: Optional[str] = os.getenv("SLACK_WEBHOOK_URL") or None
    frontend_base_url: Optional[str] = os.getenv("FRONTEND_BASE_URL") or None

    # ===== Groq (Primary - FASTEST) =====
    groq_api_key: Optional[str] = os.getenv("GROQ_API_KEY")
    groq_model: str = os.getenv("GROQ_MODEL", "qwen/qwen3.6-27b")
    groq_base_url: str = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")

    # ===== Google Gemini (Fallback 1 - Smart) =====
    gemini_api_key: Optional[str] = os.getenv("GEMINI_API_KEY")
    gemini_model: str = os.getenv("GEMINI_MODEL", "gemini-1.5-flash-002")
    gemini_base_url: str = os.getenv("GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta")

    # ===== OpenRouter (Fallback 2 - Many models) =====
    openrouter_api_key: Optional[str] = os.getenv("OPENROUTER_API_KEY")
    openrouter_model: str = os.getenv("OPENROUTER_MODEL", "google/gemini-2.0-flash-lite-preview-02-05:free")
    openrouter_base_url: str = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")

    class Config:
        extra = "ignore"

settings = Settings()
