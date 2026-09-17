from pydantic_settings import BaseSettings
from typing import Optional
from dotenv import load_dotenv
import os

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

# ===== Debug Output (shows what's loaded) =====
print("=" * 50)
print("📋 CONFIGURATION LOADED")
print("=" * 50)
print(f"🔷 GROQ:")
print(f"   API Key: {settings.groq_api_key[:15] if settings.groq_api_key else 'NOT SET'}...")
print(f"   Model: {settings.groq_model}")
print(f"   Base URL: {settings.groq_base_url}")
print()
print(f"🔷 GEMINI:")
print(f"   API Key: {settings.gemini_api_key[:15] if settings.gemini_api_key else 'NOT SET'}...")
print(f"   Model: {settings.gemini_model}")
print(f"   Base URL: {settings.gemini_base_url}")
print()
print(f"🔷 OPENROUTER:")
print(f"   API Key: {settings.openrouter_api_key[:15] if settings.openrouter_api_key else 'NOT SET'}...")
print(f"   Model: {settings.openrouter_model}")
print(f"   Base URL: {settings.openrouter_base_url}")
print("=" * 50)