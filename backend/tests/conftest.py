import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db.session import engine, SessionLocal
from app.models.database import Base
from app.config import settings

# This allows async tests to work
pytest_plugins = ['pytest_asyncio']

@pytest.fixture(scope="session")
def client():
    """Create test client."""
    Base.metadata.create_all(bind=engine)
    client = TestClient(app)
    yield client
    Base.metadata.drop_all(bind=engine)

@pytest.fixture
def db_session():
    """Create database session for tests."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@pytest.fixture
def api_key():
    """Return API key for tests."""
    return settings.api_key or "your-static-api-key-here"

@pytest.fixture
def test_event_data():
    """Return test event data."""
    return {
        "timestamp": "2026-09-17T10:31:24Z",
        "host": "ubuntu-server",
        "source_ip": "10.10.10.20",
        "event_type": "ssh_failed_login",
        "username": "admin",
        "severity": "low",
        "raw_event": "Failed password for admin from 10.10.10.20 port 51422 ssh2"
    }