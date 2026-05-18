"""Shared pytest fixtures for the EmberArmor v2 test suite.

Environment variables are set at module-load time *before* any
ember_armor import happens, because ``ember_armor.core.config``
instantiates ``SETTINGS`` at import time and will crash the interpreter
if the secrets are missing.
"""

from __future__ import annotations

import asyncio
import os
import time

# ========================================================================
# 1.  Set mandatory environment variables **BEFORE** any ember_armor import.
# ========================================================================

# Use 32+ character secrets (the minimum enforced by EmberSettings).
_TEST_API_KEY: str = "test-key-32-chars-minimum-for-ci-pipeline"
_TEST_TOKEN_SECRET: str = "test-secret-32-chars-minimum-for-ci-pipeline"

os.environ.setdefault("EMBER_API_KEY", _TEST_API_KEY)
os.environ.setdefault("EMBER_TOKEN_SECRET", _TEST_TOKEN_SECRET)

# ========================================================================
# 2.  Now it is safe to import from ember_armor.
# ========================================================================

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

from ember_armor.api.main import create_app
from ember_armor.core.circuit_breaker import CircuitBreaker
from ember_armor.core.detector import DissonanceDetector
from ember_armor.security.crypto import CryptoEngine


# ---------------------------------------------------------------------------
# Event loop — session-scoped so that async fixtures and tests share it.
# ---------------------------------------------------------------------------
@pytest_asyncio.fixture(scope="session")
async def event_loop() -> asyncio.AbstractEventLoop:
    """Create a session-scoped event loop for all async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# ---------------------------------------------------------------------------
# Settings override
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def test_settings() -> dict:
    """Return the test configuration constants."""
    return {
        "api_key": _TEST_API_KEY,
        "token_secret": _TEST_TOKEN_SECRET,
    }


# ---------------------------------------------------------------------------
# FastAPI TestClient with app created using test env vars.
# ---------------------------------------------------------------------------
@pytest.fixture(scope="function")
def client() -> TestClient:
    """Provide a TestClient for the EmberArmor FastAPI application.

    Uses context-manager mode so lifespan startup/shutdown events fire,
    initialising app.state.detector, app.state.cb_detector, etc.
    """
    # Temporarily raise rate limits so endpoint tests don't starve each other.
    from ember_armor.core.config import SETTINGS
    original_limit = SETTINGS.rate_limit_requests
    SETTINGS.rate_limit_requests = 10000
    try:
        app = create_app()
        with TestClient(app) as c:
            yield c
    finally:
        SETTINGS.rate_limit_requests = original_limit


# ---------------------------------------------------------------------------
# Authenticated request headers.
# ---------------------------------------------------------------------------
@pytest.fixture
def auth_headers(test_settings: dict) -> dict:
    """Return Authorization headers with the valid test API key."""
    return {"Authorization": f"Bearer {test_settings['api_key']}"}


# ---------------------------------------------------------------------------
# CryptoEngine instance.
# ---------------------------------------------------------------------------
@pytest.fixture
def crypto() -> CryptoEngine:
    """Provide a CryptoEngine for direct cryptographic testing."""
    return CryptoEngine()


# ---------------------------------------------------------------------------
# CircuitBreaker with aggressive test parameters.
# ---------------------------------------------------------------------------
@pytest.fixture
def circuit_breaker() -> CircuitBreaker:
    """Provide a CircuitBreaker with fast test tuning."""
    return CircuitBreaker(
        name="test-breaker",
        failure_threshold=5,
        recovery_timeout=0.5,   # Fast recovery for tests.
        window_size=2.0,        # Short window for pruning tests.
    )


# ---------------------------------------------------------------------------
# DissonanceDetector instance.
# ---------------------------------------------------------------------------
@pytest.fixture
def detector() -> DissonanceDetector:
    """Provide a DissonanceDetector for direct detection testing."""
    return DissonanceDetector()
