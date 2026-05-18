"""Rate-limiting middleware tests for EmberArmor v2.

Validates the sliding-window rate limiter: within-limit requests succeed,
excess requests receive 429, windows reset, and different IPs are tracked
independently.  Uses the middleware directly for precise control.
"""

from __future__ import annotations

import time

import pytest
from fastapi import FastAPI, Response
from starlette.testclient import TestClient

from ember_armor.api.middleware import RateLimitMiddleware


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _create_test_app(max_requests: int = 5, window_seconds: int = 60) -> TestClient:
    """Build a minimal app wrapped with RateLimitMiddleware for testing."""
    app = FastAPI()

    @app.get("/test")
    async def test_endpoint() -> dict:
        return {"status": "ok"}

    app.add_middleware(
        RateLimitMiddleware,
        max_requests=max_requests,
        window_seconds=window_seconds,
    )
    # Context-manager mode ensures proper async cleanup between tests.
    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# 1. Within limit succeeds
# ---------------------------------------------------------------------------
def test_within_limit_succeeds() -> None:
    """Requests under the threshold must all succeed with 200."""
    client = _create_test_app(max_requests=5)

    for i in range(5):
        response = client.get("/test")
        assert response.status_code == 200, (
            f"Request {i + 1} should succeed, got {response.status_code}"
        )
        assert response.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# 2. Exceeds limit returns 429
# ---------------------------------------------------------------------------
def test_exceeds_limit_returns_429() -> None:
    """The (max_requests + 1)-th request must return 429."""
    client = _create_test_app(max_requests=5)

    # Send 5 requests (at the limit).
    for _ in range(5):
        client.get("/test")

    # 6th request should be rate-limited.
    response = client.get("/test")
    assert response.status_code == 429
    assert "Rate limit exceeded" in response.text


# ---------------------------------------------------------------------------
# 3. Limit resets after window
# ---------------------------------------------------------------------------
def test_limit_resets_after_window() -> None:
    """After the window expires, the rate limit should reset."""
    window = 0.3  # 300 ms window for fast testing.
    client = _create_test_app(max_requests=2, window_seconds=window)

    # Exhaust the limit.
    client.get("/test")
    client.get("/test")
    blocked = client.get("/test")
    assert blocked.status_code == 429

    # Wait for the window to pass.
    time.sleep(window + 0.1)

    # Should be able to request again.
    response = client.get("/test")
    assert response.status_code == 200, (
        "Rate limit should have reset after window expired"
    )


# ---------------------------------------------------------------------------
# 4. Different IPs are tracked independently
# ---------------------------------------------------------------------------
def test_different_ips_independent() -> None:
    """Rate limiting must be per-IP — one IP's usage must not affect another."""
    client = _create_test_app(max_requests=3)

    # Exhaust limit for IP "1.2.3.4".
    for _ in range(3):
        client.get("/test", headers={"X-Forwarded-For": "1.2.3.4"})
    blocked = client.get("/test", headers={"X-Forwarded-For": "1.2.3.4"})
    assert blocked.status_code == 429

    # A different IP should still be allowed.
    response = client.get("/test", headers={"X-Forwarded-For": "5.6.7.8"})
    assert response.status_code == 200, (
        "Different IP was incorrectly rate-limited"
    )


# ---------------------------------------------------------------------------
# 5. Retry-After header present on 429
# ---------------------------------------------------------------------------
def test_retry_after_header_present() -> None:
    """429 responses must include a Retry-After header."""
    client = _create_test_app(max_requests=2)

    # Exhaust limit.
    client.get("/test")
    client.get("/test")
    response = client.get("/test")

    assert response.status_code == 429
    assert "Retry-After" in response.headers
    # Retry-After should be the window size (60).
    assert response.headers["Retry-After"] == "60"


# ---------------------------------------------------------------------------
# 6. Rate limit counts correctly at boundary.
# ---------------------------------------------------------------------------
def test_exact_boundary_allowed() -> None:
    """Exactly ``max_requests`` requests must all succeed."""
    client = _create_test_app(max_requests=3)

    for i in range(3):
        response = client.get("/test")
        assert response.status_code == 200, (
            f"Request {i + 1} of 3 should succeed"
        )

    # The 4th is blocked.
    assert client.get("/test").status_code == 429
