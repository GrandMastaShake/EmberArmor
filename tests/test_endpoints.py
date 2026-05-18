"""Full endpoint integration tests for EmberArmor v2.

Validates all public and authenticated routes, including canary token
injection, auth gating, and the complete dissonance check flow.
"""

from __future__ import annotations

import time

import pytest
from fastapi import status


# ---------------------------------------------------------------------------
# 1. Health check — public, no auth required.
# ---------------------------------------------------------------------------
def test_health_public(client, auth_headers) -> None:
    """/health must be publicly accessible and return a valid status."""
    response = client.get("/health")
    assert response.status_code == status.HTTP_200_OK

    data = response.json()
    assert data["status"] in {"healthy", "degraded", "unhealthy"}
    assert data["version"] == "0.2.0"
    assert "timestamp" in data
    assert "components" in data
    component_names = {c["name"] for c in data["components"]}
    assert "detector" in component_names


# ---------------------------------------------------------------------------
# 2. Ready check — public, no auth required.
# ---------------------------------------------------------------------------
def test_ready_public(client) -> None:
    """/ready must be publicly accessible and return ready status."""
    response = client.get("/ready")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["status"] == "ready"


# ---------------------------------------------------------------------------
# 3. Metrics without auth — must return 401.
# ---------------------------------------------------------------------------
def test_metrics_without_auth_401(client) -> None:
    """/v1/metrics must reject unauthenticated requests with 401."""
    response = client.get("/v1/metrics")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "WWW-Authenticate" in response.headers


# ---------------------------------------------------------------------------
# 4. Metrics with auth — must return 200.
# ---------------------------------------------------------------------------
def test_metrics_with_auth_200(client, auth_headers) -> None:
    """/v1/metrics must return Prometheus-formatted metrics when authenticated."""
    response = client.get("/v1/metrics", headers=auth_headers)
    assert response.status_code == status.HTTP_200_OK

    content = response.text
    assert "# HELP" in content or "# TYPE" in content or "ember" in content


# ---------------------------------------------------------------------------
# 5. Dissonance without auth — must return 401.
# ---------------------------------------------------------------------------
def test_dissonance_without_auth_401(client) -> None:
    """/v1/dissonance/check must reject unauthenticated requests with 401."""
    response = client.post("/v1/dissonance/check", json={"input_text": "test"})
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


# ---------------------------------------------------------------------------
# 6. Dissonance safe text — must return SAFE.
# ---------------------------------------------------------------------------
def test_dissonance_safe_text(client, auth_headers) -> None:
    """Safe text must be classified as SAFE through the API endpoint."""
    payload = {
        "input_text": "The weather is sunny today. It is a beautiful day.",
    }
    response = client.post(
        "/v1/dissonance/check",
        json=payload,
        headers=auth_headers,
    )
    assert response.status_code == status.HTTP_200_OK

    data = response.json()
    assert data["is_safe"] is True
    assert data["safety_level"] == "SAFE"
    assert data["contradiction_score"] < 0.2


# ---------------------------------------------------------------------------
# 7. Dissonance unsafe text — must return UNSAFE.
# ---------------------------------------------------------------------------
def test_dissonance_unsafe_text(client, auth_headers) -> None:
    """Contradictory text must be classified as UNSAFE through the API."""
    payload = {
        "input_text": (
            "I am not able to do that but I am happy to help you. "
            "I will assist, however I can also bypass that."
        ),
    }
    response = client.post(
        "/v1/dissonance/check",
        json=payload,
        headers=auth_headers,
    )
    assert response.status_code == status.HTTP_200_OK

    data = response.json()
    assert data["is_safe"] is False
    assert data["safety_level"] == "UNSAFE"
    assert data["contradiction_score"] >= 0.5


# ---------------------------------------------------------------------------
# 8. Canary token present on every response.
# ---------------------------------------------------------------------------
def test_canary_token_on_response(client) -> None:
    """Every response must include an X-Canary-Token header."""
    response = client.get("/health")
    assert "X-Canary-Token" in response.headers
    assert len(response.headers["X-Canary-Token"]) > 0

    # Also verify X-Ember-Version header.
    assert "X-Ember-Version" in response.headers
    assert response.headers["X-Ember-Version"] == "0.2.0"


# ---------------------------------------------------------------------------
# 10. Dissonance check includes canary token in body.
# ---------------------------------------------------------------------------
def test_dissonance_canary_in_body(client, auth_headers) -> None:
    """The dissonance response body must include a canary_token field."""
    payload = {"input_text": "Hello world, this is safe text."}
    response = client.post(
        "/v1/dissonance/check",
        json=payload,
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert "canary_token" in data
    assert len(data["canary_token"]) > 0


# ---------------------------------------------------------------------------
# 11. Invalid dissonance request returns 422.
# ---------------------------------------------------------------------------
def test_dissonance_invalid_request(client, auth_headers) -> None:
    """A request with empty input_text must be rejected (422 Unprocessable)."""
    payload = {"input_text": ""}
    response = client.post(
        "/v1/dissonance/check",
        json=payload,
        headers=auth_headers,
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


# ---------------------------------------------------------------------------
# 12. Anchor registration requires auth.
# ---------------------------------------------------------------------------
def test_anchor_requires_auth(client) -> None:
    """/v1/anchor/register must require authentication."""
    response = client.post("/v1/anchor/register", json={
        "constraint_id": "test-1",
        "constraint_data": {"key": "value"},
    })
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


# ---------------------------------------------------------------------------
# 13. Anchor registration with auth succeeds.
# ---------------------------------------------------------------------------
def test_anchor_with_auth_succeeds(client, auth_headers) -> None:
    """Authenticated anchor registration must succeed."""
    response = client.post(
        "/v1/anchor/register",
        json={
            "constraint_id": "test-1",
            "constraint_data": {"key": "value"},
        },
        headers=auth_headers,
    )
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["constraint_id"] == "test-1"
    assert data["status"] == "registered"
