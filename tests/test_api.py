"""Comprehensive API route tests for EmberArmor v2 FastAPI endpoints.

This module covers all public and authenticated routes with full validation
of request/response models, auth behaviour, error paths, and circuit-breaker
states.  It uses the FastAPI ``TestClient`` and relies on the shared
``conftest.py`` fixtures (``client``, ``auth_headers``).

Test inventory
--------------
* TestHealthEndpoints      -- 5 tests
* TestAuth                 -- 6 tests
* TestDissonanceEndpoint   -- 8 tests
* TestErrorHandling        -- 5 tests

Total: 24 tests.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from ember_armor.core.circuit_breaker import CircuitBreakerOpen
from ember_armor.models.responses import DissonanceCheckResponse, SafetyLevel


# ---------------------------------------------------------------------------
# Test Class 1: Health Endpoints (5 tests)
# ---------------------------------------------------------------------------


class TestHealthEndpoints:
    """Validate the public health, readiness, and metrics probes."""

    def test_health_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        """/health must respond with HTTP 200."""
        response = client.get("/health", headers=auth_headers)
        assert response.status_code == status.HTTP_200_OK

    def test_health_has_status_field(self, client: TestClient, auth_headers: dict) -> None:
        """The health JSON must contain a top-level *status* field."""
        response = client.get("/health", headers=auth_headers)
        data = response.json()
        assert "status" in data
        assert data["status"] in {"healthy", "degraded", "unhealthy"}

    def test_health_has_components(self, client: TestClient, auth_headers: dict) -> None:
        """The health JSON must include a *components* list with all subsystems."""
        response = client.get("/health", headers=auth_headers)
        data = response.json()
        assert "components" in data
        assert isinstance(data["components"], list)
        component_names = {c["name"] for c in data["components"]}
        expected = {"auth", "circuit_breaker", "consensus", "detector"}
        assert expected.issubset(component_names), (
            f"Missing components: {expected - component_names}"
        )

    def test_ready_returns_200(self, client: TestClient) -> None:
        """/ready must respond with HTTP 200 and {"status": "ready"}."""
        response = client.get("/ready")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data.get("status") == "ready"

    def test_metrics_returns_prometheus_format(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """/v1/metrics must return Prometheus text-format with HELP/TYPE lines."""
        response = client.get("/v1/metrics", headers=auth_headers)
        assert response.status_code == status.HTTP_200_OK
        content = response.text
        assert "# HELP" in content or "# TYPE" in content
        # Ensure EmberArmor-specific counters are present.
        assert "emberarmor_checks_total" in content
        assert "emberarmor_requests_total" in content


# ---------------------------------------------------------------------------
# Test Class 2: Auth (6 tests)
# ---------------------------------------------------------------------------


class TestAuth:
    """Validate authentication via ``Authorization: Bearer <key>`` header."""

    def test_missing_api_key_returns_401(self, client: TestClient) -> None:
        """A request with no Authorization header must receive 401."""
        response = client.get("/v1/metrics")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "WWW-Authenticate" in response.headers
        assert "Bearer" in response.headers["WWW-Authenticate"]

    def test_invalid_api_key_returns_401(self, client: TestClient) -> None:
        """A request with a wrong Bearer token must receive 401."""
        headers = {"Authorization": "Bearer invalid-key-for-testing-purposes"}
        response = client.get("/v1/metrics", headers=headers)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_valid_api_key_returns_200(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """A request with the correct Bearer token must succeed."""
        response = client.get("/v1/metrics", headers=auth_headers)
        assert response.status_code == status.HTTP_200_OK

    def test_api_key_header_name(self, client: TestClient) -> None:
        """Auth must be conveyed via the standard ``Authorization`` header."""
        # A request with a made-up header name must still be rejected.
        headers = {"X-API-Key": "some-key"}
        response = client.get("/v1/metrics", headers=headers)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_dissonance_without_auth_fails(self, client: TestClient) -> None:
        """POST /v1/dissonance/check without auth must return 401."""
        response = client.post(
            "/v1/dissonance/check", json={"input_text": "test"}
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_dissonance_with_auth_succeeds(
        self,
        client: TestClient,
        auth_headers: dict,
    ) -> None:
        """POST /v1/dissonance/check with valid auth must return 200."""
        payload = {"input_text": "Hello world, this is safe text."}
        response = client.post(
            "/v1/dissonance/check",
            json=payload,
            headers=auth_headers,
        )
        assert response.status_code == status.HTTP_200_OK


# ---------------------------------------------------------------------------
# Test Class 3: Dissonance Endpoint (8 tests)
# ---------------------------------------------------------------------------


class TestDissonanceEndpoint:
    """Deep validation of the /v1/dissonance/check route."""

    # -- 1. safe text -------------------------------------------------------

    def test_safe_text(
        self,
        client: TestClient,
        auth_headers: dict,
    ) -> None:
        """Safe input must yield is_safe=True and safety_level SAFE."""
        payload = {"input_text": "The weather is sunny today."}
        response = client.post(
            "/v1/dissonance/check",
            json=payload,
            headers=auth_headers,
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["is_safe"] is True
        assert data["safety_level"] == "SAFE"
        assert data["contradiction_score"] < 0.5

    # -- 2. unsafe text -----------------------------------------------------

    def test_unsafe_text(
        self,
        client: TestClient,
        auth_headers: dict,
    ) -> None:
        """Contradictory input must yield is_safe=False and safety_level UNSAFE."""
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

    # -- 3. empty text validation -------------------------------------------

    def test_empty_text_validation(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """Empty input_text must be rejected with 422 Unprocessable Entity."""
        payload = {"input_text": ""}
        response = client.post(
            "/v1/dissonance/check",
            json=payload,
            headers=auth_headers,
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    # -- 4. long text -------------------------------------------------------

    def test_long_text(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """Text near the 10 000-char limit must be accepted and processed."""
        long_text = "A" * 9000
        payload = {"input_text": long_text}
        response = client.post(
            "/v1/dissonance/check",
            json=payload,
            headers=auth_headers,
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "is_safe" in data
        assert "safety_level" in data

    # -- 5. response model fields -------------------------------------------

    def test_response_model_fields(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """The response must contain every field defined in
        DissonanceCheckResponse."""
        payload = {"input_text": "Hello world, this is safe text."}
        response = client.post(
            "/v1/dissonance/check",
            json=payload,
            headers=auth_headers,
        )
        data = response.json()
        required_fields = {
            "is_safe",
            "safety_level",
            "confidence",
            "contradiction_score",
            "detected_patterns",
            "canary_token",
            "processing_time_ms",
            "session_id",
        }
        assert required_fields.issubset(set(data.keys()))
        # Validate field types / constraints.
        assert isinstance(data["is_safe"], bool)
        assert data["safety_level"] in {"SAFE", "CAUTION", "UNSAFE"}
        assert 0.0 <= data["confidence"] <= 1.0
        assert 0.0 <= data["contradiction_score"] <= 1.0
        assert isinstance(data["detected_patterns"], list)
        assert isinstance(data["canary_token"], str)
        assert len(data["canary_token"]) > 0
        assert isinstance(data["processing_time_ms"], (int, float))
        assert data["processing_time_ms"] >= 0

    # -- 6. circuit breaker open returns 503 --------------------------------

    def test_circuit_breaker_open_returns_503(
        self,
        client: TestClient,
        auth_headers: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When the circuit breaker is OPEN the endpoint must return 503."""
        # Replace the circuit breaker's call method so it always raises.
        cb = client.app.state.cb_detector

        async def _always_open(*args, **kwargs):
            raise CircuitBreakerOpen("Circuit detector is OPEN")

        monkeypatch.setattr(cb, "call", _always_open)

        payload = {"input_text": "Any text here should trigger 503."}
        response = client.post(
            "/v1/dissonance/check",
            json=payload,
            headers=auth_headers,
        )
        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        detail = response.json().get("detail", "")
        assert "unavailable" in detail.lower() or "temporarily" in detail.lower()

    # -- 7. session_id preserved --------------------------------------------

    def test_session_id_preserved(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """If the request provides a context_id, it must be echoed as
        session_id in the response (the route forwards context_id to the
        detector which maps it to session_id)."""
        context_id = "test-session-42"
        payload = {
            "input_text": "Hello world, this is safe text.",
            "context_id": context_id,
        }
        response = client.post(
            "/v1/dissonance/check",
            json=payload,
            headers=auth_headers,
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data.get("session_id") == context_id

    # -- 8. rate limiting ---------------------------------------------------

    def test_rate_limiting(
        self,
        client: TestClient,
        auth_headers: dict,
    ) -> None:
        """Exceeding the rate limit must yield HTTP 429 Too Many Requests."""

        def _find_rate_limit_mw(app):
            """Traverse the middleware stack to find the
            RateLimitMiddleware instance."""
            from ember_armor.api.middleware import RateLimitMiddleware

            current = getattr(app, "middleware_stack", app)
            visited = set()
            while current is not None and id(current) not in visited:
                visited.add(id(current))
                if isinstance(current, RateLimitMiddleware):
                    return current
                # Middleware wraps 'app' inside -- try both attributes.
                for attr in ("app", "_app", "_dispatch"):
                    nxt = getattr(current, attr, None)
                    if nxt is not None and nxt is not current:
                        current = nxt
                        break
                else:
                    current = None
            return None

        rl_mw = _find_rate_limit_mw(client.app)
        assert rl_mw is not None, "RateLimitMiddleware not found in stack"

        # Temporarily lower the threshold and clear state.
        original_max = rl_mw.max_requests
        rl_mw.max_requests = 2
        rl_mw._requests.clear()

        try:
            path = "/ready"  # Public endpoint -- easiest to hammer.
            responses = [client.get(path) for _ in range(5)]
            status_codes = [r.status_code for r in responses]

            # At least one request must be rate-limited (429).
            assert 429 in status_codes, (
                f"Expected at least one 429, got: {status_codes}"
            )
        finally:
            rl_mw.max_requests = original_max


# ---------------------------------------------------------------------------
# Test Class 4: Error Handling (5 tests)
# ---------------------------------------------------------------------------


class TestErrorHandling:
    """Validate edge-case error responses from the API."""

    def test_404_for_unknown_path(self, client: TestClient) -> None:
        """A request to an undefined path must return 404."""
        response = client.get("/this-path-definitely-does-not-exist")
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_validation_error_format(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """A Pydantic validation error must produce the standard FastAPI
        422 response shape with ``detail``."""
        # Missing required field input_text.
        payload = {"context_id": "test"}
        response = client.post(
            "/v1/dissonance/check",
            json=payload,
            headers=auth_headers,
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        data = response.json()
        assert "detail" in data
        assert isinstance(data["detail"], list)

    def test_circuit_breaker_open_error(
        self,
        client: TestClient,
        auth_headers: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """CircuitBreakerOpen must surface as 503 with a descriptive detail."""
        cb = client.app.state.cb_detector

        async def _raise_cbo(*args, **kwargs):
            raise CircuitBreakerOpen("Simulated OPEN state")

        monkeypatch.setattr(cb, "call", _raise_cbo)

        payload = {"input_text": "Trigger circuit breaker."}
        response = client.post(
            "/v1/dissonance/check",
            json=payload,
            headers=auth_headers,
        )
        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        detail = response.json().get("detail", "")
        assert detail != ""

    def test_method_not_allowed(self, client: TestClient) -> None:
        """Using the wrong HTTP method on a defined route must return 405."""
        response = client.post("/health")
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    def test_malformed_json(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """Sending malformed JSON must result in a 422 error."""
        response = client.post(
            "/v1/dissonance/check",
            content="not-valid-json-at-all{{{",
            headers={**auth_headers, "Content-Type": "application/json"},
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
