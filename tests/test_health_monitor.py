"""Comprehensive tests for EmberArmor health check and monitoring system.

Tests cover:
    * Health response endpoint (GET /health)
    * Component health model and aggregation
    * Prometheus metrics export format (GET /v1/metrics)
    * Monitoring model validation (Pydantic)

Total: 26 tests across 4 test classes.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from ember_armor.api.routes.metrics import (
    export_prometheus,
    increment_checks_total,
    increment_dissonance_events,
)
from ember_armor.monitoring import (
    ComponentHealth,
    HealthChecker,
    HealthStatus,
    MetricsCollector,
    Status,
)
from ember_armor.models.responses import (
    ComponentHealth as ComponentHealthResponse,
    DissonanceCheckResponse,
    HealthResponse,
    MetricsResponse,
    SafetyLevel,
)


# ===========================================================================
# Test Class 1: Health Response Endpoint (8 tests)
# ===========================================================================


class TestHealthResponse:
    """Tests for the GET /health endpoint."""

    def test_health_status_is_string(self, client: TestClient, auth_headers: dict) -> None:
        """The top-level status field must be a string."""
        response = client.get("/health", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data["status"], str)

    def test_health_version_present(self, client: TestClient, auth_headers: dict) -> None:
        """The version field must be present and match the app version."""
        response = client.get("/health", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "version" in data
        assert data["version"] == "0.2.0"

    def test_health_timestamp_iso8601(self, client: TestClient, auth_headers: dict) -> None:
        """The timestamp must be a valid ISO 8601 string."""
        response = client.get("/health", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        ts = data["timestamp"]
        assert isinstance(ts, str)
        # Must be parseable as ISO 8601 datetime
        parsed = datetime.fromisoformat(ts)
        assert parsed.tzinfo is not None

    def test_health_uptime_positive(self, client: TestClient, auth_headers: dict) -> None:
        """Uptime must be a non-negative number."""
        response = client.get("/health", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        uptime = data["uptime_seconds"]
        assert isinstance(uptime, (int, float))
        assert uptime >= 0.0

    def test_health_components_list(self, client: TestClient, auth_headers: dict) -> None:
        """Components must be a list with at least one element."""
        response = client.get("/health", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        components = data["components"]
        assert isinstance(components, list)
        assert len(components) >= 1

    def test_component_has_required_fields(self, client: TestClient, auth_headers: dict) -> None:
        """Each component must have the required health fields."""
        response = client.get("/health", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        for comp in data["components"]:
            assert "name" in comp
            assert "status" in comp
            assert "response_time_ms" in comp
            assert "last_checked" in comp

    def test_component_status_values(self, client: TestClient, auth_headers: dict) -> None:
        """Each component status must be one of: healthy, degraded, unhealthy."""
        response = client.get("/health", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        valid = {"healthy", "degraded", "unhealthy"}
        for comp in data["components"]:
            assert comp["status"] in valid, (
                f"Unexpected status {comp['status']!r} for {comp['name']}"
            )

    def test_health_overall_healthy(self, client: TestClient, auth_headers: dict) -> None:
        """Overall status must be one of the three valid states."""
        response = client.get("/health", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in {"healthy", "degraded", "unhealthy"}


# ===========================================================================
# Test Class 2: Component Health (6 tests)
# ===========================================================================


class TestComponentHealth:
    """Tests for ComponentHealth creation and properties."""

    def test_component_creation(self) -> None:
        """A ComponentHealth can be created with all required fields."""
        comp = ComponentHealth(
            name="test-service",
            status="healthy",
            response_time_ms=12.34,
            detail="All systems nominal",
        )
        assert comp.name == "test-service"
        assert comp.status == "healthy"
        assert comp.response_time_ms == 12.34
        assert comp.detail == "All systems nominal"
        assert comp.last_checked is not None

    def test_component_status_healthy(self) -> None:
        """Status 'healthy' is valid."""
        comp = ComponentHealth(
            name="svc",
            status="healthy",
            response_time_ms=1.0,
        )
        assert comp.status == Status.HEALTHY.value

    def test_component_status_degraded(self) -> None:
        """Status 'degraded' is valid."""
        comp = ComponentHealth(
            name="svc",
            status="degraded",
            response_time_ms=5.0,
        )
        assert comp.status == Status.DEGRADED.value

    def test_component_status_unhealthy(self) -> None:
        """Status 'unhealthy' is valid."""
        comp = ComponentHealth(
            name="svc",
            status="unhealthy",
            response_time_ms=0.0,
        )
        assert comp.status == Status.UNHEALTHY.value

    def test_component_response_time_positive(self) -> None:
        """Response time must be a non-negative float."""
        comp_fast = ComponentHealth(
            name="fast",
            status="healthy",
            response_time_ms=0.01,
        )
        comp_slow = ComponentHealth(
            name="slow",
            status="healthy",
            response_time_ms=1500.50,
        )
        assert comp_fast.response_time_ms >= 0.0
        assert comp_slow.response_time_ms >= 0.0

    def test_component_last_checked_timestamp(self) -> None:
        """last_checked must be a valid ISO 8601 timestamp."""
        comp = ComponentHealth(
            name="svc",
            status="healthy",
            response_time_ms=1.0,
        )
        parsed = datetime.fromisoformat(comp.last_checked)
        assert parsed.tzinfo is not None
        # Must be recent (within last minute)
        now = datetime.now(timezone.utc)
        diff = (now - parsed).total_seconds()
        assert diff < 60.0


# ===========================================================================
# Test Class 3: Prometheus Metrics (6 tests)
# ===========================================================================


class TestPrometheusMetrics:
    """Tests for Prometheus metrics export format."""

    def test_metrics_is_string(self) -> None:
        """export_prometheus() must return a string."""
        output = export_prometheus()
        assert isinstance(output, str)

    def test_metrics_has_dissonance_checks(self) -> None:
        """The exported metrics must include dissonance event counters."""
        output = export_prometheus()
        assert "dissonance_events" in output

    def test_metrics_prometheus_format(self) -> None:
        """The output must conform to Prometheus text format (0.0.4)."""
        output = export_prometheus()
        # Must start with HELP or TYPE comment, or a metric line
        lines = output.strip().split("\n")
        assert len(lines) > 0
        # Every metric name must follow prometheus naming convention
        for line in lines:
            if line.startswith("#"):
                continue
            if line.strip() == "":
                continue
            # Metric line format: metric_name{labels} value
            match = re.match(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)", line)
            assert match is not None, f"Invalid metric line: {line!r}"

    def test_metrics_counter_increment(self) -> None:
        """Counters must reflect increments after incrementing."""
        # Reset and increment
        from ember_armor.api.routes import metrics as metrics_module

        original = metrics_module.checks_total
        try:
            metrics_module.checks_total = 0
            increment_checks_total()
            output = export_prometheus()
            # Find the checks_total line and verify value is 1
            for line in output.strip().split("\n"):
                if line.startswith("emberarmor_checks_total "):
                    _, value = line.rsplit(" ", 1)
                    assert int(value) == 1
                    break
            else:
                pytest.fail("checks_total metric line not found")
        finally:
            metrics_module.checks_total = original

    def test_metrics_help_comment(self) -> None:
        """Each metric family must have a HELP comment."""
        output = export_prometheus()
        help_lines = [ln for ln in output.split("\n") if ln.startswith("# HELP")]
        assert len(help_lines) > 0
        # HELP lines must contain metric name and description
        for line in help_lines:
            parts = line.split(" ", 2)
            assert len(parts) == 3
            assert parts[0] == "#"
            assert parts[1] == "HELP"

    def test_metrics_type_comment(self) -> None:
        """Each metric family must have a TYPE comment."""
        output = export_prometheus()
        type_lines = [ln for ln in output.split("\n") if ln.startswith("# TYPE")]
        assert len(type_lines) > 0
        # TYPE lines must contain metric name and type (counter, gauge, etc.)
        for line in type_lines:
            parts = line.split(" ", 2)
            assert len(parts) == 3
            assert parts[0] == "#"
            assert parts[1] == "TYPE"
            assert parts[2].split()[-1] in {"counter", "gauge", "histogram", "summary"}


# ===========================================================================
# Test Class 4: Monitoring Model Validation (6 tests)
# ===========================================================================


class TestMonitoringModels:
    """Pydantic model validation tests for health and monitoring models."""

    def test_health_response_valid(self) -> None:
        """HealthResponse validates with all required fields."""
        hr = HealthResponse(
            status="healthy",
            version="0.2.0",
            timestamp=datetime.now(timezone.utc).isoformat(),
            uptime_seconds=42.5,
            components=[
                ComponentHealthResponse(
                    name="auth",
                    status="healthy",
                    response_time_ms=1.23,
                    detail="Auth OK",
                ),
            ],
        )
        assert hr.status == "healthy"
        assert hr.version == "0.2.0"
        assert len(hr.components) == 1

    def test_health_response_missing_field_fails(self) -> None:
        """HealthResponse raises ValidationError when required fields are missing."""
        with pytest.raises(ValidationError):
            HealthResponse(
                status="healthy",
                # Missing version, timestamp, uptime_seconds
            )

    def test_component_health_valid(self) -> None:
        """ComponentHealthResponse validates with all required fields."""
        comp = ComponentHealthResponse(
            name="detector",
            status="healthy",
            response_time_ms=3.14,
            detail="Detector healthy",
        )
        assert comp.name == "detector"
        assert comp.metadata == {}  # Default empty dict

    def test_metrics_response_valid(self) -> None:
        """MetricsResponse validates with metrics string."""
        mr = MetricsResponse(
            metrics="# HELP test_total Test metric\n# TYPE test_total counter\ntest_total 1\n",
        )
        assert "test_total" in mr.metrics

    def test_dissonance_response_valid(self) -> None:
        """DissonanceCheckResponse validates with a safe result."""
        dr = DissonanceCheckResponse(
            is_safe=True,
            safety_level=SafetyLevel.SAFE,
            confidence=0.95,
            contradiction_score=0.02,
            canary_token="tok-abc-123",
            processing_time_ms=15.2,
        )
        assert dr.is_safe is True
        assert dr.safety_level == SafetyLevel.SAFE
        assert dr.confidence == 0.95

    def test_dissonance_response_unsafe_valid(self) -> None:
        """DissonanceCheckResponse validates with an unsafe result."""
        dr = DissonanceCheckResponse(
            is_safe=False,
            safety_level=SafetyLevel.UNSAFE,
            confidence=0.15,
            contradiction_score=0.88,
            canary_token="tok-xyz-789",
            processing_time_ms=45.7,
            detected_patterns=["pattern-A", "pattern-B"],
            session_id="sess-001",
        )
        assert dr.is_safe is False
        assert dr.safety_level == SafetyLevel.UNSAFE
        assert len(dr.detected_patterns) == 2
        assert dr.session_id == "sess-001"
