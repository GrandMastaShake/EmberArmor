from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class SafetyLevel(str, Enum):
    """Safety classification levels for dissonance check results.

    Values:
        SAFE: No contradictions detected.
        CAUTION: Minor contradictions detected — review recommended.
        UNSAFE: Significant contradictions detected — content blocked.
    """

    SAFE = "SAFE"
    CAUTION = "CAUTION"
    UNSAFE = "UNSAFE"


class DissonanceCheckResponse(BaseModel):
    """Response from a dissonance check operation.

    Attributes:
        is_safe: Whether the checked content is considered safe.
        safety_level: The safety classification level.
        confidence: Confidence score (0.0 to 1.0).
        contradiction_score: Contradiction score (0.0 to 1.0).
        detected_patterns: List of regex patterns that matched.
        canary_token: Cryptographic token for exfiltration detection.
        processing_time_ms: Time spent processing in milliseconds.
        session_id: Optional session identifier from the request.
    """

    is_safe: bool = Field(
        ...,
        description="Whether the content passed the safety check",
    )
    safety_level: SafetyLevel = Field(
        ...,
        description="Safety classification level",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score between 0.0 and 1.0",
    )
    contradiction_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Contradiction score between 0.0 and 1.0",
    )
    detected_patterns: list[str] = Field(
        default_factory=list,
        description="Regex patterns that matched during detection",
    )
    canary_token: str = Field(
        ...,
        description="Canary token for exfiltration detection",
    )
    processing_time_ms: float = Field(
        ...,
        description="Processing time in milliseconds",
    )
    session_id: str | None = Field(
        default=None,
        description="Session identifier from the request",
    )


class ComponentHealth(BaseModel):
    """Health status of a single component.

    Attributes:
        name: Component identifier.
        status: One of: healthy | degraded | unhealthy.
        response_time_ms: Check duration in milliseconds.
        detail: Human-readable detail message.
        last_checked: ISO timestamp of the check.
        metadata: Extra check data.
    """

    name: str = Field(..., description="Component identifier")
    status: str = Field(
        ..., description="One of: healthy | degraded | unhealthy"
    )
    response_time_ms: float = Field(
        ..., description="Check duration in milliseconds"
    )
    detail: str | None = Field(
        default=None, description="Human-readable detail message"
    )
    last_checked: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO timestamp of the check",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Extra check data"
    )


class HealthResponse(BaseModel):
    """Health check response with per-component status.

    Attributes:
        status: Aggregated service status (healthy | degraded | unhealthy).
        version: Application version string.
        timestamp: ISO 8601 timestamp of the check.
        uptime_seconds: Service uptime in seconds.
        components: List of component health records.
    """

    status: str = Field(
        ..., description="Aggregated status: healthy | degraded | unhealthy"
    )
    version: str = Field(..., description="Application version")
    timestamp: str = Field(
        ..., description="ISO 8601 timestamp of the health check"
    )
    uptime_seconds: float = Field(
        ..., description="Service uptime in seconds"
    )
    components: list[ComponentHealth] = Field(
        default_factory=list,
        description="Per-component health status records",
    )


class MetricsResponse(BaseModel):
    """Prometheus metrics response.

    Attributes:
        metrics: Raw Prometheus exposition-format metrics text.
    """

    metrics: str = Field(
        ...,
        description="Raw Prometheus text-formatted metrics",
    )
