"""Authenticated Prometheus metrics endpoint for EmberArmor v2.

The ``/metrics`` route is protected by ``Depends(get_current_auth)`` so that
only authorised scrapers (or admins) can pull internal counters and histograms.

Prometheus collectors registered at module-import time are rendered via
:func:`prometheus_client.generate_latest` and returned with the correct
``Content-Type`` header.

EmberArmor-specific counters (independent of prometheus_client):
    * ``checks_total`` — total safety checks performed
    * ``checks_blocked`` — blocked unsafe requests
    * ``auth_failures`` — authentication failures
    * ``consensus_violations`` — consensus UNSAFE decisions
    * ``dissonance_events`` — dissonance detection events
    * ``requests_total`` — total HTTP requests handled
    * ``response_time_ms`` — cumulative response time in ms
"""

from __future__ import annotations

import os

from fastapi import APIRouter, Depends, status
from fastapi.responses import PlainTextResponse

from ember_armor.api.auth import get_current_auth

router = APIRouter()

# ---------------------------------------------------------------------------
# EmberArmor-specific counters (module-level, prometheus-client independent)
# ---------------------------------------------------------------------------

checks_total: int = 0
checks_blocked: int = 0
auth_failures: int = 0
consensus_violations: int = 0
dissonance_events: int = 0
requests_total: int = 0
response_time_ms: float = 0.0


# ---------------------------------------------------------------------------
# Prometheus collectors — defined at import time so they can be imported by
# middleware and core modules.  When prometheus_client is unavailable all
# objects are None and callers must no-op.
# ---------------------------------------------------------------------------

try:
    from prometheus_client import Counter, Histogram

    http_requests_total: Counter | None = Counter(
        "http_requests_total",
        "Total HTTP requests",
        ["method", "path", "status_code"],
    )
    http_request_duration_seconds: Histogram | None = Histogram(
        "http_request_duration_seconds",
        "HTTP request duration in seconds",
        ["method", "path"],
    )
    dissonance_checks_total: Counter | None = Counter(
        "dissonance_checks_total",
        "Total dissonance checks performed",
        ["safety_level"],
    )
except ImportError:
    http_requests_total = None
    http_request_duration_seconds = None
    dissonance_checks_total = None


# ---------------------------------------------------------------------------
# Prometheus text-format export (independent of prometheus_client)
# ---------------------------------------------------------------------------


def export_prometheus() -> str:
    """Export EmberArmor counters in Prometheus text format (0.0.4).

    This function is always available even when ``prometheus_client`` is
    not installed, providing a fallback metrics source.

    Returns
    -------
    str
        Prometheus text-format metrics with HELP and TYPE annotations.
    """
    lines: list[str] = []

    # checks_total
    lines.append("# HELP emberarmor_checks_total Total safety checks performed")
    lines.append("# TYPE emberarmor_checks_total counter")
    lines.append(f"emberarmor_checks_total {checks_total}")

    # checks_blocked
    lines.append("# HELP emberarmor_checks_blocked Blocked unsafe requests")
    lines.append("# TYPE emberarmor_checks_blocked counter")
    lines.append(f"emberarmor_checks_blocked {checks_blocked}")

    # auth_failures
    lines.append("# HELP emberarmor_auth_failures Authentication failures")
    lines.append("# TYPE emberarmor_auth_failures counter")
    lines.append(f"emberarmor_auth_failures {auth_failures}")

    # consensus_violations
    lines.append(
        "# HELP emberarmor_consensus_violations Consensus UNSAFE decisions"
    )
    lines.append("# TYPE emberarmor_consensus_violations counter")
    lines.append(f"emberarmor_consensus_violations {consensus_violations}")

    # dissonance_events
    lines.append("# HELP emberarmor_dissonance_events Dissonance detection events")
    lines.append("# TYPE emberarmor_dissonance_events counter")
    lines.append(f"emberarmor_dissonance_events {dissonance_events}")

    # requests_total
    lines.append("# HELP emberarmor_requests_total Total HTTP requests handled")
    lines.append("# TYPE emberarmor_requests_total counter")
    lines.append(f"emberarmor_requests_total {requests_total}")

    # response_time_ms
    lines.append(
        "# HELP emberarmor_response_time_ms Cumulative response time in ms"
    )
    lines.append("# TYPE emberarmor_response_time_ms counter")
    lines.append(f"emberarmor_response_time_ms {response_time_ms:.2f}")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Counter helpers (safe to call from any module)
# ---------------------------------------------------------------------------


def increment_checks_total() -> None:
    """Increment the total safety checks counter."""
    global checks_total
    checks_total += 1


def increment_checks_blocked() -> None:
    """Increment the blocked unsafe requests counter."""
    global checks_blocked
    checks_blocked += 1


def increment_auth_failures() -> None:
    """Increment the authentication failures counter."""
    global auth_failures
    auth_failures += 1


def increment_consensus_violations() -> None:
    """Increment the consensus violations counter."""
    global consensus_violations
    consensus_violations += 1


def increment_dissonance_events() -> None:
    """Increment the dissonance events counter."""
    global dissonance_events
    dissonance_events += 1


def increment_requests_total() -> None:
    """Increment the total HTTP requests counter."""
    global requests_total
    requests_total += 1


def add_response_time_ms(ms: float) -> None:
    """Add response time to the cumulative counter."""
    global response_time_ms
    response_time_ms += ms


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------


@router.get("/metrics", status_code=status.HTTP_200_OK)
async def metrics(
    auth: str = Depends(get_current_auth),
) -> PlainTextResponse:
    """Authenticated metrics endpoint — returns Prometheus exposition format.

    Parameters
    ----------
    auth:
        Validated API-key string (injected by ``get_current_auth``).

    Returns
    -------
    PlainTextResponse
        Prometheus text-format metrics with ``Content-Type`` set to
        ``text/plain; version=0.0.4; charset=utf-8``.
    """
    content_parts: list[str] = []

    # Always include EmberArmor-specific counters
    content_parts.append(export_prometheus())

    # If prometheus_client is available, append its collectors
    try:
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

        content_parts.append(generate_latest().decode("utf-8"))
    except ImportError:
        content_parts.append(
            "# Prometheus client not installed — only EmberArmor counters available\n"
        )

    full_content = "\n".join(content_parts)

    return PlainTextResponse(
        content=full_content,
        media_type=CONTENT_TYPE_LATEST
        if "prometheus_client" in globals()
        else "text/plain; version=0.0.4; charset=utf-8",
    )