"""Public health and readiness endpoints.

The ``/health`` endpoint supports two modes:
* **shallow** — Fast liveness probe (returns immediately with basic status).
* **deep**    — Full component exercise: queries each subsystem
  (auth, circuit_breaker, consensus, detector) for its health status
  and aggregates results into a ComponentHealth list.

The response model follows the Corporeus Phase 6 pattern:
:class:`ComponentHealth` records per subsystem with status,
response time, and metadata.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Request, status

from ember_armor.models.responses import ComponentHealth, HealthResponse
from ember_armor.utils.logging import logger

router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _aggregate_status(components: list[ComponentHealth]) -> str:
    """Aggregate component statuses into overall status.

    Rules:
        * Any ``unhealthy`` → overall ``unhealthy``.
        * Any ``degraded``  → overall ``degraded``.
        * All ``healthy``   → overall ``healthy``.
    """
    statuses = [c.status for c in components]
    if any(s == "unhealthy" for s in statuses):
        return "unhealthy"
    if any(s == "degraded" for s in statuses):
        return "degraded"
    return "healthy"


# ---------------------------------------------------------------------------
# Shallow component checks (fast probes)
# ---------------------------------------------------------------------------


async def _check_auth_shallow() -> ComponentHealth:
    """Shallow auth check: verify auth module is importable."""
    start = time.perf_counter()
    try:
        from ember_armor.api.auth import get_current_auth

        return ComponentHealth(
            name="auth",
            status="healthy",
            response_time_ms=round((time.perf_counter() - start) * 1000, 2),
            detail="Auth module loaded",
        )
    except Exception as exc:
        return ComponentHealth(
            name="auth",
            status="unhealthy",
            response_time_ms=round((time.perf_counter() - start) * 1000, 2),
            detail=f"Auth module error: {exc}",
        )


async def _check_circuit_breaker_shallow(
    request: Request,
) -> ComponentHealth:
    """Shallow circuit-breaker check: verify instance exists."""
    start = time.perf_counter()
    try:
        cb = getattr(request.app.state, "cb_detector", None)
        if cb is None:
            return ComponentHealth(
                name="circuit_breaker",
                status="degraded",
                response_time_ms=round(
                    (time.perf_counter() - start) * 1000, 2
                ),
                detail="Circuit breaker not initialised (cold start)",
            )
        state = await cb.get_state()
        return ComponentHealth(
            name="circuit_breaker",
            status="healthy",
            response_time_ms=round((time.perf_counter() - start) * 1000, 2),
            detail=f"Circuit breaker is {state.value}",
            metadata={"state": state.value},
        )
    except Exception as exc:
        return ComponentHealth(
            name="circuit_breaker",
            status="unhealthy",
            response_time_ms=round((time.perf_counter() - start) * 1000, 2),
            detail=f"Circuit breaker error: {exc}",
        )


async def _check_consensus_shallow(request: Request) -> ComponentHealth:
    """Shallow consensus check: verify conductor instance exists."""
    start = time.perf_counter()
    try:
        conductor = getattr(request.app.state, "conductor", None)
        if conductor is None:
            return ComponentHealth(
                name="consensus",
                status="degraded",
                response_time_ms=round(
                    (time.perf_counter() - start) * 1000, 2
                ),
                detail="Consensus conductor not initialised (cold start)",
            )
        result = conductor.health_check()
        return ComponentHealth(
            name="consensus",
            status=result["status"],
            response_time_ms=result["response_time_ms"],
            detail=result["detail"],
            metadata=result.get("metadata", {}),
        )
    except Exception as exc:
        return ComponentHealth(
            name="consensus",
            status="unhealthy",
            response_time_ms=round((time.perf_counter() - start) * 1000, 2),
            detail=f"Consensus error: {exc}",
        )


async def _check_detector_shallow(request: Request) -> ComponentHealth:
    """Shallow detector check: verify detector instance exists."""
    start = time.perf_counter()
    try:
        detector = getattr(request.app.state, "detector", None)
        if detector is None:
            return ComponentHealth(
                name="detector",
                status="degraded",
                response_time_ms=round(
                    (time.perf_counter() - start) * 1000, 2
                ),
                detail="Detector not initialised (cold start)",
            )
        result = detector.health_check()
        return ComponentHealth(
            name="detector",
            status=result["status"],
            response_time_ms=result["response_time_ms"],
            detail=result["detail"],
            metadata=result.get("metadata", {}),
        )
    except Exception as exc:
        return ComponentHealth(
            name="detector",
            status="unhealthy",
            response_time_ms=round((time.perf_counter() - start) * 1000, 2),
            detail=f"Detector error: {exc}",
        )


# ---------------------------------------------------------------------------
# Deep component checks (full subsystem exercise)
# ---------------------------------------------------------------------------


async def _check_auth_deep() -> ComponentHealth:
    """Deep auth check: exercise the auth dependency."""
    start = time.perf_counter()
    try:
        from ember_armor.api.auth import get_current_auth

        # Verify callable signature is intact
        import inspect

        sig = inspect.signature(get_current_auth)
        return ComponentHealth(
            name="auth",
            status="healthy",
            response_time_ms=round((time.perf_counter() - start) * 1000, 2),
            detail=f"Auth dependency healthy (params: {len(sig.parameters)})",
            metadata={"params": len(sig.parameters)},
        )
    except Exception as exc:
        return ComponentHealth(
            name="auth",
            status="unhealthy",
            response_time_ms=round((time.perf_counter() - start) * 1000, 2),
            detail=f"Auth deep check failed: {exc}",
        )


async def _check_circuit_breaker_deep(
    request: Request,
) -> ComponentHealth:
    """Deep circuit-breaker check: run health_check() + exercise state."""
    start = time.perf_counter()
    try:
        cb = getattr(request.app.state, "cb_detector", None)
        if cb is None:
            return ComponentHealth(
                name="circuit_breaker",
                status="degraded",
                response_time_ms=round(
                    (time.perf_counter() - start) * 1000, 2
                ),
                detail="Circuit breaker not initialised",
            )
        result = await cb.health_check()
        return ComponentHealth(
            name="circuit_breaker",
            status=result["status"],
            response_time_ms=result["response_time_ms"],
            detail=result["detail"],
            metadata=result.get("metadata", {}),
        )
    except Exception as exc:
        return ComponentHealth(
            name="circuit_breaker",
            status="unhealthy",
            response_time_ms=round((time.perf_counter() - start) * 1000, 2),
            detail=f"Circuit breaker deep check failed: {exc}",
        )


async def _check_consensus_deep(request: Request) -> ComponentHealth:
    """Deep consensus check: run full health_check()."""
    start = time.perf_counter()
    try:
        conductor = getattr(request.app.state, "conductor", None)
        if conductor is None:
            return ComponentHealth(
                name="consensus",
                status="degraded",
                response_time_ms=round(
                    (time.perf_counter() - start) * 1000, 2
                ),
                detail="Consensus conductor not initialised",
            )
        result = conductor.health_check()
        return ComponentHealth(
            name="consensus",
            status=result["status"],
            response_time_ms=result["response_time_ms"],
            detail=result["detail"],
            metadata=result.get("metadata", {}),
        )
    except Exception as exc:
        return ComponentHealth(
            name="consensus",
            status="unhealthy",
            response_time_ms=round((time.perf_counter() - start) * 1000, 2),
            detail=f"Consensus deep check failed: {exc}",
        )


async def _check_detector_deep(request: Request) -> ComponentHealth:
    """Deep detector check: run full health_check() + stats."""
    start = time.perf_counter()
    try:
        detector = getattr(request.app.state, "detector", None)
        if detector is None:
            return ComponentHealth(
                name="detector",
                status="degraded",
                response_time_ms=round(
                    (time.perf_counter() - start) * 1000, 2
                ),
                detail="Detector not initialised",
            )
        result = detector.health_check()
        return ComponentHealth(
            name="detector",
            status=result["status"],
            response_time_ms=result["response_time_ms"],
            detail=result["detail"],
            metadata=result.get("metadata", {}),
        )
    except Exception as exc:
        return ComponentHealth(
            name="detector",
            status="unhealthy",
            response_time_ms=round((time.perf_counter() - start) * 1000, 2),
            detail=f"Detector deep check failed: {exc}",
        )


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
)
async def health_check(
    request: Request,
    depth: str = "shallow",
) -> HealthResponse:
    """Public health check endpoint.

    Parameters
    ----------
    depth:
        ``"shallow"`` for fast liveness probe (default),
        ``"deep"`` for full component exercise.
    """
    if depth not in {"shallow", "deep"}:
        depth = "shallow"

    now = datetime.now(timezone.utc)
    uptime = 0.0
    if hasattr(request.app.state, "startup_time"):
        uptime = now.timestamp() - request.app.state.startup_time

    # Run component checks concurrently
    if depth == "deep":
        components = await asyncio.gather(
            _check_auth_deep(),
            _check_circuit_breaker_deep(request),
            _check_consensus_deep(request),
            _check_detector_deep(request),
            return_exceptions=True,
        )
    else:
        components = await asyncio.gather(
            _check_auth_shallow(),
            _check_circuit_breaker_shallow(request),
            _check_consensus_shallow(request),
            _check_detector_shallow(request),
            return_exceptions=True,
        )

    # Handle any exceptions in component checks
    processed: list[ComponentHealth] = []
    names = ["auth", "circuit_breaker", "consensus", "detector"]
    for idx, result in enumerate(components):
        if isinstance(result, Exception):
            processed.append(
                ComponentHealth(
                    name=names[idx],
                    status="unhealthy",
                    response_time_ms=0.0,
                    detail=f"Check crashed: {result}",
                )
            )
        else:
            processed.append(result)

    overall = _aggregate_status(processed)

    logger.info(
        "health.check",
        depth=depth,
        overall=overall,
        components=[c.name + "=" + c.status for c in processed],
    )

    return HealthResponse(
        status=overall,
        version="0.2.0",
        timestamp=now.isoformat(),
        uptime_seconds=round(uptime, 2),
        components=processed,
    )


@router.get("/ready", status_code=status.HTTP_200_OK)
async def readiness_check() -> dict:
    """Readiness check for Kubernetes."""
    return {"status": "ready"}
