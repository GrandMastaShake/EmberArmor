"""FastAPI dependency-injection functions for EmberArmor v2.

Each dependency extracts a shared subsystem from :attr:`request.app.state`
so that route handlers receive ready-to-use components without manual
look-ups.

Usage::

    @router.post("/check")
    async def check(
        request: DissonanceCheckRequest,
        detector: DissonanceDetector = Depends(get_detector),
    ) -> DissonanceCheckResponse:
        ...

All dependencies are ``async`` so they play nicely with FastAPI's DI system
and can be awaited in path-operation functions without blocking.
"""

from __future__ import annotations

from typing import Any

from fastapi import Request

# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


async def get_detector(request: Request) -> Any:
    """Dependency: return the :class:`DissonanceDetector` from app state.

    The detector is attached to ``app.state.detector`` during application
    startup (see :func:`create_app`).
    """
    return request.app.state.detector


# ---------------------------------------------------------------------------
# Circuit Breaker
# ---------------------------------------------------------------------------


async def get_circuit_breaker(request: Request) -> Any:
    """Dependency: return the :class:`CircuitBreaker` from app state.

    The circuit breaker wraps the detector and protects downstream calls
    from cascading failures.
    """
    return request.app.state.cb_detector


# ---------------------------------------------------------------------------
# Conductor
# ---------------------------------------------------------------------------


async def get_conductor(request: Request) -> Any:
    """Dependency: return the :class:`EnsembleConductor` from app state.

    The conductor coordinates ensemble voting across multiple safety
    subsystems.
    """
    return request.app.state.conductor


# ---------------------------------------------------------------------------
# Audit Logger
# ---------------------------------------------------------------------------


async def get_audit_logger(request: Request) -> Any:
    """Dependency: return the audit logger from app state.

    The audit logger records tamper-evident security events.
    """
    return request.app.state.audit
