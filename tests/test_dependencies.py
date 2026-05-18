"""Tests for FastAPI dependency injection functions."""

from __future__ import annotations

import pytest

from ember_armor.api.dependencies import (
    get_audit_logger,
    get_circuit_breaker,
    get_conductor,
    get_detector,
)


@pytest.mark.asyncio
async def test_get_detector(client) -> None:
    """get_detector must return the DissonanceDetector from app state."""
    from ember_armor.api.main import create_app
    from fastapi.testclient import TestClient

    app = create_app()
    with TestClient(app) as tc:
        # Build a mock request with app.state properly initialised.
        from starlette.requests import Request
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "app": tc.app,
        }
        request = Request(scope)
        detector = await get_detector(request)
        from ember_armor.core.detector import DissonanceDetector
        assert isinstance(detector, DissonanceDetector)


@pytest.mark.asyncio
async def test_get_circuit_breaker(client) -> None:
    """get_circuit_breaker must return the CircuitBreaker from app state."""
    from starlette.requests import Request
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [],
        "app": client.app,
    }
    request = Request(scope)
    cb = await get_circuit_breaker(request)
    from ember_armor.core.circuit_breaker import CircuitBreaker
    assert isinstance(cb, CircuitBreaker)


@pytest.mark.asyncio
async def test_get_conductor(client) -> None:
    """get_conductor must return the EnsembleConductor from app state."""
    from starlette.requests import Request
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [],
        "app": client.app,
    }
    request = Request(scope)
    conductor = await get_conductor(request)
    from ember_armor.core.consensus import EnsembleConductor
    assert isinstance(conductor, EnsembleConductor)


@pytest.mark.asyncio
async def test_get_audit_logger(client) -> None:
    """get_audit_logger must return the AuditLogger from app state."""
    from starlette.requests import Request
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [],
        "app": client.app,
    }
    request = Request(scope)
    audit = await get_audit_logger(request)
    from ember_armor.security.audit import AuditLogger
    assert isinstance(audit, AuditLogger)
