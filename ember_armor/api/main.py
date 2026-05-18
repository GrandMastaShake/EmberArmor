"""FastAPI application factory for EmberArmor v2."""

from __future__ import annotations

import time
from contextlib import asynccontextmanager

from fastapi import FastAPI

from ember_armor.api.middleware import (
    CanaryTokenMiddleware,
    RateLimitMiddleware,
    RequestLoggingMiddleware,
    SecurityHeadersMiddleware,
)
from ember_armor.api.routes import anchor, dissonance, health, metrics
from ember_armor.core.circuit_breaker import CircuitBreaker
from ember_armor.core.config import SETTINGS
from ember_armor.core.consensus import EnsembleConductor
from ember_armor.core.detector import DissonanceDetector
from ember_armor.core.sonar_agent import SonarConsensusAgent, SONAR_AGENT_WEIGHT
from ember_armor.security.audit import AuditLogger
from ember_armor.utils.logging import configure_logging, logger


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management."""
    configure_logging(SETTINGS.log_level, structured=SETTINGS.structured_logging)
    logger.info("app.startup", version="0.2.0", env="production")

    # Initialize circuit breakers
    app.state.cb_detector = CircuitBreaker(
        name="detector",
        failure_threshold=SETTINGS.cb_failure_threshold,
        recovery_timeout=SETTINGS.cb_recovery_timeout,
    )
    app.state.detector = DissonanceDetector()
    app.state.conductor = EnsembleConductor()
    app.state.audit = AuditLogger()

    # Initialize Sonar consensus agent (load-bearing Perplexity integration)
    app.state.sonar_agent = SonarConsensusAgent(
        api_key=SETTINGS.sonar_api_key,
        model=SETTINGS.sonar_model,
    )
    if SETTINGS.sonar_enabled:
        app.state.conductor.register_agent(
            "sonar_live_intel",
            app.state.sonar_agent.vote,
            weight=SETTINGS.sonar_agent_weight,
        )
        logger.info(
            "sonar.registered",
            model=SETTINGS.sonar_model,
            weight=SETTINGS.sonar_agent_weight,
            api_key_present=bool(SETTINGS.sonar_api_key),
        )
    else:
        logger.warning("sonar.disabled", reason="EMBER_SONAR_ENABLED=false")

    app.state.startup_time = time.time()

    yield

    # Graceful shutdown — close Sonar HTTP client
    await app.state.sonar_agent.close()
    logger.info("app.shutdown", uptime=time.time() - app.state.startup_time)


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="EmberArmor",
        description="AI Behavioral Safety Infrastructure",
        version="0.2.0",
        docs_url=None,  # Disable docs in production (security)
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    # Middleware (order matters: outermost first)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(CanaryTokenMiddleware)
    app.add_middleware(
        RateLimitMiddleware,
        max_requests=SETTINGS.rate_limit_requests,
        window_seconds=SETTINGS.rate_limit_window,
    )

    # Routes
    app.include_router(health.router, tags=["health"])
    app.include_router(metrics.router, prefix="/v1", tags=["metrics"])
    app.include_router(dissonance.router, prefix="/v1", tags=["dissonance"])
    app.include_router(anchor.router, prefix="/v1", tags=["anchor"])

    return app
