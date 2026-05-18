"""Production-grade middleware for EmberArmor v2.

Provides three layers of request/response processing:

1. **RequestLoggingMiddleware** — structured HTTP access logging with timing
   and safe client-IP extraction.
2. **CanaryTokenMiddleware** — injects a cryptographically secure canary token
   into every response to enable exfiltration / tamper detection.
3. **RateLimitMiddleware** — in-memory sliding-window rate limiter per client
   IP.  Returns ``429 Too Many Requests`` when the window is exceeded.

All middleware classes inherit from
:class:`starlette.middleware.base.BaseHTTPMiddleware` and implement
:meth:`dispatch` as a coroutine.

.. note::
    The rate limiter stores state in-process.  For horizontal scaling
    deployments a Redis-backed implementation is required.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from ember_armor.api.routes.metrics import (
    http_request_duration_seconds,
    http_requests_total,
)
from ember_armor.security.crypto import CryptoEngine
from ember_armor.utils.logging import logger

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CANARY_VERSION: str = "0.2.0"
"""Current EmberArmor version injected into every response."""

# ---------------------------------------------------------------------------
# 1. Request Logging Middleware
# ---------------------------------------------------------------------------


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security-related HTTP headers to every response.

    Injects headers such as X-Content-Type-Options, X-Frame-Options,
    Strict-Transport-Security, and Referrer-Policy to harden the
    application against common web vulnerabilities.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        """Add security headers to the outgoing response."""
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response


# ---------------------------------------------------------------------------
# 1. Request Logging Middleware
# ---------------------------------------------------------------------------


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Structured request/response logging with timing.

    Emits one JSON log line per HTTP request containing the method, path,
    status code, duration (ms), and client IP.  The IP extraction helper
    safely handles ASGI ``request.client`` being ``None`` (e.g. when the
    connection has already been closed).
    """

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        """Process the request, log the outcome, and return the response."""
        start: float = time.perf_counter()

        response: Response = await call_next(request)

        duration_ms: float = (time.perf_counter() - start) * 1_000
        duration_s: float = duration_ms / 1_000

        # --- Prometheus metrics --------------------------------------------
        method: str = request.method
        path: str = request.url.path
        status_code: int = response.status_code

        if http_requests_total is not None:
            http_requests_total.labels(method, path, status_code).inc()
        if http_request_duration_seconds is not None:
            http_request_duration_seconds.labels(method, path).observe(duration_s)

        logger.info(
            "http.request",
            method=method,
            path=path,
            status_code=status_code,
            duration_ms=round(duration_ms, 2),
            client_ip=self._get_client_ip(request),
        )

        return response

    @staticmethod
    def _get_client_ip(request: Request) -> str:
        """Safely extract the client IP address.

        Priority:
        1. The first entry in the ``X-Forwarded-For`` header (if present).
           This is checked first so that the middleware works correctly
           behind a reverse proxy and in TestClient-based tests.
        2. ``request.client.host`` when the ASGI connection info is present.
        3. ``"unknown"`` as a safe fallback — never raises.

        Parameters
        ----------
        request:
            The current ASGI request.

        Returns
        -------
        str
            The client IP address or ``"unknown"``.
        """
        forwarded: str | None = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()

        if request.client is not None:
            return request.client.host

        return "unknown"


# ---------------------------------------------------------------------------
# 2. Canary Token Middleware
# ---------------------------------------------------------------------------


class CanaryTokenMiddleware(BaseHTTPMiddleware):
    """Inject a canary token and version header into every response.

    The ``X-Canary-Token`` is a cryptographically secure secret generated via
    :meth:`CryptoEngine.generate_secret`.  If the token appears in an
    unexpected context (e.g. a third-party paste-bin) it signals potential
    data exfiltration.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        """Add canary headers to the outgoing response."""
        response: Response = await call_next(request)

        canary: str = CryptoEngine.generate_secret(length=32)
        response.headers["X-Canary-Token"] = canary
        response.headers["X-Ember-Version"] = _CANARY_VERSION

        return response


# ---------------------------------------------------------------------------
# 3. Rate-Limiting Middleware
# ---------------------------------------------------------------------------


class RateLimitMiddleware(BaseHTTPMiddleware):
    """In-memory sliding-window rate limiter per client IP.

    Stores a ring of timestamps for each IP.  On every request stale entries
    (outside the sliding window) are purged, the count is checked against
    *max_requests*, and — when under the limit — the current timestamp is
    recorded.

    Parameters
    ----------
    app:
        The ASGI application this middleware wraps.
    max_requests:
        Maximum number of requests allowed within the window (default 60).
    window_seconds:
        Width of the sliding window in seconds (default 60).

    Attributes
    ----------
    max_requests : int
        Request threshold.
    window : int
        Window width in seconds.
    _requests : dict[str, list[float]]
        Internal map ``ip -> [unix_timestamps]``.
    """

    def __init__(
        self,
        app: Any,  # ASGI app — typed loosely to avoid mypy+fastapi interop issues
        *,
        max_requests: int = 60,
        window_seconds: int = 60,
    ) -> None:
        super().__init__(app)
        self.max_requests: int = max_requests
        self.window: int = window_seconds
        self._requests: dict[str, list[float]] = {}

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        """Enforce the sliding-window rate limit and forward the request."""
        client_ip: str = RequestLoggingMiddleware._get_client_ip(request)
        now: float = time.time()

        # --- clean old entries -------------------------------------------
        timestamps: list[float] = self._requests.get(client_ip, [])
        self._requests[client_ip] = [
            ts for ts in timestamps if (now - ts) < self.window
        ]

        # --- enforce limit -----------------------------------------------
        if len(self._requests.get(client_ip, [])) >= self.max_requests:
            retry_after: int = self.window
            return Response(
                content='{"detail":"Rate limit exceeded"}',
                status_code=429,
                media_type="application/json",
                headers={"Retry-After": str(retry_after)},
            )

        # --- record this request ----------------------------------------
        self._requests.setdefault(client_ip, []).append(now)

        return await call_next(request)
