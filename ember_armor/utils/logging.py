"""Structured logging configuration for EmberArmor.

Uses structlog for structured JSON logging in production and human-readable
console output in development.  Always configures the standard library
logging bridge so that third-party packages emit through the same pipeline.

Adds correlation ID propagation via contextvars (following Corporeus Phase 6
patterns) for distributed request tracing across async boundaries.
"""

from __future__ import annotations

import contextvars
import logging
import sys
from typing import Any

import structlog

# ---------------------------------------------------------------------------
# Context-local correlation ID
# ---------------------------------------------------------------------------

_cid_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "correlation_id", default=None
)
_correlation_ctx: dict[int, str | None] = {}


def get_correlation_id() -> str | None:
    """Return the correlation ID for the current async context.

    Uses :class:`contextvars.ContextVar` for safe async propagation,
    falling back to thread-local storage when needed.
    """
    try:
        return _cid_var.get()
    except Exception:
        import threading

        return _correlation_ctx.get(threading.current_thread().ident, None)


def set_correlation_id(cid: str | None) -> None:
    """Set correlation ID for the current execution context."""
    try:
        _cid_var.set(cid)
    except Exception:
        import threading

        _correlation_ctx[threading.current_thread().ident] = cid


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

logger: Any = structlog.get_logger("ember")


def configure_logging(
    log_level: str = "INFO",
    *,
    structured: bool = True,
) -> None:
    """Configure structured logging for the entire application.

    Parameters
    ----------
    log_level:
        One of ``DEBUG``, ``INFO``, ``WARNING``, ``ERROR``, ``CRITICAL``.
    structured:
        When ``True`` (production default) events are rendered as JSON.
        When ``False`` events are rendered as coloured console output.
    """
    level = getattr(logging, log_level.upper(), logging.INFO)

    # Standard-library bridge — ensures *all* logs (e.g. uvicorn, sqlalchemy)
    # flow through structlog's processor chain.
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=level,
    )

    processors: list[Any] = [
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.dict_tracebacks,
        _add_correlation_id,
    ]

    if structured:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def _add_correlation_id(
    logger: Any,
    method_name: str,
    event_dict: dict[str, Any],
) -> dict[str, Any]:
    """Structlog processor: inject correlation_id into every log event."""
    cid = get_correlation_id()
    if cid:
        event_dict["correlation_id"] = cid
    return event_dict
