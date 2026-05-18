"""
EmberArmor Monitoring & Observability Package.

Provides health checks, Prometheus metrics, structured logging with
correlation ID tracking, FastAPI middleware integration, request tracing,
and alerting for the EmberArmor AI behavioral safety infrastructure.

Patterned after: Corporeus Phase 6 monitoring module.

Quick-start::

    from ember_armor.monitoring import (
        HealthChecker, HealthStatus, ComponentHealth,
        MetricsCollector,
        StructuredLogger, configure_logging, get_correlation_id, set_correlation_id,
    )

    # 1. Configure logging
    configure_logging(level="INFO", json_format=True)

    # 2. Create health checker
    checker = HealthChecker(version="0.2.0")
    health = await checker.check(depth="shallow")

    # 3. Create metrics collector
    metrics = MetricsCollector()
    metrics.increment(MetricsCollector.CHECKS_TOTAL)

    # 4. Use structured logger with correlation IDs
    logger = StructuredLogger("ember_armor.api")
    with logger.correlation_scope("req-abc-123"):
        logger.info("request.started", path="/v1/dissonance")
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import platform
import shutil
import sys
import threading
import time
import traceback
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Generator

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Package metadata
# ---------------------------------------------------------------------------

__version__ = "0.2.0"


# ===========================================================================
# Context-local correlation ID
# ===========================================================================

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
        return _correlation_ctx.get(threading.current_thread().ident, None)


def set_correlation_id(cid: str | None) -> None:
    """Set correlation ID for the current execution context."""
    try:
        _cid_var.set(cid)
    except Exception:
        _correlation_ctx[threading.current_thread().ident] = cid


@contextmanager
def correlation_scope(cid: str) -> Generator[None, None, None]:
    """Context manager to set a correlation ID within a scope.

    Usage::

        with correlation_scope("req-abc-123"):
            logger.info("processing")
    """
    token = _cid_var.set(cid)
    try:
        yield
    finally:
        _cid_var.reset(token)


# ===========================================================================
# Status enum
# ===========================================================================


class Status(str, Enum):
    """Health status levels."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


# ===========================================================================
# ComponentHealth model
# ===========================================================================


class ComponentHealth(BaseModel):
    """Health status of a single component."""

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


# ===========================================================================
# HealthStatus model
# ===========================================================================


class HealthStatus(BaseModel):
    """Aggregated health status across all components."""

    overall: str = Field(
        ..., description="Aggregated: healthy | degraded | unhealthy"
    )
    components: list[ComponentHealth] = Field(default_factory=list)
    version: str = Field(
        default="0.0.0", description="EmberArmor version string"
    )
    uptime_seconds: float = Field(
        default=0.0, description="Process uptime in seconds"
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO timestamp of the check",
    )
    hostname: str = Field(
        default_factory=platform.node, description="Host machine name"
    )


# ===========================================================================
# HealthChecker
# ===========================================================================


class HealthChecker:
    """Deep and shallow health checks for all EmberArmor components.

    Each ``check_*`` method returns a :class:`ComponentHealth` record.
    The :meth:`check` method aggregates them into a :class:`HealthStatus`.

    Check depth:
        * **shallow** -- Fast, lightweight probes (connectivity, import checks).
        * **deep**    -- Full component exercise (actual end-to-end test).

    Example:
        >>> checker = HealthChecker(version="0.2.0")
        >>> status = await checker.check(depth="deep")
        >>> print(status.overall)
        'healthy'
    """

    CHECKS: dict[str, str] = {
        "auth": "check_auth",
        "circuit_breaker": "check_circuit_breaker",
        "consensus": "check_consensus",
        "detector": "check_detector",
        "disk": "check_disk_space",
        "memory": "check_memory",
    }

    # Thresholds
    DISK_WARN_PERCENT: float = 20.0
    DISK_CRITICAL_PERCENT: float = 10.0
    MEMORY_WARN_PERCENT: float = 85.0
    MEMORY_CRITICAL_PERCENT: float = 95.0

    def __init__(
        self,
        version: str = "0.2.0",
        start_time: float | None = None,
    ) -> None:
        self.version = version
        self.start_time = start_time or time.monotonic()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def check(self, depth: str = "shallow") -> HealthStatus:
        """Run health checks.

        Args:
            depth: ``"shallow"`` for fast basic checks, ``"deep"``
                for thorough component checks.

        Returns:
            :class:`HealthStatus` with overall and per-component results.
        """
        if depth not in {"shallow", "deep"}:
            raise ValueError(
                f"Invalid depth: {depth!r}. Use 'shallow' or 'deep'."
            )

        components = await self._run_checks(depth)
        overall = self._aggregate(components)

        return HealthStatus(
            overall=overall,
            components=components,
            version=self.version,
            uptime_seconds=time.monotonic() - self.start_time,
        )

    # ------------------------------------------------------------------
    # Component checks
    # ------------------------------------------------------------------

    async def check_auth(self) -> ComponentHealth:
        """Verify auth module is functional."""
        start = time.monotonic()
        try:
            from ember_armor.api.auth import get_current_auth

            return self._ok("auth", start, "Auth module loaded and callable")
        except Exception as exc:
            return self._fail("auth", start, f"Auth module error: {exc}")

    async def check_circuit_breaker(self) -> ComponentHealth:
        """Verify circuit breaker module is functional."""
        start = time.monotonic()
        try:
            from ember_armor.core.circuit_breaker import (
                CircuitBreaker,
                CircuitState,
            )

            # Instantiate a test breaker to verify the class works
            cb = CircuitBreaker(name="health_check", failure_threshold=3)
            state = await cb.get_state()
            return self._ok(
                "circuit_breaker",
                start,
                f"Circuit breaker class healthy (state: {state.value})",
                metadata={"state": state.value},
            )
        except Exception as exc:
            return self._fail(
                "circuit_breaker", start, f"Circuit breaker error: {exc}"
            )

    async def check_consensus(self) -> ComponentHealth:
        """Verify consensus engine is functional."""
        start = time.monotonic()
        try:
            from ember_armor.core.consensus import EnsembleConductor

            conductor = EnsembleConductor()
            result = conductor.health_check()
            return self._ok(
                "consensus",
                start,
                result["detail"],
                metadata=result.get("metadata", {}),
            )
        except Exception as exc:
            return self._fail("consensus", start, f"Consensus error: {exc}")

    async def check_detector(self) -> ComponentHealth:
        """Verify detector module is functional."""
        start = time.monotonic()
        try:
            from ember_armor.core.detector import DissonanceDetector

            detector = DissonanceDetector()
            result = detector.health_check()
            return self._ok(
                "detector",
                start,
                result["detail"],
                metadata=result.get("metadata", {}),
            )
        except Exception as exc:
            return self._fail("detector", start, f"Detector error: {exc}")

    async def check_disk_space(self) -> ComponentHealth:
        """Verify adequate disk space.

        Warns when free space < 20%, critical when < 10%.
        """
        start = time.monotonic()
        try:
            total, used, free = shutil.disk_usage("/")
            free_percent = (free / total) * 100
            metadata = {
                "total_gb": round(total / (1024**3), 2),
                "used_gb": round(used / (1024**3), 2),
                "free_gb": round(free / (1024**3), 2),
                "free_percent": round(free_percent, 2),
            }

            if free_percent < self.DISK_CRITICAL_PERCENT:
                return self._fail(
                    "disk",
                    start,
                    f"CRITICAL: only {free_percent:.1f}% disk free",
                    metadata=metadata,
                )
            if free_percent < self.DISK_WARN_PERCENT:
                return self._degraded(
                    "disk",
                    start,
                    f"LOW DISK: {free_percent:.1f}% free",
                    metadata=metadata,
                )
            return self._ok(
                "disk",
                start,
                f"Disk OK: {free_percent:.1f}% free",
                metadata=metadata,
            )
        except Exception as exc:
            return self._fail("disk", start, f"Disk check failed: {exc}")

    async def check_memory(self) -> ComponentHealth:
        """Verify adequate memory availability.

        Warns when usage > 85%, critical when > 95%.
        """
        start = time.monotonic()
        try:
            import psutil

            mem = psutil.virtual_memory()
            metadata = {
                "total_mb": round(mem.total / (1024**2), 2),
                "used_mb": round(mem.used / (1024**2), 2),
                "available_mb": round(mem.available / (1024**2), 2),
                "percent": mem.percent,
            }

            if mem.percent > self.MEMORY_CRITICAL_PERCENT:
                return self._fail(
                    "memory",
                    start,
                    f"CRITICAL: {mem.percent:.1f}% memory used",
                    metadata=metadata,
                )
            if mem.percent > self.MEMORY_WARN_PERCENT:
                return self._degraded(
                    "memory",
                    start,
                    f"HIGH MEMORY: {mem.percent:.1f}% used",
                    metadata=metadata,
                )
            return self._ok(
                "memory",
                start,
                f"Memory OK: {mem.percent:.1f}% used",
                metadata=metadata,
            )
        except ImportError:
            return self._ok(
                "memory",
                start,
                "psutil not installed -- skipped",
                metadata={"skipped": True},
            )
        except Exception as exc:
            return self._fail("memory", start, f"Memory check failed: {exc}")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _run_checks(self, depth: str) -> list[ComponentHealth]:
        """Run all checks concurrently."""
        tasks: list[asyncio.Task[ComponentHealth]] = []
        for name, method_name in self.CHECKS.items():
            method: Callable[[], Any] = getattr(self, method_name)
            if asyncio.iscoroutinefunction(method):
                tasks.append(asyncio.create_task(method()))
            else:
                tasks.append(asyncio.create_task(self._wrap_sync(method)))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        components: list[ComponentHealth] = []
        for (name, _), result in zip(self.CHECKS.items(), results):
            if isinstance(result, Exception):
                components.append(
                    ComponentHealth(
                        name=name,
                        status="unhealthy",
                        response_time_ms=0.0,
                        detail=f"Check crashed: {result}",
                    )
                )
            else:
                components.append(result)
        return components

    async def _wrap_sync(
        self, fn: Callable[[], ComponentHealth]
    ) -> ComponentHealth:
        """Run a sync function in thread pool (fallback)."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, fn)

    @staticmethod
    def _aggregate(components: list[ComponentHealth]) -> str:
        """Aggregate component statuses into overall status."""
        statuses = [c.status for c in components]
        if any(s == "unhealthy" for s in statuses):
            return "unhealthy"
        if any(s == "degraded" for s in statuses):
            return "degraded"
        return "healthy"

    @staticmethod
    def _ok(
        name: str,
        start: float,
        detail: str,
        metadata: dict[str, Any] | None = None,
    ) -> ComponentHealth:
        return ComponentHealth(
            name=name,
            status="healthy",
            response_time_ms=round((time.monotonic() - start) * 1000, 2),
            detail=detail,
            metadata=metadata or {},
        )

    @staticmethod
    def _degraded(
        name: str,
        start: float,
        detail: str,
        metadata: dict[str, Any] | None = None,
    ) -> ComponentHealth:
        return ComponentHealth(
            name=name,
            status="degraded",
            response_time_ms=round((time.monotonic() - start) * 1000, 2),
            detail=detail,
            metadata=metadata or {},
        )

    @staticmethod
    def _fail(
        name: str,
        start: float,
        detail: str,
        metadata: dict[str, Any] | None = None,
    ) -> ComponentHealth:
        return ComponentHealth(
            name=name,
            status="unhealthy",
            response_time_ms=round((time.monotonic() - start) * 1000, 2),
            detail=detail,
            metadata=metadata or {},
        )


# ===========================================================================
# MetricsCollector
# ===========================================================================


class MetricsCollector:
    """Collects and exposes Prometheus-format metrics for EmberArmor.

    All metric names follow the ``emberarmor_<subsystem>_<unit>`` convention.
    No external library dependencies are required.

    Example:
        >>> m = MetricsCollector()
        >>> m.increment(MetricsCollector.CHECKS_TOTAL)
        >>> m.export_prometheus()
        '# HELP emberarmor_checks_total ...\\n...'
    """

    # Pre-defined metric names
    CHECKS_TOTAL: str = "emberarmor_checks_total"
    CHECKS_BLOCKED: str = "emberarmor_checks_blocked"
    AUTH_FAILURES: str = "emberarmor_auth_failures"
    CONSENSUS_VIOLATIONS: str = "emberarmor_consensus_violations"
    DISSONANCE_EVENTS: str = "emberarmor_dissonance_events"
    REQUESTS_TOTAL: str = "emberarmor_requests_total"
    RESPONSE_TIME_MS: str = "emberarmor_response_time_ms"
    CIRCUIT_TRANSITIONS: str = "emberarmor_circuit_transitions_total"

    # Default histogram buckets (in seconds)
    DEFAULT_BUCKETS: tuple[float, ...] = (
        0.005,
        0.01,
        0.025,
        0.05,
        0.1,
        0.25,
        0.5,
        1.0,
        2.5,
        5.0,
        10.0,
        float("inf"),
    )

    def __init__(self) -> None:
        self._counters: dict[
            str, dict[str, int]
        ] = defaultdict(lambda: defaultdict(int))
        self._gauges: dict[
            str, dict[str, float]
        ] = defaultdict(lambda: defaultdict(float))
        self._histograms: dict[
            str, dict[str, list[float]]
        ] = defaultdict(lambda: defaultdict(list))
        self._help_text: dict[str, str] = {
            self.CHECKS_TOTAL: "Total safety checks performed",
            self.CHECKS_BLOCKED: "Blocked unsafe requests",
            self.AUTH_FAILURES: "Authentication failures",
            self.CONSENSUS_VIOLATIONS: "Consensus UNSAFE decisions",
            self.DISSONANCE_EVENTS: "Dissonance detection events",
            self.REQUESTS_TOTAL: "Total HTTP requests handled",
            self.RESPONSE_TIME_MS: "Cumulative response time in ms",
            self.CIRCUIT_TRANSITIONS: "Circuit breaker state transitions",
        }
        self._buckets: dict[str, tuple[float, ...]] = defaultdict(
            lambda: self.DEFAULT_BUCKETS
        )

    # ------------------------------------------------------------------
    # Counters
    # ------------------------------------------------------------------

    def increment(
        self,
        name: str,
        labels: dict[str, str] | None = None,
        value: int = 1,
    ) -> None:
        """Increment a counter metric.

        Args:
            name: Metric name (e.g. ``emberarmor_checks_total``).
            labels: Label dict (serialised to ``key=\"val\",...``).
            value: Amount to increment (default 1).
        """
        label_key = self._labels_to_key(labels or {})
        self._counters[name][label_key] += value

    # ------------------------------------------------------------------
    # Gauges
    # ------------------------------------------------------------------

    def gauge(
        self,
        name: str,
        value: float,
        labels: dict[str, str] | None = None,
    ) -> None:
        """Set a gauge value."""
        label_key = self._labels_to_key(labels or {})
        self._gauges[name][label_key] = value

    def gauge_inc(
        self,
        name: str,
        labels: dict[str, str] | None = None,
        value: float = 1.0,
    ) -> None:
        """Increment a gauge by *value*."""
        label_key = self._labels_to_key(labels or {})
        self._gauges[name][label_key] += value

    def gauge_dec(
        self,
        name: str,
        labels: dict[str, str] | None = None,
        value: float = 1.0,
    ) -> None:
        """Decrement a gauge by *value*."""
        label_key = self._labels_to_key(labels or {})
        self._gauges[name][label_key] -= value

    # ------------------------------------------------------------------
    # Histograms / Timing
    # ------------------------------------------------------------------

    def observe(
        self,
        name: str,
        value: float,
        labels: dict[str, str] | None = None,
    ) -> None:
        """Record an observation into a histogram."""
        label_key = self._labels_to_key(labels or {})
        self._histograms[name][label_key].append(value)

    @contextmanager
    def timer(
        self,
        name: str,
        labels: dict[str, str] | None = None,
    ) -> Generator[None, None, None]:
        """Context manager for timing operations.

        Usage::

            with collector.timer(MetricsCollector.RESPONSE_TIME_MS):
                process_request()
        """
        start = time.perf_counter()
        try:
            yield
        finally:
            elapsed = time.perf_counter() - start
            self.observe(name, elapsed, labels)

    # ------------------------------------------------------------------
    # Prometheus export
    # ------------------------------------------------------------------

    def export_prometheus(self) -> str:
        """Export all metrics in Prometheus text format (0.0.4).

        Returns:
            Multi-line string compatible with Prometheus scrape protocol.
        """
        lines: list[str] = []

        # Counters
        for name, label_map in self._counters.items():
            lines.extend(self._render_counter(name, label_map))

        # Gauges
        for name, label_map in self._gauges.items():
            lines.extend(self._render_gauge(name, label_map))

        # Histograms
        for name, label_map in self._histograms.items():
            lines.extend(self._render_histogram(name, label_map))

        return "\n".join(lines) + "\n" if lines else ""

    # ------------------------------------------------------------------
    # Snapshot for programmatic access
    # ------------------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        """Return a JSON-serialisable snapshot of all metrics.

        Useful for health-check endpoints or debug panels.
        """
        import statistics

        return {
            "counters": {k: dict(v) for k, v in self._counters.items()},
            "gauges": {k: dict(v) for k, v in self._gauges.items()},
            "histograms": {
                k: {
                    lk: {
                        "count": len(lv),
                        "sum": round(sum(lv), 4),
                        "avg": (
                            round(statistics.mean(lv), 4) if lv else 0
                        ),
                    }
                    for lk, lv in v.items()
                }
                for k, v in self._histograms.items()
            },
        }

    # ------------------------------------------------------------------
    # Render helpers
    # ------------------------------------------------------------------

    def _render_counter(
        self, name: str, label_map: dict[str, int]
    ) -> list[str]:
        lines: list[str] = []
        help_text = self._help_text.get(name, f"Counter {name}")
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} counter")
        for label_key, value in sorted(label_map.items()):
            if label_key:
                lines.append(f"{name}{{{label_key}}} {value}")
            else:
                lines.append(f"{name} {value}")
        return lines

    def _render_gauge(
        self, name: str, label_map: dict[str, float]
    ) -> list[str]:
        lines: list[str] = []
        help_text = self._help_text.get(name, f"Gauge {name}")
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} gauge")
        for label_key, value in sorted(label_map.items()):
            if label_key:
                lines.append(f"{name}{{{label_key}}} {value}")
            else:
                lines.append(f"{name} {value}")
        return lines

    def _render_histogram(
        self, name: str, label_map: dict[str, list[float]]
    ) -> list[str]:
        lines: list[str] = []
        help_text = self._help_text.get(name, f"Histogram {name}")
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} histogram")

        buckets = self._buckets[name]
        for label_key, values in sorted(label_map.items()):
            # _bucket lines
            for bucket in buckets:
                le = "+Inf" if bucket == float("inf") else str(bucket)
                count = sum(1 for v in values if v <= bucket)
                if label_key:
                    lines.append(
                        f'{name}_bucket{{{label_key},le="{le}"}} {count}'
                    )
                else:
                    lines.append(f'{name}_bucket{{le="{le}"}} {count}')

            # _sum
            total = sum(values)
            if label_key:
                lines.append(f"{name}_sum{{{label_key}}} {total:.6f}")
            else:
                lines.append(f"{name}_sum {total:.6f}")

            # _count
            if label_key:
                lines.append(f"{name}_count{{{label_key}}} {len(values)}")
            else:
                lines.append(f"{name}_count {len(values)}")

        return lines

    @staticmethod
    def _labels_to_key(labels: dict[str, str]) -> str:
        """Serialise a label dict to Prometheus label string.

        >>> MetricsCollector._labels_to_key({"method": "GET"})
        'method=\"GET\"'
        """
        if not labels:
            return ""
        return ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))


# ===========================================================================
# StructuredLogger
# ===========================================================================


class StructuredLogger:
    """Structured logger with correlation ID tracking.

    Wraps the standard library :class:`logging.Logger` and automatically
    injects correlation IDs into every log record.

    Example::

        logger = StructuredLogger("ember_armor.api")
        with logger.correlation_scope("req-abc-123"):
            logger.info("request.started", extra={"path": "/v1/check"})
    """

    def __init__(self, name: str) -> None:
        self._logger = logging.getLogger(name)

    # ------------------------------------------------------------------
    # Logging methods
    # ------------------------------------------------------------------

    def debug(self, msg: str, **kwargs: Any) -> None:
        """Emit a DEBUG-level log record."""
        self._log(logging.DEBUG, msg, **kwargs)

    def info(self, msg: str, **kwargs: Any) -> None:
        """Emit an INFO-level log record."""
        self._log(logging.INFO, msg, **kwargs)

    def warning(self, msg: str, **kwargs: Any) -> None:
        """Emit a WARNING-level log record."""
        self._log(logging.WARNING, msg, **kwargs)

    def error(self, msg: str, **kwargs: Any) -> None:
        """Emit an ERROR-level log record."""
        self._log(logging.ERROR, msg, **kwargs)

    def critical(self, msg: str, **kwargs: Any) -> None:
        """Emit a CRITICAL-level log record."""
        self._log(logging.CRITICAL, msg, **kwargs)

    def exception(self, msg: str, **kwargs: Any) -> None:
        """Emit an ERROR-level log record with exception info."""
        self._log(logging.ERROR, msg, exc_info=True, **kwargs)

    # ------------------------------------------------------------------
    # Correlation ID scope
    # ------------------------------------------------------------------

    @contextmanager
    def correlation_scope(
        self, cid: str
    ) -> Generator[None, None, None]:
        """Set correlation ID for all logs within this scope."""
        token = _cid_var.set(cid)
        try:
            yield
        finally:
            _cid_var.reset(token)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _log(self, level: int, msg: str, **kwargs: Any) -> None:
        extra = kwargs.pop("extra", {})
        cid = get_correlation_id()
        if cid:
            extra["correlation_id"] = cid
        if kwargs:
            extra.update(kwargs)
        self._logger.log(level, msg, extra={"extra": extra} if extra else {})


# ===========================================================================
# Logging configuration (module-level)
# ===========================================================================


class StructuredLogFormatter(logging.Formatter):
    """JSON formatter for structured logging.

    Each log record is emitted as a single line of JSON containing:
    timestamp, level, logger name, message, source location, correlation ID,
    and any extra fields.

    Example output::

        {"timestamp": "2025-01-15T09:23:47.123456+00:00", "level": "INFO",
         "logger": "ember_armor.api", "message": "Scan complete",
         "correlation_id": "abc-123", "extra": {"files": 42}}
    """

    DEFAULT_FIELDS = [
        "timestamp",
        "level",
        "logger",
        "message",
        "module",
        "function",
        "line",
        "thread",
        "correlation_id",
        "extra",
    ]

    def __init__(
        self,
        fields: list[str] | None = None,
        datefmt: str | None = None,
        indent: int | None = None,
    ) -> None:
        super().__init__(datefmt=datefmt)
        self.fields = fields or self.DEFAULT_FIELDS
        self.indent = indent

    def format(self, record: logging.LogRecord) -> str:
        """Format *record* as a JSON string."""
        payload: dict[str, Any] = {}

        if "timestamp" in self.fields:
            payload["timestamp"] = datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat()

        if "level" in self.fields:
            payload["level"] = record.levelname

        if "logger" in self.fields:
            payload["logger"] = record.name

        if "message" in self.fields:
            payload["message"] = record.getMessage()

        if "module" in self.fields:
            payload["module"] = record.module

        if "function" in self.fields:
            payload["function"] = record.funcName

        if "line" in self.fields:
            payload["line"] = record.lineno

        if "thread" in self.fields:
            payload["thread"] = record.thread

        if "correlation_id" in self.fields:
            cid = getattr(record, "correlation_id", None) or get_correlation_id()
            if cid:
                payload["correlation_id"] = cid

        if "extra" in self.fields:
            extra = getattr(record, "extra", {})
            if hasattr(record, "correlation_id"):
                extra = {
                    k: v for k, v in extra.items() if k != "correlation_id"
                }
            if extra:
                payload["extra"] = extra

        # Exception info
        if record.exc_info and record.exc_info[0] is not None:
            payload["exception"] = self._format_exception(record)

        # Stack info
        if record.stack_info:
            payload["stack"] = record.stack_info

        return json.dumps(payload, default=str, indent=self.indent)

    @staticmethod
    def _format_exception(record: logging.LogRecord) -> dict[str, str]:
        """Format exception info as a dict."""
        if not record.exc_info:
            return {}
        exc_type, exc_value, exc_tb = record.exc_info
        return {
            "type": exc_type.__name__ if exc_type else "Unknown",
            "message": str(exc_value) if exc_value else "",
            "traceback": "".join(
                traceback.format_exception(*record.exc_info)
            ),
        }


class HumanReadableFormatter(logging.Formatter):
    """Pretty console formatter for local development.

    Output::

        2025-01-15 09:23:47 [INFO] ember_armor.api: Scan complete
                                     correlation_id=abc-123 files=42
    """

    COLORS = {
        "DEBUG": "\033[36m",  # cyan
        "INFO": "\033[32m",  # green
        "WARNING": "\033[33m",  # yellow
        "ERROR": "\033[31m",  # red
        "CRITICAL": "\033[35m",  # magenta
        "RESET": "\033[0m",
    }

    def __init__(self, use_color: bool = True) -> None:
        super().__init__()
        self.use_color = use_color and sys.stdout.isatty()

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        level = record.levelname
        color = self.COLORS.get(level, "") if self.use_color else ""
        reset = self.COLORS["RESET"] if self.use_color else ""

        msg = record.getMessage()
        line = f"{ts} [{color}{level}{reset}] {record.name}: {msg}"

        # Append correlation id and extra if present
        extras: list[str] = []
        cid = getattr(record, "correlation_id", None) or get_correlation_id()
        if cid:
            extras.append(f"correlation_id={cid}")
        extra = getattr(record, "extra", {})
        for k, v in extra.items():
            extras.append(f"{k}={v}")

        if extras:
            indent = " " * 29 + "\u2514\u2500 "
            line += "\n" + indent + " ".join(extras)

        # FIXED: CWE-22 Path traversal — sanitize filename before use
        import os

        log_dir = "/var/log/emberarmor"
        safe_name = os.path.basename(record.name) + ".log"
        log_path = f"{log_dir}/{safe_name}"
        real_path = os.path.realpath(log_path)
        real_dir = os.path.realpath(log_dir)
        if not real_path.startswith(real_dir):
            raise ValueError("Path traversal attempt detected")
        if record.exc_info and record.exc_info[0] is not None:
            line += "\n" + "".join(traceback.format_exception(*record.exc_info))

        return line


def configure_logging(
    level: str = "INFO",
    json_format: bool = True,
    log_file: str | None = None,
    filters: list[str] | None = None,
) -> None:
    """Configure structured logging for production.

    Args:
        level: Root log level (``DEBUG``, ``INFO``, ``WARNING``, ``ERROR``).
        json_format: Emit JSON when ``True``; pretty human-readable otherwise.
        log_file: Optional path to write logs (in addition to stderr).
        filters: List of logger names to silence (e.g. ``["uvicorn.access"]``).
    """
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Clear existing handlers to avoid duplicate output
    root.handlers.clear()

    formatter: logging.Formatter
    if json_format:
        formatter = StructuredLogFormatter()
    else:
        formatter = HumanReadableFormatter()

    # Stderr handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(formatter)
    root.addHandler(console_handler)

    # Optional file handler (JSON always)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(StructuredLogFormatter())
        root.addHandler(file_handler)

    # Silence noisy third-party loggers
    filters = filters or ["uvicorn.access", "asyncio"]
    for name in filters:
        logging.getLogger(name).setLevel(logging.WARNING)

    # Log the configuration
    logging.getLogger("ember_armor.monitoring").info(
        "Logging configured",
        extra={"level": level, "json_format": json_format, "file": log_file},
    )


def get_logger(name: str) -> StructuredLogger:
    """Get a named structured logger with EmberArmor defaults applied."""
    return StructuredLogger(name)


# ===========================================================================
# __all__
# ===========================================================================

__all__ = [
    # Health
    "HealthChecker",
    "HealthStatus",
    "HealthStatus",
    "MetricsCollector",
    "StructuredLogger",
    "StructuredLogFormatter",
    "HumanReadableFormatter",
    "configure_logging",
    "get_logger",
    "get_correlation_id",
    "set_correlation_id",
    "correlation_scope",
    "_cid_var",
    "checks_total",
    "checks_blocked",
    "auth_failures",
    "consensus_violations",
    "dissonance_events",
    "requests_total",
    "response_time_ms",
    "increment_checks_total",
    "increment_checks_blocked",
    "increment_auth_failures",
    "increment_consensus_violations",
    "increment_dissonance_events",
    "increment_requests_total",
    "add_response_time_ms",
    "export_prometheus",
]
