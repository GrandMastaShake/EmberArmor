"""Thread-safe circuit breaker with fixed off-by-one pruning.

The ``_prune_window`` method uses ``>= cutoff`` (inclusive) so that
failure entries whose timestamp is *exactly* at the window boundary are
retained.  The previous implementation used ``> cutoff`` (exclusive) which
silently dropped one failure per pruning cycle — a classic off-by-one that
made the breaker tolerant of one extra failure per window.

Design notes
------------
* Uses ``asyncio.Lock`` (not threading.Lock) because the caller is async.
* All state mutations are serialised through the same lock.
* The ``call`` method acquires the lock only for state checks, releases it
  for the protected function, then re-acquires it for result recording.
  This avoids holding the lock across I/O.
* ``@dataclass`` is **not** used for ``CircuitBreaker`` because it is a
  stateful object with complex ``__init__`` semantics; only ``_FailureEntry``
  is a dataclass.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine

from ember_armor.utils.logging import logger


class CircuitState(str, Enum):
    """Circuit-breaker state machine states."""

    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


@dataclass
class _FailureEntry:
    """Single failure observation inside the sliding window."""

    timestamp: float
    error: str | None = None


class CircuitBreakerOpen(Exception):
    """Raised when the circuit breaker is OPEN and a call is attempted."""


class CircuitBreaker:
    """Thread-safe circuit breaker with fixed off-by-one pruning.

    Parameters
    ----------
    name:
        Human-readable identifier (used in log lines).
    failure_threshold:
        Number of failures within *window_size* that trips the breaker.
    recovery_timeout:
        Seconds to wait before transitioning OPEN → HALF_OPEN.
    window_size:
        Sliding-window width in seconds.  Failures older than
        ``now - window_size`` are pruned.
    """

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        window_size: float = 60.0,
    ) -> None:
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.window_size = window_size

        # Mutable state — all access must be serialised through ``_lock``.
        self._state: CircuitState = CircuitState.CLOSED
        self._failures: list[_FailureEntry] = []
        self._last_failure_time: float | None = None
        self._lock: asyncio.Lock = asyncio.Lock()

        # Transition counters for observability
        self._transitions: dict[str, int] = {
            "open": 0,
            "close": 0,
            "half_open": 0,
        }
        self._last_transition_time: float | None = None

    async def call(
        self,
        func: Callable[..., Coroutine[Any, Any, Any]],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Execute *func* with circuit-breaker protection.

        1. Check state under lock.
        2. If OPEN → raise ``CircuitBreakerOpen``.
        3. If HALF_OPEN → log and proceed (one trial call).
        4. Release lock and call *func*.
        5. On success → ``_record_success``.
        6. On failure → ``_record_failure`` then re-raise.
        """
        async with self._lock:
            await self._check_state()

            if self._state == CircuitState.OPEN:
                logger.warning("circuit.open", breaker=self.name)
                raise CircuitBreakerOpen(f"Circuit {self.name} is OPEN")

            if self._state == CircuitState.HALF_OPEN:
                logger.info("circuit.half_open", breaker=self.name)

        try:
            result: Any = await func(*args, **kwargs)
        except Exception as exc:
            await self._record_failure(str(exc))
            raise

        await self._record_success()
        return result

    # ------------------------------------------------------------------
    # State-checking helpers (private)
    # ------------------------------------------------------------------

    async def _check_state(self) -> None:
        """Transition OPEN → HALF_OPEN once *recovery_timeout* has elapsed."""
        if self._state == CircuitState.OPEN:
            if self._last_failure_time is not None:
                elapsed: float = time.time() - self._last_failure_time
                if elapsed > self.recovery_timeout:
                    self._state = CircuitState.HALF_OPEN
                    self._transitions["half_open"] += 1
                    self._last_transition_time = time.time()
                    logger.info(
                        "circuit.recovery",
                        breaker=self.name,
                        elapsed_seconds=round(elapsed, 2),
                    )

    async def _record_success(self) -> None:
        """On success: HALF_OPEN → CLOSED transition + reset failures."""
        async with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.CLOSED
                self._failures.clear()
                self._transitions["close"] += 1
                self._last_transition_time = time.time()
                logger.info("circuit.closed", breaker=self.name)

    async def _record_failure(self, error: str) -> None:
        """Record a failure, prune the window, then check the threshold.

        The prune-before-check order is deliberate: we discard stale failures
        *before* counting, so that only in-window failures contribute to the
        trip decision.
        """
        async with self._lock:
            now: float = time.time()
            self._failures.append(_FailureEntry(timestamp=now, error=error))
            self._last_failure_time = now
            self._prune_window(now)

            if len(self._failures) >= self.failure_threshold:
                self._state = CircuitState.OPEN
                self._transitions["open"] += 1
                self._last_transition_time = now
                logger.error(
                    "circuit.tripped",
                    breaker=self.name,
                    failures=len(self._failures),
                    threshold=self.failure_threshold,
                )

    def _prune_window(self, now: float) -> None:
        """Remove failure entries that fall outside the sliding window.

        CRITICAL FIX: uses ``>= cutoff`` (inclusive) so that a failure whose
        timestamp is *exactly* at ``now - window_size`` is retained.  The
        previous implementation used ``> cutoff`` (exclusive) which silently
        dropped one legitimate failure per pruning cycle.
        """
        cutoff: float = now - self.window_size
        self._failures = [
            entry for entry in self._failures if entry.timestamp >= cutoff
        ]

    # ------------------------------------------------------------------
    # Observability
    # ------------------------------------------------------------------

    async def get_state(self) -> CircuitState:
        """Return the current circuit state (acquires lock)."""
        async with self._lock:
            await self._check_state()
            return self._state

    async def get_failure_count(self) -> int:
        """Return the number of failures inside the current window."""
        async with self._lock:
            self._prune_window(time.time())
            return len(self._failures)

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    async def health_check(self) -> dict[str, Any]:
        """Return health status for this circuit breaker.

        Returns a dict suitable for constructing a ComponentHealth record.
        Status is "unhealthy" when OPEN, "degraded" when HALF_OPEN,
        and "healthy" when CLOSED.
        """
        start: float = time.perf_counter()
        state = await self.get_state()
        failure_count = await self.get_failure_count()
        elapsed_ms: float = (time.perf_counter() - start) * 1000

        status_map = {
            CircuitState.CLOSED: "healthy",
            CircuitState.HALF_OPEN: "degraded",
            CircuitState.OPEN: "unhealthy",
        }

        return {
            "name": f"circuit_breaker.{self.name}",
            "status": status_map.get(state, "unhealthy"),
            "response_time_ms": round(elapsed_ms, 2),
            "detail": (
                f"Circuit {self.name} is {state.value}; "
                f"{failure_count} failures in window"
            ),
            "metadata": {
                "state": state.value,
                "failure_count": failure_count,
                "failure_threshold": self.failure_threshold,
                "transitions": dict(self._transitions),
                "last_transition_time": self._last_transition_time,
            },
        }

    @property
    def transition_metrics(self) -> dict[str, int]:
        """Export transition counts as metrics."""
        return dict(self._transitions)

    @property
    def as_decorator(
        self,
    ) -> Callable[
        [Callable[..., Coroutine[Any, Any, Any]]],
        Callable[..., Coroutine[Any, Any, Any]],
    ]:
        """Return a decorator that wraps *func* with this circuit breaker.

        Usage::

            cb = CircuitBreaker("my-cb", failure_threshold=3)

            @cb.as_decorator
            async def my_func():
                ...
        """

        def _decorator(
            func: Callable[..., Coroutine[Any, Any, Any]],
        ) -> Callable[..., Coroutine[Any, Any, Any]]:
            async def _wrapper(*args: Any, **kwargs: Any) -> Any:
                return await self.call(func, *args, **kwargs)

            return _wrapper

        return _decorator
