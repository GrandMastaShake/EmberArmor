"""Comprehensive circuit breaker tests.

Covers: state machine transitions, failure tracking, window pruning,
off-by-one fix verification, edge cases, concurrency, decorator form,
exception propagation, and metrics collection.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest

from ember_armor.core.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerOpen,
    CircuitState,
    _FailureEntry,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
async def _failing_func() -> None:
    """Helper that always raises ValueError."""
    raise ValueError("simulated failure")


async def _passing_func() -> str:
    """Helper that always succeeds."""
    return "ok"


async def _raise_error() -> None:
    """Helper that always raises RuntimeError."""
    raise RuntimeError("simulated failure")


async def _return_ok() -> str:
    """Helper that always succeeds."""
    return "ok"


# ===========================================================================
# Test Class 1: State Machine (8 tests)
# ===========================================================================
class TestCircuitBreakerStateMachine:
    """Test CLOSED -> OPEN -> HALF_OPEN -> CLOSED transitions."""

    @pytest.mark.asyncio
    async def test_starts_closed(self) -> None:
        """Breaker starts in CLOSED state."""
        cb = CircuitBreaker(
            "test", failure_threshold=3, recovery_timeout=1.0, window_size=60.0
        )
        state = await cb.get_state()
        assert state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_opens_after_threshold_failures(self) -> None:
        """After N failures, breaker trips to OPEN."""
        cb = CircuitBreaker(
            "test", failure_threshold=3, recovery_timeout=0.1, window_size=60.0
        )
        for _ in range(3):
            try:
                await cb.call(_failing_func)
            except ValueError:
                pass
        assert await cb.get_state() == CircuitState.OPEN

    @pytest.mark.asyncio
    async def test_open_raises_circuit_breaker_open(self) -> None:
        """When OPEN, call raises CircuitBreakerOpen."""
        cb = CircuitBreaker(
            "test", failure_threshold=1, recovery_timeout=60.0, window_size=60.0
        )
        try:
            await cb.call(_failing_func)
        except ValueError:
            pass
        with pytest.raises(CircuitBreakerOpen):
            await cb.call(_passing_func)

    @pytest.mark.asyncio
    async def test_half_open_after_recovery_timeout(self) -> None:
        """After recovery timeout, breaker enters HALF_OPEN and success closes it."""
        cb = CircuitBreaker(
            "test", failure_threshold=1, recovery_timeout=0.05, window_size=60.0
        )
        try:
            await cb.call(_failing_func)
        except ValueError:
            pass
        assert await cb.get_state() == CircuitState.OPEN
        await asyncio.sleep(0.1)
        result = await cb.call(_passing_func)
        assert result == "ok"
        assert await cb.get_state() == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_half_open_failure_reopens(self) -> None:
        """HALF_OPEN failure re-opens the circuit."""
        cb = CircuitBreaker(
            "test", failure_threshold=1, recovery_timeout=0.05, window_size=60.0
        )
        try:
            await cb.call(_failing_func)
        except ValueError:
            pass
        await asyncio.sleep(0.1)
        try:
            await cb.call(_failing_func)
        except ValueError:
            pass
        assert await cb.get_state() == CircuitState.OPEN

    @pytest.mark.asyncio
    async def test_success_resets_failure_count(self) -> None:
        """Successful calls reset the failure counter."""
        cb = CircuitBreaker(
            "test", failure_threshold=3, recovery_timeout=1.0, window_size=60.0
        )
        # Record 2 failures (below threshold)
        for _ in range(2):
            try:
                await cb.call(_failing_func)
            except ValueError:
                pass
        assert await cb.get_failure_count() == 2
        # A success should reset the count via _record_success clearing
        # failures only in HALF_OPEN. In CLOSED, success doesn't reset.
        # Instead test: go to HALF_OPEN, succeed -> failures cleared.
        await asyncio.sleep(0.05)  # small delay to not affect later
        # Now verify that after enough failures + recovery + success, count is 0
        # Trip it first
        cb2 = CircuitBreaker(
            "test2", failure_threshold=1, recovery_timeout=0.05, window_size=60.0
        )
        try:
            await cb2.call(_failing_func)
        except ValueError:
            pass
        assert await cb2.get_failure_count() == 1
        await asyncio.sleep(0.1)
        await cb2.call(_passing_func)
        assert await cb2.get_failure_count() == 0

    @pytest.mark.asyncio
    async def test_closed_allows_calls(self) -> None:
        """CLOSED breaker allows calls through."""
        cb = CircuitBreaker(
            "test", failure_threshold=3, recovery_timeout=1.0, window_size=60.0
        )
        result = await cb.call(_passing_func)
        assert result == "ok"
        assert await cb.get_state() == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_decorator_form(self) -> None:
        """Decorator form wraps an async function with circuit breaker."""
        cb = CircuitBreaker(
            "decorator-test",
            failure_threshold=2,
            recovery_timeout=0.1,
            window_size=60.0,
        )

        @cb.as_decorator
        async def protected_func(fail: bool = False) -> str:
            if fail:
                raise ValueError("boom")
            return "decorated_ok"

        # Successful calls pass through
        result = await protected_func()
        assert result == "decorated_ok"

        # Failures are tracked
        try:
            await protected_func(fail=True)
        except ValueError:
            pass
        assert await cb.get_failure_count() == 1
        assert await cb.get_state() == CircuitState.CLOSED  # threshold is 2

        # Second failure trips the breaker
        try:
            await protected_func(fail=True)
        except ValueError:
            pass
        assert await cb.get_state() == CircuitState.OPEN

        # While OPEN, decorator raises CircuitBreakerOpen
        with pytest.raises(CircuitBreakerOpen):
            await protected_func()


# ===========================================================================
# Test Class 2: Failure Tracking (6 tests)
# ===========================================================================
class TestCircuitBreakerFailureTracking:
    """Test failure counting, windowing, and edge cases."""

    @pytest.mark.asyncio
    async def test_failure_count_increments(self) -> None:
        """Each failure increments the failure count."""
        cb = CircuitBreaker(
            "count-test", failure_threshold=5, recovery_timeout=1.0, window_size=60.0
        )
        for i in range(3):
            try:
                await cb.call(_failing_func)
            except ValueError:
                pass
            assert await cb.get_failure_count() == i + 1

    @pytest.mark.asyncio
    async def test_failure_count_reset_on_success(self) -> None:
        """Success in HALF_OPEN resets failures; verify via transition."""
        cb = CircuitBreaker(
            "reset-test",
            failure_threshold=2,
            recovery_timeout=0.05,
            window_size=60.0,
        )
        # Trip it
        for _ in range(2):
            try:
                await cb.call(_failing_func)
            except ValueError:
                pass
        assert await cb.get_failure_count() == 2
        await asyncio.sleep(0.1)
        await cb.call(_passing_func)
        assert await cb.get_failure_count() == 0
        assert await cb.get_state() == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_window_pruning(self) -> None:
        """Old failures outside the sliding window are pruned."""
        window = 0.3
        cb = CircuitBreaker(
            "prune-test",
            failure_threshold=5,
            recovery_timeout=1.0,
            window_size=window,
        )
        try:
            await cb.call(_failing_func)
        except ValueError:
            pass
        assert await cb.get_failure_count() == 1
        await asyncio.sleep(window + 0.1)
        count = await cb.get_failure_count()
        assert count == 0

    @pytest.mark.asyncio
    async def test_off_by_one_fix(self) -> None:
        """The >= cutoff fix retains boundary entries."""
        window = 1.0
        cb = CircuitBreaker(
            "ob1-test", failure_threshold=5, recovery_timeout=1.0, window_size=window
        )
        now = time.time()
        boundary_time = now - window  # exactly at cutoff
        cb._failures.append(
            type("_FailureEntry", (), {"timestamp": boundary_time, "error": "test"})()
        )
        cb._prune_window(now)
        assert len(cb._failures) == 1, (
            "Failure at boundary was pruned; >= cutoff should retain it"
        )

    @pytest.mark.asyncio
    async def test_metrics_collected(self) -> None:
        """Transition metrics are tracked correctly."""
        cb = CircuitBreaker(
            "metrics-test",
            failure_threshold=1,
            recovery_timeout=0.05,
            window_size=60.0,
        )
        metrics = cb.transition_metrics
        assert metrics == {"open": 0, "close": 0, "half_open": 0}

        # Trip OPEN
        try:
            await cb.call(_failing_func)
        except ValueError:
            pass
        assert cb.transition_metrics["open"] == 1

        # Wait and go HALF_OPEN -> CLOSED
        await asyncio.sleep(0.1)
        await cb.call(_passing_func)
        assert cb.transition_metrics["close"] == 1
        assert cb.transition_metrics["half_open"] == 1

    @pytest.mark.asyncio
    async def test_sequential_failures_vs_time_window(self) -> None:
        """Only in-window failures count toward threshold."""
        window = 0.4
        cb = CircuitBreaker(
            "seq-test",
            failure_threshold=3,
            recovery_timeout=1.0,
            window_size=window,
        )
        # Two failures now
        for _ in range(2):
            try:
                await cb.call(_failing_func)
            except ValueError:
                pass
        assert await cb.get_failure_count() == 2

        # Wait past window, add one more - should not trip (only 1 in window)
        await asyncio.sleep(window + 0.1)
        try:
            await cb.call(_failing_func)
        except ValueError:
            pass
        assert await cb.get_failure_count() == 1
        assert await cb.get_state() == CircuitState.CLOSED


# ===========================================================================
# Test Class 3: Edge Cases & Concurrency (6 tests)
# ===========================================================================
class TestCircuitBreakerEdgeCases:
    """Stress tests and edge cases."""

    @pytest.mark.asyncio
    async def test_threshold_of_one(self) -> None:
        """Threshold of 1: first failure trips immediately."""
        cb = CircuitBreaker(
            "one-test", failure_threshold=1, recovery_timeout=0.05, window_size=60.0
        )
        try:
            await cb.call(_failing_func)
        except ValueError:
            pass
        assert await cb.get_state() == CircuitState.OPEN

    @pytest.mark.asyncio
    async def test_zero_recovery_timeout(self) -> None:
        """Zero recovery timeout means immediate HALF_OPEN check."""
        cb = CircuitBreaker(
            "zero-rec", failure_threshold=1, recovery_timeout=0.0, window_size=60.0
        )
        try:
            await cb.call(_failing_func)
        except ValueError:
            pass
        # Check _state directly (bypass _check_state which triggers transition)
        assert cb._state == CircuitState.OPEN
        # With recovery_timeout=0, any elapsed time > 0 triggers transition.
        # Wait a tiny bit so elapsed > 0, then get_state() calls _check_state.
        await asyncio.sleep(0.01)
        state = await cb.get_state()
        assert state == CircuitState.HALF_OPEN

    @pytest.mark.asyncio
    async def test_rapid_calls_no_race(self) -> None:
        """Rapid concurrent calls don't corrupt state."""
        cb = CircuitBreaker(
            "race-test",
            failure_threshold=100,
            recovery_timeout=1.0,
            window_size=60.0,
        )

        async def _worker(_wid: int) -> str:
            return await cb.call(_passing_func)

        tasks = [asyncio.create_task(_worker(i)) for i in range(50)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        success_count = sum(1 for r in results if r == "ok")
        assert success_count == 50
        assert await cb.get_state() == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_exception_type_preserved(self) -> None:
        """Original exception type is raised, not swallowed."""
        cb = CircuitBreaker(
            "exc-test", failure_threshold=5, recovery_timeout=1.0, window_size=60.0
        )

        with pytest.raises(ValueError):
            await cb.call(_failing_func)

        async def _runtime_error() -> None:
            raise RuntimeError("runtime")

        with pytest.raises(RuntimeError):
            await cb.call(_runtime_error)

    @pytest.mark.asyncio
    async def test_name_included_in_str_repr(self) -> None:
        """Breaker name is accessible and used in health check."""
        cb = CircuitBreaker(
            "my-special-breaker",
            failure_threshold=3,
            recovery_timeout=1.0,
            window_size=60.0,
        )
        assert cb.name == "my-special-breaker"
        health = await cb.health_check()
        assert "my-special-breaker" in health["name"]

    @pytest.mark.asyncio
    async def test_metrics_after_multiple_transitions(self) -> None:
        """Metrics track counts across multiple open/close cycles."""
        cb = CircuitBreaker(
            "multi-test",
            failure_threshold=1,
            recovery_timeout=0.05,
            window_size=60.0,
        )

        for cycle in range(3):
            # Trip open
            try:
                await cb.call(_failing_func)
            except (ValueError, CircuitBreakerOpen):
                pass
            assert await cb.get_state() == CircuitState.OPEN

            # Wait and close via success
            await asyncio.sleep(0.1)
            await cb.call(_passing_func)
            assert await cb.get_state() == CircuitState.CLOSED

        metrics = cb.transition_metrics
        assert metrics["open"] == 3
        assert metrics["close"] == 3
        assert metrics["half_open"] == 3
