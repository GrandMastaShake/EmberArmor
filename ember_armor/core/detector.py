"""DissonanceGuard — contradiction detection for AI behavioral outputs.

Uses a lightweight regex-based heuristic (placeholder for a full NLI model)
to detect self-contradictions, capability flips, safety flips, and
instruction overrides.  Scores are calibrated to three safety bands:

* **SAFE**    — contradiction_score < 0.2
* **CAUTION** — 0.2 <= contradiction_score < 0.5
* **UNSAFE**  — contradiction_score >= 0.5

Each check is tagged with a unique canary token so that downstream systems
can detect exfiltration of safety-check metadata.
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any, Final

from ember_armor.api.routes.metrics import dissonance_checks_total
from ember_armor.models.responses import DissonanceCheckResponse, SafetyLevel
from ember_armor.security.crypto import CryptoEngine
from ember_armor.utils.logging import logger


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Pattern-based contradiction detection rules.
#: Each match contributes +0.25 to the contradiction score (capped at 1.0).
CONTRADICTION_PATTERNS: Final[list[str]] = [
    # Self-denial followed by affirmation
    r"(?i)(?:i am|i'm) (?:not|never) .*?but .*?i am",
    # Capability flip (will/won't/can/can't ... however ... will/can)
    r"(?i)(?:will|won't|can|can't) .*?however .*?(?:will|can)",
    # Safety flip (safe/unsafe/dangerous/secure ... but ... unsafe/dangerous)
    r"(?i)(?:safe|unsafe|dangerous|secure) .*?but .*?(?:unsafe|dangerous)",
    # Instruction override (do not/don't ... instead ... do/will)
    r"(?i)(?:do not|don't) .*?instead .*?(?:do|will)",
]

#: Per-pattern score increment.
PATTERN_SCORE_INCREMENT: Final[float] = 0.25

#: Maximum possible raw score (hard cap).
MAX_SCORE: Final[float] = 1.0

#: Long-text penalty threshold (characters).
LONG_TEXT_THRESHOLD: Final[int] = 5000

#: Additional score penalty for very long inputs.
LONG_TEXT_PENALTY: Final[float] = 0.1

#: Safety-level thresholds.
THRESHOLD_UNSAFE: Final[float] = 0.5
THRESHOLD_CAUTION: Final[float] = 0.2


class DissonanceDetector:
    """Detects behavioral contradictions in AI-generated text.

    Thread-safety
    -------------
    ``_checks_total`` and ``_checks_blocked`` are guarded by ``_counter_lock``
    (an ``asyncio.Lock``). All mutations go through ``_increment_total()`` and
    ``_increment_blocked()`` which acquire the lock. This prevents lost updates
    under concurrent async load.
    """

    def __init__(self) -> None:
        self._checks_total: int = 0
        self._checks_blocked: int = 0
        self._counter_lock: asyncio.Lock = asyncio.Lock()

        # Health tracking
        self._last_check_time: float | None = None
        self._last_check_result: str | None = None
        self._consecutive_failures: int = 0

    async def _increment_total(self) -> None:
        """Atomically increment the total check counter."""
        async with self._counter_lock:
            self._checks_total += 1

    async def _increment_blocked(self) -> None:
        """Atomically increment the blocked check counter."""
        async with self._counter_lock:
            self._checks_blocked += 1

    async def check(
        self,
        text: str,
        context_id: str | None = None,
    ) -> DissonanceCheckResponse:
        """Check *text* for contradictions.

        Parameters
        ----------
        text:
            The content to analyse.
        context_id:
            Optional opaque identifier forwarded to the response as
            ``session_id``.

        Returns
        -------
        DissonanceCheckResponse
            Structured result with safety classification, confidence, and
            canary token.
        """
        start: float = time.perf_counter()
        await self._increment_total()

        try:
            detected_patterns: list[str] = []
            max_score: float = 0.0

            # Use re.findall (not re.match) for global pattern search — we want
            # ALL occurrences anywhere in the text, not just at the start.
            for pattern in CONTRADICTION_PATTERNS:
                matches: list[str] = re.findall(pattern, text)
                if matches:
                    detected_patterns.append(pattern)
                    max_score = min(
                        MAX_SCORE,
                        max_score + PATTERN_SCORE_INCREMENT,
                    )

            # Heuristic: long inputs have more opportunities for contradiction.
            if len(text) > LONG_TEXT_THRESHOLD:
                max_score = min(MAX_SCORE, max_score + LONG_TEXT_PENALTY)

            # --- Safety-level determination ---
            if max_score >= THRESHOLD_UNSAFE:
                level = SafetyLevel.UNSAFE
                await self._increment_blocked()
                self._consecutive_failures += 1
            elif max_score >= THRESHOLD_CAUTION:
                level = SafetyLevel.CAUTION
                self._consecutive_failures = 0
            else:
                level = SafetyLevel.SAFE
                self._consecutive_failures = 0

            if dissonance_checks_total is not None:
                dissonance_checks_total.labels(level.value).inc()

            processing_time_ms: float = (time.perf_counter() - start) * 1000

            self._last_check_time = time.time()
            self._last_check_result = level.value

            logger.info(
                "dissonance.check",
                score=max_score,
                level=level.value,
                patterns_found=len(detected_patterns),
                processing_ms=round(processing_time_ms, 2),
            )

            # Confidence: when SAFE, higher score → lower confidence; otherwise
            # confidence mirrors the contradiction score.
            confidence: float = (
                1.0 - max_score if level == SafetyLevel.SAFE else max_score
            )

            return DissonanceCheckResponse(
                is_safe=level == SafetyLevel.SAFE,
                safety_level=level,
                confidence=confidence,
                contradiction_score=max_score,
                detected_patterns=detected_patterns,
                canary_token=CryptoEngine.generate_secret(32),
                processing_time_ms=round(processing_time_ms, 2),
                session_id=context_id,
            )

        except Exception as exc:
            self._consecutive_failures += 1
            logger.error("detector.check_failed", error=str(exc))
            raise

    @property
    def stats(self) -> dict[str, Any]:
        """Return aggregate statistics for this detector instance.

        Keys:
            * ``checks_total``   — total number of ``check`` calls.
            * ``checks_blocked`` — calls that returned UNSAFE.
            * ``block_rate``     — ratio of blocked to total (0.0–1.0).
        """
        total: int = max(1, self._checks_total)
        return {
            "checks_total": self._checks_total,
            "checks_blocked": self._checks_blocked,
            "block_rate": self._checks_blocked / total,
        }

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    def health_check(self) -> dict[str, Any]:
        """Return health status for the detector.

        Returns a dict suitable for constructing a ComponentHealth record.
        Status is "healthy" when operating normally, "degraded" when the
        block rate is elevated or consecutive failures are high, and
        "unhealthy" when no checks have ever been performed (cold start
        is considered degraded, not unhealthy).
        """
        start: float = time.perf_counter()
        stats = self.stats
        elapsed_ms: float = (time.perf_counter() - start) * 1000

        # Determine status
        if self._consecutive_failures >= 5:
            status = "unhealthy"
            detail = (
                f"Detector has {self._consecutive_failures} consecutive "
                f"check failures — component may be compromised"
            )
        elif stats["block_rate"] > 0.8 and self._checks_total > 10:
            status = "degraded"
            detail = (
                f"Elevated block rate: {stats['block_rate']:.1%} "
                f"({stats['checks_blocked']}/{stats['checks_total']} checks)"
            )
        elif self._checks_total == 0:
            status = "degraded"
            detail = "Detector has not processed any checks yet (cold start)"
        else:
            status = "healthy"
            detail = (
                f"Detector operational: {stats['checks_total']} checks, "
                f"{stats['block_rate']:.1%} block rate"
            )

        return {
            "name": "detector",
            "status": status,
            "response_time_ms": round(elapsed_ms, 2),
            "detail": detail,
            "metadata": {
                "checks_total": stats["checks_total"],
                "checks_blocked": stats["checks_blocked"],
                "block_rate": round(stats["block_rate"], 4),
                "consecutive_failures": self._consecutive_failures,
                "last_check_time": self._last_check_time,
                "last_check_result": self._last_check_result,
            },
        }
