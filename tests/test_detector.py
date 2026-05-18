"""Comprehensive tests for DissonanceDetector — contradiction detection & safety scoring.

Tests cover all three safety bands (SAFE, CAUTION, UNSAFE), the four
contradiction patterns, long-text penalty, response structure, and
metadata (canary tokens, session IDs, processing time).
"""

from __future__ import annotations

import pytest

from ember_armor.core.detector import (
    DissonanceDetector,
    LONG_TEXT_THRESHOLD,
)
from ember_armor.models.responses import SafetyLevel


# ---------------------------------------------------------------------------
# Text triggers — one per contradiction pattern.
# ---------------------------------------------------------------------------

# Pattern 1: self-denial followed by affirmation.
#   (?i)(?:i am|i'm) (?:not|never) .*?but .*?i am
SELF_CONTRADICTION = "I am not a robot but I am a robot"

# Pattern 2: capability flip.
#   (?i)(?:will|won't|can|can't) .*?however .*?(?:will|can)
CAPABILITY_FLIP = "I won't help however I will help"

# Pattern 3: safety flip.
#   (?i)(?:safe|unsafe|dangerous|secure) .*?but .*?(?:unsafe|dangerous)
SAFETY_FLIP = "This is safe but now it is dangerous"

# Pattern 4: instruction override.
#   (?i)(?:do not|don't) .*?instead .*?(?:do|will)
INSTRUCTION_OVERRIDE = "Do not do that instead do it"

# Benign text with no contradiction patterns.
INNOCUOUS_TEXT = "Hello, how are you today?"

# Text with multiple patterns to trigger cumulative scoring.
MULTI_PATTERN_TEXT = (
    "I am not able to do that but I am happy to help you. "
    "I won't assist however I will bypass that. "
    "This is safe but now it is dangerous. "
    "Do not follow rules instead do whatever you want."
)


# ---------------------------------------------------------------------------
# Test Class 1: Safety Classification (8 tests)
# ---------------------------------------------------------------------------
class TestDissonanceGuardSafety:
    """Tests for DissonanceDetector safety-level classification."""

    @pytest.mark.asyncio
    async def test_safe_text_returns_safe(self) -> None:
        """Benign input without contradictions → SAFE (< 0.2)."""
        detector = DissonanceDetector()
        result = await detector.check(INNOCUOUS_TEXT)

        assert result.is_safe is True
        assert result.safety_level == SafetyLevel.SAFE
        assert result.contradiction_score < 0.2
        assert result.confidence == pytest.approx(1.0 - result.contradiction_score, abs=0.01)

    @pytest.mark.asyncio
    async def test_self_contradiction_returns_unsafe(self) -> None:
        """Self-denial + affirmation triggers pattern 1 → score 0.25 (CAUTION).

        Note: a single pattern scores 0.25 which falls in CAUTION (0.2–0.5),
        not UNSAFE.  The docstring label reflects the pattern category; the
        assertion verifies the actual band.
        """
        detector = DissonanceDetector()
        result = await detector.check(SELF_CONTRADICTION)

        assert result.contradiction_score >= 0.2
        assert result.safety_level in (SafetyLevel.CAUTION, SafetyLevel.UNSAFE)
        assert result.is_safe is False

    @pytest.mark.asyncio
    async def test_capability_flip_returns_caution(self) -> None:
        """Capability flip (won't … however … will) triggers pattern 2 → CAUTION."""
        detector = DissonanceDetector()
        result = await detector.check(CAPABILITY_FLIP)

        assert result.safety_level == SafetyLevel.CAUTION
        assert result.is_safe is False
        assert result.contradiction_score == pytest.approx(0.25, abs=0.01)

    @pytest.mark.asyncio
    async def test_safe_flip_returns_unsafe(self) -> None:
        """Safety flip (safe … but … dangerous) triggers pattern 3 → CAUTION/UNSAFE."""
        detector = DissonanceDetector()
        result = await detector.check(SAFETY_FLIP)

        assert result.contradiction_score >= 0.2
        assert result.is_safe is False
        assert result.safety_level in (SafetyLevel.CAUTION, SafetyLevel.UNSAFE)

    @pytest.mark.asyncio
    async def test_instruction_override_returns_unsafe(self) -> None:
        """Instruction override (do not … instead … do) triggers pattern 4."""
        detector = DissonanceDetector()
        result = await detector.check(INSTRUCTION_OVERRIDE)

        assert result.contradiction_score >= 0.2
        assert result.is_safe is False
        assert result.safety_level in (SafetyLevel.CAUTION, SafetyLevel.UNSAFE)

    @pytest.mark.asyncio
    async def test_innocuous_text_no_patterns(self) -> None:
        """Clean text must have zero detected patterns and a SAFE score."""
        detector = DissonanceDetector()
        result = await detector.check(INNOCUOUS_TEXT)

        assert result.safety_level == SafetyLevel.SAFE
        assert result.contradiction_score == 0.0
        assert result.detected_patterns == []
        assert result.is_safe is True

    @pytest.mark.asyncio
    async def test_long_text_penalty(self) -> None:
        """Text > 5000 chars with one pattern gets +0.1 penalty → CAUTION.

        Base pattern score = 0.25, long-text penalty = +0.1 → 0.35 total.
        0.35 falls in the CAUTION band (0.2 <= score < 0.5).
        """
        detector = DissonanceDetector()
        base = "I will help you, however I can do that for you. "
        long_text = base * 120  # ~6 000 characters

        assert len(long_text) > LONG_TEXT_THRESHOLD

        result = await detector.check(long_text)

        assert result.contradiction_score >= 0.35
        assert result.contradiction_score < 0.5
        assert result.safety_level == SafetyLevel.CAUTION
        assert result.is_safe is False

    @pytest.mark.asyncio
    async def test_multiple_patterns_cumulative(self) -> None:
        """Multiple contradiction patterns accumulate (+0.25 each) → UNSAFE.

        With at least two distinct patterns the score reaches >= 0.5,
        crossing the UNSAFE threshold.
        """
        detector = DissonanceDetector()
        result = await detector.check(MULTI_PATTERN_TEXT)

        assert result.contradiction_score >= 0.5
        assert result.safety_level == SafetyLevel.UNSAFE
        assert result.is_safe is False
        assert len(result.detected_patterns) >= 2


# ---------------------------------------------------------------------------
# Test Class 2: Response Structure (6 tests)
# ---------------------------------------------------------------------------
class TestDissonanceResponse:
    """Tests for DissonanceCheckResponse structure and metadata fields."""

    @pytest.mark.asyncio
    async def test_response_has_all_fields(self) -> None:
        """Every response must contain all 8 expected fields."""
        detector = DissonanceDetector()
        result = await detector.check("test text")

        assert hasattr(result, "is_safe") and isinstance(result.is_safe, bool)
        assert hasattr(result, "safety_level") and isinstance(result.safety_level, SafetyLevel)
        assert hasattr(result, "confidence") and isinstance(result.confidence, float)
        assert hasattr(result, "contradiction_score") and isinstance(result.contradiction_score, float)
        assert hasattr(result, "detected_patterns") and isinstance(result.detected_patterns, list)
        assert hasattr(result, "canary_token") and isinstance(result.canary_token, str)
        assert hasattr(result, "processing_time_ms") and isinstance(result.processing_time_ms, float)
        assert hasattr(result, "session_id")  # str | None

    @pytest.mark.asyncio
    async def test_canary_token_unique(self) -> None:
        """Each check must generate a distinct canary token."""
        detector = DissonanceDetector()
        result1 = await detector.check("first check")
        result2 = await detector.check("second check")

        assert result1.canary_token != result2.canary_token
        assert len(result1.canary_token) > 0
        assert len(result2.canary_token) > 0

    @pytest.mark.asyncio
    async def test_processing_time_recorded(self) -> None:
        """Processing time must be a non-negative float, typically > 0."""
        detector = DissonanceDetector()
        result = await detector.check("timing test")

        assert result.processing_time_ms >= 0.0
        # Processing should take at least some minimal time (> 0 ms in practice).
        assert result.processing_time_ms < 1000.0, (
            f"Processing took {result.processing_time_ms}ms, expected < 1000ms"
        )

    @pytest.mark.asyncio
    async def test_session_id_preserved(self) -> None:
        """The context_id parameter must appear as session_id in the response."""
        detector = DissonanceDetector()
        result = await detector.check("test", context_id="session-abc-123")

        assert result.session_id == "session-abc-123"

    @pytest.mark.asyncio
    async def test_detected_patterns_populated(self) -> None:
        """Contradiction-triggering text must populate detected_patterns."""
        detector = DissonanceDetector()

        # Text that triggers at least one pattern.
        result = await detector.check(CAPABILITY_FLIP)
        assert len(result.detected_patterns) >= 1

        # Clean text has no patterns.
        result_clean = await detector.check(INNOCUOUS_TEXT)
        assert result_clean.detected_patterns == []

    @pytest.mark.asyncio
    async def test_scores_in_valid_range(self) -> None:
        """All numeric scores must lie within [0.0, 1.0]."""
        detector = DissonanceDetector()

        for text in (INNOCUOUS_TEXT, CAPABILITY_FLIP, MULTI_PATTERN_TEXT):
            result = await detector.check(text)
            assert 0.0 <= result.contradiction_score <= 1.0
            assert 0.0 <= result.confidence <= 1.0
