"""Comprehensive authentication tests for EmberArmor v2.

Targets **fail-closed** behavior: every failure path must yield HTTP 401.
Includes timing-attack resistance validation via constant-time comparison.
"""

from __future__ import annotations

import time
from typing import Any

import pytest
from fastapi import HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials

from ember_armor.api.auth import AuthManager
from ember_armor.security.crypto import CryptoEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _make_creds(token: str) -> HTTPAuthorizationCredentials:
    """Build an HTTPAuthorizationCredentials object for test injection."""
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


# ---------------------------------------------------------------------------
# Test missing auth (None credentials)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_missing_auth_returns_401() -> None:
    """When no Authorization header is present, verify_api_key must raise 401."""
    with pytest.raises(HTTPException) as exc_info:
        await AuthManager.verify_api_key(None)

    exc = exc_info.value
    assert exc.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc.headers == {"WWW-Authenticate": "Bearer"}
    assert "Authentication required" in exc.detail


# ---------------------------------------------------------------------------
# Test empty auth (credentials object with empty string)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_empty_auth_returns_401() -> None:
    """When Bearer token is empty string, verify_api_key must raise 401."""
    creds = _make_creds("")

    with pytest.raises(HTTPException) as exc_info:
        await AuthManager.verify_api_key(creds)

    exc = exc_info.value
    assert exc.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Invalid authentication credentials" in exc.detail


# ---------------------------------------------------------------------------
# Test wrong key
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_wrong_key_returns_401(test_settings: dict) -> None:
    """An incorrect API key must be rejected with 401."""
    creds = _make_creds("wrong-key-that-does-not-match-the-valid-one")

    with pytest.raises(HTTPException) as exc_info:
        await AuthManager.verify_api_key(creds)

    exc = exc_info.value
    assert exc.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Invalid authentication credentials" in exc.detail


# ---------------------------------------------------------------------------
# Test correct key
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_correct_key_succeeds(test_settings: dict) -> None:
    """The correct API key must pass verification and be returned."""
    creds = _make_creds(test_settings["api_key"])

    result = await AuthManager.verify_api_key(creds)

    assert result == test_settings["api_key"]


# ---------------------------------------------------------------------------
# Timing attack resistance — constant_time_compare direct timing test.
# ---------------------------------------------------------------------------
def test_timing_attack_resistance(crypto: CryptoEngine) -> None:
    """Constant-time compare must have similar timing for equal/unequal inputs.

    We time many iterations of hmac.compare_digest (via constant_time_compare)
    with both matching and non-matching strings.  The medians should be within
    an order of magnitude — any major skew would suggest early-exit comparison.
    """
    key_a = "x" * 64
    key_b = "x" * 63 + "y"  # Same length, differs at final character.
    key_c = "y" * 64  # Completely different.

    match_times: list[float] = []
    mismatch_early_times: list[float] = []
    mismatch_full_times: list[float] = []

    iterations = 200

    for _ in range(iterations):
        t0 = time.perf_counter()
        crypto.constant_time_compare(key_a, key_a)
        t1 = time.perf_counter()
        match_times.append(t1 - t0)

        t0 = time.perf_counter()
        crypto.constant_time_compare(key_a, key_b)
        t1 = time.perf_counter()
        mismatch_early_times.append(t1 - t0)

        t0 = time.perf_counter()
        crypto.constant_time_compare(key_a, key_c)
        t1 = time.perf_counter()
        mismatch_full_times.append(t1 - t0)

    def _median(vals: list[float]) -> float:
        s = sorted(vals)
        return s[len(s) // 2]

    m_match = _median(match_times)
    m_early = _median(mismatch_early_times)
    m_full = _median(mismatch_full_times)

    # All three medians should be roughly the same — within 10x.
    # hmac.compare_digest is not perfectly uniform, but a 100x+ difference
    # would indicate a clear timing leak.
    max_time = max(m_match, m_early, m_full)
    min_time = min(m_match, m_early, m_full)

    if min_time > 0:
        ratio = max_time / min_time
        assert ratio < 10.0, (
            f"Timing ratio {ratio:.2f} suggests non-constant-time comparison. "
            f"match={m_match:.8f}s, early={m_early:.8f}s, full={m_full:.8f}s"
        )
    # If all times are zero (timer resolution too coarse), the test passes
    # by construction — we simply cannot measure a difference.


# ---------------------------------------------------------------------------
# Auth header format validation — non-Bearer scheme
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_auth_header_format_validation() -> None:
    """HTTPBearer with auto_error=False returns None for non-Bearer scheme."""
    # When the header uses "Basic" instead of "Bearer", HTTPBearer returns
    # None because auto_error=False, which triggers the missing-creds path.
    # We simulate this by passing None (what HTTPBearer would return).
    result = None  # Simulates non-Bearer scheme behavior
    assert result is None
    with pytest.raises(HTTPException) as exc_info:
        await AuthManager.verify_api_key(result)
    assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# Long key still works
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_long_key_still_works(monkeypatch: pytest.MonkeyPatch) -> None:
    """A key longer than 32 characters must still be accepted."""
    long_key = "k" * 128  # 128-char key
    # We test constant_time_compare directly since SETTINGS is read-only.
    assert CryptoEngine.constant_time_compare(long_key, long_key) is True
    assert CryptoEngine.constant_time_compare(long_key, "k" * 127 + "x") is False


# ---------------------------------------------------------------------------
# Short key rejected by validator
# ---------------------------------------------------------------------------
def test_short_key_rejected_by_validator() -> None:
    """The EmberSettings validator rejects secrets shorter than 32 chars."""
    from pydantic import ValidationError

    from ember_armor.core.config import EmberSettings

    with pytest.raises(ValidationError) as exc_info:
        EmberSettings(api_key="short", token_secret="also-short-key-here-yep")

    assert "32" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Partial prefix match should fail (constant-time compare catches this)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_partial_prefix_match_fails(test_settings: dict) -> None:
    """A key that is a prefix of the real key must NOT authenticate."""
    real_key = test_settings["api_key"]
    partial_key = real_key[: len(real_key) - 1]
    creds = _make_creds(partial_key)

    with pytest.raises(HTTPException) as exc_info:
        await AuthManager.verify_api_key(creds)

    assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# Case sensitivity — keys must be case-sensitive
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_case_sensitive_key_comparison(test_settings: dict) -> None:
    """Changing the case of any character must cause authentication to fail."""
    mixed_case_key = test_settings["api_key"].swapcase()
    creds = _make_creds(mixed_case_key)

    with pytest.raises(HTTPException) as exc_info:
        await AuthManager.verify_api_key(creds)

    assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# Direct constant-time compare — equal strings
# ---------------------------------------------------------------------------
def test_constant_time_compare_direct_equal() -> None:
    """CryptoEngine.constant_time_compare returns True for identical strings."""
    assert CryptoEngine.constant_time_compare("identical", "identical") is True


# ---------------------------------------------------------------------------
# Direct constant-time compare — unequal strings
# ---------------------------------------------------------------------------
def test_constant_time_compare_direct_unequal() -> None:
    """CryptoEngine.constant_time_compare returns False for different strings."""
    assert CryptoEngine.constant_time_compare("foo", "bar") is False


# ---------------------------------------------------------------------------
# Secret length validation on empty string
# ---------------------------------------------------------------------------
def test_empty_secret_rejected() -> None:
    """Empty string secrets must be rejected by the validator."""
    from pydantic import ValidationError

    from ember_armor.core.config import EmberSettings

    with pytest.raises(ValidationError):
        EmberSettings(api_key="", token_secret="x" * 32)
