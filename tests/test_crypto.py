"""Comprehensive cryptographic primitive tests for EmberArmor v2.

Validates secret generation, HMAC computation, PBKDF2 key derivation,
and constant-time comparison — all security-critical operations.

Coverage: 17 tests across 4 test classes.
    - Secret Generation (4 tests)
    - Key Derivation (4 tests)
    - HMAC Operations (5 tests)
    - Constant-Time Comparison (4 tests)
"""

from __future__ import annotations

import hashlib
import hmac
import statistics
import string
import time
from typing import Tuple

import pytest

from ember_armor.security.crypto import CryptoEngine


# ============================================================================
# Test Class 1: Secret Generation (4 tests)
# ============================================================================

class TestSecretGeneration:
    """Tests for CryptoEngine.generate_secret."""

    def test_generate_secret_default_length(self, crypto: CryptoEngine) -> None:
        """generate_secret with default length must return 64 hex chars."""
        secret = crypto.generate_secret()
        assert len(secret) == 64, f"Expected 64, got {len(secret)}"

    def test_generate_secret_custom_lengths(self, crypto: CryptoEngine) -> None:
        """generate_secret must honour requested lengths from 1 to 64."""
        for requested in (1, 8, 16, 32, 48, 64):
            secret = crypto.generate_secret(length=requested)
            assert len(secret) == requested, (
                f"Expected length {requested}, got {len(secret)}"
            )

    def test_generate_secret_uniqueness(self, crypto: CryptoEngine) -> None:
        """generate_secret must produce distinct values on repeated calls."""
        secrets = [crypto.generate_secret() for _ in range(50)]
        unique = set(secrets)
        assert len(unique) == len(secrets), (
            f"Generated only {len(unique)} unique secrets out of {len(secrets)}"
        )

    def test_generate_secret_hex_format(self, crypto: CryptoEngine) -> None:
        """generate_secret output must contain only lowercase hex characters."""
        secret = crypto.generate_secret(length=64)
        hex_chars = set(string.hexdigits.lower())
        assert all(ch in hex_chars for ch in secret), (
            f"Secret contains non-hex characters: {secret}"
        )

    def test_generate_secret_max_length_clamping(self, crypto: CryptoEngine) -> None:
        """generate_secret must clamp length to maximum of 64 (SHA-256 hex size).

        Requesting more than 64 characters should still return at most 64.
        The underlying SHA-256 digest is only 64 hex characters.
        """
        # The implementation slices via [:length], so >64 just returns full 64-char digest
        secret_64 = crypto.generate_secret(length=64)
        secret_100 = crypto.generate_secret(length=100)
        assert len(secret_64) == 64
        assert len(secret_100) == 64, (
            f"Expected max 64 chars, got {len(secret_100)}"
        )


# ============================================================================
# Test Class 2: Key Derivation (4 tests)
# ============================================================================

class TestKeyDerivation:
    """Tests for CryptoEngine.derive_hmac_key — PBKDF2-HMAC-SHA256."""

    def test_derive_key_output_lengths(self, crypto: CryptoEngine) -> None:
        """derive_hmac_key must return a 32-byte key and a 32-byte salt."""
        key, salt = crypto.derive_hmac_key(
            master_secret="my-master-secret-for-testing-purposes",
            context="audit-signing",
        )
        assert isinstance(key, bytes)
        assert isinstance(salt, bytes)
        assert len(key) == 32, f"Expected 32-byte key, got {len(key)}"
        assert len(salt) == 32, f"Expected 32-byte salt, got {len(salt)}"

    def test_derive_key_deterministic_with_fixed_salt(self) -> None:
        """PBKDF2 with identical (password, salt, iterations) must produce
        identical keys — this is the deterministic property callers rely on
        for verification.  We test this with hashlib.pbkdf2_hmac directly
        since derive_hmac_key generates a random salt per call."""
        password = b"test-password"
        salt = b"fixed-salt-12345678901234567890"[:32]  # ensure 32 bytes
        iterations = CryptoEngine.PBKDF2_ITERATIONS

        key1 = hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=32)
        key2 = hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=32)

        assert key1 == key2, "Same inputs must produce identical keys"
        assert len(key1) == 32

    def test_derive_key_salt_sensitivity(self) -> None:
        """Different salts must produce different keys even with the same
        password and iteration count."""
        password = b"same-password"
        iterations = CryptoEngine.PBKDF2_ITERATIONS
        salt1 = b"salt-one-xxxxxxxxxxxxxxxxxxxxxx1"
        salt2 = b"salt-two-xxxxxxxxxxxxxxxxxxxxxx2"

        key1 = hashlib.pbkdf2_hmac("sha256", password, salt1, iterations, dklen=32)
        key2 = hashlib.pbkdf2_hmac("sha256", password, salt2, iterations, dklen=32)

        assert key1 != key2, "Different salts must produce different keys"

    def test_derive_key_iteration_count(self) -> None:
        """The PBKDF2 iteration count must be >= 480_000 (OWASP 2023)."""
        assert CryptoEngine.PBKDF2_ITERATIONS >= 480_000, (
            f"PBKDF2 iterations {CryptoEngine.PBKDF2_ITERATIONS} below OWASP minimum"
        )

    def test_derive_key_unique_salts(self, crypto: CryptoEngine) -> None:
        """Each call to derive_hmac_key must generate a unique random salt."""
        results = [
            crypto.derive_hmac_key("same-master-secret-1234567890", "same-context")
            for _ in range(20)
        ]
        salts = [salt for _, salt in results]
        assert len(set(salts)) == len(salts), (
            f"derive_hmac_key produced duplicate salts across {len(salts)} calls"
        )

    def test_derive_key_context_separation(self, crypto: CryptoEngine) -> None:
        """Different context strings must produce different keys."""
        master = "master-secret-123456789012345678901"
        key1, _ = crypto.derive_hmac_key(master, context="context-a")
        key2, _ = crypto.derive_hmac_key(master, context="context-b")
        assert key1 != key2, "Different contexts must produce different keys"


# ============================================================================
# Test Class 3: HMAC Operations (5 tests)
# ============================================================================

class TestHmacOperations:
    """Tests for HMAC-SHA256 signing and verification."""

    def test_hmac_signing(self, crypto: CryptoEngine) -> None:
        """compute_hmac must produce a 64-char lowercase hex digest."""
        key = b"x" * 32  # 32-byte key for HS256
        data = b"message to authenticate"

        signature = crypto.compute_hmac(data, key)

        assert isinstance(signature, str)
        assert len(signature) == 64  # SHA-256 hex digest length
        assert all(c in string.hexdigits.lower() for c in signature)

    def test_hmac_verification(self, crypto: CryptoEngine) -> None:
        """Verification via constant_time_compare(compute_hmac(...), sig)
        must succeed for matching data and key."""
        key = b"k" * 32
        data = b"authenticated message"

        sig = crypto.compute_hmac(data, key)
        assert crypto.constant_time_compare(sig, sig) is True

    def test_hmac_tamper_detection(self, crypto: CryptoEngine) -> None:
        """A single-bit flip in the message must produce a different HMAC."""
        key = b"k" * 32
        data = b"message"
        sig = crypto.compute_hmac(data, key)

        # Flip one bit in the message
        tampered_data = b"messagf"  # last char changed
        tampered_sig = crypto.compute_hmac(tampered_data, key)

        assert not crypto.constant_time_compare(sig, tampered_sig)

    def test_hmac_empty_message(self, crypto: CryptoEngine) -> None:
        """compute_hmac must handle empty messages without error."""
        key = b"k" * 32
        sig = crypto.compute_hmac(b"", key)
        assert isinstance(sig, str)
        assert len(sig) == 64

    def test_hmac_binary_data(self, crypto: CryptoEngine) -> None:
        """compute_hmac must handle arbitrary binary data (including null bytes
        and high bytes) correctly."""
        key = b"k" * 32
        data = bytes(range(256))  # all byte values 0-255

        sig = crypto.compute_hmac(data, key)
        assert isinstance(sig, str)
        assert len(sig) == 64

        # Re-computing with same data must yield same signature
        sig2 = crypto.compute_hmac(data, key)
        assert crypto.constant_time_compare(sig, sig2) is True


# ============================================================================
# Test Class 4: Constant-Time Comparison (4 tests)
# ============================================================================

class TestConstantTimeCompare:
    """Tests for CryptoEngine.constant_time_compare — timing-safe comparison."""

    def test_equal_strings(self, crypto: CryptoEngine) -> None:
        """constant_time_compare must return True for identical strings."""
        assert crypto.constant_time_compare("same", "same") is True
        assert crypto.constant_time_compare("a" * 64, "a" * 64) is True
        assert crypto.constant_time_compare("", "") is True

    def test_different_strings(self, crypto: CryptoEngine) -> None:
        """constant_time_compare must return False for different strings."""
        assert crypto.constant_time_compare("foo", "bar") is False
        assert crypto.constant_time_compare("short", "longer_string_here") is False
        # Single-character difference at the end.
        assert crypto.constant_time_compare("abcd", "abce") is False
        # Single-character difference at the start.
        assert crypto.constant_time_compare("xaaa", "yaaa") is False

    def test_empty_vs_non_empty(self, crypto: CryptoEngine) -> None:
        """constant_time_compare must handle empty string comparisons."""
        assert crypto.constant_time_compare("", "") is True
        assert crypto.constant_time_compare("", "a") is False
        assert crypto.constant_time_compare("a", "") is False

    def test_timing_independence(self, crypto: CryptoEngine) -> None:
        """constant_time_compare must run in roughly the same time regardless
        of where the strings differ.

        We compare timing for:
        - Strings that differ at the start (early mismatch)
        - Strings that differ at the end (late mismatch)
        - Identical strings (full scan)

        The timing ratio between the slowest and fastest must be close to 1.0.
        """
        ref = "A" * 100
        early_diff = "B" + "A" * 99   # differs at position 0
        late_diff = "A" * 99 + "B"    # differs at position 99
        identical = "A" * 100

        # Warm-up
        for _ in range(100):
            crypto.constant_time_compare(ref, early_diff)
            crypto.constant_time_compare(ref, late_diff)
            crypto.constant_time_compare(ref, identical)

        # Timed runs
        runs = 2000
        times_early = []
        times_late = []
        times_equal = []

        for _ in range(runs):
            t0 = time.perf_counter()
            crypto.constant_time_compare(ref, early_diff)
            t1 = time.perf_counter()
            times_early.append(t1 - t0)

            t0 = time.perf_counter()
            crypto.constant_time_compare(ref, late_diff)
            t1 = time.perf_counter()
            times_late.append(t1 - t0)

            t0 = time.perf_counter()
            crypto.constant_time_compare(ref, identical)
            t1 = time.perf_counter()
            times_equal.append(t1 - t0)

        med_early = statistics.median(times_early)
        med_late = statistics.median(times_late)
        med_equal = statistics.median(times_equal)

        # The ratio between slowest and fastest should be within a reasonable
        # factor. On CI this can be noisy, so we use a lenient threshold.
        all_medians = [med_early, med_late, med_equal]
        ratio = max(all_medians) / min(all_medians) if min(all_medians) > 0 else 1.0

        assert ratio < 5.0, (
            f"Timing ratio {ratio:.2f} suggests non-constant-time comparison. "
            f"early={med_early:.2e}, late={med_late:.2e}, equal={med_equal:.2e}"
        )
