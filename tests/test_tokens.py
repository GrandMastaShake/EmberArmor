"""Comprehensive tests for TokenManager — JWT-style token lifecycle.

Coverage: 15 tests across 3 test classes.
    - Token Creation (5 tests)
    - Token Verification (6 tests)
    - Token Refresh (4 tests)
"""

from __future__ import annotations

import time
from datetime import timedelta
from unittest.mock import patch

import pytest
from jose import jwt

from ember_armor.security.tokens import TokenManager, _ALGORITHM


# ============================================================================
# Test Class 1: Token Creation (5 tests)
# ============================================================================

class TestTokenCreation:
    """Tests for TokenManager.create_token."""

    def test_create_token_basic(self) -> None:
        """create_token must return a compact-serialised JWT string."""
        token = TokenManager.create_token(subject="test-user")
        assert isinstance(token, str)
        assert len(token) > 0
        # JWT format: three base64-url segments separated by dots.
        parts = token.split(".")
        assert len(parts) == 3, f"Expected 3 JWT parts, got {len(parts)}"

    def test_create_token_custom_expiry(self) -> None:
        """create_token must honour a custom expires_delta."""
        short_delta = timedelta(minutes=5)
        token = TokenManager.create_token(
            subject="test-user",
            expires_delta=short_delta,
        )
        payload = TokenManager.verify_token(token)

        iat = payload["iat"]
        exp = payload["exp"]
        lifetime = exp - iat

        # Allow 5 seconds of clock skew tolerance.
        assert 4 * 60 <= lifetime <= 6 * 60, (
            f"Expected ~5 min lifetime, got {lifetime:.1f}s"
        )

    def test_create_token_subject_preserved(self) -> None:
        """The subject claim must be present in the created token payload."""
        token = TokenManager.create_token(subject="my-special-subject")
        payload = TokenManager.verify_token(token)
        assert payload["sub"] == "my-special-subject"

    def test_create_token_algorithm_pinned(self) -> None:
        """Tokens must be signed with HS256 only (algorithm pinning).

        We decode the header without verification to check the algorithm claim.
        """
        token = TokenManager.create_token(subject="test-user")
        parts = token.split(".")
        # Decode the JWT header (first segment) to inspect algorithm.
        import base64
        header_b64 = parts[0] + "=="  # pad for base64 decoding
        header_json = base64.urlsafe_b64decode(header_b64).decode("utf-8")
        import json
        header = json.loads(header_json)
        assert header["alg"] == "HS256", (
            f"Expected HS256, got {header.get('alg')}"
        )

    def test_create_token_has_all_registered_claims(self) -> None:
        """Created tokens must contain all required registered claims:
        sub, iat, exp, jti, type.
        """
        token = TokenManager.create_token(subject="test-subject")
        payload = TokenManager.verify_token(token)

        assert "sub" in payload and payload["sub"] == "test-subject"
        assert "iat" in payload and isinstance(payload["iat"], (int, float))
        assert "exp" in payload and isinstance(payload["exp"], (int, float))
        assert "jti" in payload and isinstance(payload["jti"], str) and payload["jti"]
        assert payload.get("type") == "access"


# ============================================================================
# Test Class 2: Token Verification (6 tests)
# ============================================================================

class TestTokenVerification:
    """Tests for TokenManager.verify_token."""

    def test_verify_valid_token(self) -> None:
        """verify_token must correctly decode a valid token."""
        token = TokenManager.create_token(subject="test-user")
        payload = TokenManager.verify_token(token)

        assert payload["sub"] == "test-user"
        assert payload["type"] == "access"
        assert "jti" in payload
        assert "iat" in payload
        assert "exp" in payload

    def test_verify_expired_token(self) -> None:
        """verify_token must raise ValueError for an expired token."""
        token = TokenManager.create_token(
            subject="test-user",
            expires_delta=timedelta(seconds=-1),
        )

        with pytest.raises(ValueError) as exc_info:
            TokenManager.verify_token(token)
        assert "Invalid token" in str(exc_info.value)

    def test_verify_tampered_token(self) -> None:
        """verify_token must raise ValueError when the payload is tampered."""
        token = TokenManager.create_token(subject="test-user")
        parts = token.split(".")
        # Corrupt the payload segment (second part) — flip a few chars.
        parts[1] = parts[1][:-5] + "XXXXX"
        tampered = ".".join(parts)

        with pytest.raises(ValueError):
            TokenManager.verify_token(tampered)

    def test_verify_wrong_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """verify_token must raise ValueError when verified with a different
        secret.  We monkeypatch TokenManager._secret to simulate a secret
        mismatch (e.g. a different server/instance)."""
        token = TokenManager.create_token(subject="test-user")
        monkeypatch.setattr(
            TokenManager, "_secret", "different-secret-32-chars-long!!!"
        )

        with pytest.raises(ValueError):
            TokenManager.verify_token(token)

    def test_verify_malformed_token(self) -> None:
        """verify_token must raise ValueError for malformed / non-JWT strings."""
        malformed_inputs = [
            "not-a-valid-token",
            "",
            "only-two.parts",
            "too.many.parts.here.now",
            "...",
        ]
        for bad in malformed_inputs:
            with pytest.raises(ValueError):
                TokenManager.verify_token(bad)

    def test_verify_algorithm_confusion(self) -> None:
        """Algorithm confusion attack: a token with alg=none in the header
        must be rejected.  TokenManager pins algorithms=["HS256"], so any
        token that doesn't use HS256 must fail verification.

        We manually craft a JWT with alg='none' since python-jose does not
        support encoding with that algorithm.
        """
        import base64
        import json

        # Header claims alg='none' — attacker tries to bypass signature.
        header = json.dumps({"typ": "JWT", "alg": "none"}).encode()
        # Payload with valid claims.
        payload = json.dumps(
            {"sub": "attacker", "iat": 1, "exp": 9999999999, "jti": "x", "type": "access"}
        ).encode()

        # Build the token: base64url(header) + "." + base64url(payload) + "." + ""
        b64_header = base64.urlsafe_b64encode(header).rstrip(b"=").decode()
        b64_payload = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
        bad_token = f"{b64_header}.{b64_payload}."

        with pytest.raises(ValueError):
            TokenManager.verify_token(bad_token)


# ============================================================================
# Test Class 3: Token Refresh (4 tests)
# ============================================================================

class TestTokenRefresh:
    """Tests for TokenManager.refresh_token — immutable refresh semantics."""

    def test_refresh_immutable(self) -> None:
        """refresh_token must mint a brand-new token; the original must
        remain valid until expiry and the new token must be different."""
        from datetime import timedelta

        # Create a token with a very short lifetime (2s) so we quickly
        # enter the refresh window (last 50% = after 1s).
        token = TokenManager.create_token(
            subject="test-user",
            expires_delta=timedelta(seconds=2),
        )

        # Wait until we're in the refresh window.
        time.sleep(1.1)

        new_token = TokenManager.refresh_token(token)

        # The new token must be a different string.
        assert new_token != token
        # The original token must still be verifiable.
        payload_orig = TokenManager.verify_token(token)
        assert payload_orig["sub"] == "test-user"

    def test_refresh_new_jti(self) -> None:
        """The refreshed token must have a new jti (JWT ID)."""
        from datetime import timedelta

        token = TokenManager.create_token(
            subject="test-user",
            expires_delta=timedelta(seconds=2),
        )
        time.sleep(1.1)

        new_token = TokenManager.refresh_token(token)

        payload_orig = TokenManager.verify_token(token)
        payload_new = TokenManager.verify_token(new_token)

        assert payload_new["jti"] != payload_orig["jti"], (
            "Refreshed token must have a new jti"
        )

    def test_refresh_expiry_extension(self) -> None:
        """The refreshed token must have a later expiry than the original."""
        from datetime import timedelta

        token = TokenManager.create_token(
            subject="test-user",
            expires_delta=timedelta(seconds=2),
        )
        time.sleep(1.1)

        new_token = TokenManager.refresh_token(token)

        payload_orig = TokenManager.verify_token(token)
        payload_new = TokenManager.verify_token(new_token)

        assert payload_new["exp"] > payload_orig["exp"], (
            "Refreshed token must have extended expiry"
        )

    def test_refresh_verify_after_refresh(self) -> None:
        """A token obtained via refresh must itself pass verification."""
        from datetime import timedelta

        token = TokenManager.create_token(
            subject="refresh-test-subject",
            expires_delta=timedelta(seconds=2),
        )
        time.sleep(1.1)

        new_token = TokenManager.refresh_token(token)
        payload = TokenManager.verify_token(new_token)

        assert payload["sub"] == "refresh-test-subject"
        assert payload["type"] == "access"
        assert "jti" in payload
        assert "iat" in payload
        assert "exp" in payload
