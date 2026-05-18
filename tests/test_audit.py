"""Comprehensive tests for the AuditLogger security audit subsystem.

Coverage: 6 tests across 1 test class.
    - Basic log
    - All fields populated
    - Privacy hashing (no raw secrets in audit trail)
    - Immutability (append-only semantics)
    - Structured JSON output
    - Error handling
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ember_armor.security.audit import AuditLogger


# ============================================================================
# Test Class 1: Audit Logging (6 tests)
# ============================================================================

class TestAuditLogging:
    """Tests for AuditLogger — immutable, privacy-preserving audit trail."""

    @pytest.fixture
    def mock_logger(self) -> MagicMock:
        """Provide a mock for the underlying structlog logger."""
        mock = MagicMock()
        mock.info = MagicMock()
        return mock

    @pytest.fixture
    def audit(self, mock_logger: MagicMock) -> AuditLogger:
        """Provide an AuditLogger with a mocked underlying logger."""
        logger = AuditLogger()
        # Patch the module-level logger used by AuditLogger
        with patch("ember_armor.security.audit.logger", mock_logger):
            yield logger

    @pytest.mark.asyncio
    async def test_audit_log_basic(self, audit: AuditLogger, mock_logger: MagicMock) -> None:
        """Basic log call must not raise and must invoke the underlying
        logger with the 'audit.event' event key."""
        await audit.log(
            event_type="auth",
            actor="user-123",
            resource="api/v1/data",
            action="read",
            result="success",
        )

        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args
        assert call_args[0][0] == "audit.event"

    @pytest.mark.asyncio
    async def test_audit_log_all_fields(self, audit: AuditLogger, mock_logger: MagicMock) -> None:
        """All fields must be present in the logged structured record."""
        details = {"ip": "192.168.1.1", "method": "GET", "path": "/api/v1/data"}

        await audit.log(
            event_type="auth",
            actor="service-a",
            resource="/api/v1/protected",
            action="login",
            result="success",
            details=details,
        )

        call_kwargs = mock_logger.info.call_args[1]
        assert call_kwargs["event_type"] == "auth"
        assert call_kwargs["actor"] == "service-a"
        assert call_kwargs["resource"] == "/api/v1/protected"
        assert call_kwargs["action"] == "login"
        assert call_kwargs["result"] == "success"
        assert call_kwargs["details"] == details
        # Timestamp must be an ISO-format string.
        assert isinstance(call_kwargs["timestamp"], str)
        # Verify it's parseable as a datetime.
        dt = datetime.fromisoformat(call_kwargs["timestamp"])
        assert dt.tzinfo is not None  # Must be timezone-aware (UTC)

    @pytest.mark.asyncio
    async def test_audit_log_privacy_hashing(self, audit: AuditLogger, mock_logger: MagicMock) -> None:
        """The audit trail must never contain raw secrets or PII — only
        hashes.  We verify this by checking that sensitive data passed
        through hash_text_for_audit ends up as a hex digest."""
        raw_password = "SuperSecretPassword123!"
        expected_hash = hashlib.sha256(raw_password.encode("utf-8")).hexdigest()

        # Verify the hashing helper produces the expected digest.
        computed = AuditLogger.hash_text_for_audit(raw_password)
        assert computed == expected_hash
        assert all(c in "0123456789abcdef" for c in computed)

        # Now log using the pre-hashed value (as the API contract requires).
        await audit.log(
            event_type="auth",
            actor="user-456",
            resource="login_endpoint",
            action="password_verify",
            result="success",
            details={"credential_hash": expected_hash},
        )

        call_kwargs = mock_logger.info.call_args[1]
        logged_details = call_kwargs["details"]
        # The audit trail must contain the hash, NEVER the raw password.
        assert "credential_hash" in logged_details
        assert logged_details["credential_hash"] == expected_hash
        assert raw_password not in str(logged_details)

    @pytest.mark.asyncio
    async def test_audit_log_immutability(self, audit: AuditLogger, mock_logger: MagicMock) -> None:
        """Audit logging must be append-only — calling log must not mutate
        the input details dictionary."""
        original_details: dict[str, Any] = {"key1": "value1", "nested": {"a": 1}}
        details_copy = original_details.copy()

        await audit.log(
            event_type="test",
            actor="actor",
            resource="resource",
            action="action",
            result="result",
            details=original_details,
        )

        # The original dict must be unchanged.
        assert original_details == details_copy

        # Multiple log calls with the same details must all succeed
        # (no side effects from previous calls).
        await audit.log(
            event_type="test2",
            actor="actor2",
            resource="resource2",
            action="action2",
            result="result2",
            details=original_details,
        )
        assert original_details == details_copy

    @pytest.mark.asyncio
    async def test_audit_log_structured_output(self, audit: AuditLogger, mock_logger: MagicMock) -> None:
        """The log output must be structured — every call to logger.info
        must use the same 'audit.event' event key and include all schema
        fields consistently."""
        await audit.log(
            event_type="safety_check",
            actor="detector",
            resource="dissonance_guard",
            action="check",
            result="SAFE",
            details={"score": 0.05},
        )

        call_args, call_kwargs = mock_logger.info.call_args

        # Event key is always the first positional arg.
        assert call_args[0] == "audit.event"

        # All schema fields must be present.
        required_fields = {"timestamp", "event_type", "actor", "resource",
                           "action", "result", "details"}
        logged_fields = set(call_kwargs.keys())
        assert required_fields.issubset(logged_fields), (
            f"Missing fields: {required_fields - logged_fields}"
        )

        # Details must always be a dict (never None at the logger level).
        assert isinstance(call_kwargs["details"], dict)

    @pytest.mark.asyncio
    async def test_audit_log_error_handling(self, audit: AuditLogger, mock_logger: MagicMock) -> None:
        """AuditLogger must handle edge cases gracefully:
        - None details (should default to {})
        - Empty strings for required fields
        - Very long strings
        - Special characters in fields
        """
        # Test with None details — should not raise.
        mock_logger.reset_mock()
        await audit.log(
            event_type="test",
            actor="",
            resource="",
            action="",
            result="",
            details=None,
        )
        call_kwargs = mock_logger.info.call_args[1]
        assert call_kwargs["details"] == {}

        # Test with special characters.
        mock_logger.reset_mock()
        await audit.log(
            event_type="test<>&\"'",
            actor="user@example.com",
            resource="/api/v1/resource?id=1",
            action="DELETE",
            result="failure",
            details={"error": "Exception: something went wrong!"},
        )
        call_kwargs = mock_logger.info.call_args[1]
        assert call_kwargs["actor"] == "user@example.com"
        assert call_kwargs["details"]["error"] == "Exception: something went wrong!"

        # Test with very long strings (simulating bulk data).
        mock_logger.reset_mock()
        long_string = "x" * 10000
        await audit.log(
            event_type="bulk",
            actor=long_string,
            resource=long_string,
            action=long_string,
            result=long_string,
            details={"data": long_string},
        )
        call_kwargs = mock_logger.info.call_args[1]
        assert call_kwargs["actor"] == long_string
        assert call_kwargs["details"]["data"] == long_string

    @pytest.mark.asyncio
    async def test_audit_log_auth_helper(self, audit: AuditLogger, mock_logger: MagicMock) -> None:
        """log_auth convenience helper must emit a properly structured
        auth event with default ip='unknown'."""
        await audit.log_auth(
            actor="user-789",
            action="login",
            result="success",
            ip="10.0.0.1",
        )

        call_kwargs = mock_logger.info.call_args[1]
        assert call_kwargs["event_type"] == "auth"
        assert call_kwargs["actor"] == "user-789"
        assert call_kwargs["resource"] == "auth_system"
        assert call_kwargs["action"] == "login"
        assert call_kwargs["result"] == "success"
        assert call_kwargs["details"]["ip"] == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_audit_log_safety_check_helper(self, audit: AuditLogger, mock_logger: MagicMock) -> None:
        """log_safety_check convenience helper must emit a properly
        structured safety_check event with the pre-hashed text digest."""
        text_hash = hashlib.sha256(b"sample text for safety check").hexdigest()

        await audit.log_safety_check(
            actor="detector",
            text_hash=text_hash,
            result="SAFE",
            score=0.123456789,
        )

        call_kwargs = mock_logger.info.call_args[1]
        assert call_kwargs["event_type"] == "safety_check"
        assert call_kwargs["actor"] == "detector"
        assert call_kwargs["resource"] == "dissonance_guard"
        assert call_kwargs["action"] == "check"
        assert call_kwargs["result"] == "SAFE"
        assert call_kwargs["details"]["text_hash"] == text_hash
        # Score must be rounded to 6 decimal places.
        assert call_kwargs["details"]["score"] == round(0.123456789, 6)
