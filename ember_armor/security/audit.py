"""Immutable structured audit logging for EmberArmor v2.

Every security-relevant event is logged as an immutable, timestamped,
structured record.  Raw user content is NEVER written to the audit trail;
only cryptographic hashes (e.g. SHA-256) of sensitive inputs are stored.

Design principles
-----------------
- **Append-only**: Audit entries are never updated or deleted.
- **Privacy-preserving**: Raw text, PII, or credentials are never logged.
- **Structured**: All events use the same schema so they can be
  aggregated by SIEM / log analysis tools without brittle regex parsing.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from ember_armor.utils.logging import logger


class AuditLogger:
    """Immutable audit logger for security events.

    All methods are ``async`` so they can be awaited in FastAPI
    dependency-injected routes without blocking the event loop.
    """

    async def log(
        self,
        *,
        event_type: str,
        actor: str,
        resource: str,
        action: str,
        result: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Log a structured audit event.

        Parameters
        ----------
        event_type:
            High-level event category (e.g. ``"auth"``, ``"safety_check"``).
        actor:
            Identity that performed the action (user-id, service-name, etc.).
        resource:
            The resource that was acted upon.
        action:
            The specific action taken (e.g. ``"login"``, ``"check"``).
        result:
            Outcome of the action (e.g. ``"success"``, ``"failure"``).
        details:
            Arbitrary key/value context.  **Must not contain raw secrets
            or PII** — only hashes, identifiers, and safe metadata.
        """
        logger.info(
            "audit.event",
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            actor=actor,
            resource=resource,
            action=action,
            result=result,
            details=details or {},
        )

    async def log_auth(
        self,
        *,
        actor: str,
        action: str,
        result: str,
        ip: str = "unknown",
    ) -> None:
        """Log an authentication-related event.

        Parameters
        ----------
        actor:
            The identity attempting authentication.
        action:
            The auth action (e.g. ``"login"``, ``"logout"``, ``"refresh"``).
        result:
            Outcome (``"success"`` or ``"failure"``).
        ip:
            Client IP address (default ``"unknown"`` if unavailable).
        """
        await self.log(
            event_type="auth",
            actor=actor,
            resource="auth_system",
            action=action,
            result=result,
            details={"ip": ip},
        )

    async def log_safety_check(
        self,
        *,
        actor: str,
        text_hash: str,
        result: str,
        score: float,
    ) -> None:
        """Log a safety-check event with a **pre-hashed** text digest.

        .. warning::
            This method accepts the **hash** of the evaluated text, not
            the text itself.  Callers must compute the hash (e.g.
            ``hashlib.sha256(text.encode()).hexdigest()``) before calling.
            Raw user input is never written to the audit trail.

        Parameters
        ----------
        actor:
            The entity that submitted the text for checking.
        text_hash:
            SHA-256 hex digest of the raw text that was evaluated.
        result:
            Outcome classification (e.g. ``"SAFE"``, ``"CAUTION"``,
            ``"UNSAFE"``).
        score:
            Numerical safety score (0.0–1.0).
        """
        await self.log(
            event_type="safety_check",
            actor=actor,
            resource="dissonance_guard",
            action="check",
            result=result,
            details={
                "text_hash": text_hash,
                "score": round(score, 6),
            },
        )

    @staticmethod
    def hash_text_for_audit(text: str) -> str:
        """Compute the SHA-256 hex digest of *text* for audit logging.

        This is a convenience helper so callers never accidentally pass
        raw text into the audit trail.

        Parameters
        ----------
        text:
            The raw user text to hash.

        Returns
        -------
        str
            Lower-case hex-encoded SHA-256 digest.
        """
        return hashlib.sha256(text.encode("utf-8")).hexdigest()
