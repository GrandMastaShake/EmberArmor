"""JWT-style token lifecycle management for EmberArmor v2.

Provides creation, verification, and refresh of signed bearer tokens.
All tokens are signed with ``HS256`` using the master secret loaded from
``SETTINGS.token_secret``.

Security design
---------------
- **Algorithm pinning**: Only ``HS256`` is accepted; the ``algorithms``
  parameter to *jose* is hard-coded to a single-element tuple to prevent
  algorithm-confusion attacks.
- **Fail-closed**: Any verification error raises ``ValueError`` so
  callers cannot accidentally proceed with an unverified token.
- **Immutable refresh**: Refreshing mints a brand-new token (new ``jti``,
  new ``iat``, new ``exp``) rather than mutating the old payload.
- **Random identifiers**: Token IDs are generated with
  ``secrets.token_urlsafe`` — never ``uuid4``.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from jose import JWTError, jwt

from ember_armor.core.config import SETTINGS

# ---------------------------------------------------------------------------
# Security constants — frozen at module load time
# ---------------------------------------------------------------------------
_ALGORITHM: str = "HS256"
_REFRESH_WINDOW_RATIO: float = 0.5  # token is refreshable in last 50 % of life
_DEFAULT_EXPIRE: timedelta = timedelta(minutes=30)


class TokenManager:
    """Create, verify, and refresh JWT-style bearer tokens.

    The signing key is read once from ``SETTINGS.token_secret`` at
    class-definition time and stored as a class attribute.  This avoids
    repeated config lookups on the hot path.
    """

    _secret: str = SETTINGS.token_secret

    # --- public API ---------------------------------------------------------

    @classmethod
    def create_token(
        cls,
        subject: str,
        expires_delta: timedelta | None = None,
    ) -> str:
        """Create a signed JWT for *subject*.

        Registered claims injected automatically:

        - ``sub``  — the *subject* parameter
        - ``iat``  — issuance time (UTC)
        - ``exp``  — expiration time (UTC)
        - ``jti``  — unique token ID (``secrets.token_urlsafe``)
        - ``type`` — ``"access"``

        Parameters
        ----------
        subject:
            The entity this token represents (user-id, service-name, …).
        expires_delta:
            Token lifetime.  Defaults to 30 minutes when ``None``.

        Returns
        -------
        str
            Compact-serialised JWT (three base64-url segments).
        """
        now: datetime = datetime.now(timezone.utc)
        delta: timedelta = expires_delta or _DEFAULT_EXPIRE
        jti: str = secrets.token_urlsafe(32)

        payload: dict[str, Any] = {
            "sub": subject,
            "iat": now,
            "exp": now + delta,
            "jti": jti,
            "type": "access",
        }

        return jwt.encode(payload, cls._secret, algorithm=_ALGORITHM)

    @classmethod
    def verify_token(cls, token: str) -> dict[str, Any]:
        """Verify and decode a token.

        Parameters
        ----------
        token:
            Compact-serialised JWT.

        Returns
        -------
        dict
            The decoded payload (all registered and custom claims).

        Raises
        ------
        ValueError
            If the token is malformed, expired, has an invalid signature,
            or uses an unexpected algorithm.
        """
        try:
            decoded: dict[str, Any] = jwt.decode(
                token,
                cls._secret,
                algorithms=[_ALGORITHM],
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "require": ["sub", "exp", "iat", "jti"],
                },
            )
        except JWTError as exc:
            raise ValueError(f"Invalid token: {exc}") from exc

        return decoded

    @classmethod
    def refresh_token(cls, token: str) -> str:
        """Refresh a token if it is within the refresh window.

        A token is refreshable when the current time falls in the last
        ``_REFRESH_WINDOW_RATIO`` (default 50 %) of its lifetime.  This
        prevents indefinite refresh chains while still allowing
        legitimate users to obtain a new token before expiry.

        The refreshed token has a new ``jti``, ``iat``, and ``exp``;
        only the ``sub`` claim is carried forward.

        Parameters
        ----------
        token:
            The existing token to refresh.

        Returns
        -------
        str
            A brand-new signed JWT.

        Raises
        ------
        ValueError
            If the token is invalid, already expired, or not yet within
            the refresh window.
        """
        # Verify first — raises ValueError on any problem.
        payload: dict[str, Any] = cls.verify_token(token)

        iat: float = payload.get("iat", 0)
        exp: float = payload.get("exp", 0)
        now: float = datetime.now(timezone.utc).timestamp()

        lifetime: float = exp - iat
        if lifetime <= 0:
            raise ValueError("Token has invalid lifetime")

        refresh_threshold: float = exp - (lifetime * _REFRESH_WINDOW_RATIO)

        if now < refresh_threshold:
            raise ValueError(
                "Token not yet refreshable — refresh window opens at "
                f"{datetime.fromtimestamp(refresh_threshold, tz=timezone.utc).isoformat()}"
            )

        subject: str = payload.get("sub", "")
        if not subject:
            raise ValueError("Token missing subject claim")

        # Mint a brand-new token — same subject, fresh timestamps & jti.
        return cls.create_token(subject)
