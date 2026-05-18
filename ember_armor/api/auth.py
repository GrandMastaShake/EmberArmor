"""Fail-closed authentication for EmberArmor v2.

This module implements the CRITICAL security fix identified during the Centuria
39-agent review: **mandatory fail-closed bearer-token authentication**.

Design decisions
----------------
* ``HTTPBearer(auto_error=False)`` — we handle *all* error paths ourselves so
  that no exception can leak through unauthenticated.
* ``CryptoEngine.constant_time_compare`` — every API-key comparison runs in
  constant time to prevent timing attacks.
* Every failure path raises ``HTTPException(status_code=401)`` with a
  ``WWW-Authenticate: Bearer`` header.
* Auth failures are logged as structured warnings for SIEM ingestion.
"""

from __future__ import annotations

from fastapi import HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ember_armor.core.config import SETTINGS
from ember_armor.security.crypto import CryptoEngine
from ember_armor.utils.logging import logger

# ---------------------------------------------------------------------------
# Bearer-token extractor — auto_error=False is the KEY fail-closed property.
# When False, missing/invalid Authorization headers yield *None* instead of
# raising automatically, letting our explicit verification control every path.
# ---------------------------------------------------------------------------

security: HTTPBearer = HTTPBearer(auto_error=False)


class AuthManager:
    """Mandatory fail-closed authentication manager.

    Every verification method **must** raise ``HTTPException(401)`` on any
    failure.  There are no soft-failure or fallback paths.
    """

    @staticmethod
    async def verify_api_key(
        credentials: HTTPAuthorizationCredentials | None = Security(security),
    ) -> str:
        """Verify the bearer API key.  FAILS CLOSED — any error = 401.

        Parameters
        ----------
        credentials:
            The parsed HTTP Authorization credentials.  Will be ``None`` when
            the ``Authorization`` header is missing, malformed, or uses a
            scheme other than ``Bearer`` (because *auto_error* is ``False``).

        Returns
        -------
        str
            The validated API-key credential string on success.

        Raises
        ------
        HTTPException
            ``401 Unauthorized`` on *every* failure path, with the
            ``WWW-Authenticate: Bearer`` header required by RFC 7235.
        """
        # --- Path 1: no credentials object at all (missing/malformed header) ---
        if credentials is None:
            logger.warning(
                "auth.missing_credentials",
                detail="Authorization header missing or malformed",
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # --- Path 2: credentials object present but token string is empty ---
        if not credentials.credentials:
            logger.warning(
                "auth.empty_credentials",
                detail="Bearer token is empty",
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # --- Path 3: constant-time comparison against the configured API key ---
        if not CryptoEngine.constant_time_compare(
            credentials.credentials,
            SETTINGS.api_key,
        ):
            logger.warning(
                "auth.invalid_key",
                detail="Supplied API key does not match configured key",
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # --- Success: return the validated credential ---
        return credentials.credentials


# ---------------------------------------------------------------------------
# Public export — used as ``Depends(get_current_auth)`` in route definitions.
# ---------------------------------------------------------------------------

get_current_auth = AuthManager.verify_api_key
