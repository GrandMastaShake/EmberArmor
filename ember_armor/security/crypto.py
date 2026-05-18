"""Production-grade cryptographic operations for EmberArmor v2.

Implements the security-critical primitives identified during the Centuria review:
- Secure secret generation (token_urlsafe, NOT uuid4)
- PBKDF2-HMAC-SHA256 key derivation (480 000+ iterations)
- HMAC-SHA256 computation
- Constant-time comparison (hmac.compare_digest, NEVER ==)

All operations use only standard-library modules (hashlib, hmac, secrets)
to minimize supply-chain attack surface.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Tuple


class CryptoEngine:
    """Production-grade cryptographic operations.

    Every method is a staticmethod so the class acts as a pure namespace;
    no instance state is required (and none is stored).
    """

    # ------------------------------------------------------------------
    # Key-derivation parameters — hardened defaults (OWASP 2023)
    # ------------------------------------------------------------------
    PBKDF2_ITERATIONS: int = 480_000
    SALT_LENGTH: int = 32  # 256 bits
    KEY_LENGTH: int = 32  # 256 bits (SHA-256 output size)

    @staticmethod
    def generate_secret(length: int = 64) -> str:
        """Generate a cryptographically secure secret.

        Pipeline:  secrets.token_urlsafe -> SHA-256 -> hex[:*length*]

        The double-hashing step guarantees uniform entropy distribution
        even if token_urlsafe output has structural bias, and yields a
        deterministic-length hex string suitable for storage in fixed-width
        database columns.

        Parameters
        ----------
        length:
            Desired length of the returned hex string (default 64).
            Clamped to a maximum of 64 because the underlying SHA-256
            digest is only 64 hex characters.

        Returns
        -------
        str
            Cryptographically secure hex-encoded secret.
        """
        raw: str = secrets.token_urlsafe(length)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:length]

    @staticmethod
    def derive_hmac_key(
        master_secret: str,
        context: str,
    ) -> Tuple[bytes, bytes]:
        """Derive a per-context HMAC key via PBKDF2-HMAC-SHA256.

        A unique 32-byte random salt is generated for every call and
        returned alongside the derived key.  Callers must store the salt
        alongside the ciphertext so that verification can reproduce the
        same key deterministically.

        Parameters
        ----------
        master_secret:
            The high-entropy master secret used as the PBKDF2 password.
        context:
            A domain-separation string (e.g. "audit-signing") that is
            prepended to the master secret to ensure keys for different
            purposes are cryptographically independent.

        Returns
        -------
        Tuple[bytes, bytes]
            ``(key, salt)`` where *key* is the 32-byte derived key and
            *salt* is the 32-byte random salt used during derivation.
        """
        salt: bytes = secrets.token_bytes(CryptoEngine.SALT_LENGTH)
        key: bytes = hashlib.pbkdf2_hmac(
            "sha256",
            (context + master_secret).encode("utf-8"),
            salt,
            CryptoEngine.PBKDF2_ITERATIONS,
            dklen=CryptoEngine.KEY_LENGTH,
        )
        return key, salt

    @staticmethod
    def compute_hmac(data: bytes, key: bytes) -> str:
        """Compute HMAC-SHA256 over *data* using *key*.

        Parameters
        ----------
        data:
            The payload to authenticate.
        key:
            The secret key (must be 32 bytes for HS256).

        Returns
        -------
        str
            Lower-case hex-encoded HMAC digest.
        """
        return hmac.new(key, data, hashlib.sha256).hexdigest()

    @staticmethod
    def constant_time_compare(a: str, b: str) -> bool:
        """Constant-time string comparison to prevent timing attacks.

        Uses ``hmac.compare_digest`` which runs in time proportional to
        the *longer* of the two inputs, revealing no information about
        where (or whether) the strings differ.

        .. warning::
            Never use ``==`` or ``str.startswith`` to compare secrets.

        Parameters
        ----------
        a:
            First string (e.g. submitted API key).
        b:
            Second string (e.g. stored API key).

        Returns
        -------
        bool
            ``True`` iff the strings are identical.
        """
        return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
