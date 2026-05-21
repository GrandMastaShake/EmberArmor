"""EmberArmor settings — fail-closed configuration management.

All secrets **must** be provided via environment variables (``EMBER_*``).
The module-level ``SETTINGS`` singleton is instantiated at import time so
that the application refuses to start when secrets are missing or too short.
"""

from __future__ import annotations

import sys

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# We avoid importing from ember_armor.utils.logging at the top level to
# prevent a circular import: config → logger → structlog → …  The logger is
# imported locally inside the validator so that the module can still be
# imported in contexts where structlog is not yet configured.


class EmberSettings(BaseSettings):
    """Production-grade settings for EmberArmor.

    Secrets are **mandatory** — the system will not start without them.
    All non-secret fields carry safe, fail-closed defaults.
    """

    model_config = SettingsConfigDict(
        env_prefix="EMBER_",
        # .env file is only loaded when EMBER_ENV=development is set.
        # In production deployments secrets are injected via environment
        # variables or a secrets manager — never from a writable .env file.
        # An attacker who can write .env could escalate privileges by
        # overriding EMBER_API_KEY or EMBER_TOKEN_SECRET.
        env_file=(".env" if __import__("os").environ.get("EMBER_ENV") == "development" else None),
        env_file_encoding="utf-8",
        case_sensitive=False,
        # Extra fields are rejected — typos in env vars are caught early.
        extra="forbid",
        populate_by_name=True,
    )

    # ------------------------------------------------------------------
    # API & Security  (MANDATORY — no defaults, system refuses to start)
    # ------------------------------------------------------------------
    api_key: str = Field(
        ...,  # noqa: W501
        min_length=32,
        description="Master API key for authentication — must be >= 32 chars",
    )
    token_secret: str = Field(
        ...,  # noqa: W501
        min_length=32,
        description="Secret key for token signing — must be >= 32 chars",
    )

    # ------------------------------------------------------------------
    # Application
    # ------------------------------------------------------------------
    app_name: str = "EmberArmor"
    debug: bool = False
    host: str = "127.0.0.1"
    port: int = 8000

    # ------------------------------------------------------------------
    # Rate Limiting
    # ------------------------------------------------------------------
    rate_limit_requests: int = 60
    rate_limit_window: int = 60

    # ------------------------------------------------------------------
    # Circuit Breaker
    # ------------------------------------------------------------------
    cb_failure_threshold: int = 5
    cb_recovery_timeout: float = 30.0
    cb_window_size: float = 60.0

    # ------------------------------------------------------------------
    # Sonar (Perplexity) — Live threat intelligence
    # Optional: if not set, Sonar agent votes REVIEW on all calls (fail-closed).
    # ------------------------------------------------------------------
    sonar_api_key: str | None = Field(
        default=None,
        description="Perplexity API key for Sonar live threat intelligence",
        alias="PERPLEXITY_API_KEY",
    )
    sonar_model: str = Field(
        default="sonar-pro",
        description="Sonar model to use for consensus votes and TTP enrichment",
    )
    sonar_enabled: bool = Field(
        default=True,
        description="Enable/disable Sonar consensus agent. When disabled, falls back to local-only consensus.",
    )
    sonar_agent_weight: float = Field(
        default=0.40,
        ge=0.0,
        le=1.0,
        description="Voting weight for the Sonar consensus agent in EnsembleConductor",
    )

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------
    log_level: str = "INFO"
    structured_logging: bool = True

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------
    @field_validator("api_key", "token_secret", mode="before")
    @classmethod
    def validate_secret_length(cls, v: object) -> str:
        """Ensure secrets are at least 32 characters.

        This validator runs *before* pydantic's built-in ``min_length``
        check so that we can emit a clear, actionable error message.
        """
        s = str(v) if v is not None else ""
        if len(s) < 32:
            raise ValueError(
                "Secret must be at least 32 characters. "
                f"Received {len(s)} characters. "
                "Set EMBER_API_KEY and EMBER_TOKEN_SECRET environment variables."
            )
        return s


# ---------------------------------------------------------------------------
# Singleton — fails at import time if secrets are missing / too short.
# ---------------------------------------------------------------------------

def _instantiate_settings() -> EmberSettings:
    """Create the settings singleton with user-friendly error reporting."""
    try:
        return EmberSettings()
    except Exception as exc:
        # Emit a plain stderr message *before* the logger is available so
        # that operators see the failure even in container environments.
        print(
            f"\n[EmberArmor FATAL] Configuration error: {exc}\n"
            "\nEmberArmor requires the following environment variables:\n"
            "  EMBER_API_KEY       — Master API key (>= 32 characters)\n"
            "  EMBER_TOKEN_SECRET  — Token signing secret (>= 32 characters)\n"
            "\nThe system will NOT start without valid secrets.\n",
            file=sys.stderr,
        )
        # Attempt structured logging if structlog happens to be available.
        try:
            from ember_armor.utils.logging import logger  # type: ignore[import]

            logger.error("config.validation_failed", error=str(exc))
        except Exception:
            pass  # Logger not yet available — plain stderr above is sufficient.
        raise


SETTINGS: EmberSettings = _instantiate_settings()
