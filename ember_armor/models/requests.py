from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator


class DissonanceCheckRequest(BaseModel):
    """Request to check for behavioral contradictions in AI-generated text.

    Attributes:
        input_text: The text to analyze for contradictions. Must be non-empty.
        context_id: Optional identifier for the conversation context.
        session_id: Optional session identifier for tracking.
        metadata: Optional arbitrary metadata for the request.
    """

    input_text: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="Text to analyze for contradictions",
    )
    context_id: str | None = Field(
        default=None,
        max_length=256,
        description="Conversation context identifier",
    )
    session_id: str | None = Field(
        default=None,
        max_length=256,
        description="Session identifier for tracking",
    )
    metadata: dict[str, Any] | None = Field(
        default=None,
        description="Arbitrary metadata for the request",
    )

    @field_validator("input_text")
    @classmethod
    def _validate_input_text_not_empty(cls, v: str) -> str:
        """Ensure input_text is not empty or whitespace-only after stripping."""
        if not v.strip():
            raise ValueError("input_text cannot be empty or whitespace")
        return v


class TemporalAnchorRequest(BaseModel):
    """Request to register a temporal constraint.

    Attributes:
        constraint_id: Unique identifier for the constraint.
        constraint_data: Arbitrary data defining the constraint.
        ttl_seconds: Time-to-live in seconds (60 to 86400).
    """

    constraint_id: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Unique identifier for the constraint",
    )
    constraint_data: dict[str, Any] = Field(
        ...,
        description="Constraint definition data",
    )
    ttl_seconds: int = Field(
        default=3600,
        ge=60,
        le=86400,
        description="Time-to-live in seconds (60 to 86400)",
    )


class AuthRequest(BaseModel):
    """Authentication request.

    Attributes:
        api_key: The API key to authenticate with. Minimum 32 characters.
    """

    api_key: str = Field(
        ...,
        min_length=32,
        description="API key for authentication (min 32 characters)",
    )
