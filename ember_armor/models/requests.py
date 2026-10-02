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


class LedgerCheckRequest(BaseModel):
    """A proposed tool call to check against the constraint ledger.

    The fields are those of a Claude Code PreToolUse hook payload, so a host
    can post that payload unchanged; other fields are ignored.

    Attributes:
        tool_name: Name of the tool the agent wants to call.
        tool_input: The input the tool would be called with.
        cwd: Working directory of the call.
        session_id: Session identifier (used by history rules).
    """

    tool_name: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Name of the tool the agent wants to call",
    )
    tool_input: dict[str, Any] = Field(
        default_factory=dict,
        description="The input the tool would be called with",
    )
    cwd: str = Field(
        default="",
        max_length=4096,
        description="Working directory of the call",
    )
    session_id: str = Field(
        default="",
        max_length=256,
        description="Session identifier (used by history rules)",
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
