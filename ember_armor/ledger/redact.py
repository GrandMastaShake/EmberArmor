"""Replace secret-shaped values before anything is written to the audit log."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

REDACTED = "[REDACTED]"
MAX_TEXT = 256
MAX_ITEMS = 64
MAX_DEPTH = 4
_ELLIPSIS = "...[truncated]"

_NAMES = (
    r"pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|"
    r"credential|authorization"
)
_KEY_RE = re.compile(_NAMES, re.IGNORECASE)
_ASSIGNMENT_RE = re.compile(
    rf"(?i)\b([\w.-]*(?:{_NAMES})[\w.-]*)(\s*[=:]\s*)"
    r"(?:(?:bearer|basic)\s+)?(\"[^\"]*\"|'[^']*'|\S+)"
)
_SHAPES = (
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*", re.DOTALL), REDACTED),
    (re.compile(r"(?i)\b(bearer|basic)\s+[\w.~+/=-]{8,}"), rf"\1 {REDACTED}"),
    (re.compile(r"://[^/\s:@]+:[^/\s@]+@"), f"://{REDACTED}@"),
    (re.compile(r"\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}"), REDACTED),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"), REDACTED),
    (re.compile(r"\bgithub_pat_\w{20,}"), REDACTED),
    (re.compile(r"\bxox[abprs]-[\w-]{10,}"), REDACTED),
    (re.compile(r"\bA[KS]IA[0-9A-Z]{16}\b"), REDACTED),
    (re.compile(r"\bAIza[\w-]{30,}"), REDACTED),
    (re.compile(r"\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}"), REDACTED),
    (
        re.compile(r"\b(?=[\w-]*[a-z])(?=[\w-]*[A-Z])(?=[\w-]*\d)[A-Za-z0-9_-]{32,}\b"),
        REDACTED,
    ),
)


def redact_text(text: str, limit: int = MAX_TEXT) -> str:
    """Replace secret-shaped substrings of *text* and cap its length."""
    text = _ASSIGNMENT_RE.sub(rf"\1\2{REDACTED}", text)
    for pattern, replacement in _SHAPES:
        text = pattern.sub(replacement, text)
    if len(text) > limit:
        text = text[:limit] + _ELLIPSIS
    return text


def redact_argv(argv: Sequence[str]) -> list[str]:
    """Redact an argument vector, including the value after ``--password``."""
    out: list[str] = []
    secret_next = False
    for arg in argv[:MAX_ITEMS]:
        out.append(REDACTED if secret_next else redact_text(arg))
        secret_next = (
            arg.startswith("-") and "=" not in arg and _KEY_RE.search(arg) is not None
        )
    return out


def redact_value(value: Any, depth: int = 0) -> Any:
    """Redact a structured tool input (nested maps and lists)."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, bool | int | float) or value is None:
        return value
    if depth >= MAX_DEPTH:
        return _ELLIPSIS
    if isinstance(value, Mapping):
        return {
            str(key): REDACTED
            if _KEY_RE.search(str(key)) and not isinstance(item, Mapping | list)
            else redact_value(item, depth + 1)
            for key, item in list(value.items())[:MAX_ITEMS]
        }
    if isinstance(value, list | tuple):
        return [redact_value(item, depth + 1) for item in value[:MAX_ITEMS]]
    return redact_text(str(value))
