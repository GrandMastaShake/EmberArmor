"""Replace secret-shaped values before anything is written to the audit log.

Redaction is a best effort on text the gate did not write.  It knows common
names (``password``, ``token``, ``api_key``, ``cookie``), common shapes
(bearer tokens, key prefixes, long mixed or hexadecimal strings) and the
flags a few programs take their secrets on (``docker login -p``,
``curl -u``).  A secret with an unremarkable name and shape, passed where
nothing marks it, is not recognised.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

from ember_armor.ledger.shell.core import program_name

TYPE_CHECKING = False
if TYPE_CHECKING:
    from typing import Any

REDACTED = "[REDACTED]"
MAX_TEXT = 256
MAX_ITEMS = 64
MAX_DEPTH = 4
_ELLIPSIS = "...[truncated]"

#: Names that mark a secret.  The short ones only count as a whole word
#: (``key``, ``api_key``, ``STRIPE_KEY``; not ``keyboard``).
_NAMES = (
    r"pass(?:word|wd)?|secret|token|credential|authorization|cookie|signature|"
    r"(?<![A-Za-z0-9])(?:[A-Za-z0-9]*key|auth|pwd|pw|sig)(?![A-Za-z0-9])"
)
_KEY_RE = re.compile(_NAMES, re.IGNORECASE)
_VALUE = r"(?:(?:bearer|basic)\s+)?(\"[^\"]*\"|'[^']*'|\S+)"
#: ``name=value`` and ``name: value``; possessive so a long run cannot backtrack.
_ASSIGNMENT_RE = re.compile(rf"(?i)((?:{_NAMES})[\w.-]*+\s*[=:]\s*){_VALUE}")
_SPACE_RE = re.compile(r"(\s+)")
_SHAPES = (
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*", re.DOTALL), REDACTED),
    (re.compile(r"(?i)\b(bearer|basic)\s+[\w.~+/=-]{8,}"), rf"\1 {REDACTED}"),
    (re.compile(r"://[^/\s@]+@"), f"://{REDACTED}@"),
    (re.compile(r"\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}"), REDACTED),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"), REDACTED),
    (re.compile(r"\bgithub_pat_\w{20,}"), REDACTED),
    (re.compile(r"\bxox[abprs]-[\w-]{10,}"), REDACTED),
    (re.compile(r"\bA[KS]IA[0-9A-Z]{16}\b"), REDACTED),
    (re.compile(r"\bAIza[\w-]{30,}"), REDACTED),
    (re.compile(r"\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}"), REDACTED),
)
_LONG_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{32,}")
_MIN_MIXED = 6

#: Flags whose value is a secret for these programs, whatever the flag's name:
#: the argument that must be present (``login``), if any, and the flags.
_SECRET_FLAGS: dict[str, tuple[str | None, frozenset[str]]] = {
    "docker": ("login", frozenset({"-p"})),
    "podman": ("login", frozenset({"-p"})),
    "sshpass": (None, frozenset({"-p"})),
    "mysql": (None, frozenset({"-p"})),
    "mariadb": (None, frozenset({"-p"})),
    "mysqldump": (None, frozenset({"-p"})),
    "curl": (None, frozenset({"-u", "--user", "--proxy-user"})),
    "wget": (None, frozenset({"--user", "--http-user"})),
    "vercel": (None, frozenset({"-t"})),
    "vc": (None, frozenset({"-t"})),
}
#: Programs that take the password glued to ``-p`` (``mysql -pSECRET``).
_ATTACHED_PASSWORD = frozenset({"mysql", "mariadb", "mysqldump"})


def _secret_shaped(match: re.Match[str]) -> str:
    """Redact a long token that mixes letters and digits like a generated key."""
    token = match.group()
    digits = sum(char.isdigit() for char in token)
    letters = sum(char.isalpha() for char in token)
    cased = token != token.lower() and token != token.upper()
    generated = digits >= _MIN_MIXED and letters >= _MIN_MIXED
    return REDACTED if generated or (cased and digits) else token


def _names_secret(flag: str) -> bool:
    """True for a flag whose value is secret by its name (``--api-key``)."""
    return flag.startswith("-") and "=" not in flag and bool(_KEY_RE.search(flag))


def _flag_values(text: str) -> str:
    """Redact the word after a secret-named flag inside one string.

    Covers a script kept as a single argument (``eval "deploy --key X"``).
    """
    pieces = _SPACE_RE.split(text)
    for index in range(2, len(pieces), 2):
        if _names_secret(pieces[index - 2]):
            pieces[index] = REDACTED
    return "".join(pieces)


def writable(text: str) -> str:
    """*text* with half a surrogate pair turned into its escape.

    JSON can carry one (``"\\ud83d"``) and UTF-8 cannot, so a field that
    held one could be neither hashed nor written.
    """
    if text.isascii():
        return text
    return text.encode("utf-8", "backslashreplace").decode("utf-8")


def session_key(value: Any) -> str:
    """A session id as the gate keeps it, logs it and looks it up.

    Text that can be written, capped like every logged field.  One form
    everywhere, so the entries of a session are found again whatever the
    host sent as its id.
    """
    return writable(str(value or ""))[:MAX_TEXT]


def redact_path(path: str, limit: int = 4 * MAX_TEXT) -> str:
    """Cap a path and replace the unmistakable key shapes in it.

    The name-based and long-token rules are left out: they would blank
    ordinary directory names such as a session's scratch directory.
    """
    for pattern, replacement in _SHAPES:
        path = pattern.sub(replacement, path[: 2 * limit])
    return path if len(path) <= limit else path[:limit] + _ELLIPSIS


def redact_text(text: str, limit: int = MAX_TEXT) -> str:
    """Replace secret-shaped substrings of *text* and cap its length.

    Only the first ``8 * limit`` characters are examined, so a huge argument
    cannot make the patterns slow; everything past *limit* is cut anyway.
    """
    text = _ASSIGNMENT_RE.sub(rf"\1{REDACTED}", text[: 8 * limit])
    text = _flag_values(text)
    for pattern, replacement in _SHAPES:
        text = pattern.sub(replacement, text)
    text = _LONG_TOKEN_RE.sub(_secret_shaped, text)
    if len(text) > limit:
        text = text[:limit] + _ELLIPSIS
    return text


def redact_argv(argv: Sequence[str]) -> list[str]:
    """Redact an argument vector, including the value after ``--password``."""
    program = program_name(argv[0]) if argv else ""
    needed, secret_flags = _SECRET_FLAGS.get(program, (None, frozenset()))
    if needed is not None and needed not in argv:
        secret_flags = frozenset()
    out: list[str] = []
    secret_next = False
    for arg in argv[:MAX_ITEMS]:
        if secret_next:
            out.append(REDACTED)
        elif program in _ATTACHED_PASSWORD and arg.startswith("-p") and len(arg) > 2:
            out.append(f"-p{REDACTED}")
        else:
            out.append(redact_text(arg))
        secret_next = _names_secret(arg) or arg in secret_flags
    return out


def redact_value(value: Any, depth: int = 0, *, secret: bool = False) -> Any:
    """Redact a structured tool input (nested maps and lists).

    Everything below a secret-named key is replaced, however it is nested.
    """
    if isinstance(value, Mapping | list | tuple):
        if depth >= MAX_DEPTH:
            return _ELLIPSIS
        if isinstance(value, Mapping):
            return {
                str(key)[:MAX_TEXT]: redact_value(
                    item, depth + 1, secret=secret or bool(_KEY_RE.search(str(key)))
                )
                for key, item in list(value.items())[:MAX_ITEMS]
            }
        items = value[:MAX_ITEMS]
        return [redact_value(item, depth + 1, secret=secret) for item in items]
    if secret:
        return REDACTED
    if isinstance(value, bool | int | float) or value is None:
        return value
    return redact_text(str(value))
