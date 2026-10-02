"""Path normalisation and pattern matching for the constraint ledger.

Every path is brought to one textual form before any rule sees it: forward
slashes, an upper-case drive letter, no ``.``/``..`` segments, no trailing
slash except on a root (``/`` or ``C:/``).  The *flavour* (Windows or POSIX)
is a parameter, never read from the running interpreter, so both behaviours
can be tested on any machine.  Nothing here touches the filesystem.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from functools import lru_cache

_DRIVE_RE = re.compile(r"([A-Za-z]):(.*)", re.DOTALL)
_MSYS_RE = re.compile(r"/([A-Za-z])(/.*)?", re.DOTALL)
_UNC_RE = re.compile(r"//([^/]+)/([^/]+)(/.*)?", re.DOTALL)
_VAR_RE = re.compile(r"\$\{(?:env:)?(\w+)\}|\$(?:env:)?(\w+)|%(\w+)%", re.IGNORECASE)
_WILD_ROOT_RE = re.compile(r"(\*\*|[?*]:)")

#: Environment variables that may be expanded inside a path.
PATH_VARIABLES = (
    "HOME",
    "USERPROFILE",
    "TEMP",
    "TMP",
    "TMPDIR",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "SYSTEMROOT",
    "WINDIR",
)


def expand_variables(text: str, variables: Mapping[str, str]) -> str:
    """Replace ``$NAME``, ``${NAME}``, ``$env:NAME`` and ``%NAME%``.

    Only names present in *variables* (looked up in upper case) are replaced;
    anything else is left exactly as written.
    """

    def substitute(match: re.Match[str]) -> str:
        name = next(g for g in match.groups() if g)
        return variables.get(name.upper(), match.group(0))

    return _VAR_RE.sub(substitute, text) if variables else text


def _split_root(text: str, windows: bool) -> tuple[str | None, str]:
    """Return ``(root, rest)``; ``root`` is ``None`` for a relative path."""
    if windows:
        if match := _DRIVE_RE.fullmatch(text):
            return f"{match.group(1).upper()}:/", match.group(2)
        if match := _UNC_RE.fullmatch(text):
            return f"//{match.group(1)}/{match.group(2)}/", match.group(3) or ""
        if match := _MSYS_RE.fullmatch(text):
            return f"{match.group(1).upper()}:/", match.group(2) or ""
    if text.startswith("/"):
        return "/", text
    return None, text


def normalize(
    raw: str,
    cwd: str,
    *,
    windows: bool,
    home: str | None = None,
    variables: Mapping[str, str] | None = None,
) -> str:
    """Resolve *raw* against *cwd* and return the normalised path.

    Parameters
    ----------
    raw:
        The path as written in the tool call (quotes already removed).
    cwd:
        Working directory of the call.  It is normalised the same way.
    windows:
        Path flavour.  On Windows backslashes are separators, drive letters
        are upper-cased and the MSYS form ``/c/Users`` means ``C:/Users``.
    home:
        Home directory used for ``~``; ``None`` leaves ``~`` untouched.
    variables:
        Upper-case variable names to values, expanded before resolution.
    """
    text = expand_variables(raw.strip(), variables or {})
    if windows:
        text = text.replace("\\", "/")
    if home and (text == "~" or text.startswith("~/")):
        text = home.rstrip("/\\") + text[1:]
        if windows:
            text = text.replace("\\", "/")
    root, rest = _split_root(text, windows)
    if root is None:
        base = cwd.replace("\\", "/") if windows else cwd
        root, base_rest = _split_root(base, windows)
        if root is None:
            root = "/"
        rest = f"{base_rest}/{rest}"
    segments: list[str] = []
    for segment in rest.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if segments:
                segments.pop()
            continue
        segments.append(segment)
    return root + "/".join(segments)


def resolve_pattern(
    pattern: str,
    base: str,
    *,
    windows: bool,
    home: str | None = None,
    variables: Mapping[str, str] | None = None,
    bare_anywhere: bool = False,
) -> str:
    """Normalise a rule's path pattern, keeping its wildcards.

    A pattern starting with ``**``, ``?:`` or ``*:`` is already absolute.
    With *bare_anywhere*, a pattern without any separator (``*.pem``) matches
    that name in any directory.  Everything else is resolved like a path,
    relative patterns against *base*.
    """
    text = pattern.replace("\\", "/") if windows else pattern
    if bare_anywhere and "/" not in text and not text.startswith(("~", "$", "%")):
        return f"**/{text}"
    if _WILD_ROOT_RE.match(text):
        return text if text.endswith(":/") else text.rstrip("/")
    return normalize(pattern, base, windows=windows, home=home, variables=variables)


@lru_cache(maxsize=1024)
def _glob_regex(pattern: str, windows: bool, under: bool) -> re.Pattern[str]:
    if under:
        pattern = pattern.rstrip("/")
    out: list[str] = []
    i, n = 0, len(pattern)
    while i < n:
        char = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif char == "*":
            out.append("[^/]*")
            i += 1
        elif char == "?":
            out.append("[^/]")
            i += 1
        elif char == "[" and (close := pattern.find("]", i + 2)) != -1:
            body = pattern[i + 1 : close].replace("\\", "\\\\")
            if body.startswith("!"):
                body = "^" + body[1:]
            out.append(f"[{body}]")
            i = close + 1
        else:
            out.append(re.escape(char))
            i += 1
    if under:
        out.append("(?:/.*)?")
    return re.compile("".join(out), re.IGNORECASE | re.DOTALL if windows else re.DOTALL)


def matches_glob(path: str, pattern: str, *, windows: bool) -> bool:
    """True when the whole normalised *path* matches the resolved *pattern*.

    ``**`` crosses directory separators; ``*`` and ``?`` do not.  Matching is
    case-insensitive for the Windows flavour.
    """
    return _glob_regex(pattern, windows, False).fullmatch(path) is not None


def is_under(path: str, directory: str, *, windows: bool) -> bool:
    """True when *path* is *directory* itself or anything inside it.

    *directory* is a resolved pattern and may contain wildcards, so
    ``**/node_modules`` covers every ``node_modules`` tree.
    """
    return _glob_regex(directory, windows, True).fullmatch(path) is not None
