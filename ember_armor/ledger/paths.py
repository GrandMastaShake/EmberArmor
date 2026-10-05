"""Path normalisation and pattern matching for the constraint ledger.

Every path is brought to one textual form before any rule sees it: forward
slashes, an upper-case drive letter, no ``.``/``..`` segments, no trailing
slash except on a root (``/`` or ``C:/``).  The *flavour* (Windows or POSIX)
is a parameter, never read from the running interpreter, so both behaviours
can be tested on any machine.  Nothing here touches the filesystem.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from functools import lru_cache

from ember_armor.ledger.shell.core import UNKNOWN_DIR

__all__ = [
    "NO_PATH",
    "PATH_VARIABLES",
    "UNKNOWN_DIR",
    "Lookup",
    "PathFact",
    "expand_variables",
    "is_under",
    "matches_glob",
    "may_match",
    "normalize",
    "resolve_pattern",
]

_DRIVE_RE = re.compile(r"([A-Za-z]):(.*)", re.DOTALL)
_MSYS_RE = re.compile(r"/([A-Za-z])(/.*)?", re.DOTALL)
_UNC_RE = re.compile(r"//([^/]+)/([^/]+)(/.*)?", re.DOTALL)
#: ``//c/Users``: the MSYS drive form with its slash doubled, not a host ``c``.
_MSYS_DOUBLED_RE = re.compile(r"//([A-Za-z])(/.*)?", re.DOTALL)
_DEVICE_RE = re.compile(r"//[?.]/(UNC/)?", re.IGNORECASE)
_LOCAL_SHARE_RE = re.compile(
    r"//(?:localhost|127\.0\.0\.1)/([A-Za-z])\$(/.*)?", re.IGNORECASE | re.DOTALL
)
_MOUNT_RE = re.compile(r"/(?:mnt|cygdrive)/([A-Za-z])(/.*)?", re.DOTALL)
_VAR_RE = re.compile(
    r"\$\{env:(\w+)\}|\$env:(\w+)|%(\w+)%|\$\{(\w+)\}|\$(\w+)", re.IGNORECASE
)
#: A path segment that still holds a variable or a substitution.
_OPEN_RE = re.compile(r"[$`]|%\w+%")
_WILD_ROOT_RE = re.compile(r"(\*\*|[?*]:)")
_CLASS_RE = re.compile(r"\[[^\]]*\]")
#: Characters that mean something to ``re`` inside a class and nothing to a
#: glob (the backslash first: the others are escaped with one).
_CLASS_SPECIAL = ("\\", "[", "&", "|", "~")
_WILDCARDS = frozenset("*?[")
_MAX_EXPANSIONS = 4
#: Stands in for a rule pattern that names an unset variable: no path has it.
NO_PATH = "\x00"

#: ``lookup(name)`` gives the value of a shell variable, or ``None``.
Lookup = Callable[[str], str | None]


@dataclass(frozen=True)
class PathFact:
    """One path a call touches: ``op`` is ``read``, ``write`` or ``delete``.

    ``cwd`` is the directory in effect where a shell command touches the
    path: empty for the working directory of the call, :data:`UNKNOWN_DIR`
    when it cannot be known.  ``source`` is the index of that command among
    the commands of the call (``-1`` for a file tool).  Neither is part of
    the fact's identity.
    """

    path: str
    op: str
    recursive: bool = False
    cwd: str = field(default="", compare=False)
    source: int = field(default=-1, compare=False)


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
    "HOMEDRIVE",
    "HOMEPATH",
    "EMBER_HOME",
)


def expand_variables(
    text: str, variables: Mapping[str, str], lookup: Lookup | None = None
) -> str:
    """Replace ``$NAME``, ``${NAME}``, ``$env:NAME`` and ``%NAME%``.

    ``$env:NAME`` and ``%NAME%`` are environment variables: they are looked
    up in *variables* in upper case.  A plain ``$NAME`` is a shell variable:
    *lookup* resolves it when given (case rules are the shell's), otherwise
    it is read from *variables* too.  A value may itself hold references;
    they are expanded as well, a bounded number of times.  Anything unknown
    is left exactly as written.
    """

    def substitute(match: re.Match[str]) -> str:
        name = next(g for g in match.groups() if g)
        plain = match.group(4) or match.group(5)
        if plain and lookup is not None:
            value = lookup(plain)
        else:
            value = variables.get(name.upper())
        return match.group(0) if value is None else value

    if not variables and lookup is None:
        return text
    for _ in range(_MAX_EXPANSIONS):
        expanded = _VAR_RE.sub(substitute, text)
        if expanded == text:
            break
        text = expanded
    return text


def _split_root(text: str, windows: bool) -> tuple[str | None, str]:
    """Return ``(root, rest)``; ``root`` is ``None`` for a relative path."""
    if windows:
        if match := _DEVICE_RE.match(text):
            # ``\\?\C:\x`` is ``C:\x``; ``\\?\UNC\host\share`` is ``\\host\share``.
            text = ("//" if match.group(1) else "") + text[match.end() :]
        local = (
            _LOCAL_SHARE_RE.fullmatch(text)
            or _MOUNT_RE.fullmatch(text)
            or _MSYS_DOUBLED_RE.fullmatch(text)
        )
        if local:
            return f"{local.group(1).upper()}:/", local.group(2) or ""
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
    lookup: Lookup | None = None,
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
        are upper-cased, the MSYS form ``/c/Users`` means ``C:/Users``, and
        so do ``/mnt/c/Users``, ``\\\\?\\C:\\Users`` and ``\\\\localhost\\C$\\Users``.
    home:
        Home directory used for ``~``; ``None`` leaves ``~`` untouched.
    variables:
        Upper-case variable names to values, expanded before resolution.
    lookup:
        Resolver for plain ``$NAME`` shell variables (see
        :func:`expand_variables`).
    """
    text = expand_variables(raw.strip(), variables or {}, lookup)
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
            # What lies above a segment that was not resolved is not known:
            # ``$DIR/..`` stays as written, it is not the directory before it.
            if segments and (segments[-1] == ".." or _OPEN_RE.search(segments[-1])):
                segments.append(segment)
            elif segments:
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
    relative patterns against *base*.  A pattern whose variable is not set
    (``$TMPDIR`` on Windows) resolves to :data:`NO_PATH` and matches nothing.
    """
    if variables is not None and _VAR_RE.search(expand_variables(pattern, variables)):
        return NO_PATH
    text = pattern.replace("\\", "/") if windows else pattern
    if bare_anywhere and "/" not in text and not text.startswith(("~", "$", "%")):
        return f"**/{text}"
    if _WILD_ROOT_RE.match(text):
        return text if text.endswith(":/") else text.rstrip("/")
    return normalize(pattern, base, windows=windows, home=home, variables=variables)


def _class(body: str) -> str | None:
    """The regular expression for ``[body]`` of a glob, if it is a class.

    ``None`` for a body that is none (a range that runs backwards, ``[!]``):
    the bracket is then literal text, as a bracket that is never closed is.
    A pattern from a ledger must not be able to make the matcher raise.
    """
    negated = body.startswith("!")
    inner = body[1:] if negated else body
    for special in _CLASS_SPECIAL:
        inner = inner.replace(special, "\\" + special)
    group = f"[{'^' if negated else ''}{inner}]"
    try:
        re.compile(group)
    except re.error:
        return None
    return group


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
        elif (
            char == "["
            and (close := pattern.find("]", i + 2)) != -1
            and (group := _class(pattern[i + 1 : close])) is not None
        ):
            out.append(group)
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


def _abbreviates(operand: str, pattern: str) -> bool:
    """True when the wildcarded *operand* abbreviates a name *pattern* describes.

    Some file name must fit both, and the operand's own literal text must
    fall on literal text of the pattern: ``.env*`` and ``.env.*`` abbreviate
    ``.env.local``, ``id_*`` abbreviates ``id_rsa``.  ``readme*`` does not
    abbreviate ``*key*.pem``, although ``readme-key.pem`` would fit both: its
    text says nothing about keys.  A pattern that is only wildcards (every
    file of a directory) is abbreviated by any operand.
    """
    a, b = _CLASS_RE.sub("?", operand), _CLASS_RE.sub("?", pattern)
    anything = not b.strip("*?")
    seen: set[tuple[int, int]] = set()
    todo = [(0, 0)]
    while todo:
        i, j = todo.pop()
        if (i, j) in seen:
            continue
        seen.add((i, j))
        if i == len(a) and j == len(b):
            return True
        x, y = a[i : i + 1], b[j : j + 1]
        if x == "*":
            todo.append((i + 1, j))
            if y:
                todo.append((i, j + 1))
        elif y == "*":
            todo.append((i, j + 1))
            if x and (anything or x == "?"):
                todo.append((i + 1, j))
        elif x and y and (x == y or "?" in (x, y)):
            todo.append((i + 1, j + 1))
    return False


def may_match(path: str, pattern: str, *, windows: bool) -> bool:
    """True when *path* matches *pattern*, or may once a shell expands it.

    A shell operand can still hold wildcards (``cat .env*``).  When its last
    segment starts with literal text and holds a wildcard, the question is
    whether that segment abbreviates a name the pattern describes (see
    :func:`_abbreviates`).  A segment that is only an extension (``*.json``)
    or only wildcards is too unspecific to count.  The directory part matches
    as written.
    """
    if matches_glob(path, pattern, windows=windows):
        return True
    directory, _, name = path.rpartition("/")
    if not name or name[0] in _WILDCARDS or not _WILDCARDS.intersection(name):
        return False
    pattern_directory, _, pattern_name = pattern.rpartition("/")
    if not matches_glob(directory, pattern_directory, windows=windows):
        return False
    if windows:
        name, pattern_name = name.lower(), pattern_name.lower()
    return _abbreviates(name, pattern_name)


def is_under(path: str, directory: str, *, windows: bool) -> bool:
    """True when *path* is *directory* itself or anything inside it.

    *directory* is a resolved pattern and may contain wildcards, so
    ``**/node_modules`` covers every ``node_modules`` tree.
    """
    return _glob_regex(directory, windows, True).fullmatch(path) is not None
