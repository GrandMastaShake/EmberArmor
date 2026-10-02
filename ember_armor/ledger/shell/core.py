"""Shared data structures and tables for the shell parsers.

The parsers read command *strings* and describe them.  Nothing in this
package runs a command, starts a process or touches the filesystem.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

MAX_COMMAND_CHARS = 200_000
MAX_DEPTH = 8

#: Reason kinds a call can be marked ``dynamic_shell`` with.
DYNAMIC_KINDS = (
    "parse_error",
    "eval",
    "variable_command",
    "nested_dynamic",
    "encoded_command",
    "pipe_to_shell",
    "decoder_pipe",
    "download_pipe",
)

BASH_SHELLS = frozenset({"bash", "sh", "zsh", "dash", "ksh", "ash"})
POWERSHELLS = frozenset({"powershell", "pwsh"})
INTERPRETERS = frozenset({"python", "python3", "perl", "ruby", "node", "php"})
DOWNLOADERS = frozenset(
    {"curl", "wget", "fetch", "http", "invoke-webrequest", "invoke-restmethod"}
)
DECODERS = frozenset(
    {"base64", "base32", "xxd", "openssl", "gunzip", "gzip", "zcat", "uudecode"}
)
_EXE_SUFFIXES = (".exe", ".cmd", ".bat", ".com")
_FIND_EXEC = frozenset({"-exec", "-execdir", "-ok", "-okdir"})


class ParseError(Exception):
    """The command string could not be resolved to literal commands."""


@dataclass(frozen=True)
class Redirect:
    """A redirection of a simple command: ``op`` is ``read`` or ``write``."""

    op: str
    target: str


@dataclass(frozen=True)
class SimpleCommand:
    """One simple command as an argument vector.

    ``argv`` may be empty for a bare redirection (``> file``).  Variable
    references that could not be resolved stay in the text as written.
    """

    argv: tuple[str, ...]
    shell: str
    redirects: tuple[Redirect, ...] = ()


@dataclass(frozen=True)
class Dynamic:
    """Why a command string is not fully literal."""

    kind: str
    detail: str = ""


@dataclass
class ParseResult:
    """Everything a parser learned from one command string."""

    commands: list[SimpleCommand] = field(default_factory=list)
    dynamic: list[Dynamic] = field(default_factory=list)
    variables: dict[str, str] = field(default_factory=dict)

    def merge(self, other: ParseResult) -> None:
        """Append the findings of a nested parse."""
        self.commands.extend(other.commands)
        self.dynamic.extend(other.dynamic)
        self.variables.update(other.variables)


#: ``recurse(text, shell, depth)`` parses a nested literal shell string.
Recurse = Callable[[str, str, int], ParseResult]


def program_name(arg: str, *, fold: bool = True) -> str:
    """Program name without directory and executable suffix.

    Lower-cased unless *fold* is false (POSIX shells are case-sensitive).
    """
    name = arg.replace("\\", "/").rsplit("/", 1)[-1]
    for suffix in _EXE_SUFFIXES:
        if name.lower().endswith(suffix) and len(name) > len(suffix):
            name = name[: -len(suffix)]
            break
    return name.lower() if fold else name


def find_targets(args: Sequence[str]) -> tuple[list[str], bool]:
    """Paths a ``find`` invocation acts on.

    Returns
    -------
    tuple[list[str], bool]
        The start directories, each extended by the ``-name`` pattern when
        there is one, and whether such a name filter was present.
    """
    roots: list[str] = []
    for arg in args:
        if arg.startswith(("-", "(", "!")):
            break
        roots.append(arg)
    roots = roots or ["."]
    names = [args[i + 1] for i, a in enumerate(args[:-1]) if a in ("-name", "-iname")]
    if not names:
        return roots, False
    return [f"{root.rstrip('/')}/{names[0]}" for root in roots], True


def find_exec(args: Sequence[str]) -> list[tuple[str, ...]]:
    """Commands a ``find`` runs through ``-exec``, with ``{}`` filled in."""
    targets, _ = find_targets(args)
    commands: list[tuple[str, ...]] = []
    for i, arg in enumerate(args):
        if arg in _FIND_EXEC:
            rest = args[i + 1 :]
            ends = [j for j, a in enumerate(rest) if a in (";", "+")]
            inner = rest[: ends[0]] if ends else rest
            commands.append(tuple(targets[0] if a == "{}" else a for a in inner))
    return [command for command in commands if command]


def pipe_kind(upstream: Sequence[str]) -> str:
    """Classify what feeds a shell that reads its script from a pipe.

    Parameters
    ----------
    upstream:
        Lower-cased program names of the earlier pipeline stages.
    """
    if any(name in DOWNLOADERS for name in upstream):
        return "download_pipe"
    if any(name in DECODERS for name in upstream):
        return "decoder_pipe"
    return "pipe_to_shell"
