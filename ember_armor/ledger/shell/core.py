"""Shared data structures and tables for the shell parsers.

The parsers read command *strings* and describe them.  Nothing in this
package runs a command, starts a process or touches the filesystem.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

MAX_COMMAND_CHARS = 200_000
MAX_COMMANDS = 2_000
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
#: Pipeline stages that only select from what they are fed.  A command reading
#: from one of them is still fed by the stage before it.
SELECTORS = frozenset(
    {"grep", "egrep", "fgrep", "sort", "uniq", "head", "tail", "where-object",
     "where", "?", "select-object", "sort-object"}
)  # fmt: skip
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
    ``stdin`` is the literal text handed to the command by a here-document
    or here-string.  ``upstream`` is the argument vector of the pipeline
    stage that feeds the command (stages that only select are skipped).
    """

    argv: tuple[str, ...]
    shell: str
    redirects: tuple[Redirect, ...] = ()
    stdin: str = ""
    upstream: tuple[str, ...] = ()


@dataclass(frozen=True)
class Dynamic:
    """Why a command string is not fully literal."""

    kind: str
    detail: str = ""


@dataclass
class ParseResult:
    """Everything a parser learned from one command string.

    ``variables`` holds each shell variable that was given exactly one
    value made of literal text and plain variable references (kept as
    written).  ``choices`` holds loop variables and arrays over literal
    words.  ``unknown`` names every variable whose value the parser cannot
    know: assigned from a command, read from input, or assigned twice.
    Names are as written for Bash and lower-cased for PowerShell.
    ``scopes`` are index ranges of commands that run in a process of their
    own (a subshell, a substitution, a nested shell): a ``cd`` inside one
    does not move the commands after it.  ``assigned`` names every variable
    the string sets in the environment of a command: any assignment in Bash
    (alone, in front of a command, through ``export`` or ``env``, also
    ``unset``), and ``$env:NAME`` in PowerShell.
    """

    commands: list[SimpleCommand] = field(default_factory=list)
    dynamic: list[Dynamic] = field(default_factory=list)
    variables: dict[str, str] = field(default_factory=dict)
    choices: dict[str, tuple[str, ...]] = field(default_factory=dict)
    unknown: set[str] = field(default_factory=set)
    scopes: list[tuple[int, int]] = field(default_factory=list)
    assigned: list[str] = field(default_factory=list)

    def assign(self, name: str, value: str | tuple[str, ...] | None) -> None:
        """Record an assignment to *name*.

        *value* is the literal text, a tuple of literal alternatives, or
        ``None`` when it cannot be known.  A second, different assignment
        makes the name unknown: the parser does not track which one is in
        force where.
        """
        if value is None or name in self.unknown:
            self.forget(name)
        elif isinstance(value, tuple):
            if name in self.variables or self.choices.setdefault(name, value) != value:
                self.forget(name)
        elif name in self.choices or self.variables.setdefault(name, value) != value:
            self.forget(name)

    def forget(self, name: str) -> None:
        """Mark *name* as a variable whose value is not known."""
        self.unknown.add(name)
        self.variables.pop(name, None)
        self.choices.pop(name, None)

    def merge(self, other: ParseResult) -> None:
        """Append the findings of a nested shell, which is a scope of its own."""
        offset = len(self.commands)
        self.scopes.append((offset, offset + len(other.commands)))
        self.scopes += [(low + offset, high + offset) for low, high in other.scopes]
        self.commands.extend(other.commands)
        self.dynamic.extend(other.dynamic)
        self.assigned.extend(other.assigned)
        for name in other.unknown:
            self.forget(name)
        for name, value in other.variables.items():
            self.assign(name, value)
        for name, values in other.choices.items():
            self.assign(name, values)


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


def lister_targets(argv: Sequence[str]) -> tuple[list[str], bool] | None:
    """Paths a listing command names on its output, if it is a literal lister.

    Understands ``find``, ``ls -d`` and ``Get-ChildItem`` (with ``-Filter``
    or ``-Include`` and ``-Recurse``).  Used for a delete that takes its
    targets from a pipe.

    Returns
    -------
    tuple[list[str], bool] | None
        The targets and whether the lister walks whole trees below them (so
        a delete of its output is recursive), or ``None`` when *argv* is not
        a recognised lister.
    """
    if not argv:
        return None
    name = program_name(argv[0])
    args = list(argv[1:])
    if name == "find":
        targets, named = find_targets(args)
        return targets, not named
    if name == "ls" and any(a.startswith("-") and "d" in a for a in args):
        targets = [a for a in args if not a.startswith("-")]
        return (targets, True) if targets else None
    if name != "get-childitem":
        return None
    roots: list[str] = []
    names: list[str] = []
    recurse = False
    i = 0
    while i < len(args):
        arg = args[i]
        lowered = arg.lower()
        if not lowered.startswith("-") or len(lowered) < 2:
            roots.append(arg)
        elif "-recurse".startswith(lowered):
            recurse = True
        elif any(p.startswith(lowered) for p in ("-path", "-literalpath")):
            roots += args[i + 1 : i + 2]
            i += 1
        elif any(p.startswith(lowered) for p in ("-filter", "-include")):
            names += args[i + 1 : i + 2]
            i += 1
        elif any(p.startswith(lowered) for p in ("-exclude", "-depth", "-attributes")):
            i += 1
        i += 1
    roots = roots or ["."]
    if not names:
        return roots, recurse
    middle = "/**/" if recurse else "/"
    trimmed = [root.rstrip("/\\") for root in roots]
    return [f"{root}{middle}{name}" for root in trimmed for name in names], False


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
