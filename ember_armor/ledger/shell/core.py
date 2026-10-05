"""Shared data structures and tables for the shell parsers.

The parsers read command *strings* and describe them.  Nothing in this
package runs a command, starts a process or touches the filesystem.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

MAX_COMMAND_CHARS = 200_000
#: The directory a command runs in when the command string does not say
#: (``cd $SOMEWHERE``).  No normalised path has this form.
UNKNOWN_DIR = "?"
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
#: Commands that move the shell itself to another directory.
MOVERS = frozenset(
    {"cd", "chdir", "pushd", "popd", "set-location", "push-location", "pop-location"}
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
    ``stdin`` is the literal text handed to the command by a here-document
    or here-string.  ``upstream`` is the argument vector of the pipeline
    stage that feeds the command (stages that only select are skipped).
    ``chdir`` holds the directories that wrappers removed from the command
    start it in, outermost first (``env -C dir``, ``sudo -D dir``,
    ``pnpm -C dir exec``); an entry is :data:`UNKNOWN_DIR` when the directory
    cannot be known.  ``cwd`` is not set by the parsers: it is the directory
    in effect when the command runs, filled in when facts are extracted
    (empty for the working directory of the call, :data:`UNKNOWN_DIR` when
    it cannot be known).
    """

    argv: tuple[str, ...]
    shell: str
    redirects: tuple[Redirect, ...] = ()
    stdin: str = ""
    upstream: tuple[str, ...] = ()
    chdir: tuple[str, ...] = ()
    cwd: str = field(default="", compare=False)


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
    ``unset``), and ``$env:NAME`` in PowerShell.  ``entered`` maps the index
    of a scope to the shell that names its start and the directories its
    starter puts it in, outermost first (``env -C dir sh -c '...'``, ``pwsh
    -WorkingDirectory dir -Command ...``).
    ``kept`` holds the indexes of scopes that run in the shell itself
    (``eval``, ``Invoke-Expression``): a ``cd`` inside one stays in force
    after it.

    ``guards`` maps the index of a scope to how its commands run, when that
    is not "once, in a process of their own": ``maybe`` (they may not run:
    the right side of ``&&`` or ``||``, a branch of ``if`` or ``case``),
    ``loop`` (any number of times: a loop body, a script block handed to a
    command or stored) or ``defined`` (not now: the body of a function,
    whose name is in ``named``).  A ``cd`` in such a scope moves the
    commands in it; where the shell is after it is worked out when facts
    are extracted (see :func:`ember_armor.ledger.shellpaths.shell_facts`).
    Of two scopes with the same range the later one in ``scopes`` is the
    outer one.  ``placed`` holds the indexes of the commands that ``find
    -exec`` runs with the name of each file found filled in: a directory
    option of such a command names a different place every time.
    """

    commands: list[SimpleCommand] = field(default_factory=list)
    dynamic: list[Dynamic] = field(default_factory=list)
    variables: dict[str, str] = field(default_factory=dict)
    choices: dict[str, tuple[str, ...]] = field(default_factory=dict)
    unknown: set[str] = field(default_factory=set)
    scopes: list[tuple[int, int]] = field(default_factory=list)
    assigned: list[str] = field(default_factory=list)
    entered: dict[int, tuple[str, tuple[str, ...]]] = field(default_factory=dict)
    kept: set[int] = field(default_factory=set)
    guards: dict[int, str] = field(default_factory=dict)
    named: dict[int, str] = field(default_factory=dict)
    placed: set[int] = field(default_factory=set)

    def guard(self, low: int, high: int, kind: str, name: str = "") -> None:
        """Record that the commands from *low* up to *high* run as *kind* says.

        *kind* is ``maybe``, ``loop`` or ``defined`` (see ``guards``); *name*
        is the function a ``defined`` range is the body of.
        """
        if high <= low:
            return
        number = len(self.scopes)
        self.scopes.append((low, high))
        self.guards[number] = kind
        if name:
            self.named[number] = name

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

    def merge(
        self,
        other: ParseResult,
        chdir: tuple[str, ...] = (),
        *,
        starter: str = "",
        keep: bool = False,
    ) -> None:
        """Append the findings of a nested shell, which is a scope of its own.

        *chdir* names the directories its starter puts it in, outermost
        first, as the shell *starter* reads them.  *keep* is set for a script
        the shell runs itself (``eval``): a ``cd`` in it stays in force
        afterwards.
        """
        offset = len(self.commands)
        first = len(self.scopes)
        # The scopes of the script come first: of two scopes with the same
        # range the later one is the outer one.
        self.scopes += [(low + offset, high + offset) for low, high in other.scopes]
        for inner, chain in other.entered.items():
            self.entered[first + inner] = chain
        self.kept.update(first + inner for inner in other.kept)
        for inner, kind in other.guards.items():
            self.guards[first + inner] = kind
        for inner, name in other.named.items():
            self.named[first + inner] = name
        self.placed.update(index + offset for index in other.placed)
        number = len(self.scopes)
        self.scopes.append((offset, offset + len(other.commands)))
        if chdir:
            self.entered[number] = (starter, chdir)
        if keep:
            self.kept.add(number)
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


class _Frame:
    """One compound command that is open while a list is parsed.

    ``tag`` names the construct and ``kind`` says how its commands run
    (empty: once, where they stand).  ``seen`` is how far the current and-or
    list was looked at and ``plain`` whether it holds, since the last range
    was opened, a command that is not a move.  ``open`` are the starts of
    the ranges an operator opened and ``ends_on`` the operator that ends
    them (they all end on the same one), ``tails`` the ranges that last as
    long as the frame, and ``branch`` the start of the branch being read.
    (A plain class: every shell call defines it.)
    """

    __slots__ = ("branch", "ends_on", "kind", "low", "name", "open", "plain", "seen",
                 "tag", "tails")  # fmt: skip

    def __init__(self, tag: str, kind: str, name: str, low: int) -> None:
        self.tag = tag
        self.kind = kind
        self.name = name
        self.low = self.seen = low
        self.plain = False
        self.open: list[int] = []
        self.ends_on = ""
        self.tails: list[tuple[int, str]] = []
        self.branch: int | None = None


class Guards:
    """Tells a parse result which commands of a list may not run.

    A parser reports the operators and the compound commands of one list
    as it reads them, and the ranges of commands that depend on them are
    recorded with :meth:`ParseResult.guard`:

    - what follows ``&&`` may not run when a command before it is not a
      move (a ``cd`` is taken to succeed), up to the next ``||``;
    - what follows ``||`` may not run, up to the next ``&&``;
    - a branch (:meth:`branch`) may not run, and a frame entered with a
      kind runs as that kind says.
    """

    __slots__ = ("frames", "out")

    def __init__(self, out: ParseResult) -> None:
        self.out = out
        self.frames = [_Frame("", "", "", len(out.commands))]

    def _close(self, frame: _Frame, operator: str = "") -> None:
        """Record the ranges of *frame* that *operator* ends (all: a list end)."""
        if operator and frame.ends_on != operator:
            return
        now = len(self.out.commands)
        for low in reversed(frame.open):
            self.out.guard(low, now, "maybe")
        frame.open = []

    def _reset(self, frame: _Frame) -> None:
        frame.seen = len(self.out.commands)
        frame.plain = False

    def link(self, operator: str) -> None:
        """An ``&&`` or ``||`` was read after the command before it."""
        frame, now = self.frames[-1], len(self.out.commands)
        self._close(frame, operator)
        frame.plain = frame.plain or any(
            not command.argv or program_name(command.argv[0]) not in MOVERS
            for command in self.out.commands[frame.seen : now]
        )
        frame.seen = now
        if operator == "||":
            # What follows is skipped up to the next ``&&``.
            frame.open.append(now)
            frame.ends_on = "&&"
        elif frame.plain:
            # Later moves depend on this one only when something that can
            # fail stands between them.
            frame.open.append(now)
            frame.ends_on = "||"
            frame.plain = False

    def note(self) -> None:
        """Something that can fail was read and is no command (``[[ ... ]]``)."""
        self.frames[-1].plain = True

    def end(self) -> None:
        """The and-or list being read is over (``;``, a newline, ``&``)."""
        self._close(self.frames[-1])
        self._reset(self.frames[-1])

    def enter(self, tag: str, kind: str = "", name: str = "") -> None:
        """A compound command opens; *kind* says how its commands run."""
        self.frames.append(_Frame(tag, kind, name, len(self.out.commands)))

    def tail(self, kind: str) -> None:
        """What follows runs as *kind* says, to the end of the current frame."""
        self.frames[-1].tails.append((len(self.out.commands), kind))

    def branch(self, tag: str, *, more: bool = True, open_one: bool = False) -> None:
        """A branch of the innermost *tag* frame ends; with *more*, one starts.

        With *open_one* nothing happens when a branch is being read already
        (the ``then`` behind an ``elif``, whose condition is part of it).
        """
        frame = next((f for f in reversed(self.frames[1:]) if f.tag == tag), None)
        if frame is None or (open_one and frame.branch is not None):
            return
        while self.frames[-1] is not frame:
            self._leave()
        self._close(frame)
        now = len(self.out.commands)
        if frame.branch is not None:
            self.out.guard(frame.branch, now, "maybe")
        frame.branch = now if more else None
        self._reset(frame)

    def _leave(self) -> None:
        frame = self.frames.pop()
        self._close(frame)
        now = len(self.out.commands)
        if frame.branch is not None:
            self.out.guard(frame.branch, now, "maybe")
        for low, kind in reversed(frame.tails):
            self.out.guard(low, now, kind)
        if frame.kind:
            self.out.guard(frame.low, now, frame.kind, frame.name)

    def leave(self, tag: str) -> None:
        """The innermost compound command called *tag* closes."""
        if any(frame.tag == tag for frame in self.frames[1:]):
            while self.frames[-1].tag != tag:
                self._leave()
            self._leave()

    def finish(self) -> None:
        """The list is over: close whatever is still open."""
        while len(self.frames) > 1:
            self._leave()
        frame = self.frames[0]
        self._close(frame)
        now = len(self.out.commands)
        for low, kind in reversed(frame.tails):
            self.out.guard(low, now, kind)
        frame.tails = []
        self._reset(frame)


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
    return [command for command, _ in find_runs(args)]


def find_runs(
    args: Sequence[str], *, filled: bool = True
) -> list[tuple[tuple[str, ...], bool]]:
    """Commands a ``find`` runs, and whether each runs where its file lies.

    ``-execdir`` and ``-okdir`` start the command in the directory of the
    file found, which the command string does not name.  With *filled*
    false the commands are given as written, ``{}`` left in place.
    """
    targets, _ = find_targets(args)
    commands: list[tuple[tuple[str, ...], bool]] = []
    for i, arg in enumerate(args):
        if arg in _FIND_EXEC:
            rest = args[i + 1 :]
            ends = [j for j, a in enumerate(rest) if a in (";", "+")]
            inner = rest[: ends[0]] if ends else rest
            command = tuple(targets[0] if filled and a == "{}" else a for a in inner)
            commands.append((command, arg.endswith("dir")))
    return [(command, moved) for command, moved in commands if command]
