"""Which paths a parsed shell command reads, writes or deletes.

Only recognised commands contribute paths (``rm``, ``cat``, ``Remove-Item``,
``del`` and so on), plus every redirection.  Unknown programs contribute
nothing: the ledger does not guess what an arbitrary tool does with its
arguments.  ``cd``, ``pushd`` and ``popd`` are followed so later relative
paths resolve correctly; a move inside a subshell ends with the subshell.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace

from ember_armor.ledger.paths import UNKNOWN_DIR, PathFact
from ember_armor.ledger.shell import ParseResult, SimpleCommand, program_name
from ember_armor.ledger.shell.argv import (
    has_flag,
    operand_positions,
    operands,
    option_args,
)
from ember_armor.ledger.shell.core import (
    MOVERS,
    find_exec,
    find_targets,
    lister_targets,
)

__all__ = ["PathFact", "shell_facts", "shell_paths"]

_NULL_TARGETS = frozenset(
    {"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty", "nul", "$null"}
)
_PROVIDER_RE = re.compile(r"(?:[A-Za-z]{2,}:|[A-Za-z]+::)")
#: ``FileSystem::C:\x`` is the plain path ``C:\x``.
_FILESYSTEM_RE = re.compile(
    r"(?:Microsoft\.PowerShell\.Core\\)?FileSystem::", re.IGNORECASE
)
_WILD_TAIL_RE = re.compile(r"(^|[/\\])\*$")


@dataclass(frozen=True, eq=False, repr=False)
class _Native:
    """Path behaviour of a POSIX or ``cmd.exe`` program.

    ``op`` applies to every operand after the first ``skip``; ``last`` (if
    set) overrides it for the final operand when there are at least two.
    ``name_flags`` carry a file-name pattern the program looks for below
    its operands (``grep --include``, ``rg -g``).
    """

    op: str
    value_flags: frozenset[str] = frozenset()
    recursive: tuple[str, ...] = ()
    skip: int = 0
    last: str | None = None
    write_flags: tuple[str, ...] = ()
    name_flags: tuple[str, ...] = ()


@dataclass(frozen=True, eq=False, repr=False)
class _Cmdlet:
    """Path behaviour of a PowerShell cmdlet.

    ``params`` maps a value-taking parameter name to the operation on its
    value (``None`` when the value is not a path).  ``positional`` gives the
    operation for each operand in order; ``rest`` covers further operands and
    ``last`` the final one when there are at least two.
    """

    params: Mapping[str, str | None]
    positional: tuple[str | None, ...] = ()
    rest: str | None = None
    last: str | None = None


#: Operation of a moved source.  The file leaves its place (a write) and its
#: content arrives somewhere else (a read), so a move yields both path facts.
_MOVE = "move"
_READERS = ("cat", "tac", "nl", "less", "more", "bat", "strings", "xxd", "od",
            "hexdump", "base64", "source", ".", "diff")  # fmt: skip
_GREP_VALUES = frozenset({"-e", "-f", "-m", "-A", "-B", "-C", "-g", "-t",
                          "--include", "--exclude", "--exclude-dir", "--glob",
                          "--type"})  # fmt: skip
_RSYNC_VALUES = frozenset(
    {"-e", "--rsh", "--exclude", "--include", "--exclude-from", "--include-from",
     "--files-from", "-f", "--filter", "--rsync-path", "--port", "--bwlimit",
     "--timeout", "--log-file", "--backup-dir", "--suffix", "--chmod", "--chown",
     "-T", "--temp-dir", "--compare-dest", "--copy-dest", "--link-dest",
     "--partial-dir", "--password-file", "-B", "--block-size"}
)  # fmt: skip
_BASH: dict[str, _Native] = {
    **{name: _Native("read") for name in _READERS},
    "head": _Native("read", frozenset({"-n", "-c"})),
    "tail": _Native("read", frozenset({"-n", "-c"})),
    "grep": _Native("read", _GREP_VALUES, skip=1, name_flags=("--include",)),
    "egrep": _Native("read", _GREP_VALUES, skip=1, name_flags=("--include",)),
    "fgrep": _Native("read", _GREP_VALUES, skip=1, name_flags=("--include",)),
    "rg": _Native("read", _GREP_VALUES, skip=1, name_flags=("-g", "--glob")),
    "awk": _Native("read", frozenset({"-f", "-F", "-v"}), skip=1),
    "cut": _Native("read", frozenset({"-d", "-f", "-b", "-c"})),
    "sort": _Native("read", frozenset({"-k", "-t", "-o", "-S", "-T"})),
    "rm": _Native("delete", recursive=("-r", "-R", "--recursive")),
    "rmdir": _Native("delete"),
    "unlink": _Native("delete"),
    "cp": _Native("read", frozenset({"-t", "-S"}), last="write"),
    "mv": _Native(_MOVE, frozenset({"-t", "-S"}), last="write"),
    "tee": _Native("write"),
    "touch": _Native("write", frozenset({"-d", "-t", "-r"})),
    "truncate": _Native("write", frozenset({"-s", "-r"})),
    # Programs that send or pack the files they are given.
    "scp": _Native(
        "read",
        frozenset({"-i", "-P", "-o", "-F", "-c", "-l", "-S", "-J", "-D"}),
        last="write",
    ),
    "rsync": _Native("read", _RSYNC_VALUES, last="write"),
    "zip": _Native("read", frozenset({"-x", "-i", "-b", "-t", "-tt", "-n"}), skip=1),
    "sed": _Native(
        "read", frozenset({"-e", "-f"}), skip=1, write_flags=("-i", "--in-place")
    ),  # fmt: skip
}
_CMD: dict[str, _Native] = {
    "del": _Native("delete", recursive=("/s",)),
    "erase": _Native("delete", recursive=("/s",)),
    "rd": _Native("delete", recursive=("/s",)),
    "rmdir": _Native("delete", recursive=("/s",)),
    "type": _Native("read"),
    "copy": _Native("read", last="write"),
    "move": _Native(_MOVE, last="write"),
}

_COMMON_VALUES: dict[str, None] = dict.fromkeys(
    ("erroraction", "ea", "warningaction", "wa", "informationaction", "errorvariable",
     "ev", "warningvariable", "outvariable", "ov", "outbuffer", "pipelinevariable",
     "filter", "include", "exclude", "stream", "credential", "encoding")
)  # fmt: skip


def _cmdlet(
    paths: Mapping[str, str],
    values: Sequence[str] = (),
    positional: tuple[str | None, ...] = (),
    rest: str | None = None,
    last: str | None = None,
) -> _Cmdlet:
    params = {**_COMMON_VALUES, **dict.fromkeys(values), **paths}
    return _Cmdlet(params, positional, rest, last)


def _path_params(op: str) -> dict[str, str]:
    return {"path": op, "literalpath": op}


_WEB_REQUEST = _cmdlet(
    {"infile": "read", "outfile": "write"},
    ("uri", "method", "headers", "body", "contenttype", "useragent", "timeoutsec",
     "proxy", "form"),
)  # fmt: skip
_POWERSHELL: dict[str, _Cmdlet] = {
    "remove-item": _cmdlet(_path_params("delete"), rest="delete"),
    "get-content": _cmdlet(
        _path_params("read"),
        ("totalcount", "first", "head", "tail", "last", "readcount", "delimiter"),
        rest="read",
    ),
    "set-content": _cmdlet(_path_params("write"), ("value",), ("write", None)),
    "add-content": _cmdlet(_path_params("write"), ("value",), ("write", None)),
    "clear-content": _cmdlet(_path_params("write"), rest="write"),
    "out-file": _cmdlet(
        {"filepath": "write", "literalpath": "write"},
        ("width", "inputobject"),
        ("write",),
    ),
    "tee-object": _cmdlet(
        {"filepath": "write", "literalpath": "write"},
        ("variable", "inputobject"),
        ("write",),
    ),
    "new-item": _cmdlet(
        {"path": "write"}, ("name", "itemtype", "value", "target"), ("write",)
    ),
    "copy-item": _cmdlet(
        {**_path_params("read"), "destination": "write"}, rest="read", last="write"
    ),
    "move-item": _cmdlet(
        {**_path_params(_MOVE), "destination": "write"}, rest=_MOVE, last="write"
    ),
    "rename-item": _cmdlet(_path_params("write"), ("newname",), ("write", None)),
    "select-string": _cmdlet(
        _path_params("read"), ("pattern", "context"), (None,), rest="read"
    ),
    "compress-archive": _cmdlet(
        {**_path_params("read"), "destinationpath": "write"},
        ("compressionlevel",),
        ("read", "write"),
    ),
    "invoke-webrequest": _WEB_REQUEST,
    "invoke-restmethod": _WEB_REQUEST,
}
#: curl options whose value names a file: what is read from it or written to it.
_CURL_UPLOADS = {"-T": "read", "--upload-file": "read", "-K": "read",
                 "--config": "read", "-o": "write", "--output": "write"}  # fmt: skip
_CURL_DATA = frozenset(
    {"-d", "--data", "--data-binary", "--data-ascii", "--data-urlencode", "--json"}
)
_CURL_FORMS = frozenset({"-F", "--form"})
_WGET_FILES = {"--post-file": "read", "--body-file": "read", "-O": "write",
               "--output-document": "write"}  # fmt: skip
_TAR_VALUES = frozenset(
    {"-C", "--directory", "-T", "--files-from", "-X", "--exclude-from",
     "--exclude", "-I", "--use-compress-program"}
)  # fmt: skip
_GIT_VALUES = frozenset(
    {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix",
     "--config-env", "--attr-source"}
)  # fmt: skip
_CD = frozenset({"cd", "chdir", "set-location"})
_PUSHD = frozenset({"pushd", "push-location"})
_POPD = frozenset({"popd", "pop-location"})
_PREVIOUS = frozenset({"-", "~-", "$OLDPWD", "${OLDPWD}"})
_REMOVERS = frozenset({"rm", "rmdir", "unlink"})
#: A delete whose targets arrive on a pipe from something that is not a
#: literal lister is treated as acting on the working directory: unknown,
#: so assume nearby.
_UNKNOWN_TARGET = "."
#: Operands that stand for what the pipe delivers.
_PIPED = frozenset({"{}", "$_", "$_.fullname", "$psitem", "$psitem.fullname"})
_WHATIF_ON = frozenset({"", "$true", "true", "1"})

#: ``resolve(raw, cwd, shell)``: the normalised paths *raw* can stand for.
Resolve = Callable[[str, str, str], list[str]]


class _Chdir:
    """Options of a program that make it run in another directory.

    ``flags`` take the directory as their value.  ``value_flags`` are other
    options in front of the subcommand that take a value.  ``late`` says
    what such a flag means after the first operand: the program reads it all
    the same (``read``), it is another option there (``ignore``), or that
    depends on the subcommand (``unknown``).  ``attached`` accepts ``-Cdir``.
    ``unknown`` options name the place in a way the gate does not follow,
    and ``plus`` allows a ``+toolchain`` word in front of the options.
    ``cluster`` are the letters of options without a value that may stand
    in one word in front of the directory option (``make -sC dir``), and
    ``shortest`` is the length from which the start of a long option is
    read as that option (``make --dir=x``; 0: never).

    Like ``_Where`` and ``_Places`` below this is a plain class: every
    shell call loads this module, and defining a dataclass takes the hook
    about as long as parsing a short command.
    """

    __slots__ = ("attached", "cluster", "flags", "late", "plus", "shortest",
                 "unknown", "value_flags")  # fmt: skip

    def __init__(
        self,
        flags: Iterable[str],
        value_flags: Iterable[str] = (),
        *,
        late: str = "unknown",
        attached: bool = False,
        unknown: Iterable[str] = (),
        plus: bool = False,
        cluster: str = "",
        shortest: int = 0,
    ) -> None:
        self.flags = frozenset(flags)
        self.value_flags = frozenset(value_flags)
        self.late = late
        self.attached = attached
        self.unknown = frozenset(unknown)
        self.plus = plus
        self.cluster = frozenset(cluster)
        self.shortest = shortest

    def spelled(self, flag: str) -> str:
        """The option *flag* stands for: itself, or the one it abbreviates."""
        if not self.shortest or len(flag) < self.shortest or flag[:2] != "--":
            return flag
        found = [known for known in self.flags if known.startswith(flag)]
        return found[0] if len(found) == 1 else flag

    def split(self, arg: str) -> str:
        """*arg* without the value-less options clustered in front of a flag.

        ``-sC`` and ``-skCdir`` become ``-C`` and ``-Cdir``; anything else
        comes back as it is.
        """
        if not self.cluster or arg[:1] != "-" or arg[:2] == "--":
            return arg
        for at in range(1, len(arg)):
            if f"-{arg[at]}" in self.flags:
                return f"-{arg[at:]}"
            if arg[at] not in self.cluster:
                break
        return arg


_MAKE = _Chdir(
    ("-C", "--directory"),
    late="read",
    attached=True,
    cluster="bBdehiknpqrRsStvw",
    shortest=4,
)
#: Programs whose own options say where they run.
_CHDIR: dict[str, _Chdir] = {
    # After the subcommand ``-C`` is another option (``git commit -C HEAD``).
    "git": _Chdir(
        ("-C",), _GIT_VALUES, late="ignore", unknown=("--git-dir", "--work-tree")
    ),
    "make": _MAKE,
    "gmake": _MAKE,
    "npm": _Chdir(("--prefix", "-C"), late="read"),
    "pnpm": _Chdir(("-C", "--dir"), ("-F", "--filter")),
    "yarn": _Chdir(("--cwd",)),
    "cargo": _Chdir(("-C",), ("-Z", "--config", "--color"), plus=True),
}
#: A directory nobody can name from the command string: a wildcard, a
#: command substitution, what a pipe delivers, another user's home.
_VAGUE_RE = re.compile(r"[*?\[`]|\{\}|^~[^/\\]")
#: The same in a resolved path, where a variable may have brought it in
#: (``for d in */; do cd "$d"``); a ``~`` that is still there names no home
#: the gate knows.
_VAGUE_PATH_RE = re.compile(r"[*?\[`]|\{\}|(?:^|/)~")
_UNRESOLVED_RE = re.compile(r"\$|%\w+%")
#: ``D:`` and ``D:dir``: the directory the shell last had on that drive.
_DRIVE_RELATIVE_RE = re.compile(r"[A-Za-z]:(?![/\\])")
#: Passes over the commands of loops before the directory inside them is
#: simply taken as unknown (see ``_Tracker``).
_TRIAL_STEPS = 20_000
#: Directories the shell may be in at once, for relative paths, before the
#: call is marked as one the gate could not read in full.
MAX_PLACES = 8
#: ``pushd +1`` and ``popd -2`` rotate the directory stack.
_STACK_ENTRY_RE = re.compile(r"[+-]\d*")
#: Stand in for an unknown directory, to tell an absolute target from a
#: relative one: only an absolute one resolves the same from both.
_NOWHERE, _ELSEWHERE = "/\x00nowhere", "/\x00elsewhere"
_CD_FLAGS = frozenset("LPe@")
#: Parameters of ``Set-Location``, ``Push-Location`` and ``Pop-Location``;
#: the ones in :data:`_PS_VALUES` take a value that is not a directory.
_PS_VALUES = frozenset(
    {"erroraction", "warningaction", "informationaction", "errorvariable",
     "warningvariable", "informationvariable", "outvariable", "outbuffer",
     "pipelinevariable"}
)  # fmt: skip
_PS_LOCATION = ("path", "literalpath", "passthru", "stackname", "verbose", "debug",
                "usetransaction", *sorted(_PS_VALUES))  # fmt: skip
_PS_ALIASES = {"ea": "erroraction", "wa": "warningaction", "ev": "errorvariable",
               "infa": "informationaction", "wv": "warningvariable",
               "iv": "informationvariable", "ov": "outvariable", "ob": "outbuffer",
               "pv": "pipelinevariable", "vb": "verbose", "db": "debug",
               "pspath": "literalpath", "lp": "literalpath"}  # fmt: skip


@dataclass(eq=False, repr=False)
class _Location:
    """Working directory while walking the commands of one call."""

    current: str
    previous: str
    stack: list[str] = field(default_factory=list)


class _Where:
    """The directory commands run in while walking one call.

    ``None`` stands for a directory the command string does not name.
    ``moves`` counts the commands that moved the shell so far.
    """

    __slots__ = ("current", "moves", "previous", "stack")

    def __init__(
        self,
        current: str | None,
        previous: str | None = None,
        stack: Sequence[str | None] = (),
        moves: int = 0,
    ) -> None:
        self.current = current
        self.previous = previous
        self.stack = list(stack)
        self.moves = moves

    def copy(self) -> _Where:
        """The same place, with a directory stack of its own."""
        return _Where(self.current, self.previous, self.stack, self.moves)

    def lose(self) -> None:
        """Nothing is known any more: not the directory, not the stack."""
        self.current = self.previous = None
        self.stack = [None] * len(self.stack)
        self.moves += 1

    def differs(self, other: _Where) -> bool:
        """True when the shell is not where *other* is, or its stack differs."""
        return self.current != other.current or self.stack != other.stack


def _is_null(target: str) -> bool:
    lowered = target.lower()
    return lowered in _NULL_TARGETS or lowered.startswith(("/dev/fd/", "&"))


def _piped_targets(
    command: SimpleCommand, targets: list[str], recursive: bool, op: str
) -> tuple[list[str], bool]:
    """Targets of a delete or read, taken from the feeding lister if none is named.

    ``find . -name x | xargs rm -rf`` and ``Get-ChildItem dist | Remove-Item``
    act on what the lister prints.  A lister that walks a whole tree makes a
    delete recursive.  A delete fed by anything else falls back to the
    working directory.
    """
    if targets and not all(target.lower() in _PIPED for target in targets):
        return targets, recursive
    listed = lister_targets(command.upstream)
    if listed is not None:
        return listed[0], op == "delete" and (recursive or listed[1])
    if op == "delete":
        return targets or [_UNKNOWN_TARGET], recursive
    return targets, recursive


def _named_below(command: SimpleCommand, flags: Sequence[str]) -> list[str]:
    """File-name patterns given with *flags* (``--include=X``, ``-g X``)."""
    args = command.argv[1:]
    names: list[str] = []
    for index, arg in enumerate(args):
        flag, attached, value = arg.partition("=")
        if flag not in flags:
            continue
        if not attached:
            value = args[index + 1] if index + 1 < len(args) else ""
        if value and not value.startswith("!"):
            names.append(value)
    return names


def _native_paths(command: SimpleCommand, spec: _Native) -> list[tuple[str, str, bool]]:
    slash = command.shell == "cmd"
    targets = operands(command, spec.value_flags, slash_flags=slash)[spec.skip :]
    recursive = any(has_flag(command, flag) for flag in spec.recursive)
    op = spec.op
    if any(has_flag(command, flag) for flag in spec.write_flags):
        op = "write"
    if op in ("delete", "read"):
        targets, recursive = _piped_targets(command, targets, recursive, op)
    found = [(target, op, recursive) for target in targets]
    if spec.last and len(found) >= 2:
        found[-1] = (found[-1][0], spec.last, False)
    for name in _named_below(command, spec.name_flags):
        roots = [root.rstrip("/") for root in targets or ["."]]
        found += [(f"{root}/**/{name}", op, False) for root in roots]
    return found


def _resolve_param(name: str, spec: _Cmdlet) -> str | None:
    """Full parameter name for a possibly abbreviated ``-Name``."""
    lowered = name.lstrip("-").lower()
    if lowered in spec.params:
        return lowered
    return next((p for p in spec.params if p.startswith(lowered)), None)


def _what_if(command: SimpleCommand) -> bool:
    """True when the cmdlet only reports what it would do (``-WhatIf``).

    ``-WhatIf:$false`` switches the preview off: the command really runs.
    """
    for arg in command.argv[1:]:
        name, _, value = arg.lower().partition(":")
        if len(name) > 1 and "-whatif".startswith(name) or name == "-wi":
            return value in _WHATIF_ON
    return False


def _cmdlet_paths(command: SimpleCommand, spec: _Cmdlet) -> list[tuple[str, str, bool]]:
    if _what_if(command):
        return []
    recursive = has_flag(command, "-recurse")
    found: list[tuple[str, str | None]] = []
    loose: list[str] = []
    args = command.argv[1:]
    named: set[str] = set()
    i = 0
    while i < len(args):
        arg = args[i]
        if len(arg) > 1 and arg[0] == "-" and not arg[1].isdigit():
            name, attached, value = arg.partition(":")
            param = _resolve_param(name, spec)
            if param is not None and not attached and i + 1 < len(args):
                i += 1
                value = args[i]
            if param is not None and value:
                named.add(param)
                found.append((value, spec.params[param]))
        else:
            loose.append(arg)
        i += 1
    for index, arg in enumerate(loose):
        op = spec.positional[index] if index < len(spec.positional) else spec.rest
        found.append((arg, op))
    if spec.last and "destination" not in named and len(loose) >= 2:
        found[-1] = (loose[-1], spec.last)
    named_targets = [path for path, op in found if op]
    if spec.rest in ("delete", "read"):
        targets, recursive = _piped_targets(
            command, named_targets, recursive, spec.rest
        )
        if targets != named_targets:
            found = [(target, spec.rest) for target in targets]
    return [(path, op, recursive and op == "delete") for path, op in found if op]


def _dd_paths(command: SimpleCommand) -> list[tuple[str, str, bool]]:
    found = []
    for arg in command.argv[1:]:
        if arg.startswith("if="):
            found.append((arg[3:], "read", False))
        elif arg.startswith("of="):
            found.append((arg[3:], "write", False))
    return found


def _option_values(command: SimpleCommand, flags: Mapping[str, str]) -> list[str]:
    """Values of the given options: ``-o x``, ``--output=x`` or ``-ox``."""
    args = command.argv[1:]
    found: list[tuple[str, str]] = []
    for index, arg in enumerate(args):
        flag, attached, value = arg.partition("=")
        short = arg[:2] if len(arg) > 2 and arg[1] != "-" else ""
        if flag in flags and flag.startswith("--") and attached:
            found.append((flag, value))
        elif arg in flags and index + 1 < len(args):
            found.append((arg, args[index + 1]))
        elif short in flags:
            found.append((short, arg[2:]))
    return [f"{flag}\0{value}" for flag, value in found if value]


def _curl_paths(command: SimpleCommand) -> list[tuple[str, str, bool]]:
    """Files a ``curl`` invocation uploads, posts or writes.

    ``-T file``, ``-d @file``, ``--data-binary @file``, ``-F name=@file`` and
    ``-o file``.  Data without ``@`` is literal text, not a file.
    """
    found: list[tuple[str, str, bool]] = []
    every = {**_CURL_UPLOADS, **dict.fromkeys(_CURL_DATA | _CURL_FORMS, "read")}
    for item in _option_values(command, every):
        flag, _, value = item.partition("\0")
        if flag in _CURL_FORMS:
            value = value.partition("=")[2].partition(";")[0]
            if value[:1] not in ("@", "<"):
                continue
            value = value[1:]
        elif flag in _CURL_DATA:
            if "@" not in value or (flag != "--data-urlencode" and value[0] != "@"):
                continue
            value = value.partition("@")[2]
        if value and value != "-":
            found.append((value, every[flag], False))
    return found


def _wget_paths(command: SimpleCommand) -> list[tuple[str, str, bool]]:
    found = []
    for item in _option_values(command, _WGET_FILES):
        flag, _, value = item.partition("\0")
        if value != "-":
            found.append((value, _WGET_FILES[flag], False))
    return found


def _tar_paths(command: SimpleCommand) -> list[tuple[str, str, bool]]:
    """Files a ``tar`` that creates or extends an archive packs into it."""
    args = list(command.argv[1:])
    if args and not args[0].startswith("-"):
        args[0] = f"-{args[0]}"  # the old style: ``tar czf out.tgz files``
    letters = "".join(a[1:] for a in args if a.startswith("-") and a[1:2] != "-")
    creates = set("cru") & set(letters) or any(
        a in ("--create", "--append", "--update") for a in args
    )
    if not creates:
        return []
    files: list[str] = []
    skip = False
    for arg in args:
        if skip:
            skip = False
        elif arg.startswith("--"):
            skip = arg in _TAR_VALUES or arg == "--file"
        elif arg.startswith("-") and len(arg) > 1:
            skip = arg[-1] in "fCTXI"
        else:
            files.append(arg)
    return [(name, "read", False) for name in files]


def _archiver_paths(command: SimpleCommand) -> list[tuple[str, str, bool]]:
    """Files ``7z a archive files...`` packs."""
    words = operands(command)
    if len(words) < 3 or words[0] not in ("a", "u"):
        return []
    return [(name, "read", False) for name in words[2:]]


def _git_paths(command: SimpleCommand) -> list[tuple[str, str, bool]]:
    """Files ``git add`` stages: their content goes into the repository."""
    positions = operand_positions(command, _GIT_VALUES)
    if not positions or command.argv[positions[0]] != "add":
        return []
    argv = command.argv
    base = [argv[i + 1] for i in range(1, positions[0] - 1) if argv[i] == "-C"]
    prefix = "/".join(base) + "/" if base else ""
    return [(f"{prefix}{argv[i]}", "read", False) for i in positions[1:]]


_CUSTOM: dict[str, Callable[[SimpleCommand], list[tuple[str, str, bool]]]] = {
    "curl": _curl_paths,
    "wget": _wget_paths,
    "tar": _tar_paths,
    "bsdtar": _tar_paths,
    "7z": _archiver_paths,
    "7za": _archiver_paths,
    "git": _git_paths,
}


def _find_paths(command: SimpleCommand) -> list[tuple[str, str, bool]]:
    """What a ``find`` deletes with ``-delete`` or ``-exec rm``.

    Without a ``-name`` filter the whole tree goes, however the removal is
    spelled (``find ~ -type f -exec rm -f {} +``).  With one, ``-exec rm``
    is already covered by the command it runs.
    """
    args = command.argv[1:]
    targets, named = find_targets(args)
    if "-delete" in args:
        return [(target, "delete", not named) for target in targets]
    removes = any(program_name(inner[0]) in _REMOVERS for inner in find_exec(args))
    if removes and not named:
        return [(target, "delete", True) for target in targets]
    return []


def _command_paths(command: SimpleCommand) -> list[tuple[str, str, bool]]:
    return [
        (path, op, recursive)
        for path, kind, recursive in _recognised_paths(command)
        for op in (("write", "read") if kind == _MOVE else (kind,))
    ]


def _recognised_paths(command: SimpleCommand) -> list[tuple[str, str, bool]]:
    name = program_name(command.argv[0])
    if command.shell == "powershell" and name in _POWERSHELL:
        return _cmdlet_paths(command, _POWERSHELL[name])
    if command.shell == "cmd":
        return _native_paths(command, _CMD[name]) if name in _CMD else []
    if name == "dd":
        return _dd_paths(command)
    if name == "find":
        return _find_paths(command)
    if name in _CUSTOM:
        return _CUSTOM[name](command)
    return _native_paths(command, _BASH[name]) if name in _BASH else []


def _change_directory(
    command: SimpleCommand, place: _Location, resolve: Resolve, home: str | None
) -> None:
    """Follow ``cd``, ``pushd`` or ``popd`` (no move if the target is unclear)."""
    name = program_name(command.argv[0])
    if command.shell == "powershell":
        targets = [a for a in command.argv[1:] if not a.startswith("-")]
    else:
        targets = operands(command, slash_flags=command.shell == "cmd")
    destination: str | None = None
    if name in _POPD:
        destination = place.stack.pop() if place.stack else None
    elif not targets:
        if name in _PUSHD:
            destination = place.stack.pop() if place.stack else None
        elif command.shell == "bash":
            destination = home
    elif len(targets) == 1 and targets[0] in _PREVIOUS:
        destination = place.previous
    elif len(targets) == 1:
        resolved = resolve(targets[0], place.current, command.shell)
        if len(resolved) == 1 and "$" not in resolved[0]:
            destination = resolved[0]
    if destination is None:
        return
    if name in _PUSHD:
        place.stack.append(place.current)
    place.previous, place.current = place.current, destination


def _moved_too(
    also: list[str],
    command: SimpleCommand,
    current: str,
    resolve: Resolve,
    home: str | None,
) -> list[str]:
    """The other directories the shell may be in, after *command* moved it.

    Each one moves as the shell did (an absolute ``cd`` brings them all to
    *current*, where the shell is now).
    """
    moved: list[str] = []
    for other in also:
        spot = _Location(other, other)
        _change_directory(command, spot, resolve, home)
        if spot.current != current and spot.current not in moved:
            moved.append(spot.current)
    return moved


class _Places:
    """Works out the directories that commands name (``None``: unknown)."""

    __slots__ = ("resolve", "windows")

    def __init__(self, resolve: Resolve, windows: bool) -> None:
        self.resolve = resolve
        self.windows = windows

    def directory(self, target: str, base: str | None, shell: str) -> str | None:
        """The directory *target* names seen from *base*.

        Unknown: a variable nobody set, a wildcard, an expression, several
        values, or a relative path seen from a directory that is itself
        unknown.  In PowerShell and ``cmd.exe`` a path such as ``\\dir`` lies
        on the drive the shell is on, so it is known only when that is.
        """
        if qualified := _FILESYSTEM_RE.match(target):
            target = target[qualified.end() :]
        vague = shell == "powershell" and (
            target[:1] in "(@{" or _PROVIDER_RE.match(target) is not None
        )
        if vague or _VAGUE_RE.search(target):
            return None
        if self.windows and _DRIVE_RELATIVE_RE.match(target):
            # Known only when the shell is on that drive: then it is a
            # relative path.
            on_drive = base is not None and base[:2].upper() == target[:2].upper()
            if shell == "bash" or not on_drive:
                return None
            target = target[2:] or "."
        found = self.resolve(target, _NOWHERE if base is None else base, shell)
        if len(found) != 1 or _UNRESOLVED_RE.search(found[0]):
            return None
        if _VAGUE_PATH_RE.search(found[0]):
            return None
        if base is None and self.resolve(target, _ELSEWHERE, shell) != found:
            return None
        path = found[0]
        if self.windows and shell != "bash" and path[:1] == "/" and path[:2] != "//":
            if base is None or base[1:3] != ":/":
                return None
            return base[:2] + path
        return path

    def follow(
        self, targets: Sequence[str], start: str | None, shell: str
    ) -> str | None:
        """Where a chain of moves ends, each relative to the one before."""
        current = start
        for target in targets:
            current = self.directory(target, current, shell)
        return current


def _ps_parameter(name: str) -> str | None:
    """The one parameter of a PowerShell location cmdlet that *name* abbreviates."""
    if name in _PS_ALIASES:
        return _PS_ALIASES[name]
    found = [known for known in _PS_LOCATION if known.startswith(name)]
    return found[0] if len(found) == 1 else None


def _location_targets(command: SimpleCommand) -> list[str] | None:
    """The directories a ``cd``-like command names, or ``None`` when unclear.

    Unclear: an option that changes what the command does (``pushd -n``,
    ``popd +1``, ``-StackName``), or one this function does not know.
    """
    args = command.argv[1:]
    if command.shell != "powershell":
        slash = command.shell == "cmd"
        for arg in option_args(command):
            if slash and arg.startswith("/"):
                known = arg.lstrip("/").lower() == "d"
            elif arg.startswith("-") and len(arg) > 1:
                known = not slash and set(arg[1:]) <= _CD_FLAGS
            else:
                continue
            if not known:
                return None
        return operands(command, slash_flags=slash)
    targets: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if len(arg) > 1 and arg[0] == "-":
            name, attached, value = arg[1:].partition(":")
            parameter = _ps_parameter(name.lower())
            if parameter in ("path", "literalpath"):
                if not attached:
                    i += 1
                    value = args[i] if i < len(args) else ""
                targets.append(value)
            elif parameter in _PS_VALUES:
                i += 0 if attached else 1
            elif parameter is None or parameter == "stackname":
                return None
        else:
            targets.append(arg)
        i += 1
    return targets


def _move(
    command: SimpleCommand, where: _Where, places: _Places, home: str | None
) -> None:
    """Follow ``cd``, ``pushd`` or ``popd`` for the directory commands run in.

    Unlike :func:`_change_directory`, a target that is unclear leaves the
    directory unknown: a rule scoped to a directory must not be escaped by a
    ``cd`` the gate cannot read.
    """
    name = program_name(command.argv[0])
    shell = command.shell
    targets = _location_targets(command)
    destination: str | None = None
    if targets is None or len(targets) > 1:
        pass
    elif name in _POPD:
        # An empty stack: what an earlier command of the terminal left there.
        if not targets and where.stack:
            destination = where.stack.pop()
    elif not targets:
        if name in _PUSHD:
            if shell == "powershell":
                where.stack.append(where.current)  # it pushes and stays
            if shell != "bash" or not where.stack:
                return
            destination = where.stack.pop()  # Bash swaps the top two
        elif shell == "bash":
            destination = home
        elif shell == "cmd":
            return  # it prints the directory
        # PowerShell: home from version 6.2 on, nowhere before that.
    elif targets[0] in _PREVIOUS:
        destination = where.previous
    elif not _STACK_ENTRY_RE.fullmatch(targets[0]):
        destination = places.directory(targets[0], where.current, shell)
        plain = shell == "cmd" and name in _CD and not has_flag(command, "/d")
        if plain and places.windows:
            # Without ``/d`` cmd.exe stays where it is when the directory
            # lies on another drive.
            if destination is None or where.current is None:
                destination = None
            elif destination[:2] != where.current[:2]:
                return
    if name in _PUSHD:
        where.stack.append(where.current)
    where.previous, where.current = where.current, destination


def _piped(commands: Sequence[SimpleCommand], index: int) -> bool:
    """True when the command at *index* is one stage of a pipeline."""
    command = commands[index]
    feeds = index + 1 < len(commands) and commands[index + 1].upstream == command.argv
    return bool(command.upstream) or feeds


def _switches_drive(command: SimpleCommand) -> bool:
    """True for ``D:`` on its own in PowerShell or ``cmd.exe``."""
    word = command.argv[0]
    alone = len(command.argv) == 1 and len(word) == 2 and word[1] == ":"
    return alone and word[0].isalpha() and command.shell != "bash"


def _directory_options(command: SimpleCommand, spec: _Chdir) -> list[str] | None:
    """Directories the command's own options move it to, in order.

    ``None`` when an option says the directory is another one without
    naming it in a way the gate can follow.
    """
    found: list[str] = []
    late = False
    args = option_args(command)
    i = 0
    while i < len(args):
        arg = spec.split(args[i])
        flag, attached, value = arg.partition("=")
        flag = spec.spelled(flag)
        named = flag in spec.flags
        short = spec.attached and arg[:2] in spec.flags and not arg.startswith("--")
        if named or (short and len(arg) > 2):
            if named and not attached:
                i += 1
                value = args[i] if i < len(args) else ""
            elif not named:
                value = arg[2:]
            if late and spec.late != "read":
                if spec.late == "unknown":
                    return None
            elif not value:
                return None
            else:
                found.append(value)
        elif flag in spec.unknown and not late:
            return None
        elif arg in spec.value_flags and not late:
            i += 1
        elif not (arg.startswith("-") and len(arg) > 1):
            late = late or not (spec.plus and arg.startswith("+"))
        i += 1
    return found


def _run_directory(
    command: SimpleCommand, start: str | None, places: _Places, placed: bool = False
) -> tuple[str | None, str | None]:
    """Where the command's operands are relative to, and where it runs.

    The first is the shell's directory moved by the wrappers that were
    removed (``env -C dir``); the second also follows the program's own
    directory options (``git -C dir``).  ``None`` stands for unknown.  A
    *placed* command was given the name of each file ``find`` found: a
    directory option of its own then names a different place every time.
    """
    started = places.follow(command.chdir, start, command.shell)
    spec = _CHDIR.get(program_name(command.argv[0])) if command.argv else None
    if spec is None:
        return started, started
    options = _directory_options(command, spec)
    if options is None or (options and placed):
        return started, None
    return started, places.follow(options, started, command.shell)


class _Tracker:
    """Follows the directory the shell is in through the scopes of one call.

    A scope of the parse result runs in a process of its own (the shell is
    afterwards where it was before), unless the parser said otherwise:

    - ``maybe``: its commands may not run.  When they move the shell, the
      directory after them is unknown.
    - ``loop``: its commands run any number of times.  One pass is tried
      first: unless it ends where it began (``pushd dir; ...; popd``), the
      directory is unknown from the first command on, and after the loop.
    - ``defined``: the body of a function.  The shell is afterwards where it
      was, and a later call of a function whose body moves makes the
      directory unknown.

    ``left`` holds the scopes that are open: where each ends, its number,
    where the shell was when it began, and whether it is a loop that does
    not end where it began.
    """

    __slots__ = ("budget", "commands", "functions", "home", "movers", "opening",
                 "parsed", "places", "settled", "started", "trials")  # fmt: skip

    def __init__(self, parsed: ParseResult, places: _Places, home: str | None) -> None:
        self.parsed = parsed
        self.commands = parsed.commands
        self.places = places
        self.home = home
        opening: dict[int, list[tuple[int, int]]] = {}
        for number, (low, high) in enumerate(parsed.scopes):
            if high > low:
                opening.setdefault(low, []).append((high, number))
        for found in opening.values():
            found.sort(reverse=True)  # the outer scope first
        self.opening = opening
        self.functions = frozenset(parsed.named.values())
        self.movers: set[str] = set()
        self.settled: set[str] = set()
        #: Where a nested shell starts, by scope, for the path tracker.
        self.started: dict[int, str | None] = {}
        self.budget = _TRIAL_STEPS
        self.trials = 0

    def arrive(self, index: int, where: _Where, left: list[_Open]) -> _Where:
        """Where the shell is when the command at *index* starts."""
        while left and left[-1][0] <= index:
            where = self._leave(where, left.pop())
        for position, (high, number) in enumerate(self.opening.get(index, ())):
            self._enter(index, position, high, number, where, left)
        return where

    def _enter(
        self,
        low: int,
        position: int,
        high: int,
        number: int,
        where: _Where,
        left: list[_Open],
    ) -> None:
        kind = self.parsed.guards.get(number, "")
        before: _Where | None = where.copy()
        wild = False
        if kind == "loop":
            end = self._trial(low, position + 1, high, where)
            wild = end is None or end.differs(where)
            if wild:
                where.lose()
            elif end is not None and end.previous != where.previous:
                where.previous = None
        elif not kind:
            if number in self.parsed.kept:
                before = None
            if number in self.parsed.entered:
                starter, chain = self.parsed.entered[number]
                where.current = self.places.follow(chain, where.current, starter)
                if not self.trials:
                    self.started[number] = where.current
        left.append((high, number, before, wild))

    def _leave(self, where: _Where, scope: _Open) -> _Where:
        _, number, before, wild = scope
        if before is None:
            return where  # ``eval``: its moves stay in force
        kind = self.parsed.guards.get(number, "")
        if not kind:
            return before
        if kind == "defined":
            name = self.parsed.named.get(number, "")
            if where.moves != before.moves:
                self.movers.add(name)
            self.settled.add(name)
            return before
        if wild or where.differs(before):
            where.lose()
        elif where.previous != before.previous:
            where.previous = None
        return where

    def _trial(
        self, low: int, position: int, high: int, where: _Where
    ) -> _Where | None:
        """Where one pass over a loop ends; ``None`` when that costs too much."""
        self.budget -= high - low
        if self.budget < 0:
            return None
        where = where.copy()
        left: list[_Open] = []
        self.trials += 1
        try:
            inner = self.opening.get(low, ())
            for at in range(position, len(inner)):
                self._enter(low, at, *inner[at], where, left)
            for index in range(low, high):
                if index > low:
                    where = self.arrive(index, where, left)
                self.step(index, where)
            while left:
                where = self._leave(where, left.pop())
        finally:
            self.trials -= 1
        return where

    def step(self, index: int, where: _Where) -> None:
        """Let the command at *index* move the shell, if it does."""
        command = self.commands[index]
        if not command.argv:
            return
        if program_name(command.argv[0]) in MOVERS:
            if command.shell == "bash" and _piped(self.commands, index):
                # A stage of a pipeline runs in a process of its own, unless
                # the shell is told otherwise: the gate takes neither as given,
                # so neither where the shell is nor where it was is known.
                where.previous = where.current = None
            else:
                _move(command, where, self.places, self.home)
            where.moves += 1
        elif _switches_drive(command):
            # ``D:`` goes to wherever the shell last was on that drive.
            where.previous, where.current = where.current, None
            where.moves += 1
        elif self.functions:
            word = command.argv[0]
            name = word if command.shell == "bash" else word.lower()
            # A function that is defined further on may move as well.
            unsettled = name in self.movers or name not in self.settled
            if name in self.functions and unsettled:
                where.lose()


#: An open scope: where it ends, its number, where the shell was when it
#: began (``None``: its moves stay), and whether it is a loop that moves.
_Open = tuple[int, int, _Where | None, bool]


def shell_facts(
    parsed: ParseResult,
    cwd: str,
    resolve: Resolve,
    home: str | None = None,
    *,
    origin: str | None = None,
    windows: bool = False,
    known: bool = True,
    crowded: Callable[[], None] | None = None,
) -> tuple[list[PathFact], list[str]]:
    """Paths the parsed commands touch, and the directory each command runs in.

    Parameters
    ----------
    parsed:
        Result of :func:`ember_armor.ledger.shell.parse_shell`.
    cwd:
        Normalised directory the command string starts in.
    resolve:
        ``resolve(raw_path, cwd, shell)`` returning the normalised paths the
        operand can stand for (several for a loop variable).
    home:
        Normalised home directory, where a bare ``cd`` goes in Bash.
    origin:
        Normalised working directory of the call, when it is not *cwd*.
    windows:
        Path flavour: on Windows a path without a drive letter in
        PowerShell or ``cmd.exe`` lies on the drive the shell is on.
    known:
        False when nothing says where the command string starts: its
        commands then run in an unknown directory until one names an
        absolute one.  Paths are still resolved against *cwd*.
    crowded:
        Called when moves that may not have run leave the shell in more
        than :data:`MAX_PLACES` possible directories: the paths are then
        not all resolved.

    Returns
    -------
    tuple[list[PathFact], list[str]]
        The paths, normalised and de-duplicated, and for each command the
        directory in effect when it runs: empty for *origin*,
        :data:`~ember_armor.ledger.paths.UNKNOWN_DIR` when the command
        string does not say.  The directory follows ``cd``, ``pushd`` and
        ``popd``, the directory options of wrappers and nested shells, and
        the program's own (``git -C``, ``make -C``, ``npm --prefix``, ``pnpm
        -C``, ``yarn --cwd``, ``cargo -C``).  It is unknown after a move
        that may not have run (a branch, a loop body, the right side of
        ``&&`` or ``||``) and after a call of a function that moves.  After
        such a move a relative path is resolved both ways: against the
        directory the move leads to and against the one before it.
    """
    origin = cwd if origin is None else origin
    places = _Places(resolve, windows)

    def label(directory: str | None) -> str:
        if directory is None:
            return UNKNOWN_DIR
        return "" if directory == origin else directory

    facts: dict[tuple[PathFact, str], PathFact] = {}
    directories: list[str] = []
    place = _Location(cwd, cwd)
    # Where else the shell may be, for relative paths: the directory before
    # a move that may not have run.
    also: list[str] = []
    where = _Where(cwd if known else None)
    tracker = _Tracker(parsed, places, home)
    left: list[_Open] = []
    shelved: list[tuple[int, bool, _Location, list[str]]] = []
    for index, command in enumerate(parsed.commands):
        while shelved and shelved[-1][0] <= index:
            _, guarded, before, others = shelved.pop()
            if not guarded:
                # A process of its own ends with its moves.
                place, also = before, others
                continue
            # A branch, a loop or a function body: the shell may as well be
            # wherever it could be before.
            for other in (before.current, *others):
                if other in (place.current, *also):
                    continue
                if len(also) < MAX_PLACES:
                    also.append(other)
                elif crowded is not None:
                    crowded()
        where = tracker.arrive(index, where, left)
        for high, number in tracker.opening.get(index, ()):
            snapshot = replace(place, stack=list(place.stack))
            shelved.append((high, number in parsed.guards, snapshot, list(also)))
            started = tracker.started.pop(number, None)
            if started is not None:
                # The paths of a nested shell are relative to where it starts.
                place.current = started
        # A redirection is opened by the shell, in the shell's directory.
        here = label(where.current)
        bases = (place.current, *also)
        for redirect in command.redirects:
            if _is_null(redirect.target):
                continue
            for base in bases:
                for path in resolve(redirect.target, base, command.shell):
                    fact = PathFact(path, redirect.op, False, here, index)
                    facts.setdefault((fact, here), fact)
        if not command.argv:
            directories.append(here)
            continue
        if program_name(command.argv[0]) in MOVERS:
            directories.append(here)
            _change_directory(command, place, resolve, home)
            also = _moved_too(also, command, place.current, resolve, home)
            tracker.step(index, where)
            continue
        if _switches_drive(command):
            directories.append(here)
            tracker.step(index, where)
            continue
        placed = index in parsed.placed
        started, runs = _run_directory(command, where.current, places, placed)
        tracker.step(index, where)
        directory = label(runs)
        directories.append(directory)
        # Operands are relative to where the wrappers start the command.
        if command.chdir and started is not None:
            bases = (started,)
        for raw, op, recursive in _command_paths(command):
            if qualified := _FILESYSTEM_RE.match(raw):
                raw = raw[qualified.end() :]
            if _PROVIDER_RE.match(raw):
                continue
            if recursive:
                raw = _WILD_TAIL_RE.sub(r"\1.", raw)
            for base in bases:
                for path in resolve(raw, base, command.shell):
                    fact = PathFact(path, op, recursive, directory, index)
                    facts.setdefault((fact, directory), fact)
    return list(facts.values()), directories


def shell_paths(
    parsed: ParseResult, cwd: str, resolve: Resolve, home: str | None = None
) -> list[PathFact]:
    """Paths touched by the parsed commands, normalised and de-duplicated.

    Takes the parameters of :func:`shell_facts`.
    """
    return shell_facts(parsed, cwd, resolve, home)[0]
