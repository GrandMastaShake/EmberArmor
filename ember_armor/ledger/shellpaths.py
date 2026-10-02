"""Which paths a parsed shell command reads, writes or deletes.

Only recognised commands contribute paths (``rm``, ``cat``, ``Remove-Item``,
``del`` and so on), plus every redirection.  Unknown programs contribute
nothing: the ledger does not guess what an arbitrary tool does with its
arguments.  ``cd``, ``pushd`` and ``popd`` are followed so later relative
paths resolve correctly; a move inside a subshell ends with the subshell.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace

from ember_armor.ledger.shell import ParseResult, SimpleCommand, program_name
from ember_armor.ledger.shell.argv import has_flag, operand_positions, operands
from ember_armor.ledger.shell.core import find_exec, find_targets, lister_targets

_NULL_TARGETS = frozenset(
    {"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty", "nul", "$null"}
)
_PROVIDER_RE = re.compile(r"(?:[A-Za-z]{2,}:|[A-Za-z]+::)")
#: ``FileSystem::C:\x`` is the plain path ``C:\x``.
_FILESYSTEM_RE = re.compile(
    r"(?:Microsoft\.PowerShell\.Core\\)?FileSystem::", re.IGNORECASE
)
_WILD_TAIL_RE = re.compile(r"(^|[/\\])\*$")


@dataclass(frozen=True)
class PathFact:
    """One path a call touches: ``op`` is ``read``, ``write`` or ``delete``."""

    path: str
    op: str
    recursive: bool = False


@dataclass(frozen=True)
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


@dataclass(frozen=True)
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
    "mv": _Native("write", frozenset({"-t", "-S"})),
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
    "move": _Native("write"),
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
        {**_path_params("write"), "destination": "write"}, rest="write"
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
_GIT_VALUES = frozenset({"-C", "-c", "--git-dir", "--work-tree", "--namespace"})
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


@dataclass
class _Location:
    """Working directory while walking the commands of one call."""

    current: str
    previous: str
    stack: list[str] = field(default_factory=list)


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


def shell_paths(
    parsed: ParseResult, cwd: str, resolve: Resolve, home: str | None = None
) -> list[PathFact]:
    """Paths touched by the parsed commands, normalised and de-duplicated.

    Parameters
    ----------
    parsed:
        Result of :func:`ember_armor.ledger.shell.parse_shell`.
    cwd:
        Normalised working directory of the call.
    resolve:
        ``resolve(raw_path, cwd, shell)`` returning the normalised paths the
        operand can stand for (several for a loop variable).
    home:
        Normalised home directory, where a bare ``cd`` goes in Bash.
    """
    facts: dict[PathFact, None] = {}
    place = _Location(cwd, cwd)
    opening: dict[int, list[int]] = {}
    for low, high in parsed.scopes:
        if high > low:
            opening.setdefault(low, []).append(high)
    left: list[tuple[int, _Location]] = []
    for index, command in enumerate(parsed.commands):
        while left and left[-1][0] <= index:
            place = left.pop()[1]
        for high in sorted(opening.get(index, ()), reverse=True):
            left.append((high, replace(place, stack=list(place.stack))))
        for redirect in command.redirects:
            if not _is_null(redirect.target):
                for path in resolve(redirect.target, place.current, command.shell):
                    facts[PathFact(path, redirect.op)] = None
        if not command.argv:
            continue
        if program_name(command.argv[0]) in _CD | _PUSHD | _POPD:
            _change_directory(command, place, resolve, home)
            continue
        for raw, op, recursive in _command_paths(command):
            if qualified := _FILESYSTEM_RE.match(raw):
                raw = raw[qualified.end() :]
            if _PROVIDER_RE.match(raw):
                continue
            if recursive:
                raw = _WILD_TAIL_RE.sub(r"\1.", raw)
            for path in resolve(raw, place.current, command.shell):
                facts[PathFact(path, op, recursive)] = None
    return list(facts)
