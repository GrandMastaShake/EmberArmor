"""Which paths a parsed shell command reads, writes or deletes.

Only recognised commands contribute paths (``rm``, ``cat``, ``Remove-Item``,
``del`` and so on), plus every redirection.  Unknown programs contribute
nothing: the ledger does not guess what an arbitrary tool does with its
arguments.  ``cd`` is followed so later relative paths resolve correctly.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from ember_armor.ledger.shell import ParseResult, SimpleCommand, program_name
from ember_armor.ledger.shell.argv import has_flag, operands
from ember_armor.ledger.shell.core import find_targets

_NULL_TARGETS = frozenset(
    {"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty", "nul", "$null"}
)
_PROVIDER_RE = re.compile(r"(?:[A-Za-z]{2,}:|[A-Za-z]+::)")
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
    """

    op: str
    value_flags: frozenset[str] = frozenset()
    recursive: tuple[str, ...] = ()
    skip: int = 0
    last: str | None = None
    write_flags: tuple[str, ...] = ()


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
            "hexdump", "base64", "source", ".")  # fmt: skip
_GREP_VALUES = frozenset({"-e", "-f", "-m", "-A", "-B", "-C", "-g", "-t",
                          "--include", "--exclude", "--exclude-dir", "--glob",
                          "--type"})  # fmt: skip
_BASH: dict[str, _Native] = {
    **{name: _Native("read") for name in _READERS},
    "head": _Native("read", frozenset({"-n", "-c"})),
    "tail": _Native("read", frozenset({"-n", "-c"})),
    "grep": _Native("read", _GREP_VALUES, skip=1),
    "egrep": _Native("read", _GREP_VALUES, skip=1),
    "fgrep": _Native("read", _GREP_VALUES, skip=1),
    "rg": _Native("read", _GREP_VALUES, skip=1),
    "rm": _Native("delete", recursive=("-r", "-R", "--recursive")),
    "rmdir": _Native("delete"),
    "unlink": _Native("delete"),
    "cp": _Native("read", frozenset({"-t", "-S"}), last="write"),
    "mv": _Native("write", frozenset({"-t", "-S"})),
    "tee": _Native("write"),
    "touch": _Native("write", frozenset({"-d", "-t", "-r"})),
    "truncate": _Native("write", frozenset({"-s", "-r"})),
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
}
_CD_PROGRAMS = frozenset({"cd", "pushd", "chdir", "set-location", "push-location"})
#: A delete whose targets arrive on a pipe (``xargs rm``, ``... | Remove-Item``)
#: is treated as acting on the working directory: unknown, so assume nearby.
_UNKNOWN_TARGET = "."

Resolve = Callable[[str, str], str]


def _is_null(target: str) -> bool:
    lowered = target.lower()
    return lowered in _NULL_TARGETS or lowered.startswith(("/dev/fd/", "&"))


def _native_paths(command: SimpleCommand, spec: _Native) -> list[tuple[str, str, bool]]:
    slash = command.shell == "cmd"
    targets = operands(command, spec.value_flags, slash_flags=slash)[spec.skip :]
    recursive = any(has_flag(command, flag) for flag in spec.recursive)
    op = spec.op
    if any(has_flag(command, flag) for flag in spec.write_flags):
        op = "write"
    if op == "delete" and not targets:
        targets = [_UNKNOWN_TARGET]
    found = [(target, op, recursive) for target in targets]
    if spec.last and len(found) >= 2:
        found[-1] = (found[-1][0], spec.last, False)
    return found


def _resolve_param(name: str, spec: _Cmdlet) -> str | None:
    """Full parameter name for a possibly abbreviated ``-Name``."""
    lowered = name.lstrip("-").lower()
    if lowered in spec.params:
        return lowered
    return next((p for p in spec.params if p.startswith(lowered)), None)


def _cmdlet_paths(command: SimpleCommand, spec: _Cmdlet) -> list[tuple[str, str, bool]]:
    if has_flag(command, "-whatif"):
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
    if spec.rest == "delete" and not found:
        found.append((_UNKNOWN_TARGET, "delete"))
    return [(path, op, recursive and op == "delete") for path, op in found if op]


def _dd_paths(command: SimpleCommand) -> list[tuple[str, str, bool]]:
    found = []
    for arg in command.argv[1:]:
        if arg.startswith("if="):
            found.append((arg[3:], "read", False))
        elif arg.startswith("of="):
            found.append((arg[3:], "write", False))
    return found


def _find_paths(command: SimpleCommand) -> list[tuple[str, str, bool]]:
    if "-delete" not in command.argv:
        return []
    targets, named = find_targets(command.argv[1:])
    return [(target, "delete", not named) for target in targets]


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
    return _native_paths(command, _BASH[name]) if name in _BASH else []


def _change_directory(command: SimpleCommand, cwd: str, resolve: Resolve) -> str:
    """Working directory after a ``cd``-like command (unchanged if unclear)."""
    if command.shell == "powershell":
        targets = [a for a in command.argv[1:] if not a.startswith("-")]
    else:
        targets = operands(command, slash_flags=command.shell == "cmd")
    if len(targets) != 1 or targets[0] == "-":
        return cwd
    resolved = resolve(targets[0], cwd)
    return cwd if "$" in resolved else resolved


def shell_paths(parsed: ParseResult, cwd: str, resolve: Resolve) -> list[PathFact]:
    """Paths touched by the parsed commands, normalised and de-duplicated.

    Parameters
    ----------
    parsed:
        Result of :func:`ember_armor.ledger.shell.parse_shell`.
    cwd:
        Normalised working directory of the call.
    resolve:
        ``resolve(raw_path, cwd)`` returning the normalised path.
    """
    facts: dict[PathFact, None] = {}
    current = cwd
    for command in parsed.commands:
        for redirect in command.redirects:
            if not _is_null(redirect.target):
                facts[PathFact(resolve(redirect.target, current), redirect.op)] = None
        if not command.argv:
            continue
        if program_name(command.argv[0]) in _CD_PROGRAMS:
            current = _change_directory(command, current, resolve)
            continue
        for raw, op, recursive in _command_paths(command):
            if _PROVIDER_RE.match(raw):
                continue
            if recursive:
                raw = _WILD_TAIL_RE.sub(r"\1.", raw)
            facts[PathFact(resolve(raw, current), op, recursive)] = None
    return list(facts)
