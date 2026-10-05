"""Facts extracted from one proposed tool call.

Rules are never evaluated on raw text.  :func:`extract` turns the host's tool
call (tool name, working directory, tool input) into :class:`Facts`: parsed
shell commands, the paths the call reads, writes or deletes, dynamic-shell
reasons and the structured arguments.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from fnmatch import fnmatchcase

from ember_armor.ledger.paths import PATH_VARIABLES, Lookup, PathFact, normalize
from ember_armor.ledger.shell import (
    Dynamic,
    ParseResult,
    SimpleCommand,
    parse_shell,
    program_name,
)

TYPE_CHECKING = False
if TYPE_CHECKING:
    from typing import Any


@dataclass(frozen=True)
class ShellTool:
    """How a tool carries a shell command.

    ``shell`` is ``bash``, ``powershell``, ``cmd`` or ``native`` (PowerShell
    on Windows, Bash elsewhere); ``field`` is the input field that holds the
    command; ``cwd`` optionally names the input field with the directory the
    command starts in.
    """

    shell: str
    field: str = "command"
    cwd: str = ""


#: Tools whose input is a shell string, by name (any letter case) or glob.
#: ``shell_tools`` in ``config.json`` adds to them.
SHELL_TOOLS = {
    "Bash": ShellTool("bash"),
    "PowerShell": ShellTool("powershell"),
    "mcp__Windows-MCP__PowerShell": ShellTool("powershell"),
    "mcp__terminal__run_in_terminal": ShellTool("native", cwd="cwd"),
}
#: A longer path is not matched against rules; the call is marked instead.
MAX_PATH_CHARS = 1024
_MAX_ALTERNATIVES = 64
#: PowerShell cmdlets that create, change or remove an ``Env:NAME`` item.
_ENV_CMDLETS = frozenset(
    {"set-item", "new-item", "remove-item", "clear-item", "set-content",
     "add-content", "clear-content", "rename-item", "move-item"}
)  # fmt: skip
_ENV_ITEM_RE = re.compile(r"env:[\\/]?(\w+)", re.IGNORECASE)
#: A start directory that names no one place: a variable nobody set, a
#: wildcard, a home the gate does not know.
_UNSETTLED_RE = re.compile(r"[$`*?\[]|%\w+%|(?:^|/)~")
#: File tools: the input field holding the path, and what the tool does to it.
FILE_TOOLS = {
    "Read": ("file_path", "read"),
    "Write": ("file_path", "write"),
    "Edit": ("file_path", "write"),
    "MultiEdit": ("file_path", "write"),
    "NotebookEdit": ("notebook_path", "write"),
    "Grep": ("path", "read"),
}


@dataclass(frozen=True)
class Facts:
    """What the gate knows about one tool call.

    ``windows`` is the path flavour, ``home`` the normalised home directory
    and ``variables`` the upper-cased variables that path patterns may use.
    ``assigned`` names the variables the shell input sets (see
    :func:`assigned_names`) and ``shell`` the shell whose command the tool
    carries (empty for any other tool).  Each command and each path of a
    shell call carries the directory in effect for it (``cwd``: empty when
    that is the working directory of the call).  ``located`` is false when
    the host did not say where the call is made: ``cwd`` is then only what
    paths are resolved against, and the directory is unknown.
    """

    tool: str
    cwd: str
    session: str = ""
    windows: bool = False
    home: str | None = None
    commands: tuple[SimpleCommand, ...] = ()
    paths: tuple[PathFact, ...] = ()
    dynamic: tuple[Dynamic, ...] = ()
    assigned: tuple[str, ...] = ()
    shell: str = ""
    args: Mapping[str, Any] = field(default_factory=dict)
    variables: Mapping[str, str] = field(default_factory=dict)
    located: bool = True


def shell_tools_from(config: Mapping[str, Mapping[str, str]]) -> dict[str, ShellTool]:
    """The ``shell_tools`` setting of ``config.json`` as :class:`ShellTool`."""
    return {name: ShellTool(**entry) for name, entry in config.items()}


def shell_tool(
    tool: str, extra: Mapping[str, ShellTool] | None = None
) -> ShellTool | None:
    """How *tool* carries a shell command, if it does.

    The user's entries (*extra*) are tried first, then :data:`SHELL_TOOLS`.
    Names are compared in any letter case and may be globs.
    """
    lowered = tool.lower()
    for known in (extra or {}, SHELL_TOOLS):
        for name, spec in known.items():
            if fnmatchcase(lowered, name.lower()):
                return spec
    return None


def path_variables(env: Mapping[str, str]) -> dict[str, str]:
    """Variables from *env* that may be expanded in paths, upper-cased."""
    found = {k.upper(): v for k, v in env.items() if k.upper() in PATH_VARIABLES and v}
    home = found.get("HOME") or found.get("USERPROFILE")
    if home:
        found.setdefault("HOME", home)
    return found


def assigned_names(parsed: ParseResult) -> tuple[str, ...]:
    """Variables the parsed shell input sets in the environment of a command.

    What the parsers saw (an assignment in Bash, alone or in front of a
    command, ``export``, ``env NAME=...``, ``unset``; ``$env:NAME = ...`` and
    ``SetEnvironmentVariable`` in PowerShell), plus ``setx NAME``, ``set
    NAME=...`` in ``cmd.exe`` and a PowerShell cmdlet that changes an
    ``Env:NAME`` item.  Values are not kept.
    """
    names = list(parsed.assigned)
    for command in parsed.commands:
        if len(command.argv) < 2:
            continue
        program, args = program_name(command.argv[0]), command.argv[1:]
        if program == "setx":
            names += [arg for arg in args if not arg.startswith("/")][:1]
        elif command.shell == "cmd" and program == "set":
            name, equals, _ = " ".join(args).partition("=")
            names += [name.strip().upper()] if equals and " " not in name else []
        elif command.shell == "powershell" and program in _ENV_CMDLETS:
            found = (_ENV_ITEM_RE.fullmatch(arg) for arg in args)
            names += [match.group(1).upper() for match in found if match]
    return tuple(dict.fromkeys(names))


def _lookup(
    shell: str, parsed: ParseResult, env: Mapping[str, str], current: str
) -> Lookup:
    """Resolver for plain ``$NAME`` references of one shell.

    Bash names are case-sensitive and fall back to the environment unless
    the command string assigns them.  PowerShell names are case-insensitive
    and never read the environment (that is ``$env:NAME``); ``$HOME`` and
    ``$PWD`` are automatic.  A name the parser marked unknown stays as
    written.
    """

    def bash(name: str) -> str | None:
        if name == "PWD":
            return current
        if name in parsed.unknown:
            return None
        if name in parsed.variables:
            # Assigning an environment name: which value holds where is not
            # tracked, so neither is trusted.
            return None if name in env else parsed.variables[name]
        return env.get(name)

    def powershell(name: str) -> str | None:
        key = name.lower()
        if key in parsed.unknown:
            return None
        if key in parsed.variables:
            return parsed.variables[key]
        automatic = {"pwd": current, "home": env.get("HOME")}
        return automatic.get(key)

    return {"bash": bash, "powershell": powershell}.get(shell, lambda name: None)


def _environment(
    shell: str, parsed: ParseResult, env: Mapping[str, str]
) -> Mapping[str, str]:
    """Environment for ``$env:NAME``, without names the command reassigns."""
    if shell != "powershell":
        return env
    assigned = parsed.unknown | parsed.variables.keys()
    return {k: v for k, v in env.items() if f"env:{k.lower()}" not in assigned}


def _alternatives(
    raw: str, choices: Mapping[str, tuple[str, ...]], fold: bool
) -> list[str]:
    """*raw* with each loop variable or literal array replaced by its values."""
    texts = [raw]
    for name, values in choices.items():
        escaped = re.escape(name)
        reference = re.compile(
            rf"\$\{{{escaped}(?:\[[@*]\])?\}}|\${escaped}(?![\w\[])",
            re.IGNORECASE if fold else 0,
        )
        if not reference.search(raw):
            continue
        # Splitting and joining puts the value in as it is (no escapes).
        texts = [
            value.join(reference.split(text)) for text in texts for value in values
        ]
        if len(texts) > _MAX_ALTERNATIVES:
            return [raw]
    return texts


def _anchored(
    raw: str, windows: bool, home: str | None, variables: Mapping[str, str]
) -> bool:
    """True when *raw* names one directory wherever it is read from."""
    one, two = (
        normalize(raw, base, windows=windows, home=home, variables=variables)
        for base in ("/\x00one", "/\x00two")
    )
    return one == two


def extract(
    call: Mapping[str, Any],
    *,
    windows: bool | None = None,
    env: Mapping[str, str] | None = None,
    shell_tools: Mapping[str, ShellTool] | None = None,
) -> Facts:
    """Extract facts from a tool call.

    Parameters
    ----------
    call:
        The host's description of the call: ``tool_name``, ``tool_input``,
        ``cwd`` and ``session_id`` (the Claude Code PreToolUse shape).
    windows:
        Path flavour.  Defaults to the platform the gate runs on.
    env:
        Environment used for ``~`` and variables such as ``$HOME`` or
        ``$env:TEMP``.  Defaults to the process environment.
    shell_tools:
        The user's shell-carrying tools, in addition to :data:`SHELL_TOOLS`.

    Raises
    ------
    ValueError
        If the call has no tool name or its input is not an object.
    """
    tool = call.get("tool_name")
    tool_input = call.get("tool_input", {})
    if not isinstance(tool, str) or not tool:
        raise ValueError("tool call has no tool_name")
    if tool_input is None:
        tool_input = {}
    if not isinstance(tool_input, Mapping):
        raise ValueError("tool_input is not an object")
    windows = os.name == "nt" if windows is None else windows
    variables = path_variables(os.environ if env is None else env)
    raw_home = variables.get("HOME")
    home = normalize(raw_home, "/", windows=windows) if raw_home else None
    given = call.get("cwd")
    # A call that does not say where it is made, or says it with a relative
    # path, is made in a directory the gate does not know.
    located = isinstance(given, str) and _anchored(given, windows, None, {})
    cwd = normalize(str(given or "/"), "/", windows=windows)

    commands: tuple[SimpleCommand, ...] = ()
    dynamic: tuple[Dynamic, ...] = ()
    assigned: tuple[str, ...] = ()
    paths: list[PathFact] = []
    shell = ""
    carrier = shell_tool(tool, shell_tools)
    if carrier is not None:
        command = tool_input.get(carrier.field)
        if not isinstance(command, str):
            raise ValueError(
                f"{tool} call has no command string (field {carrier.field!r})"
            )
        shell = carrier.shell
        if shell == "native":
            shell = "powershell" if windows else "bash"
        start = tool_input.get(carrier.cwd) if carrier.cwd else None
        known = located
        if not isinstance(start, str) or not start:
            start = cwd
        else:
            known = located or _anchored(start, windows, home, variables)
            start = normalize(
                start, cwd, windows=windows, home=home, variables=variables
            )
            known = known and _UNSETTLED_RE.search(start) is None
        from ember_armor.ledger.shellpaths import shell_facts

        parsed = parse_shell(command, shell)
        overlong = crowded = False

        def crowd() -> None:
            nonlocal crowded
            crowded = True

        def resolve(raw: str, current: str, command_shell: str) -> list[str]:
            nonlocal overlong
            if len(raw) > MAX_PATH_CHARS:
                overlong = True
                return []
            lookup = _lookup(command_shell, parsed, variables, current)
            fold = command_shell == "powershell"
            return [
                normalize(
                    text,
                    current,
                    windows=windows,
                    home=home,
                    variables=_environment(command_shell, parsed, variables),
                    lookup=lookup,
                )
                for text in _alternatives(raw, parsed.choices, fold)
            ]

        paths, directories = shell_facts(
            parsed,
            start,
            resolve,
            home,
            origin=cwd if located else "",
            windows=windows,
            known=known,
            crowded=crowd,
        )
        commands = tuple(
            replace(command, cwd=directory) if directory else command
            for command, directory in zip(parsed.commands, directories, strict=True)
        )
        dynamic = tuple(parsed.dynamic)
        assigned = assigned_names(parsed)
        if overlong:
            dynamic += (Dynamic("parse_error", "path too long"),)
        if crowded:
            dynamic += (Dynamic("parse_error", "too many directories"),)
    elif tool in FILE_TOOLS:
        key, op = FILE_TOOLS[tool]
        target = tool_input.get(key)
        pattern = tool_input.get("glob") if tool == "Grep" else None
        if isinstance(pattern, str) and pattern and not pattern.startswith("!"):
            # Grep with a glob reads every file of that name below the path
            # (``!name`` leaves files out instead).
            start = target if isinstance(target, str) and target else "."
            target = f"{start}/**/{pattern}"
        if isinstance(target, str) and target:
            if len(target) > MAX_PATH_CHARS:
                raise ValueError(f"path longer than {MAX_PATH_CHARS} characters")
            resolved = normalize(
                target, cwd, windows=windows, home=home, variables=variables
            )
            paths = [PathFact(resolved, op)]
    return Facts(
        tool=tool,
        cwd=cwd,
        session=str(call.get("session_id") or ""),
        windows=windows,
        home=home,
        commands=commands,
        paths=tuple(paths),
        dynamic=dynamic,
        assigned=assigned,
        shell=shell,
        args=tool_input,
        variables=variables,
        located=located,
    )
