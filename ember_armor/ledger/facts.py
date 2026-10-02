"""Facts extracted from one proposed tool call.

Rules are never evaluated on raw text.  :func:`extract` turns the host's tool
call (tool name, working directory, tool input) into :class:`Facts`: parsed
shell commands, the paths the call reads, writes or deletes, dynamic-shell
reasons and the structured arguments.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from ember_armor.ledger.paths import PATH_VARIABLES, normalize
from ember_armor.ledger.shell import Dynamic, SimpleCommand, parse_shell
from ember_armor.ledger.shellpaths import PathFact, shell_paths

#: Tools whose ``command`` input is a shell string, and the shell that reads it.
SHELL_TOOLS = {"Bash": "bash", "PowerShell": "powershell"}
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
    """

    tool: str
    cwd: str
    session: str = ""
    windows: bool = False
    home: str | None = None
    commands: tuple[SimpleCommand, ...] = ()
    paths: tuple[PathFact, ...] = ()
    dynamic: tuple[Dynamic, ...] = ()
    args: Mapping[str, Any] = field(default_factory=dict)
    variables: Mapping[str, str] = field(default_factory=dict)


def path_variables(env: Mapping[str, str]) -> dict[str, str]:
    """Variables from *env* that may be expanded in paths, upper-cased."""
    found = {k.upper(): v for k, v in env.items() if k.upper() in PATH_VARIABLES and v}
    home = found.get("HOME") or found.get("USERPROFILE")
    if home:
        found.setdefault("HOME", home)
    return found


def extract(
    call: Mapping[str, Any],
    *,
    windows: bool | None = None,
    env: Mapping[str, str] | None = None,
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

    Raises
    ------
    ValueError
        If the call has no tool name or its input is not an object.
    """
    tool = call.get("tool_name")
    tool_input = call.get("tool_input") or {}
    if not isinstance(tool, str) or not tool:
        raise ValueError("tool call has no tool_name")
    if not isinstance(tool_input, Mapping):
        raise ValueError("tool_input is not an object")
    windows = os.name == "nt" if windows is None else windows
    variables = path_variables(os.environ if env is None else env)
    raw_home = variables.get("HOME")
    home = normalize(raw_home, "/", windows=windows) if raw_home else None
    cwd = normalize(str(call.get("cwd") or "/"), "/", windows=windows)

    commands: tuple[SimpleCommand, ...] = ()
    dynamic: tuple[Dynamic, ...] = ()
    paths: list[PathFact] = []
    command = tool_input.get("command")
    if tool in SHELL_TOOLS and isinstance(command, str):
        parsed = parse_shell(command, SHELL_TOOLS[tool])
        known = {**variables, **parsed.variables}

        def resolve(raw: str, current: str) -> str:
            return normalize(
                raw,
                current,
                windows=windows,
                home=home,
                variables={**known, "PWD": current},
            )

        commands, dynamic = tuple(parsed.commands), tuple(parsed.dynamic)
        paths = shell_paths(parsed, cwd, resolve)
    elif tool in FILE_TOOLS:
        key, op = FILE_TOOLS[tool]
        target = tool_input.get(key)
        if isinstance(target, str) and target:
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
        args=tool_input,
        variables=variables,
    )
