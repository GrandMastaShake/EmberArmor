"""Shell command-string parsers for the constraint ledger.

:func:`parse_shell` turns a Bash, PowerShell or ``cmd.exe`` command string
into simple commands, redirections and dynamic-shell reasons.  The string is
data: nothing in this package executes it.
"""

from __future__ import annotations

from ember_armor.ledger.shell.bash import parse_bash
from ember_armor.ledger.shell.cmd import parse_cmd
from ember_armor.ledger.shell.core import (
    MAX_COMMAND_CHARS,
    MAX_DEPTH,
    Dynamic,
    ParseResult,
    Redirect,
    SimpleCommand,
    program_name,
)
from ember_armor.ledger.shell.powershell import parse_powershell

__all__ = [
    "Dynamic",
    "ParseResult",
    "Redirect",
    "SimpleCommand",
    "parse_shell",
    "program_name",
]

_PARSERS = {"bash": parse_bash, "powershell": parse_powershell, "cmd": parse_cmd}


def parse_shell(text: str, shell: str, depth: int = 0) -> ParseResult:
    """Parse a command string of the given shell.

    Parameters
    ----------
    text:
        The command string, exactly as the agent proposed it.
    shell:
        ``bash``, ``powershell`` or ``cmd``.
    depth:
        Nesting depth; callers leave it at 0.

    Returns
    -------
    ParseResult
        Never raises for bad input: an input that cannot be resolved yields a
        ``parse_error`` dynamic reason instead of an empty command list.
    """
    if len(text) > MAX_COMMAND_CHARS:
        return ParseResult(dynamic=[Dynamic("parse_error", "command too long")])
    if depth > MAX_DEPTH:
        return ParseResult(dynamic=[Dynamic("parse_error", "shell nesting too deep")])
    return _PARSERS[shell](text, depth, parse_shell)
