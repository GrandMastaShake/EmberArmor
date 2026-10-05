"""Shell command-string parsers for the constraint ledger.

:func:`parse_shell` turns a Bash, PowerShell or ``cmd.exe`` command string
into simple commands, redirections and dynamic-shell reasons.  The string is
data: nothing in this package executes it.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable

from ember_armor.ledger.shell.core import (
    MAX_COMMAND_CHARS,
    MAX_COMMANDS,
    MAX_DEPTH,
    Dynamic,
    ParseResult,
    Recurse,
    Redirect,
    SimpleCommand,
    program_name,
)

__all__ = [
    "Dynamic",
    "ParseResult",
    "Redirect",
    "SimpleCommand",
    "parse_shell",
    "program_name",
]

#: The parsers are imported on first use: a call only needs its own shell.
_PARSERS = {"bash": "parse_bash", "powershell": "parse_powershell", "cmd": "parse_cmd"}


#: ``parser(text, depth, recurse)``: one shell's parser.
Parser = Callable[[str, int, Recurse], ParseResult]


def _parser(shell: str) -> Parser:
    module = importlib.import_module(f"{__name__}.{shell}")
    parser: Parser = getattr(module, _PARSERS[shell])
    return parser


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
    result = _parser(shell)(text, depth, parse_shell)
    if depth == 0 and len(result.commands) > MAX_COMMANDS:
        del result.commands[MAX_COMMANDS:]
        result.dynamic.append(Dynamic("parse_error", "too many commands"))
    return result
