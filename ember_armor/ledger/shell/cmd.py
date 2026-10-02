"""Minimal ``cmd.exe`` command-line parser for ``cmd /c "..."`` strings.

Covers what an agent realistically passes to ``cmd /c``: commands joined by
``&``, ``&&``, ``||`` and ``|``, double quotes, ``^`` escapes, parentheses,
redirections, and the ``if``/``else``/``for``/``call`` prefixes.  Nothing is
executed.
"""

from __future__ import annotations

import re

from ember_armor.ledger.shell import nested
from ember_armor.ledger.shell.core import (
    Dynamic,
    ParseResult,
    Recurse,
    Redirect,
    SimpleCommand,
)

_TOKEN_RE = re.compile(
    r"""
    (?P<space>\s+)
    | (?P<dup>\d?>&\d)
    | (?P<redirect>\d?>>?|<)
    | (?P<op>&&|\|\||[&|()])
    | (?P<word>(?:\^.|"[^"]*"?|[^\s&|()<>"^])+)
    """,
    re.VERBOSE | re.DOTALL,
)
_IF_TESTS = frozenset({"exist", "errorlevel", "defined"})


def _unquote(token: str) -> str:
    return re.sub(r"\^(.)", r"\1", token.replace('"', ""), flags=re.DOTALL)


def _strip_prefixes(argv: list[str]) -> list[str]:
    """Drop ``@``, ``call``, ``else``, ``do`` and ``if ...`` before a command."""
    while argv:
        head = argv[0].lower()
        if head.startswith("@") and len(head) > 1:
            argv = [argv[0][1:], *argv[1:]]
        elif head in ("@", "call", "else", "do"):
            argv = argv[1:]
        elif head == "if":
            rest = [a for a in argv[1:] if a.lower() not in ("/i", "not")]
            argv = rest[2:] if rest and rest[0].lower() in _IF_TESTS else rest[1:]
        else:
            break
    return argv


class _Cmd:
    """Collects the commands of one ``cmd.exe`` line."""

    def __init__(self, depth: int, recurse: Recurse) -> None:
        self.depth = depth
        self.recurse = recurse
        self.out = ParseResult()
        self.argv: list[str] = []
        self.redirects: list[Redirect] = []
        self.in_for_header = False

    def finish(self) -> None:
        """Close the command read so far."""
        argv, redirects = self.argv, tuple(self.redirects)
        self.argv, self.redirects = [], []
        lowered = [arg.lower() for arg in argv]
        if lowered[:1] == ["for"] or self.in_for_header:
            # ``for %i in (set) do command``: only what follows ``do`` runs.
            self.in_for_header = "do" not in lowered
            argv = [] if self.in_for_header else argv[lowered.index("do") + 1 :]
        command = _strip_prefixes(argv)
        if command or redirects:
            self.out.commands.append(SimpleCommand(tuple(command), "cmd", redirects))
        if command and command[0].startswith(("%", "!")):
            self.out.dynamic.append(Dynamic("variable_command", command[0][:200]))
        found = nested.inspect(command)
        if found is not None and found.kind == "script":
            self.out.merge(self.recurse(found.script, found.shell, self.depth + 1))


def parse_cmd(text: str, depth: int, recurse: Recurse) -> ParseResult:
    """Parse a ``cmd.exe`` command line.

    Parameters
    ----------
    text:
        The command line.  It is only read, never executed.
    depth:
        Current nesting depth of literal shells.
    recurse:
        Callback used to parse nested literal shell strings.
    """
    state = _Cmd(depth, recurse)
    pending: str | None = None
    for match in _TOKEN_RE.finditer(text):
        kind = match.lastgroup
        if kind == "word":
            word = _unquote(match.group())
            if pending is None:
                state.argv.append(word)
            elif word.lower() != "nul":
                state.redirects.append(Redirect(pending, word))
            pending = None
        elif kind == "redirect":
            pending = "read" if match.group() == "<" else "write"
        elif kind == "op":
            state.finish()
    state.finish()
    return state.out
