"""Minimal ``cmd.exe`` command-line parser for ``cmd /c "..."`` strings.

Covers what an agent realistically passes to ``cmd /c``: commands joined by
``&``, ``&&``, ``||``, ``|`` and newlines, double quotes, ``^`` escapes,
parentheses, redirections, and the ``if``/``else``/``for``/``call``
prefixes.  Nothing is executed.
"""

from __future__ import annotations

import re

from ember_armor.ledger.shell import nested
from ember_armor.ledger.shell.core import (
    Dynamic,
    Guards,
    ParseResult,
    Recurse,
    Redirect,
    SimpleCommand,
)

_TOKEN_RE = re.compile(
    r"""
    (?P<space>(?:[^\S\n]|\^\r?\n)+)
    | (?P<line>\n)
    | (?P<dup>\d?>&\d)
    | (?P<redirect>\d?>>?|<)
    | (?P<op>&&|\|\||[&|()])
    | (?P<word>(?:\^[^\r\n]|"[^"\n]*"?|[^\s&|()<>"^])+)
    | (?P<stray>\^)
    """,
    re.VERBOSE | re.DOTALL,
)
_IF_TESTS = frozenset({"exist", "errorlevel", "defined"})
#: ``cd..``, ``cd\`` and ``cd/d dir``: cmd.exe needs no blank after ``cd``.
_GLUED_CD_RE = re.compile(r"(cd|chdir)([.\\/].*)", re.IGNORECASE | re.DOTALL)


def _unquote(token: str) -> str:
    return re.sub(r"\^(.)", r"\1", token.replace('"', ""), flags=re.DOTALL)


def _strip_prefixes(argv: list[str]) -> tuple[list[str], bool]:
    """Drop ``@``, ``call``, ``else``, ``do`` and ``if ...`` before a command.

    Also says whether the command depends on a condition (``if``, ``else``).
    """
    conditional = False
    while argv:
        head = argv[0].lower()
        if head.startswith("@") and len(head) > 1:
            argv = [argv[0][1:], *argv[1:]]
        elif head in ("@", "call", "else", "do"):
            conditional = conditional or head == "else"
            argv = argv[1:]
        elif head == "if":
            conditional = True
            rest = [a for a in argv[1:] if a.lower() not in ("/i", "not")]
            argv = rest[2:] if rest and rest[0].lower() in _IF_TESTS else rest[1:]
        else:
            break
    return argv, conditional


class _Cmd:
    """Collects the commands of one ``cmd.exe`` line.

    ``ahead`` says how the next command or parenthesised block runs when an
    ``if``, ``else`` or ``for ... do`` came before it without a command of
    its own (``maybe`` or ``loop``).
    """

    def __init__(self, depth: int, recurse: Recurse) -> None:
        self.depth = depth
        self.recurse = recurse
        self.out = ParseResult()
        self.guards = Guards(self.out)
        self.argv: list[str] = []
        self.redirects: list[Redirect] = []
        self.in_for_header = False
        self.for_output = False
        self.ahead = ""

    def finish(self) -> None:
        """Close the command read so far."""
        argv, redirects = self.argv, tuple(self.redirects)
        self.argv, self.redirects = [], []
        lowered = [arg.lower() for arg in argv]
        loop = False
        if lowered[:1] == ["for"] or self.in_for_header:
            # ``for %i in (set) do command``: what follows ``do`` runs, and so
            # does a quoted command in the set of ``for /f``.
            if lowered[:1] == ["for"]:
                self.for_output = "/f" in lowered
            elif self.for_output and argv and argv[0][:1] in ("'", "`"):
                script = " ".join(argv).strip("'`")
                self.out.merge(self.recurse(script, "cmd", self.depth + 1))
            self.in_for_header = "do" not in lowered
            loop = not self.in_for_header
            argv = [] if self.in_for_header else argv[lowered.index("do") + 1 :]
        command, conditional = _strip_prefixes(argv)
        kind = "loop" if loop else "maybe" if conditional else ""
        if not (command or redirects):
            self.ahead = kind or self.ahead
            return
        kind = kind or self.ahead
        self.ahead = ""
        if kind:
            # ``if exist dir cd dir & git status``: all of the rest depends
            # on the condition.
            self.guards.tail(kind)
        if command and (glued := _GLUED_CD_RE.fullmatch(command[0])):
            command = [glued.group(1), glued.group(2), *command[1:]]
        self.out.commands.append(SimpleCommand(tuple(command), "cmd", redirects))
        if command and command[0].startswith(("%", "!")):
            self.out.dynamic.append(Dynamic("variable_command", command[0][:200]))
        found = nested.inspect(command)
        if found is not None and found.kind == "script":
            inner = self.recurse(found.script, found.shell, self.depth + 1)
            chdir = (found.chdir,) if found.chdir else ()
            self.out.merge(inner, chdir, starter="cmd")

    def operator(self, op: str) -> None:
        """Close the command in front of *op* and note what *op* joins."""
        self.finish()
        if op in ("&&", "||"):
            self.guards.link(op)
        elif op == "(":
            # The block after ``if`` or ``do`` runs as that says.
            self.guards.enter("(", self.ahead)
            self.ahead = ""
        elif op == ")":
            self.guards.leave("(")
        elif op != "|":
            self.guards.end()


def parse_cmd(text: str, depth: int, recurse: Recurse) -> ParseResult:
    """Parse a ``cmd.exe`` command line, or the lines of a batch script.

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
            state.operator(match.group())
        elif kind == "line":
            # A new line starts a new command, as ``&`` does.
            state.operator("&")
            pending = None
    state.finish()
    state.guards.finish()
    return state.out
