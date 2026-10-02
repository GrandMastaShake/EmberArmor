"""PowerShell command-string parser.

Turns a PowerShell script string into simple commands without running
anything.  It understands statement separators, pipelines, both quote styles,
here-strings, backtick escapes, parameters (``-Name value``; ``-Name:value``
stays one argument), comma lists, the call operators, subexpressions and script
blocks (parsed recursively), redirections and nested literal shells.  The
removal and reading aliases are mapped to their cmdlets.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field, replace

from ember_armor.ledger.shell import nested, wrappers
from ember_armor.ledger.shell.core import (
    DECODERS,
    DOWNLOADERS,
    MAX_COMMANDS,
    MAX_DEPTH,
    SELECTORS,
    Dynamic,
    ParseError,
    ParseResult,
    Recurse,
    Redirect,
    SimpleCommand,
    program_name,
)

ALIASES = {
    "rm": "Remove-Item",
    "del": "Remove-Item",
    "erase": "Remove-Item",
    "rd": "Remove-Item",
    "rmdir": "Remove-Item",
    "ri": "Remove-Item",
    "cat": "Get-Content",
    "type": "Get-Content",
    "gc": "Get-Content",
    "iex": "Invoke-Expression",
    "iwr": "Invoke-WebRequest",
    "irm": "Invoke-RestMethod",
    "cp": "Copy-Item",
    "copy": "Copy-Item",
    "cpi": "Copy-Item",
    "mv": "Move-Item",
    "move": "Move-Item",
    "mi": "Move-Item",
    "cd": "Set-Location",
    "chdir": "Set-Location",
    "sl": "Set-Location",
    "pushd": "Push-Location",
    "ni": "New-Item",
    "ac": "Add-Content",
    "sls": "Select-String",
    "tee": "Tee-Object",
    "popd": "Pop-Location",
    "gci": "Get-ChildItem",
    "ls": "Get-ChildItem",
    "dir": "Get-ChildItem",
    "%": "ForEach-Object",
    "foreach": "ForEach-Object",
    "?": "Where-Object",
    "where": "Where-Object",
    "select": "Select-Object",
    "sort": "Sort-Object",
    "start": "Start-Process",
    "saps": "Start-Process",
    "icm": "Invoke-Command",
    "sc": "Set-Content",
    "si": "Set-Item",
    "sp": "Set-ItemProperty",
    "rp": "Remove-ItemProperty",
    "clc": "Clear-Content",
    "cli": "Clear-Item",
    "rni": "Rename-Item",
    "ren": "Rename-Item",
}
_KEYWORDS = frozenset(
    {"if", "elseif", "else", "foreach", "for", "while", "do", "until", "switch",
     "try", "catch", "finally", "function", "filter", "param", "begin", "process",
     "end", "return", "throw", "break", "continue", "exit", "trap", "class", "enum",
     "using", "in", "data", "dynamicparam", "workflow"}
)  # fmt: skip
_BARE_END = frozenset(" \t\r\n;|)},>")
_TAIL_END = frozenset(" \t\r\n;|)},")
_REDIRECT_RE = re.compile(r"[1-6*]?>>?(&[1-6])?")
_VAR_RE = re.compile(r"\$(\{[^}]*\}|[\w:?^$]+)")
_PLAIN_VAR_RE = re.compile(r"\$(\{[\w:]+\}|[\w:]+)")
_ASSIGN_RE = re.compile(r"(?:[-+*/%]|\?\?)?=(?!=)")
_NUMBER_RE = re.compile(r"\d+(?:\.\d+)?(?:[kmgtp]b)?(?:\.\.\S+)?", re.IGNORECASE)
_DOWNLOAD_RE = re.compile(
    r"downloadstring|downloadfile|downloaddata|net\.webclient|"
    r"invoke-webrequest|invoke-restmethod|\b(?:iwr|irm|curl|wget)\b",
    re.IGNORECASE,
)
_DECODE_RE = re.compile(r"frombase64string", re.IGNORECASE)
_CLOSERS = {"(": ")", "[": "]", "{": "}"}
_DASHES = "\u2013\u2014\u2015"
_MODULE_RE = re.compile(r"[\w.]+\\([A-Za-z]+-[A-Za-z]+)")
_SET_ENV_RE = re.compile(r"SetEnvironmentVariable\(\s*['\"](\w+)['\"]", re.IGNORECASE)
_CMDLET_RE = re.compile(r"[A-Za-z]+-[A-Za-z]+")
_ARGUMENT_RE = re.compile(r"""(?:"[^"]*"?|[^\s"])+""")
#: Statement keywords that are followed by a pipeline, not by a block.
_LEADERS = frozenset({"return", "throw", "exit"})
_SHELL_HOSTS = frozenset({"powershell", "pwsh", "cmd", "bash", "sh", "wsl"})
#: Start-Process parameters; the ones in the second tuple take a value.
_START_SWITCHES = ("wait", "passthru", "nonewwindow", "loaduserprofile",
                   "usenewenvironment")  # fmt: skip
_START_VALUES = ("filepath", "argumentlist", "args", "credential",
                 "workingdirectory", "redirectstandarderror",
                 "redirectstandardinput", "redirectstandardoutput", "windowstyle",
                 "verb", "environment")  # fmt: skip


@dataclass
class _Word:
    """One PowerShell token: ``kind`` is bare, string, var, group, block, expr or call.

    ``literal`` is false when the text contains an expansion; ``spans`` are
    index ranges of commands parsed out of nested groups and blocks.
    """

    text: str
    kind: str = "bare"
    literal: bool = True
    spans: list[tuple[int, int]] = field(default_factory=list)


@dataclass(frozen=True)
class _Stage:
    """One pipeline element.

    ``index`` is its position in the command list (``-1`` for an
    expression) and ``blocks`` the command ranges of its script blocks.
    """

    program: str
    piped_script: bool
    raw: str
    index: int = -1
    blocks: tuple[tuple[int, int], ...] = ()


def _variable_key(reference: str) -> str:
    """Key of ``$name``, ``${name}`` or ``$scope:name`` in the parse result.

    Lower-cased, without the scope.  An environment variable keeps its
    drive: ``$env:TEMP`` is ``env:temp``.
    """
    name = reference.lstrip("$").strip("{}").lower()
    return name if name.startswith("env:") else name.rsplit(":", 1)[-1]


def _entry_value(words: list[_Word]) -> list[_Word]:
    """The value of a hashtable entry ``key = value``, which is a statement."""
    if words and words[0].kind == "bare" and "=" in words[0].text:
        rest = words[0].text.partition("=")[2]
        return ([_Word(rest)] if rest else []) + words[1:]
    if len(words) > 1 and words[1].kind == "bare" and words[1].text.startswith("="):
        rest = words[1].text[1:]
        return ([_Word(rest)] if rest else []) + words[2:]
    return words


def _after_param(words: list[_Word]) -> list[_Word]:
    """What follows a ``param(...)`` block on the same line, if there is one.

    ``& { param($x) command $x }`` is valid, also with attributes in front.
    """
    at = 0
    while at < len(words) and words[at].kind == "expr" and words[at].text[:1] == "[":
        if "]param(" in words[at].text.lower():
            return words[at + 1 :]
        at += 1
    if at < len(words) and words[at].kind == "bare":
        head = words[at].text.lower()
        if head.startswith("param("):
            return words[at + 1 :]
        if head == "param" and [w.kind for w in words[at + 1 : at + 2]] == ["group"]:
            return words[at + 2 :]
    return words


def _join_path(texts: Sequence[str]) -> str | None:
    """Path a literal ``Join-Path a b`` evaluates to, or ``None``."""
    if len(texts) < 3 or texts[0].lower() != "join-path":
        return None
    parts: list[str] = []
    for text in texts[1:]:
        named = text.lower()
        if len(named) > 1 and named[0] == "-":
            if not any(p.startswith(named) for p in ("-path", "-childpath")):
                return None
        else:
            parts.append(text.rstrip("/\\"))
    return "/".join(parts) if len(parts) >= 2 else None


class _PowerShell:
    """Single-pass lexer and parser over one PowerShell string."""

    def __init__(self, text: str, depth: int, recurse: Recurse, out: ParseResult):
        if depth > MAX_DEPTH:
            raise ParseError("shell nesting too deep")
        self.s = text
        self.n = len(text)
        self.i = 0
        self.depth = depth
        self.recurse = recurse
        self.out = out

    # -- lexer --------------------------------------------------------------
    def _skip_space(self) -> None:
        s, n = self.s, self.n
        while self.i < n:
            char = s[self.i]
            if char in " \t\r,":
                self.i += 1
            elif s.startswith(("`\n", "`\r\n"), self.i):
                self.i = s.index("\n", self.i) + 1
            elif s.startswith("<#", self.i):
                end = s.find("#>", self.i)
                self.i = n if end < 0 else end + 2
            elif char == "#":
                end = s.find("\n", self.i)
                self.i = n if end < 0 else end
            else:
                return

    def _token(self) -> tuple[str, str | bool | _Word]:
        self._skip_space()
        s = self.s
        if self.i >= self.n:
            return "eof", ""
        char = s[self.i]
        if char in "\n;)}":
            self.i += 1
            return "op", char
        if char == "|":
            op = "||" if s.startswith("||", self.i) else "|"
            self.i += len(op)
            return "op", op
        if char == "&":
            if s.startswith("&&", self.i):
                self.i += 2
                return "op", "&&"
            self.i += 1
            return "word", _Word("&", "call")
        if match := _REDIRECT_RE.match(s, self.i):
            self.i = match.end()
            return "redirect", match.group(1) is None
        return "word", self._word()

    def _nested(self, closer: str, *, table: bool = False) -> tuple[int, int]:
        low = len(self.out.commands)
        self._list(closer, table=table)
        return low, len(self.out.commands)

    def _piece(self) -> None:
        """Step over one character, string or bracketed part of an expression.

        Whatever stands in ``( )``, ``{ }``, ``@{ }`` or ``[ ]`` is parsed,
        never skipped: ``[void](cmd)``, ``$list.Add((cmd))`` and
        ``@{ a = (cmd) }`` all run ``cmd``.
        """
        s, char = self.s, self.s[self.i]
        if char == "`":
            self.i += 2
        elif char == "'":
            self._single()
        elif char == '"':
            self._double(_Word(""))
        elif s.startswith("@{", self.i):
            self.i += 2
            self._nested("}", table=True)
        elif s.startswith(("$(", "@("), self.i):
            self.i += 2
            self._nested(")")
        elif char in "({":
            self.i += 1
            self._nested(_CLOSERS[char])
        elif char == "[":
            self._index()
        else:
            self.i += 1

    def _index(self) -> None:
        """Step over a ``[...]`` type or index, parsing the groups inside it."""
        self.i += 1
        while self.i < self.n:
            if self.s[self.i] == "]":
                self.i += 1
                return
            self._piece()
        raise ParseError("unterminated [")

    def _single(self) -> str:
        """Read a single-quoted string starting at the opening quote."""
        s, i = self.s, self.i + 1
        parts: list[str] = []
        while True:
            end = s.find("'", i)
            if end < 0:
                raise ParseError("unterminated single quote")
            parts.append(s[i:end])
            if not s.startswith("''", end):
                self.i = end + 1
                return "".join(parts)
            parts.append("'")
            i = end + 2

    def _double(self, word: _Word) -> str:
        """Read a double-quoted string; record expansions on *word*."""
        s, n = self.s, self.n
        self.i += 1
        parts: list[str] = []
        while self.i < n:
            char = s[self.i]
            if char == '"':
                if not s.startswith('""', self.i):
                    self.i += 1
                    return "".join(parts)
                parts.append('"')
                self.i += 2
            elif char == "`":
                parts.append(s[self.i + 1 : self.i + 2])
                self.i += 2
            elif char == "$" and self._expansion(word, parts):
                continue
            else:
                parts.append(char)
                self.i += 1
        raise ParseError("unterminated double quote")

    def _expansion(self, word: _Word, parts: list[str]) -> bool:
        """Consume ``$(...)`` or ``$name`` at the cursor; False if a plain ``$``."""
        s, start = self.s, self.i
        if s.startswith("$(", start):
            self.i = start + 2
            span = self._nested(")")
            inner = s[start + 2 : self.i - 1].strip()
            if span[0] == span[1] and _PLAIN_VAR_RE.fullmatch(inner):
                # ``"$($env:USERPROFILE)"`` is the variable itself.
                parts.append(inner)
                word.literal = False
                return True
            word.spans.append(span)
        elif match := _VAR_RE.match(s, start):
            self.i = match.end()
        else:
            return False
        parts.append(s[start : self.i])
        word.literal = False
        return True

    def _here_string(self) -> _Word:
        s, quote = self.s, self.s[self.i + 1]
        start = s.find("\n", self.i)
        end = s.find(f"\n{quote}@", self.i)
        if start < 0 or end < 0:
            raise ParseError("unterminated here-string")
        text = s[start + 1 : end]
        word = _Word(text, "string", literal=quote == "'" or "$" not in text)
        limit = self.n
        self.i, self.n = start + 1, end
        try:
            # An expanding here-string runs its subexpressions.
            while quote == '"' and (at := s.find("$(", self.i, end)) >= 0:
                self.i = at + 2
                if s[at - 1] != "`":
                    word.spans.append(self._nested(")"))
        finally:
            self.n = limit
        self.i = end + 3
        return word

    def _tail(self) -> None:
        """Step over member access, indexing and call syntax after an expression.

        Stops in front of ``=`` so that ``[string]$x=...`` is an assignment.
        """
        s = self.s
        while self.i < self.n and s[self.i] not in _TAIL_END and s[self.i] != "=":
            self._piece()

    def _word(self) -> _Word:
        s, start = self.s, self.i
        char = s[start]
        if char in "'\"" or s.startswith(("@'", '@"'), start):
            return self._string()
        if s.startswith(("@(", "$("), start) or char == "(":
            self.i = start + (1 if char == "(" else 2)
            span = self._nested(")")
            joined = self._joined(span) if char == "(" else None
            if joined is not None:
                return _Word(joined, literal="$" not in joined)
            self._tail()
            return _Word(s[start : self.i], "group", False, [span])
        if char == "{":
            self.i = start + 1
            span = self._nested("}")
            return _Word(s[start : self.i], "block", False, [span])
        if s.startswith("@{", start):
            self.i = start + 2
            span = self._nested("}", table=True)
            self._tail()
            return _Word(s[start : self.i], "expr", False, [span])
        if char == "[":
            self._index()
            self._tail()
            return _Word(s[start : self.i], "expr", False)
        if char == "$" and (match := _VAR_RE.match(s, start)):
            self.i = match.end()
            self._tail()
            return _Word(s[start : self.i], "var", False)
        return self._bare()

    def _joined(self, span: tuple[int, int]) -> str | None:
        """Value of a ``(Join-Path a b)`` group that is used as it stands."""
        made = self.out.commands[span[0] : span[1]]
        if len(made) != 1 or self.s[self.i : self.i + 1] not in _TAIL_END | {""}:
            return None
        return _join_path(made[0].argv)

    def _string(self) -> _Word:
        if self.s[self.i] == "@":
            return self._here_string()
        if self.s[self.i] == "'":
            return _Word(self._single(), "string")
        word = _Word("", "string")
        word.text = self._double(word)
        return word

    def _bare(self) -> _Word:
        s, n = self.s, self.n
        word = _Word("")
        parts: list[str] = []
        if operator := _ASSIGN_RE.match(s, self.i):
            # ``$a=$b=command``: the operator is a word of its own.
            self.i = operator.end()
            return _Word(operator.group())
        if s[self.i] in _DASHES:
            # PowerShell reads an en dash or em dash as the parameter hyphen.
            parts.append("-")
            self.i += 1
        while self.i < n:
            char = s[self.i]
            if char in _BARE_END or char == "{" or s.startswith("&&", self.i):
                break
            if char == "`":
                if s.startswith(("`\n", "`\r\n"), self.i):
                    break
                parts.append(s[self.i + 1 : self.i + 2])
                self.i += 2
            elif char == "'":
                parts.append(self._single())
            elif char == '"':
                parts.append(self._double(word))
            elif char == "$" and self._expansion(word, parts):
                continue
            elif char == "(":
                begin = self.i
                self.i += 1
                word.spans.append(self._nested(")"))
                parts.append(s[begin : self.i])
            else:
                parts.append(char)
                self.i += 1
        word.text = "".join(parts)
        return word

    # -- parser -------------------------------------------------------------
    def run(self) -> None:
        """Parse the whole string, appending findings to the shared result."""
        self._list(None)

    def _list(self, closer: str | None, *, table: bool = False) -> None:
        """Parse statements up to *closer*; *table* reads ``key = value`` entries."""
        words: list[_Word] = []
        redirects: list[Redirect] = []
        stages: list[_Stage] = []

        def finish() -> None:
            body = _entry_value(words) if table else words
            self._end_statement(body, redirects, stages)

        while True:
            kind, value = self._token()
            if kind == "eof" or value in (")", "}"):
                if value != (closer or ""):
                    raise ParseError("unbalanced bracket")
                finish()
                self._end_pipeline(stages)
                return
            if isinstance(value, _Word):
                if value.kind == "call" and words:
                    # ``a & b``: the first command ends, ``&`` starts the next.
                    finish()
                    self._end_pipeline(stages)
                    words, redirects, stages = [], [], []
                words.append(value)
            elif kind == "redirect":
                self._redirect(bool(value), redirects)
            elif value == "\n" and not words and stages:
                continue
            else:
                finish()
                words, redirects = [], []
                if value != "|":
                    self._end_pipeline(stages)
                    stages = []

    def _redirect(self, has_target: bool, redirects: list[Redirect]) -> None:
        if not has_target:
            return
        kind, target = self._token()
        if not isinstance(target, _Word):
            raise ParseError(f"redirection without a target ({kind})")
        if target.text.lower() != "$null":
            redirects.append(Redirect("write", target.text))

    def _spans_download(self, words: list[_Word]) -> bool:
        commands = self.out.commands
        return any(
            command.argv and program_name(command.argv[0]) in DOWNLOADERS
            for word in words
            for low, high in word.spans
            for command in commands[low:high]
        )

    def _add(self, command: SimpleCommand) -> int:
        """Append a command and return its index."""
        if len(self.out.commands) >= MAX_COMMANDS:
            raise ParseError("too many commands")
        self.out.commands.append(command)
        return len(self.out.commands) - 1

    @staticmethod
    def _value(words: list[_Word]) -> str | None:
        """Text an assignment gives its variable (``None``: unknown).

        A string, a plain variable or ``Join-Path`` over those; references
        to other variables stay in the text as written.
        """
        kinds = ("bare", "string", "var")
        if any(word.spans or word.kind not in kinds for word in words):
            return None
        if any(w.kind == "var" and not _PLAIN_VAR_RE.fullmatch(w.text) for w in words):
            return None
        if len(words) == 1 and words[0].kind != "bare":
            return words[0].text
        return _join_path([word.text for word in words])

    def _assignment(self, words: list[_Word]) -> list[_Word]:
        """Drop a leading ``$name =`` and remember what it was given.

        Also ``[type]$name = ...`` and ``$a, $b = ...``; what follows the
        ``=`` is a statement of its own.
        """
        at, match = -1, None
        for index, word in enumerate(words):
            if word.kind == "bare":
                at, match = index, _ASSIGN_RE.match(word.text)
                break
            if word.kind not in ("var", "expr"):
                break
        if at < 1 or match is None:
            return words
        value = words[at + 1 :]
        targets = words[:at]
        if len(targets) == 1 and _PLAIN_VAR_RE.fullmatch(targets[0].text):
            compound = match.group() != "="
            key = _variable_key(targets[0].text)
            self.out.assign(key, None if compound else self._value(value))
            if key.startswith("env:"):
                self.out.assigned.append(key[4:].upper())
            return value
        for target in targets:
            for reference in _VAR_RE.finditer(target.text):
                self.out.forget(_variable_key(reference.group()))
        return value

    def _bind_loop(self, words: list[_Word]) -> list[_Word]:
        """Record the variable of ``foreach ($name in 'a', 'b')``.

        Returns what the loop runs over, which may be a command.
        """
        heads = [(word.kind, word.text.lower()) for word in words[:2]]
        if len(words) < 3 or heads[0][0] != "var" or heads[1] != ("bare", "in"):
            return words
        items = words[2:]
        literal = all(item.kind == "string" and item.literal for item in items)
        value = tuple(item.text for item in items) if literal else None
        self.out.assign(_variable_key(words[0].text), value)
        return items

    def _known(self, word: _Word) -> str | None:
        """Literal text a plain ``$name`` was assigned earlier, if any."""
        if word.kind != "var" or not _PLAIN_VAR_RE.fullmatch(word.text):
            return None
        known = self.out.variables.get(_variable_key(word.text))
        return None if known is None or "$" in known else known

    def _expression(
        self, redirects: list[Redirect], stages: list[_Stage], raw: str
    ) -> None:
        """Record a pipeline element that is an expression, not a command."""
        if redirects:
            self._add(SimpleCommand((), "powershell", tuple(redirects)))
        stages.append(_Stage("", False, raw))

    def _end_statement(
        self, words: list[_Word], redirects: list[Redirect], stages: list[_Stage]
    ) -> None:
        """Finish one pipeline element and add it to *stages*."""
        raw = " ".join(word.text for word in words)
        self.out.assigned += (name.upper() for name in _SET_ENV_RE.findall(raw))
        words = _after_param(self._bind_loop(words))
        while True:
            # ``$a = $b = command`` and ``return $a = command``.
            rest = self._assignment(words)
            if rest and rest[0].kind == "bare" and rest[0].text.lower() in _LEADERS:
                rest = rest[1:]
            if len(rest) == len(words):
                break
            words = rest
        called = bool(words) and (
            words[0].kind == "call" or (words[0].kind, words[0].text) == ("bare", ".")
        )
        if called:
            words = words[1:]
        if not words:
            if redirects:
                self._add(SimpleCommand((), "powershell", tuple(redirects)))
            return
        first = words[0]
        known = self._known(first) if called else None
        if known is not None:
            # ``$exe = 'C:\tool.exe'; & $exe run`` reads as the command it is.
            first = _Word(known, "string")
            words = [first, *words[1:]]
        if first.kind in ("var", "group", "expr") and called:
            self.out.dynamic.append(Dynamic("variable_command", first.text[:200]))
        expression = first.kind in ("var", "group", "expr", "block") or (
            first.kind == "string" and not called
        )
        name = first.text
        if expression or not name or name[0] in "-!" or _NUMBER_RE.fullmatch(name):
            self._expression(redirects, stages, raw)
            return
        keyword = first.kind == "bare" and name.lower() in _KEYWORDS and not called
        if keyword and not (stages and name.lower() == "foreach"):
            self._expression(redirects, stages, raw)
            return
        found = wrappers.unwrap(
            [word.text for word in words],
            [word.kind in ("bare", "string") and word.literal for word in words],
        )
        if found.capped:
            self.out.dynamic.append(Dynamic("parse_error", "too many wrappers"))
        if found.start:
            words = words[found.start :]
            first = replace(words[0], text=found.program or words[0].text)
            words = [first, *words[1:]]
            name = first.text
            if first.kind not in ("bare", "string"):
                self.out.dynamic.append(Dynamic("variable_command", name[:200]))
                self._expression(redirects, stages, raw)
                return
            if "wsl" in found.names:
                # What ``wsl`` runs is a Linux command line.
                line = nested.join_arguments([word.text for word in words], "'")
                self.out.merge(self.recurse(line, "bash", self.depth + 1))
                self._expression(redirects, stages, raw)
                return
        if not first.literal and "$" in name.replace("\\", "/").rsplit("/", 1)[-1]:
            self.out.dynamic.append(Dynamic("variable_command", name[:200]))
        qualified = _MODULE_RE.fullmatch(name)
        if qualified is not None:
            # ``Microsoft.PowerShell.Management\Remove-Item`` is ``Remove-Item``.
            name = qualified.group(1)
        program = ALIASES.get(name.lower(), name)
        cmdlet = _CMDLET_RE.fullmatch(program) is not None
        for index, word in enumerate(words[1:], start=1):
            value = self._known(word)
            # A cmdlet never takes a parameter name from a variable.
            if value is not None and not (cmdlet and value.startswith("-")):
                words[index] = _Word(value, "string")
        argv = (program, *(word.text for word in words[1:]))
        index = self._add(SimpleCommand(argv, "powershell", tuple(redirects)))
        blocks = tuple(span for w in words if w.kind == "block" for span in w.spans)
        if program.lower() == "start-process":
            self._start_process(words)
        piped = self._descend(words, argv, raw)
        stages.append(_Stage(program_name(program), piped, raw, index, blocks))

    def _start_process(self, words: list[_Word]) -> None:
        """Parse the command line a ``Start-Process`` launches, when literal."""
        named: dict[str, list[_Word]] = {}
        loose: list[_Word] = []
        i = 1
        while i < len(words):
            word = words[i]
            option = word.text.lower().lstrip("-") if word.kind == "bare" else ""
            if not option or not word.text.startswith("-"):
                loose.append(word)
                i += 1
                continue
            i += 1
            param = next((p for p in _START_VALUES if p.startswith(option)), None)
            if param is None or any(p.startswith(option) for p in _START_SWITCHES):
                continue
            values = named.setdefault(param, [])
            while i < len(words) and not (
                words[i].kind == "bare" and words[i].text.startswith("-")
            ):
                values.append(words[i])
                i += 1
        target = (named.get("filepath") or loose[:1])[:1]
        arguments = named.get("argumentlist") or named.get("args") or loose[1:]
        if not target:
            return
        program = target[0]
        if program.kind not in ("bare", "string") or not program.literal:
            self.out.dynamic.append(Dynamic("variable_command", program.text[:200]))
            return
        opaque = any(a.kind in ("var", "group", "expr", "block") for a in arguments)
        if opaque and program_name(program.text) in _SHELL_HOSTS:
            self.out.dynamic.append(Dynamic("nested_dynamic", program.text[:200]))
            return
        # The program splits the joined argument list itself, on blanks and
        # double quotes.
        line = " ".join(argument.text for argument in arguments)
        pieces = (piece.replace('"', "") for piece in _ARGUMENT_RE.findall(line))
        argv = (program.text, *pieces)
        self._add(SimpleCommand(argv, "cmd"))
        script = nested.inspect(argv)
        if script is not None and script.kind == "script":
            self.out.merge(self.recurse(script.script, script.shell, self.depth + 1))

    def _descend(self, words: list[_Word], argv: tuple[str, ...], raw: str) -> bool:
        """Handle Invoke-Expression and nested shells; True if fed by a pipe."""
        program = program_name(argv[0])
        rest = words[1:]
        if program == "invoke-expression":
            if not rest:
                return True
            pattern = _DOWNLOAD_RE.search(raw) is not None
            fetched = pattern or self._spans_download(rest)
            self.out.dynamic.append(
                Dynamic("download_pipe" if fetched else "eval", raw[:200])
            )
            if len(rest) == 1 and rest[0].kind == "string":
                # With variables in it the string is read as written.
                self.out.merge(self.recurse(rest[0].text, "powershell", self.depth + 1))
            return False
        found = nested.inspect(argv)
        if found is None:
            return False
        if found.kind == "encoded":
            self.out.dynamic.append(Dynamic("encoded_command", program))
        if found.kind == "script":
            script_words = words[found.index :]
            if any(w.kind in ("var", "group", "expr") for w in script_words):
                fetched = self._spans_download(script_words)
                kind = "download_pipe" if fetched else "nested_dynamic"
                self.out.dynamic.append(Dynamic(kind, program))
            elif not (script_words and all(w.kind == "block" for w in script_words)):
                self.out.merge(self.recurse(found.script, found.shell, self.depth + 1))
        return found.kind == "stdin"

    def _end_pipeline(self, stages: list[_Stage]) -> None:
        """Mark shells fed by a pipe and tell each command what feeds it."""
        commands = self.out.commands
        download = decoder = False
        feed: tuple[str, ...] = ()
        for position, stage in enumerate(stages):
            if position and stage.piped_script:
                kind = "pipe_to_shell"
                if download:
                    kind = "download_pipe"
                elif decoder:
                    kind = "decoder_pipe"
                self.out.dynamic.append(Dynamic(kind, stage.program))
            fed = [stage.index] if stage.index >= 0 else []
            if stage.program == "foreach-object":
                fed += [i for low, high in stage.blocks for i in range(low, high)]
            for index in fed if feed else ():
                commands[index] = replace(commands[index], upstream=feed)
            name, raw = stage.program, stage.raw
            download = download or name in DOWNLOADERS or bool(_DOWNLOAD_RE.search(raw))
            decoder = decoder or name in DECODERS or bool(_DECODE_RE.search(raw))
            if name not in SELECTORS:
                feed = commands[stage.index].argv if stage.index >= 0 else ()


def parse_powershell(text: str, depth: int, recurse: Recurse) -> ParseResult:
    """Parse a PowerShell command string.

    Parameters
    ----------
    text:
        The script string.  It is only read, never executed.
    depth:
        Current nesting depth of literal shells.
    recurse:
        Callback used to parse nested literal shell strings.

    Returns
    -------
    ParseResult
        Simple commands (aliases mapped to cmdlets), dynamic-shell reasons
        and literal variable assignments.  A parse failure yields a
        ``parse_error`` reason.
    """
    out = ParseResult()
    try:
        _PowerShell(text, depth, recurse, out).run()
    except (ParseError, RecursionError) as exc:
        out.dynamic.append(Dynamic("parse_error", str(exc) or type(exc).__name__))
    return out
