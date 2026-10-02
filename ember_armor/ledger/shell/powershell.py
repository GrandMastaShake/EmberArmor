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
from dataclasses import dataclass, field

from ember_armor.ledger.shell import nested
from ember_armor.ledger.shell.core import (
    DOWNLOADERS,
    MAX_DEPTH,
    Dynamic,
    ParseError,
    ParseResult,
    Recurse,
    Redirect,
    SimpleCommand,
    pipe_kind,
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
_ASSIGN_RE = re.compile(r"(?:[-+*/%]|\?\?)?=(?!=)")
_NUMBER_RE = re.compile(r"\d+(?:\.\d+)?(?:[kmgtp]b)?(?:\.\.\S+)?", re.IGNORECASE)
_DOWNLOAD_RE = re.compile(
    r"downloadstring|downloadfile|downloaddata|net\.webclient|"
    r"invoke-webrequest|invoke-restmethod|\b(?:iwr|irm|curl|wget)\b",
    re.IGNORECASE,
)
_DECODE_RE = re.compile(r"frombase64string", re.IGNORECASE)


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


_Stage = tuple[str, bool, str]


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

    def _nested(self, closer: str) -> tuple[int, int]:
        low = len(self.out.commands)
        self._list(closer)
        return low, len(self.out.commands)

    def _balanced(self, start: int, opener: str, closer: str) -> int:
        """Index just past the bracket closing the one at *start*, quote-aware."""
        s, depth, i = self.s, 0, start
        while i < self.n:
            char = s[i]
            if char == "`":
                i += 1
            elif char in "'\"":
                end = s.find(char, i + 1)
                if end < 0:
                    raise ParseError("unterminated quote")
                i = end
            elif char == opener:
                depth += 1
            elif char == closer:
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
        raise ParseError(f"unterminated {opener}")

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
            word.spans.append(self._nested(")"))
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
        self.i = end + 3
        text = s[start + 1 : end]
        return _Word(text, "string", literal=quote == "'" or "$" not in text)

    def _tail(self, stop_at_equals: bool) -> None:
        """Skip member access, indexing and call syntax after an expression."""
        s = self.s
        while self.i < self.n:
            char = s[self.i]
            if char in _TAIL_END or (char == "=" and stop_at_equals):
                return
            if char == "(":
                self.i = self._balanced(self.i, "(", ")")
            elif char == "[":
                self.i = self._balanced(self.i, "[", "]")
            else:
                self.i += 1

    def _word(self) -> _Word:
        s, start = self.s, self.i
        char = s[start]
        if char in "'\"" or s.startswith(("@'", '@"'), start):
            return self._string()
        if s.startswith(("@(", "$("), start) or char == "(":
            self.i = start + (1 if char == "(" else 2)
            span = self._nested(")")
            self._tail(False)
            return _Word(s[start : self.i], "group", False, [span])
        if char == "{":
            self.i = start + 1
            span = self._nested("}")
            return _Word(s[start : self.i], "block", False, [span])
        if s.startswith("@{", start) or char == "[":
            closer = "}" if char == "@" else "]"
            self.i = self._balanced(start, "{" if char == "@" else "[", closer)
            self._tail(False)
            return _Word(s[start : self.i], "expr", False)
        if char == "$" and (match := _VAR_RE.match(s, start)):
            self.i = match.end()
            self._tail(True)
            return _Word(s[start : self.i], "var", False)
        return self._bare()

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
        while self.i < n:
            char = s[self.i]
            if char in _BARE_END or s.startswith("&&", self.i):
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
            elif char in "({":
                end = self._balanced(self.i, char, ")" if char == "(" else "}")
                parts.append(s[self.i : end])
                self.i = end
            else:
                parts.append(char)
                self.i += 1
        word.text = "".join(parts)
        return word

    # -- parser -------------------------------------------------------------
    def run(self) -> None:
        """Parse the whole string, appending findings to the shared result."""
        self._list(None)

    def _list(self, closer: str | None) -> None:
        words: list[_Word] = []
        redirects: list[Redirect] = []
        stages: list[_Stage] = []
        while True:
            kind, value = self._token()
            if kind == "eof" or value in (")", "}"):
                if value != (closer or ""):
                    raise ParseError("unbalanced bracket")
                self._end_statement(words, redirects, stages)
                self._end_pipeline(stages)
                return
            if isinstance(value, _Word):
                words.append(value)
            elif kind == "redirect":
                self._redirect(bool(value), redirects)
            elif value == "\n" and not words and stages:
                continue
            else:
                self._end_statement(words, redirects, stages)
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

    def _assignment(self, words: list[_Word]) -> list[_Word]:
        """Drop a leading ``$name =`` and remember a literal string value."""
        if len(words) < 2 or words[0].kind != "var" or words[1].kind != "bare":
            return words
        match = _ASSIGN_RE.match(words[1].text)
        if match is None:
            return words
        attached = words[1].text[match.end() :]
        value = ([_Word(attached)] if attached else []) + words[2:]
        if len(value) == 1 and value[0].kind == "string" and value[0].literal:
            name = words[0].text.lstrip("$").split(":")[-1].strip("{}")
            self.out.variables[name.upper()] = value[0].text
        return value

    def _end_statement(
        self, words: list[_Word], redirects: list[Redirect], stages: list[_Stage]
    ) -> None:
        """Finish one pipeline element and add it to *stages*."""
        raw = " ".join(word.text for word in words)
        words = self._assignment(words)
        called = bool(words) and (
            words[0].kind == "call" or (words[0].kind, words[0].text) == ("bare", ".")
        )
        if called:
            words = words[1:]
        if not words:
            if redirects:
                bare = SimpleCommand((), "powershell", tuple(redirects))
                self.out.commands.append(bare)
            return
        first = words[0]
        if first.kind in ("var", "group", "expr") and called:
            self.out.dynamic.append(Dynamic("variable_command", first.text[:200]))
        expression = first.kind in ("var", "group", "expr", "block") or (
            first.kind == "string" and not called
        )
        name = first.text
        if expression or not name or name[0] in "-!" or _NUMBER_RE.fullmatch(name):
            stages.append(("", False, raw))
            return
        if first.kind == "bare" and name.lower() in _KEYWORDS and not called:
            stages.append(("", False, raw))
            return
        if not first.literal and "$" in name.replace("\\", "/").rsplit("/", 1)[-1]:
            self.out.dynamic.append(Dynamic("variable_command", name[:200]))
        program = ALIASES.get(name.lower(), name)
        argv = (program, *(word.text for word in words[1:]))
        self.out.commands.append(SimpleCommand(argv, "powershell", tuple(redirects)))
        stages.append((program_name(program), self._descend(words, argv, raw), raw))

    def _descend(self, words: list[_Word], argv: tuple[str, ...], raw: str) -> bool:
        """Handle Invoke-Expression and nested shells; True if fed by a pipe."""
        program = program_name(argv[0])
        rest = words[1:]
        if program == "invoke-expression":
            if not rest:
                return True
            fetched = self._spans_download(rest) or _DOWNLOAD_RE.search(raw)
            self.out.dynamic.append(
                Dynamic("download_pipe" if fetched else "eval", raw[:200])
            )
            if len(rest) == 1 and rest[0].kind == "string" and rest[0].literal:
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
        for index, (program, piped_script, _) in enumerate(stages):
            if not (index and piped_script):
                continue
            upstream = " | ".join(raw for _, _, raw in stages[:index])
            if _DOWNLOAD_RE.search(upstream):
                kind = "download_pipe"
            elif _DECODE_RE.search(upstream):
                kind = "decoder_pipe"
            else:
                kind = pipe_kind([name for name, _, _ in stages[:index]])
            self.out.dynamic.append(Dynamic(kind, program))


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
