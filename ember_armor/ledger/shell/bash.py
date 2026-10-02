"""Bash command-string parser.

Turns a command string into simple commands (argument vectors) without
running anything.  It understands separators, pipelines, quoting, escapes,
environment assignments, wrappers such as ``sudo``, subshells, command and
process substitution, redirections, here-documents and nested literal shells.
Whatever cannot be resolved to literal commands is reported as a
:class:`~ember_armor.ledger.shell.core.Dynamic` reason, never dropped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ember_armor.ledger.shell import nested
from ember_armor.ledger.shell.core import (
    BASH_SHELLS,
    DOWNLOADERS,
    INTERPRETERS,
    MAX_DEPTH,
    POWERSHELLS,
    Dynamic,
    ParseError,
    ParseResult,
    Recurse,
    Redirect,
    SimpleCommand,
    find_exec,
    pipe_kind,
    program_name,
)

_OPS = (
    ";;&", "&>>", "<<<", "<<-", ";;", ";&", "&&", "||", "|&", "&>", ">>", ">&",
    ">|", "<<", "<&", "<>", ";", "&", "|", "(", ")", "<", ">",
)  # fmt: skip
_REDIRECTS = frozenset(
    {"&>>", "<<<", "<<-", "&>", ">>", ">&", ">|", "<<", "<&", "<>", "<", ">"}
)
_CASE_ENDS = frozenset({";;", ";&", ";;&"})
_WORD_END = frozenset(" \t\r\n;&|()<>")
_SKIP_WORDS = frozenset(
    {"if", "then", "elif", "else", "while", "until", "do", "!", "{", "}", "fi",
     "done", "esac"}
)  # fmt: skip
_DECLARERS = frozenset({"export", "declare", "local", "readonly", "typeset"})
_RUNNERS = BASH_SHELLS | POWERSHELLS | INTERPRETERS | {"source", ".", "eval"}
_NAME_RE = re.compile(r"[A-Za-z_]\w*\+?")
_VAR_RE = re.compile(r"[A-Za-z_]\w*|[0-9@*#?$!-]")
_ONLY_VAR_RE = re.compile(r"\$\{?(\w+)\}?")
_TEST_END_RE = re.compile(r"(?<=\s)\]\](?=[\s;&|)]|$)")
_ANSI_C = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", "'": "'", '"': '"', "0": "\0"}

#: Commands that run another command: (flags that take a value, positionals to skip).
_WRAPPERS: dict[str, tuple[frozenset[str], int]] = {
    "sudo": (frozenset({"-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-r", "-t",
                        "--user", "--group", "--host", "--prompt", "--chdir"}), 0),
    "doas": (frozenset({"-u", "-C"}), 0),
    "env": (frozenset({"-u", "-C", "--unset", "--chdir"}), 0),
    "nohup": (frozenset(), 0),
    "time": (frozenset({"-f", "-o"}), 0),
    "nice": (frozenset({"-n"}), 0),
    "ionice": (frozenset({"-c", "-n", "-p"}), 0),
    "timeout": (frozenset({"-s", "-k", "--signal", "--kill-after"}), 1),
    "stdbuf": (frozenset({"-i", "-o", "-e"}), 0),
    "command": (frozenset(), 0),
    "builtin": (frozenset(), 0),
    "exec": (frozenset({"-a"}), 0),
    "xargs": (frozenset({"-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a",
                         "--max-args", "--max-procs", "--delimiter"}), 0),
    "setsid": (frozenset(), 0),
    "winpty": (frozenset(), 0),
    "busybox": (frozenset(), 0),
}  # fmt: skip


@dataclass
class _Word:
    """One shell word after quote removal.

    ``expands`` is set when the word contains a parameter or command
    expansion (kept in ``text`` as written).  ``tail_dynamic`` is set when an
    expansion follows the last ``/``, i.e. the base name is not literal.
    ``spans`` are index ranges of the commands parsed out of substitutions.
    """

    parts: list[str] = field(default_factory=list)
    text: str = ""
    quoted: bool = False
    expands: bool = False
    tail_dynamic: bool = False
    assign_at: int = -1
    seen_equals: bool = False
    spans: list[tuple[int, int]] = field(default_factory=list)

    def literal(self, text: str) -> None:
        self.parts.append(text)
        if "/" in text:
            self.tail_dynamic = False

    def expansion(self, raw: str) -> None:
        self.parts.append(raw)
        self.expands = True
        self.tail_dynamic = True


@dataclass
class _Heredoc:
    delimiter: str
    strip_tabs: bool
    body: str = ""


@dataclass
class _Pending:
    """A simple command that is still being read."""

    words: list[_Word] = field(default_factory=list)
    redirects: list[Redirect] = field(default_factory=list)
    heredocs: list[_Heredoc] = field(default_factory=list)
    herestring: _Word | None = None


def _strip_wrappers(words: list[_Word]) -> list[_Word]:
    """Remove ``sudo``-like wrappers so the wrapped command is in front."""
    while words:
        spec = _WRAPPERS.get(program_name(words[0].text))
        if spec is None or words[0].tail_dynamic:
            return words
        name = program_name(words[0].text)
        if name == "command" and any(w.text in ("-v", "-V") for w in words[1:3]):
            return words
        value_flags, skip = spec
        i = 1
        while i < len(words):
            text = words[i].text
            if text == "--":
                i += 1
                break
            if name == "env" and words[i].assign_at >= 0:
                i += 1
            elif text.startswith("-") and text != "-":
                i += 2 if text in value_flags else 1
            else:
                break
        i += skip
        if i >= len(words):
            return words
        words = words[i:]
    return words


class _Bash:
    """Single-pass lexer and parser over one command string."""

    def __init__(self, text: str, depth: int, recurse: Recurse, out: ParseResult):
        if depth > MAX_DEPTH:
            raise ParseError("shell nesting too deep")
        self.s = text
        self.n = len(text)
        self.i = 0
        self.depth = depth
        self.recurse = recurse
        self.out = out
        self.pending: list[_Heredoc] = []

    # -- lexer --------------------------------------------------------------
    def _token(self) -> tuple[str, str | _Word]:
        s, n = self.s, self.n
        while self.i < n:
            char = s[self.i]
            if char in " \t\r":
                self.i += 1
            elif s.startswith(("\\\n", "\\\r\n"), self.i):
                self.i = s.index("\n", self.i) + 1
            elif char == "#":
                end = s.find("\n", self.i)
                self.i = n if end < 0 else end
            else:
                break
        if self.i >= n:
            return "eof", ""
        if s[self.i] == "\n":
            self.i += 1
            self._read_heredocs()
            return "op", "\n"
        if s[self.i].isdigit():
            j = self.i
            while j < n and s[j].isdigit():
                j += 1
            if j < n and s[j] in "<>":
                self.i = j
        if s.startswith(("<(", ">("), self.i):
            return "word", self._word()
        for op in _OPS:
            if s.startswith(op, self.i):
                self.i += len(op)
                return "op", op
        return "word", self._word()

    def _read_heredocs(self) -> None:
        s, n = self.s, self.n
        for doc in self.pending:
            lines: list[str] = []
            while self.i < n:
                end = s.find("\n", self.i)
                end = n if end < 0 else end
                line = s[self.i : end].rstrip("\r")
                self.i = min(end + 1, n)
                if (line.lstrip("\t") if doc.strip_tabs else line) == doc.delimiter:
                    break
                lines.append(line)
            doc.body = "\n".join(lines)
        self.pending.clear()

    def _word(self) -> _Word:
        s, n = self.s, self.n
        word = _Word()
        while self.i < n:
            char = s[self.i]
            if char in _WORD_END:
                if char in "<>" and not word.parts and s.startswith("(", self.i + 1):
                    self._substitution(word, self.i, 2)
                    continue
                break
            if char == "\\":
                if s.startswith(("\\\n", "\\\r\n"), self.i):
                    self.i = s.index("\n", self.i) + 1
                    continue
                word.literal(s[self.i + 1 : self.i + 2] or "\\")
                word.quoted = True
                self.i += 2
            elif char == "'":
                end = s.find("'", self.i + 1)
                if end < 0:
                    raise ParseError("unterminated single quote")
                word.literal(s[self.i + 1 : end])
                word.quoted = True
                self.i = end + 1
            elif char == '"':
                self.i += 1
                word.quoted = True
                self._double_quoted(word)
            elif char == "$":
                self._dollar(word, in_quotes=False)
            elif char == "`":
                self._backtick(word)
            else:
                if char == "=" and not word.seen_equals:
                    # Only the first "=" can make the word an assignment.
                    word.seen_equals = True
                    name = "".join(word.parts)
                    plain = not word.quoted and not word.expands
                    if plain and _NAME_RE.fullmatch(name):
                        word.assign_at = len(name) + 1
                word.literal(char)
                self.i += 1
        word.text = "".join(word.parts)
        return word

    def _double_quoted(self, word: _Word) -> None:
        s, n = self.s, self.n
        while self.i < n:
            char = s[self.i]
            if char == '"':
                self.i += 1
                return
            if char == "\\":
                follower = s[self.i + 1 : self.i + 2]
                if follower == "\n":
                    self.i += 2
                elif follower and follower in '$`"\\':
                    word.literal(follower)
                    self.i += 2
                else:
                    word.literal("\\")
                    self.i += 1
            elif char == "$":
                self._dollar(word, in_quotes=True)
            elif char == "`":
                self._backtick(word)
            else:
                word.literal(char)
                self.i += 1
        raise ParseError("unterminated double quote")

    def _substitution(self, word: _Word, start: int, opener: int) -> None:
        """Parse ``$(...)``, ``<(...)`` or ``>(...)`` beginning at *start*."""
        self.i = start + opener
        low = len(self.out.commands)
        self._list(")")
        word.expansion(self.s[start : self.i])
        word.spans.append((low, len(self.out.commands)))

    def _dollar(self, word: _Word, *, in_quotes: bool) -> None:
        s, start = self.s, self.i
        if s.startswith("$((", start):
            self.i = self._balanced(start + 1, "(", ")")
            word.expansion(s[start : self.i])
        elif s.startswith("$(", start):
            self._substitution(word, start, 2)
        elif s.startswith("${", start):
            self.i = self._balanced(start + 1, "{", "}")
            word.expansion(s[start : self.i])
        elif not in_quotes and s.startswith("$'", start):
            self._ansi_c(word)
        elif not in_quotes and s.startswith('$"', start):
            self.i = start + 2
            word.quoted = True
            self._double_quoted(word)
        elif match := _VAR_RE.match(s, start + 1):
            self.i = match.end()
            word.expansion(s[start : self.i])
        else:
            word.literal("$")
            self.i = start + 1

    def _balanced(self, start: int, opener: str, closer: str) -> int:
        """Index just past the bracket that closes the one at *start*."""
        s, depth, i = self.s, 0, start
        while i < self.n:
            char = s[i]
            if char == "\\":
                i += 1
            elif char == opener:
                depth += 1
            elif char == closer:
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
        raise ParseError(f"unterminated {opener}")

    def _ansi_c(self, word: _Word) -> None:
        s, i = self.s, self.i + 2
        chars: list[str] = []
        while i < self.n and s[i] != "'":
            if s[i] == "\\" and i + 1 < self.n:
                chars.append(_ANSI_C.get(s[i + 1], s[i + 1]))
                i += 2
            else:
                chars.append(s[i])
                i += 1
        if i >= self.n:
            raise ParseError("unterminated $' quote")
        word.literal("".join(chars))
        word.quoted = True
        self.i = i + 1

    def _backtick(self, word: _Word) -> None:
        s, start = self.s, self.i
        end = start + 1
        while end < self.n and s[end] != "`":
            end += 2 if s[end] == "\\" else 1
        if end >= self.n:
            raise ParseError("unterminated backtick")
        inner = re.sub(r"\\([`\\$])", r"\1", s[start + 1 : end])
        low = len(self.out.commands)
        _Bash(inner, self.depth + 1, self.recurse, self.out).run()
        word.expansion(s[start : end + 1])
        word.spans.append((low, len(self.out.commands)))
        self.i = end + 1

    # -- parser -------------------------------------------------------------
    def run(self) -> None:
        """Parse the whole string, appending findings to the shared result."""
        self._list(None)

    def _list(self, closer: str | None) -> None:
        cur = _Pending()
        stages: list[tuple[str, bool]] = []
        case_depth, in_pattern = 0, False
        while True:
            kind, value = self._token()
            if kind == "eof" or (value == ")" and not in_pattern):
                if (kind == "eof") != (closer is None):
                    raise ParseError("unbalanced parenthesis")
                self._end_command(cur, stages)
                self._end_pipeline(stages)
                return
            if isinstance(value, _Word):
                bare = not cur.words and not value.quoted
                if bare and value.text == "[[":
                    self._skip_test()
                elif bare and value.text == "esac" and case_depth:
                    case_depth, in_pattern = case_depth - 1, False
                elif not in_pattern:
                    cur.words.append(value)
                    if self._opens_case(cur.words):
                        case_depth, in_pattern, cur = case_depth + 1, True, _Pending()
            elif value == ")":
                in_pattern = False
            elif in_pattern and value in ("(", "|"):
                continue
            elif value == "(":
                cur = self._open_paren(cur, stages)
            elif value in _REDIRECTS:
                self._redirect(value, cur)
            else:
                self._end_command(cur, stages)
                cur = _Pending()
                if value not in ("|", "|&"):
                    self._end_pipeline(stages)
                    stages = []
                    in_pattern = in_pattern or (case_depth > 0 and value in _CASE_ENDS)

    @staticmethod
    def _opens_case(words: list[_Word]) -> bool:
        return (
            len(words) >= 3
            and words[0].text == "case"
            and not words[0].quoted
            and words[-1].text == "in"
            and not words[-1].quoted
        )

    def _open_paren(self, cur: _Pending, stages: list[tuple[str, bool]]) -> _Pending:
        """Handle ``(``: subshell, arithmetic command or function definition."""
        if self.s.startswith("(", self.i):
            end = self._balanced(self.i - 1, "(", ")")
            if self.s.startswith("))", end - 2):
                self.i = end
                return _Pending()
        if cur.words:
            kind, value = self._token()
            if kind != "op" or value != ")":
                raise ParseError("unexpected (")
            return _Pending()
        self._list(")")
        stages.append(("", False))
        return cur

    def _skip_test(self) -> None:
        match = _TEST_END_RE.search(self.s, self.i)
        if match is None:
            raise ParseError("unterminated [[")
        self.i = match.end()

    def _redirect(self, op: str, cur: _Pending) -> None:
        kind, target = self._token()
        if not isinstance(target, _Word):
            raise ParseError(f"redirection {op} without a target ({kind})")
        if op in ("<<", "<<-"):
            doc = _Heredoc(target.text, op == "<<-")
            self.pending.append(doc)
            cur.heredocs.append(doc)
        elif op == "<<<":
            cur.herestring = target
        elif op in ("<", "<>"):
            cur.redirects.append(Redirect("read", target.text))
        elif op in (">&", "<&") and (target.text.isdigit() or target.text == "-"):
            return
        elif op != "<&":
            cur.redirects.append(Redirect("write", target.text))

    def _spans_download(self, words: list[_Word]) -> bool:
        commands = self.out.commands
        return any(
            command.argv and program_name(command.argv[0]) in DOWNLOADERS
            for word in words
            for low, high in word.spans
            for command in commands[low:high]
        )

    def _record_variables(self, words: list[_Word]) -> None:
        for word in words:
            if word.assign_at >= 0 and not word.expands:
                name = word.text[: word.assign_at - 1].rstrip("+")
                self.out.variables[name.upper()] = word.text[word.assign_at :]

    def _substitute(self, words: list[_Word]) -> list[_Word]:
        """Replace ``$NAME`` words whose literal value was assigned earlier.

        ``PY=/venv/bin/python; "$PY" -m pytest`` then reads as the command it
        is.  An unquoted reference is split on whitespace, as the shell does.
        """
        result: list[_Word] = []
        for word in words:
            match = _ONLY_VAR_RE.fullmatch(word.text) if word.expands else None
            value = self.out.variables.get(match.group(1).upper()) if match else None
            if value is None:
                result.append(word)
            else:
                parts = [value] if word.quoted else value.split()
                result.extend(_Word(text=part, quoted=word.quoted) for part in parts)
        return result

    def _end_command(self, cur: _Pending, stages: list[tuple[str, bool]]) -> None:
        """Finish the simple command in *cur* and add it to the pipeline."""
        words = list(cur.words)
        while words and not words[0].quoted:
            head = words[0].text
            if head in _SKIP_WORDS:
                words.pop(0)
            elif head == "function":
                del words[:2]
            elif head in ("for", "select", "case"):
                words = []
            else:
                break
        leading = 0
        while leading < len(words) and words[leading].assign_at >= 0:
            leading += 1
        self._record_variables(words[:leading])
        words = _strip_wrappers(self._substitute(words[leading:]))
        redirects = tuple(cur.redirects)
        if not words:
            if redirects:
                self.out.commands.append(SimpleCommand((), "bash", redirects))
            return
        argv = tuple(word.text for word in words)
        program = program_name(argv[0])
        self.out.commands.append(SimpleCommand(argv, "bash", redirects))
        if words[0].tail_dynamic:
            self.out.dynamic.append(Dynamic("variable_command", argv[0][:200]))
        if program in _DECLARERS:
            self._record_variables(words[1:])
        if program == "find":
            self.out.commands.extend(
                SimpleCommand(inner, "bash") for inner in find_exec(argv[1:])
            )
        downloaded = program in _RUNNERS and self._spans_download(words[1:])
        if downloaded:
            self.out.dynamic.append(Dynamic("download_pipe", program))
        if program == "eval":
            if not downloaded:
                self.out.dynamic.append(Dynamic("eval", " ".join(argv)[:200]))
            if not any(word.expands for word in words[1:]):
                self.out.merge(self.recurse(" ".join(argv[1:]), "bash", self.depth + 1))
        stages.append((program, self._descend(cur, words, program, downloaded)))

    def _descend(
        self, cur: _Pending, words: list[_Word], program: str, downloaded: bool
    ) -> bool:
        """Parse a nested literal shell; return True if it reads a piped script."""
        found = nested.inspect([word.text for word in words])
        if found is None:
            return False
        if found.kind == "encoded":
            self.out.dynamic.append(Dynamic("encoded_command", program))
        if found.kind == "script":
            rest = words[found.index :]
            if found.shell == "bash":
                rest = rest[:1]
            opaque = any(word.spans for word in rest) or any(
                word.expands and _ONLY_VAR_RE.fullmatch(word.text) for word in rest[:1]
            )
            if not opaque:
                self.out.merge(self.recurse(found.script, found.shell, self.depth + 1))
            elif not downloaded:
                self.out.dynamic.append(Dynamic("nested_dynamic", program))
        if found.kind != "stdin":
            return False
        if cur.heredocs or cur.herestring is not None:
            self._stdin_script(cur, found.shell, program)
            return False
        return True

    def _stdin_script(self, cur: _Pending, shell: str, program: str) -> None:
        """Parse a script handed to a shell by here-document or here-string."""
        if not shell:
            return
        if cur.herestring is not None and cur.herestring.expands:
            self.out.dynamic.append(Dynamic("nested_dynamic", program))
            return
        text = cur.heredocs[-1].body if cur.heredocs else cur.herestring.text
        self.out.merge(self.recurse(text, shell, self.depth + 1))

    def _end_pipeline(self, stages: list[tuple[str, bool]]) -> None:
        for index, (program, piped_script) in enumerate(stages):
            if index and piped_script:
                upstream = [name for name, _ in stages[:index]]
                self.out.dynamic.append(Dynamic(pipe_kind(upstream), program))


def parse_bash(text: str, depth: int, recurse: Recurse) -> ParseResult:
    """Parse a Bash command string.

    Parameters
    ----------
    text:
        The command string.  It is only read, never executed.
    depth:
        Current nesting depth of literal shells.
    recurse:
        Callback used to parse nested literal shell strings.

    Returns
    -------
    ParseResult
        Simple commands, dynamic-shell reasons and literal variable
        assignments.  A parse failure yields a ``parse_error`` reason.
    """
    out = ParseResult()
    try:
        _Bash(text, depth, recurse, out).run()
    except (ParseError, RecursionError) as exc:
        out.dynamic.append(Dynamic("parse_error", str(exc) or type(exc).__name__))
    return out
