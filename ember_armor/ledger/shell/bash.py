"""Bash command-string parser.

Turns a command string into simple commands (argument vectors) without
running anything.  It understands separators, pipelines, quoting, escapes,
environment assignments, arrays, brace expansion, wrappers such as ``sudo``
and package runners such as ``npx``, subshells, command and process
substitution, redirections, here-documents and nested literal shells.
Whatever cannot be resolved to literal commands is reported as a
:class:`~ember_armor.ledger.shell.core.Dynamic` reason, never dropped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace

from ember_armor.ledger.shell import nested, wrappers
from ember_armor.ledger.shell.core import (
    BASH_SHELLS,
    DECODERS,
    DOWNLOADERS,
    INTERPRETERS,
    MAX_COMMANDS,
    MAX_DEPTH,
    POWERSHELLS,
    SELECTORS,
    UNKNOWN_DIR,
    Dynamic,
    Guards,
    ParseError,
    ParseResult,
    Recurse,
    Redirect,
    SimpleCommand,
    find_runs,
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
#: Words a reserved word may follow and still stand where a command starts.
_LEADING = _SKIP_WORDS | {"time"}
_LOOPS = frozenset({"while", "until", "for", "select"})
_DECLARERS = frozenset({"export", "declare", "local", "readonly", "typeset"})
#: Builtins that give their operands a value the parser cannot know.
_BINDERS = frozenset({"read", "readarray", "mapfile", "getopts", "unset"})
_RUNNERS = BASH_SHELLS | POWERSHELLS | INTERPRETERS | {"source", ".", "eval"}
_ASSIGN_NAME_RE = re.compile(r"[A-Za-z_]\w*\+?")
_NAME_RE = re.compile(r"[A-Za-z_]\w*")
_VAR_RE = re.compile(r"[A-Za-z_]\w*|[0-9@*#?$!-]")
_ONLY_VAR_RE = re.compile(r"\$\{?(\w+)\}?")
_PLAIN_VAR_RE = re.compile(r"\$\{?[A-Za-z_]\w*\}?")
_TEST_END_RE = re.compile(r"(?<=\s)\]\](?=[\s;&|)]|$)")
#: Two words side by side: a command, where arithmetic would have an operator.
_COMMAND_LIKE_RE = re.compile(r"[A-Za-z_]\w*[ \t]+-{0,2}[A-Za-z_./~$\"']")
_SUBSTITUTION_RE = re.compile(r"\$\([^()`]*\)|\$\{[^{}]*\}|`[^`]*`")
_ANSI_C = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", "'": "'", '"': '"', "0": "\0"}
_EXTGLOB = frozenset("?*+@!")
_MAX_BRACE_WORDS = 64
_MAX_EXPANSIONS = 4
#: Where ``mktemp -d`` creates its directory when no template names a place.
_MKTEMP_DIR = "/tmp/mktemp"  # noqa: S108 - a path pattern, nothing is created


@dataclass(eq=False, repr=False)
class _Word:
    """One shell word after quote removal.

    ``expands`` is set when the word contains a parameter or command
    expansion (kept in ``text`` as written); ``opaque`` when one of them is
    more than a plain ``$NAME``.  ``tail_dynamic`` is set when an expansion
    follows the last ``/``, i.e. the base name is not literal.  ``spans``
    are index ranges of the commands parsed out of substitutions, ``marks``
    the indexes in ``parts`` of unquoted brace-expansion characters, and
    ``array`` the elements of a ``NAME=( ... )`` assignment.
    """

    parts: list[str] = field(default_factory=list)
    text: str = ""
    size: int = 0
    quoted: bool = False
    expands: bool = False
    opaque: bool = False
    tail_dynamic: bool = False
    assign_at: int = -1
    seen_equals: bool = False
    spans: list[tuple[int, int]] = field(default_factory=list)
    marks: list[int] = field(default_factory=list)
    array: list[_Word] | None = None

    @property
    def only_expansion(self) -> bool:
        """True when the whole word is one expansion: nothing of it is known."""
        return self.expands and len(self.parts) == 1

    def literal(self, text: str) -> None:
        self.parts.append(text)
        self.size += len(text)
        if "/" in text:
            self.tail_dynamic = False

    def expansion(self, raw: str, *, plain: bool = False) -> None:
        self.parts.append(raw)
        self.size += len(raw)
        self.expands = True
        self.opaque = self.opaque or not plain
        self.tail_dynamic = True


@dataclass(eq=False, repr=False)
class _Heredoc:
    """A here-document; ``command`` is the index of the command it feeds.

    ``expands`` is set for an unquoted delimiter: the shell then runs the
    substitutions in the body.  ``shell`` names the shell that reads the
    body as a script, when the command ended before the body was read, and
    ``chdir`` the directories that shell is started in.
    """

    delimiter: str
    strip_tabs: bool
    expands: bool = False
    body: str = ""
    command: int = -1
    shell: str = ""
    chdir: tuple[str, ...] = ()


@dataclass(eq=False, repr=False)
class _Pending:
    """A simple command that is still being read."""

    words: list[_Word] = field(default_factory=list)
    redirects: list[Redirect] = field(default_factory=list)
    heredocs: list[_Heredoc] = field(default_factory=list)
    herestring: _Word | None = None


@dataclass(frozen=True, eq=False, repr=False)
class _Stage:
    """One pipeline element: its program, whether it reads a script from the
    pipe, and the argument vector that feeds the stage after it."""

    program: str
    piped_script: bool
    feed: tuple[str, ...]


def _started_in(chdir: tuple[str, ...], found: nested.Nested) -> tuple[str, ...]:
    """Directories a nested shell starts in: its wrappers', then its own."""
    return (*chdir, found.chdir) if found.chdir else chdir


def _strip_wrappers(words: list[_Word]) -> tuple[list[_Word], wrappers.Unwrapped]:
    """Remove ``sudo``-like wrappers so the wrapped command is in front."""
    found = wrappers.unwrap(
        [word.text for word in words], [not word.tail_dynamic for word in words]
    )
    rest = words[found.start :]
    if found.program is not None and rest:
        rest = [_Word(text=found.program), *rest[1:]]
    return rest, found


def _leads(words: list[_Word]) -> bool:
    """True when the word after *words* stands where a command starts."""
    if len(words) >= 2 and words[-2].text == "function" and not words[-2].quoted:
        words = words[:-2]
    return all(not word.quoted and word.text in _LEADING for word in words)


def _first_group(tokens: list[tuple[str, bool]]) -> tuple[int, list[int], int] | None:
    """First ``{a,b}`` group: indexes of its brace, commas and closing brace."""
    opens = [i for i, (text, active) in enumerate(tokens) if active and text == "{"]
    if len(opens) > _MAX_BRACE_WORDS:
        raise ParseError("brace expansion too large")
    for start in opens:
        depth = 0
        commas: list[int] = []
        for index in range(start + 1, len(tokens)):
            text, active = tokens[index]
            if not active:
                continue
            if text == "{":
                depth += 1
            elif text == "}" and depth:
                depth -= 1
            elif text == "}":
                if commas:
                    return start, commas, index
                break
            elif depth == 0:
                commas.append(index)
    return None


def _brace_texts(tokens: list[tuple[str, bool]], depth: int = 0) -> list[str]:
    """Every text a word with unquoted ``{a,b}`` groups expands to."""
    group = _first_group(tokens)
    if group is None:
        return ["".join(text for text, _ in tokens)]
    if depth > _MAX_BRACE_WORDS:
        raise ParseError("brace expansion too large")
    start, commas, end = group
    edges = [start, *commas, end]
    texts: list[str] = []
    for low, high in zip(edges, edges[1:], strict=False):
        choice = tokens[:start] + tokens[low + 1 : high] + tokens[end + 1 :]
        texts += _brace_texts(choice, depth + 1)
        if len(texts) > _MAX_BRACE_WORDS:
            raise ParseError("brace expansion too large")
    return texts


def _expand_braces(word: _Word) -> list[_Word]:
    """The words *word* becomes after brace expansion (itself if none)."""
    if not word.marks or word.assign_at >= 0:
        return [word]
    marks = set(word.marks)
    tokens = [(part, index in marks) for index, part in enumerate(word.parts)]
    texts = _brace_texts(tokens)
    if len(texts) == 1:
        return [word]
    return [replace(word, parts=[text], text=text, marks=[]) for text in texts]


def _mktemp_directory(argv: tuple[str, ...]) -> str | None:
    """Where a literal ``mktemp -d`` invocation creates its directory."""
    flags = [arg for arg in argv[1:] if arg.startswith("-")]
    templates = [arg for arg in argv[1:] if not arg.startswith("-")]
    letters = "".join(flag[1:] for flag in flags if not flag.startswith("--"))
    long_flags = {flag for flag in flags if flag.startswith("--")}
    directory = "d" in letters or "--directory" in long_flags
    if not directory or set(letters) - set("dqt") or len(templates) > 1:
        return None
    if long_flags - {"--directory", "--quiet"}:
        return None
    if not templates:
        return _MKTEMP_DIR
    return f"/tmp/{templates[0]}" if "t" in letters else templates[0]  # noqa: S108


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
        # ``function NAME`` was read up to the name; the name of the function
        # whose body comes next.
        self.naming = False
        self.defining = ""

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
        expanded: list[tuple[int, int]] = []
        for doc in self.pending:
            lines: list[str] = []
            start = stop = self.i
            while self.i < n:
                end = s.find("\n", self.i)
                end = n if end < 0 else end
                line = s[self.i : end].rstrip("\r")
                stop = self.i
                self.i = min(end + 1, n)
                if (line.lstrip("\t") if doc.strip_tabs else line) == doc.delimiter:
                    break
                lines.append(line)
                stop = self.i
            doc.body = "\n".join(lines)
            if doc.expands:
                expanded.append((start, stop))
            if doc.command >= 0:
                # The command ended before its body was read (``<<EOF | x``).
                fed = self.out.commands[doc.command]
                text = f"{fed.stdin}\n{doc.body}".lstrip("\n")
                self.out.commands[doc.command] = replace(fed, stdin=text)
        scripts = [doc for doc in self.pending if doc.shell]
        self.pending.clear()
        for doc in scripts:
            script = self.recurse(doc.body, doc.shell, self.depth + 1)
            self.out.merge(script, doc.chdir, starter="bash")
        for start, stop in expanded:
            # An unquoted delimiter: the shell runs the body's substitutions.
            self._scan(start, stop, quotes=False)

    def _scan(
        self, start: int, end: int, *, quotes: bool = True
    ) -> list[tuple[int, int]]:
        """Parse the substitutions in a stretch of text the shell expands.

        The inside of ``[[ ]]``, of ``${name:-...}``, of arithmetic and of an
        unquoted here-document is not split into words, but ``$(...)`` and
        backticks in it still run.  Returns the command ranges they gave.
        With *quotes* false, quote characters are ordinary text (a
        here-document body).
        """
        s = self.s
        resume, limit = self.i, self.n
        holder = _Word()
        double = False
        self.i, self.n = start, end
        try:
            while self.i < end:
                char = s[self.i]
                if char == "\\":
                    self.i += 2
                elif char == "'" and quotes and not double:
                    close = s.find("'", self.i + 1, end)
                    self.i = end if close < 0 else close + 1
                elif char == '"' and quotes:
                    double = not double
                    self.i += 1
                elif s.startswith(("$(", "${"), self.i):
                    self._dollar(holder, in_quotes=True)
                elif char == "`":
                    self._backtick(holder)
                else:
                    self.i += 1
        finally:
            self.i, self.n = resume, limit
        return holder.spans

    def _word(self) -> _Word:
        s, n = self.s, self.n
        word = _Word()
        while self.i < n:
            char = s[self.i]
            if char in _WORD_END:
                if char in "<>" and not word.parts and s.startswith("(", self.i + 1):
                    self._substitution(word, self.i, 2)
                    continue
                if char == "(" and word.parts and self._group(word):
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
                    if plain and _ASSIGN_NAME_RE.fullmatch(name):
                        word.assign_at = len(name) + 1
                elif char in "{,}":
                    word.marks.append(len(word.parts))
                word.literal(char)
                self.i += 1
        word.text = "".join(word.parts)
        return word

    def _group(self, word: _Word) -> bool:
        """Read ``(`` inside a word: an array value or an extended glob."""
        if word.assign_at == word.size:
            start = self.i
            self.i += 1
            items: list[_Word] = []
            while True:
                _, value = self._token()
                if isinstance(value, _Word):
                    items.append(value)
                elif value == ")":
                    break
                elif value != "\n":
                    raise ParseError("unterminated array")
            word.array = items
            word.expansion(self.s[start : self.i])
            for item in items:
                word.spans.extend(item.spans)
            return True
        if word.parts[-1] in _EXTGLOB and self.s[self.i - 1] in _EXTGLOB:
            end = self._balanced(self.i, "(", ")")
            word.literal(self.s[self.i : end])
            self.i = end
            return True
        return False

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
        word.spans.append(self._scope(")"))
        word.expansion(self.s[start : self.i])

    def _dollar(self, word: _Word, *, in_quotes: bool) -> None:
        s, start = self.s, self.i
        if s.startswith("$((", start) and self._arithmetic(start + 1):
            self.i = self._balanced(start + 1, "(", ")")
            word.spans += self._scan(start + 3, self.i - 2)
            word.expansion(s[start : self.i])
        elif s.startswith("$(", start):
            self._substitution(word, start, 2)
        elif s.startswith("${", start):
            self.i = self._balanced(start + 1, "{", "}")
            raw = s[start : self.i]
            plain = _PLAIN_VAR_RE.fullmatch(raw) is not None
            if not plain:
                # ``${x:-$(cmd)}``: the default is expanded when it is used.
                word.spans += self._scan(start + 2, self.i - 1)
            word.expansion(raw, plain=plain)
        elif not in_quotes and s.startswith("$'", start):
            self._ansi_c(word)
        elif not in_quotes and s.startswith('$"', start):
            self.i = start + 2
            word.quoted = True
            self._double_quoted(word)
        elif match := _VAR_RE.match(s, start + 1):
            self.i = match.end()
            raw = s[start : self.i]
            word.expansion(raw, plain=_PLAIN_VAR_RE.fullmatch(raw) is not None)
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

    def _arithmetic(self, start: int) -> bool:
        """True when the ``((`` at *start* opens arithmetic, not two subshells.

        Arithmetic closes with ``))`` and never has two words side by side;
        ``((cd x; make) && (ls))`` does and is parsed as commands.
        """
        end = self._balanced(start, "(", ")")
        inner = self.s[start + 2 : end - 2]
        for _ in range(MAX_DEPTH):
            # Substitutions are operands here; they are parsed on their own.
            inner, found = _SUBSTITUTION_RE.subn("0", inner)
            if not found:
                break
        closed = self.s.startswith("))", end - 2)
        return closed and _COMMAND_LIKE_RE.search(inner) is None

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
        self.out.scopes.append(word.spans[-1])
        self.i = end + 1

    # -- parser -------------------------------------------------------------
    def run(self) -> None:
        """Parse the whole string, appending findings to the shared result."""
        self._list(None)

    def _scope(self, closer: str) -> tuple[int, int]:
        """Parse a subshell or substitution; return its command index range."""
        low = len(self.out.commands)
        self._list(closer)
        scope = (low, len(self.out.commands))
        self.out.scopes.append(scope)
        return scope

    def _list(self, closer: str | None) -> None:
        guards = Guards(self.out)
        try:
            self._commands(closer, guards)
        finally:
            # Also after a parse error: what was read keeps its ranges.
            guards.finish()

    def _commands(self, closer: str | None, guards: Guards) -> None:
        cur = _Pending()
        stages: list[_Stage] = []
        case_depth, in_pattern = 0, False
        # True behind ``&&`` or ``||``, where a new line carries the list on.
        joined = False
        while True:
            kind, value = self._token()
            if kind == "eof" or (value == ")" and not in_pattern):
                if (kind == "eof") != (closer is None):
                    raise ParseError("unbalanced parenthesis")
                self._end_command(cur, stages)
                self._end_pipeline(stages)
                return
            joined = joined and value == "\n"
            if isinstance(value, _Word):
                bare = not cur.words and not value.quoted
                if bare and value.text == "[[":
                    self._skip_test()
                    guards.note()
                elif bare and value.text == "esac" and case_depth:
                    case_depth, in_pattern = case_depth - 1, False
                    guards.leave("case")
                elif not in_pattern:
                    self._reserved(value, cur.words, guards)
                    cur.words.extend(_expand_braces(value))
                    if self._opens_case(cur.words):
                        case_depth, in_pattern, cur = case_depth + 1, True, _Pending()
                        guards.enter("case")
            elif value == ")":
                in_pattern = False
                guards.branch("case")
            elif in_pattern and value in ("(", "|"):
                continue
            elif value == "(":
                cur = self._open_paren(cur, stages, guards)
            elif value in _REDIRECTS:
                self._redirect(value, cur)
            else:
                self._end_command(cur, stages)
                cur = _Pending()
                if value in ("|", "|&"):
                    continue
                self._end_pipeline(stages)
                stages = []
                ended = case_depth > 0 and value in _CASE_ENDS
                in_pattern = in_pattern or ended
                if value in ("&&", "||"):
                    guards.link(value)
                    joined = True
                elif not joined:
                    guards.end()
                    if ended:
                        guards.branch("case", more=False)

    def _reserved(self, word: _Word, before: list[_Word], guards: Guards) -> None:
        """Tell *guards* about a reserved word that opens or closes a compound.

        The branches of ``if`` and the bodies of loops may not run, or run
        more than once, and the body of a function runs when it is called.
        """
        if self.naming:
            self.naming, self.defining = False, word.text
            return
        if word.quoted or not _leads(before):
            return
        text = word.text
        name, self.defining = self.defining, ""
        if text == "{":
            guards.enter("{", "defined" if name else "", name)
        elif text == "}":
            guards.leave("{")
        elif text == "function":
            self.naming = True
        elif text == "if":
            guards.enter("if")
        elif text == "then":
            guards.branch("if", open_one=True)
        elif text in ("elif", "else"):
            guards.branch("if")
        elif text == "fi":
            guards.leave("if")
        elif text in _LOOPS:
            guards.enter("loop", "loop")
        elif text == "done":
            guards.leave("loop")

    @staticmethod
    def _opens_case(words: list[_Word]) -> bool:
        """True when *words* end a ``case WORD in`` header.

        Also behind a keyword: ``for f in *; do case "$f" in a) ...``.
        """
        start = 0
        while start < len(words) and not words[start].quoted:
            if words[start].text not in _SKIP_WORDS:
                break
            start += 1
        rest = words[start:]
        return (
            len(rest) >= 3
            and rest[0].text == "case"
            and not rest[0].quoted
            and rest[-1].text == "in"
            and not rest[-1].quoted
        )

    def _open_paren(
        self, cur: _Pending, stages: list[_Stage], guards: Guards
    ) -> _Pending:
        """Handle ``(``: subshell, arithmetic command or function definition."""
        if self.s.startswith("(", self.i) and self._arithmetic(self.i - 1):
            end = self._balanced(self.i - 1, "(", ")")
            self._scan(self.i + 1, end - 2)
            self.i = end
            guards.note()
            return _Pending()
        if cur.words and self.s[self.i :].lstrip(" \t").startswith(")"):
            self._token()
            self.defining = cur.words[-1].text
            return _Pending()
        # A subshell, also after a keyword or wrapper: ``if (a); then``.  As
        # the body of a function it keeps its moves to itself.
        self.defining = ""
        self._scope(")")
        stages.append(_Stage("", False, ()))
        return cur

    def _skip_test(self) -> None:
        match = _TEST_END_RE.search(self.s, self.i)
        if match is None:
            raise ParseError("unterminated [[")
        self._scan(self.i, match.start())
        self.i = match.end()

    def _redirect(self, op: str, cur: _Pending) -> None:
        kind, target = self._token()
        if not isinstance(target, _Word):
            raise ParseError(f"redirection {op} without a target ({kind})")
        if op in ("<<", "<<-"):
            doc = _Heredoc(target.text, op == "<<-", expands=not target.quoted)
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

    # -- variables ----------------------------------------------------------
    def _value(self, word: _Word) -> str | tuple[str, ...] | None:
        """What an assignment word gives its variable (``None``: unknown)."""
        if word.array is not None:
            literal = word.array and not any(item.expands for item in word.array)
            return tuple(item.text for item in word.array) if literal else None
        value = word.text[word.assign_at :]
        if not word.opaque:
            return value
        if len(word.spans) == 1 and word.parts[-1] == value:
            low, high = word.spans[0]
            made = self.out.commands[low:high]
            if len(made) == 1 and made[0].argv[:1] == ("mktemp",):
                return _mktemp_directory(made[0].argv)
        return None

    def _record_variables(self, words: list[_Word]) -> None:
        for word in words:
            if word.assign_at < 0:
                continue
            name = word.text[: word.assign_at - 1]
            if name.endswith("+"):
                self.out.forget(name[:-1])
            else:
                self.out.assign(name, self._value(word))

    @staticmethod
    def _time_flags(words: list[_Word]) -> bool:
        """True when ``time`` is the program (it has flags other than ``-p``)."""
        return bool(words) and words[0].text.startswith("-") and words[0].text != "-p"

    def _record_assigned(self, words: list[_Word]) -> None:
        """Note the names of assignment words (see ``ParseResult.assigned``)."""
        for word in words:
            if word.assign_at >= 0:
                self.out.assigned.append(word.text[: word.assign_at - 1].rstrip("+"))

    def _resolved_program(self, head: _Word) -> _Word:
        """The command word with variables that hold literal text filled in.

        ``BIN=./node_modules/.bin; $BIN/vercel rm x`` then names its program.
        """
        if not head.tail_dynamic or head.opaque:
            return head
        text = self._expand(head.text)
        # A variable left in the directory part does not hide the program.
        named = "$" not in text.rsplit("/", 1)[-1]
        return _Word(text=text, quoted=True) if named else head

    def _expand(self, text: str, depth: int = 0) -> str:
        """*text* with each ``$NAME`` that was given known text filled in.

        A value may itself name variables (``PY=$VENV/bin/python``); they
        are filled in too, a bounded number of times.
        """
        variables = self.out.variables

        def value(match: re.Match[str]) -> str:
            known = variables.get(match.group().strip("${}"))
            if known is None:
                return match.group()
            deeper = "$" in known and depth < _MAX_EXPANSIONS
            return self._expand(known, depth + 1) if deeper else known

        return _PLAIN_VAR_RE.sub(value, text)

    def _exec_command(
        self, argv: tuple[str, ...], chdir: tuple[str, ...], written: tuple[str, ...]
    ) -> None:
        """Add a command that ``find -exec`` runs (wrappers and shells followed).

        *chdir* names where ``find`` starts it: the directories of ``find``
        itself, and an unknown one for ``-execdir``.  *written* is the
        command with ``{}`` still in it: a wrapper that starts it in ``{}``
        starts it somewhere else for each file found, and so does a
        directory option of its own (see ``ParseResult.placed``).
        """
        found = wrappers.unwrap(written, [True] * len(written))
        program = found.program
        if program is None or "{}" in program:
            program = argv[found.start]
        placed = "{}" in written[found.start + 1 :]
        argv = (program, *argv[found.start + 1 :])
        chdir += found.chdir
        index = self._add(SimpleCommand(argv, "bash", chdir=chdir))
        if placed:
            self.out.placed.add(index)
        script = nested.inspect(argv)
        if script is not None and script.kind == "script":
            inner = self.recurse(script.script, script.shell, self.depth + 1)
            self.out.merge(inner, _started_in(chdir, script), starter="bash")

    def _trap(self, words: list[_Word]) -> None:
        """Parse the command a ``trap`` installs (its first operand)."""
        operands = [word for word in words if not word.text.startswith("-")]
        listing = any(word.text in ("-l", "-p") for word in words[:1])
        if listing or len(operands) < 2 or not operands[0].text:
            return
        self.out.merge(self.recurse(operands[0].text, "bash", self.depth + 1))

    def _bind_loop(self, words: list[_Word]) -> None:
        """Record the variable of ``for NAME in WORDS`` (after ``for``)."""
        if not words or not _NAME_RE.fullmatch(words[0].text):
            return
        items = words[2:] if len(words) > 2 and words[1].text == "in" else []
        literal = items and not any(item.expands for item in items)
        value = tuple(item.text for item in items) if literal else None
        self.out.assign(words[0].text, value)

    def _substitute(self, words: list[_Word]) -> list[_Word]:
        """Replace ``$NAME`` words whose literal value was assigned earlier.

        ``PY=/venv/bin/python; "$PY" -m pytest`` then reads as the command it
        is.  An unquoted reference is split on whitespace, as the shell does.
        """
        result: list[_Word] = []
        for word in words:
            match = _ONLY_VAR_RE.fullmatch(word.text) if word.expands else None
            value = self.out.variables.get(match.group(1)) if match else None
            value = None if value is None else self._expand(value)
            if value is None or "$" in value:
                result.append(word)
            else:
                parts = [value] if word.quoted else value.split()
                result.extend(_Word(text=part, quoted=word.quoted) for part in parts)
        return result

    # -- commands -----------------------------------------------------------
    def _add(self, command: SimpleCommand) -> int:
        """Append a command and return its index."""
        if len(self.out.commands) >= MAX_COMMANDS:
            raise ParseError("too many commands")
        self.out.commands.append(command)
        return len(self.out.commands) - 1

    def _end_command(self, cur: _Pending, stages: list[_Stage]) -> None:
        """Finish the simple command in *cur* and add it to the pipeline."""
        words = cur.words
        first = 0
        while first < len(words) and not words[first].quoted:
            head = words[first].text
            if head in _SKIP_WORDS:
                first += 1
            elif head == "function":
                first += 2
            elif head == "time" and not self._time_flags(words[first + 1 :]):
                # The reserved word: ``time { a; b; }`` and ``time -p cmd``.
                first += 1
                while first < len(words) and words[first].text == "-p":
                    first += 1
            elif head == "coproc":
                # ``coproc NAME { ...; }`` or ``coproc command``.
                named = [word.text for word in words[first + 2 : first + 3]] == ["{"]
                first += 2 if named else 1
            elif head in ("for", "select", "case"):
                if head != "case":
                    self._bind_loop(words[first + 1 :])
                first = len(words)
            else:
                break
        leading = first
        while leading < len(words) and words[leading].assign_at >= 0:
            leading += 1
        if leading == len(words):
            # Assignments in front of a command only apply to that command.
            self._record_variables(words[first:leading])
        self._record_assigned(words[first:leading])
        words, wrapped = _strip_wrappers(self._substitute(words[leading:]))
        self.out.assigned += wrapped.assigned
        if wrapped.capped:
            self.out.dynamic.append(Dynamic("parse_error", "too many wrappers"))
        redirects = tuple(cur.redirects)
        if not words:
            if redirects:
                self._add(SimpleCommand((), "bash", redirects))
            return
        words[0] = self._resolved_program(words[0])
        argv = tuple(word.text for word in words)
        program = program_name(argv[0])
        stdin = [doc.body for doc in cur.heredocs if doc.body]
        if cur.herestring is not None:
            stdin.append(cur.herestring.text)
        feed = stages[-1].feed if stages else ()
        chdir = wrapped.chdir
        command = SimpleCommand(argv, "bash", redirects, "\n".join(stdin), feed, chdir)
        index = self._add(command)
        for doc in cur.heredocs:
            doc.command = index
        if words[0].tail_dynamic:
            self.out.dynamic.append(Dynamic("variable_command", argv[0][:200]))
        if program in _DECLARERS:
            self._record_variables(words[1:])
            self._record_assigned(words[1:])
        elif program in _BINDERS:
            for word in words[1:]:
                if _NAME_RE.fullmatch(word.text):
                    self.out.forget(word.text)
                    if program == "unset":
                        self.out.assigned.append(word.text)
        elif program == "trap":
            self._trap(words[1:])
        if program == "find":
            as_written = find_runs(argv[1:], filled=False)
            for (inner, moved), (written, _) in zip(
                find_runs(argv[1:]), as_written, strict=True
            ):
                self._exec_command(inner, chdir + (UNKNOWN_DIR,) * moved, written)
        found = nested.inspect(argv)
        downloaded = program in _RUNNERS and self._spans_download(
            self._code_words(words, program, found)
        )
        if downloaded:
            self.out.dynamic.append(Dynamic("download_pipe", program))
        if program == "eval":
            if not downloaded:
                self.out.dynamic.append(Dynamic("eval", " ".join(argv)[:200]))
            if not all(word.only_expansion for word in words[1:]):
                # Read as written: what a variable adds to it is not known.
                # The shell runs it itself, so a ``cd`` in it stays in force.
                script = " ".join(argv[1:])
                evaluated = self.recurse(script, "bash", self.depth + 1)
                self.out.merge(evaluated, keep=True)
        piped = self._descend(cur, words, program, found, downloaded, chdir)
        stages.append(_Stage(program, piped, feed if program in SELECTORS else argv))

    @staticmethod
    def _code_words(
        words: list[_Word], program: str, found: nested.Nested | None
    ) -> list[_Word]:
        """The words of a runner that are executed as code.

        The script after ``-c``, everything given to ``eval``, or else the
        first operand (the script file, as in ``bash <(curl ...)``).  Later
        arguments are data handed to a literal script.
        """
        if program == "eval":
            return words[1:]
        if found is not None and found.kind == "script":
            rest = words[found.index :]
            return rest[:1] if found.shell == "bash" else rest
        return [w for w in words[1:] if not w.text.startswith("-")][:1]

    def _descend(
        self,
        cur: _Pending,
        words: list[_Word],
        program: str,
        found: nested.Nested | None,
        downloaded: bool,
        chdir: tuple[str, ...],
    ) -> bool:
        """Parse a nested literal shell; return True if it reads a piped script.

        *chdir* names the directories the wrappers start that shell in.
        """
        if found is None:
            return False
        chdir = _started_in(chdir, found)
        if found.kind == "encoded":
            self.out.dynamic.append(Dynamic("encoded_command", program))
        if found.kind == "script":
            rest = words[found.index :]
            if found.shell == "bash":
                rest = rest[:1]
            unknown = any(word.only_expansion for word in rest[:1])
            if not unknown:
                # With substitutions in it the script is read as written.
                script = self.recurse(found.script, found.shell, self.depth + 1)
                self.out.merge(script, chdir, starter="bash")
            if (unknown or any(word.spans for word in rest)) and not downloaded:
                self.out.dynamic.append(Dynamic("nested_dynamic", program))
        if found.kind != "stdin":
            return False
        if cur.heredocs or cur.herestring is not None:
            self._stdin_script(cur, found.shell, program, chdir)
            return False
        return True

    def _stdin_script(
        self, cur: _Pending, shell: str, program: str, chdir: tuple[str, ...]
    ) -> None:
        """Parse a script handed to a shell by here-document or here-string."""
        if not shell:
            return
        text = cur.heredocs[-1].body if cur.heredocs else ""
        if cur.heredocs and any(doc is cur.heredocs[-1] for doc in self.pending):
            # ``bash <<EOF | tee log``: the body is read at the next newline.
            cur.heredocs[-1].shell = shell
            cur.heredocs[-1].chdir = chdir
            return
        if cur.herestring is not None:
            if cur.herestring.expands:
                self.out.dynamic.append(Dynamic("nested_dynamic", program))
                return
            text = cur.herestring.text
        script = self.recurse(text, shell, self.depth + 1)
        self.out.merge(script, chdir, starter="bash")

    def _end_pipeline(self, stages: list[_Stage]) -> None:
        download = decoder = False
        for index, stage in enumerate(stages):
            if index and stage.piped_script:
                kind = "pipe_to_shell"
                if download:
                    kind = "download_pipe"
                elif decoder:
                    kind = "decoder_pipe"
                self.out.dynamic.append(Dynamic(kind, stage.program))
            download = download or stage.program in DOWNLOADERS
            decoder = decoder or stage.program in DECODERS


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
        Simple commands, dynamic-shell reasons and variable assignments.  A
        parse failure yields a ``parse_error`` reason; the commands read
        before it are kept.
    """
    out = ParseResult()
    try:
        _Bash(text, depth, recurse, out).run()
    except (ParseError, RecursionError) as exc:
        out.dynamic.append(Dynamic("parse_error", str(exc) or type(exc).__name__))
    return out
