"""Evaluate ledger rules against the facts of one tool call.

Evaluation is direct: each predicate is computed on the extracted facts.
No solver is involved and no model is called.  When several rules fire the
most restrictive effect wins (``deny`` over ``ask`` over ``warn``).
"""

from __future__ import annotations

import json
import math
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from fnmatch import fnmatchcase

from ember_armor.ledger.facts import Facts
from ember_armor.ledger.model import (
    SEVERITY,
    AllPred,
    AnyPred,
    ArgPred,
    AssignsPred,
    CommandPred,
    CountExceedsPred,
    Decision,
    DynamicShellPred,
    ExceptedRule,
    ExprPred,
    FiredRule,
    NotPrecededByPred,
    NotPred,
    PathPred,
    Predicate,
    Rule,
    RuleException,
    TextRegexPred,
    exceptable,
)
from ember_armor.ledger.paths import (
    UNKNOWN_DIR,
    PathFact,
    is_under,
    matches_glob,
    may_match,
    resolve_pattern,
)
from ember_armor.ledger.shell import SimpleCommand, program_name
from ember_armor.ledger.shell.argv import has_flag, operand_positions

TYPE_CHECKING = False
if TYPE_CHECKING:
    from fractions import Fraction
    from typing import Any, Protocol

TEXT_LIMIT = 20_000
_MISSING = object()
#: ``finder(directory)``: root of the nearest enclosing git repository of a
#: normalised directory, or ``None``; see :mod:`ember_armor.ledger.repo`.
RepoFinder = Callable[[str], str | None]
#: What a relative directory of an exception resolves against: nowhere.
_NO_BASE = "/\x00"
_ERROR_CHARS = 300

#: Options that take a value and may stand before a program's subcommand.
_GLOBAL_VALUE_FLAGS: dict[str, frozenset[str]] = {
    "git": frozenset({"-C", "-c", "--git-dir", "--work-tree", "--namespace"}),
    "docker": frozenset({"--context", "-c", "--config", "-H", "--host", "-l",
                         "--log-level", "-f", "--file", "-p", "--project-name",
                         "--profile", "--env-file", "--project-directory"}),
    "kubectl": frozenset({"-n", "--namespace", "--context", "--kubeconfig",
                          "--cluster", "--user", "-s", "--server", "--as"}),
    "aws": frozenset({"--profile", "--region", "--endpoint-url", "--output"}),
    "gh": frozenset({"-R", "--repo"}),
    "npm": frozenset({"--prefix", "-w", "--workspace"}),
    "vercel": frozenset({"-t", "--token", "-S", "--scope", "--cwd", "-A",
                         "--local-config", "-Q", "--global-config"}),
}  # fmt: skip
_GLOBAL_VALUE_FLAGS["podman"] = _GLOBAL_VALUE_FLAGS["docker"]
_GLOBAL_VALUE_FLAGS["docker-compose"] = _GLOBAL_VALUE_FLAGS["docker"]
_GLOBAL_VALUE_FLAGS["gsutil"] = frozenset({"-o", "-h", "-u", "-i"})
_GLOBAL_VALUE_FLAGS["helm"] = frozenset({"-n", "--namespace", "--kube-context",
                                         "--kubeconfig"})  # fmt: skip
#: Windows tools that read their own subcommands and arguments in any letter
#: case, whichever shell starts them (``REG DELETE``, ``NETSH ADVFIREWALL``).
_CASELESS_PROGRAMS = frozenset(
    {"reg", "netsh", "sc", "net", "certutil", "bcdedit", "diskpart", "format",
     "schtasks", "wmic", "robocopy", "icacls", "takeown", "vssadmin", "wevtutil",
     "fsutil", "cipher", "setx", "manage-bde"}
)  # fmt: skip
_GLOBAL_VALUE_FLAGS["oc"] = _GLOBAL_VALUE_FLAGS["kubectl"]
_GLOBAL_VALUE_FLAGS["vc"] = _GLOBAL_VALUE_FLAGS["vercel"]
_GLOBAL_VALUE_FLAGS["pnpm"] = frozenset({"-C", "--dir", "-F", "--filter"})


@dataclass(frozen=True)
class PastCall:
    """An earlier call of the session: when it was proposed, and its facts."""

    time: float
    facts: Facts


if TYPE_CHECKING:

    class History(Protocol):
        """Source of earlier calls for the history predicates."""

        def earlier(self, session: str) -> Iterable[PastCall]:
            """Earlier calls of *session* that were proposed and not denied."""
            ...

else:

    class History:
        """Source of earlier calls for the history predicates.

        Any object with ``earlier(session)`` serves; the audit log and
        :class:`MemoryHistory` do.  (A protocol while type checking.)
        """


class MemoryHistory:
    """In-memory :class:`History`, for tests and for replaying transcripts."""

    def __init__(self, calls: Iterable[PastCall] = ()) -> None:
        self.calls = list(calls)

    def add(self, facts: Facts, when: float) -> None:
        """Record a call as having been proposed at *when* (epoch seconds)."""
        self.calls.append(PastCall(when, facts))

    def earlier(self, session: str) -> Iterable[PastCall]:
        """Recorded calls of *session*, oldest first."""
        return [call for call in self.calls if call.facts.session == session]


@dataclass(eq=False, repr=False)
class _Session:
    """The earlier calls of one session, read from the history at most once."""

    history: History
    calls: list[PastCall] | None = None

    def earlier(self, session: str) -> list[PastCall]:
        if self.calls is None:
            self.calls = list(self.history.earlier(session))
        return self.calls


@dataclass(eq=False, repr=False)
class _Roots:
    """Nearest enclosing repositories, looked up at most once per directory.

    Nothing is looked up, and the lookup module is not even loaded, until a
    rule or an exception with ``repo_root`` has to be judged.  A lookup that
    fails is recorded and answered as unknown.
    """

    find: RepoFinder | None
    windows: bool
    found: dict[str, str | None] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def root(self, directory: str) -> str | None:
        """Repository root of *directory*; ``UNKNOWN_DIR`` when not known."""
        if directory == UNKNOWN_DIR or "$" in directory:
            return UNKNOWN_DIR
        if directory not in self.found:
            if self.find is None:
                from ember_armor.ledger.repo import finder

                self.find = finder(self.windows)
            try:
                self.found[directory] = self.find(directory)
            except OSError as exc:
                problem = f"repository lookup failed for {directory}: {exc}"
                self.errors.append(problem[:_ERROR_CHARS])
                self.found[directory] = UNKNOWN_DIR
        return self.found[directory]


@dataclass(frozen=True, eq=False, repr=False)
class _Area:
    """Resolved directory scope of a rule or of an exception.

    ``lenient`` is how a directory that cannot be known is judged: inside
    for the scope of a rule (a ``cd`` the gate cannot read must not lead out
    of it), outside for an exception (and must not lead into one).
    """

    under: tuple[str, ...]
    not_under: tuple[str, ...]
    roots: tuple[str, ...]
    lenient: bool


@dataclass(frozen=True, eq=False, repr=False)
class _Context:
    """What a predicate is evaluated with.

    ``base`` is the directory relative path patterns resolve against
    (``None``: the working directory of the call) and ``area`` the directory
    scope of the rule, which its history predicates apply to earlier calls.
    """

    base: str | None
    past: _Session | None
    now: float
    roots: _Roots
    area: _Area | None = None


# ---------------------------------------------------------------------------
# Leaf predicates
# ---------------------------------------------------------------------------
def _command_matches(command: SimpleCommand, pred: CommandPred, windows: bool) -> bool:
    if pred.shell != "any" and command.shell != pred.shell:
        return False
    caseless = program_name(command.argv[0]) in _CASELESS_PROGRAMS
    fold = command.shell != "bash" or caseless

    def norm(text: str) -> str:
        return text.lower() if fold else text

    # Windows finds ``GIT`` and ``Git.exe`` as well, whichever shell asks.
    name = program_name(command.argv[0], fold=fold or windows)
    programs = {p.lower() if windows else norm(p) for p in pred.program}
    if pred.program and name not in programs:
        return False
    rest = command.argv[1:]
    if pred.subcommand:
        value_flags = _GLOBAL_VALUE_FLAGS.get(name.lower(), frozenset())
        positions = operand_positions(
            command, value_flags, slash_flags=command.shell == "cmd"
        )[: len(pred.subcommand)]
        wanted = [norm(part) for part in pred.subcommand]
        if [norm(command.argv[i]) for i in positions] != wanted:
            return False
        # What follows the subcommand: ``git -C . checkout`` has no ``.``.
        rest = command.argv[positions[-1] + 1 :]
    if pred.flags_any and not any(has_flag(command, f) for f in pred.flags_any):
        return False
    if not all(has_flag(command, flag) for flag in pred.flags_all):
        return False
    if any(has_flag(command, flag) for flag in pred.flags_none):
        return False
    args = [norm(arg) for arg in rest]

    def listed(globs: Iterable[str]) -> bool:
        return any(fnmatchcase(arg, norm(glob)) for arg in args for glob in globs)

    if pred.args_any_glob and not listed(pred.args_any_glob):
        return False
    if listed(pred.args_none_glob):
        return False
    if pred.regex is not None:
        texts = (" ".join(rest), command.stdin, " ".join(command.upstream))
        return any(pred.regex.search(text[:TEXT_LIMIT]) for text in texts)
    return True


def _resolve(
    pattern: str, base: str | None, facts: Facts, *, bare: bool = False
) -> str:
    return resolve_pattern(
        pattern,
        base or facts.cwd,
        windows=facts.windows,
        home=facts.home,
        variables=facts.variables,
        bare_anywhere=bare,
    )


def _anywhere(pattern: str) -> bool:
    """True for a resolved pattern that does not depend on a location."""
    return pattern.startswith("**/")


def _under_any(path: str, directories: Iterable[str], windows: bool) -> bool:
    """True when *path* is inside one of the resolved *directories*."""
    return any(is_under(path, directory, windows=windows) for directory in directories)


def _within(path: str, cwd: str, directories: list[str], windows: bool) -> bool:
    """True when *path* is, or is inside, one of *directories* seen from *cwd*.

    A directory counts only when it is not the working directory and not
    above it: the part of the path it shares with *cwd* is never looked at.
    ``**/build`` therefore covers ``./build/x`` and ``../build``, and neither
    a project that lies below some directory named ``build`` nor that
    directory itself.
    """
    if not directories:
        return False
    parts, base = path.split("/"), cwd.split("/")
    if windows:
        base = [segment.lower() for segment in base]
    shared = 0
    for mine, theirs in zip(parts, base, strict=False):
        if (mine.lower() if windows else mine) != theirs:
            break
        shared += 1
    for end in range(shared + 1, len(parts) + 1):
        candidate = "/".join(parts[:end])
        if any(matches_glob(candidate, d, windows=windows) for d in directories):
            return True
    return False


def _path_holds(pred: PathPred, base: str | None, facts: Facts) -> bool:
    """True when one path of the call satisfies every field of *pred*."""
    if not facts.paths:
        return False
    windows = facts.windows
    under = [_resolve(d, base, facts) for d in pred.under]
    not_under = [_resolve(d, base, facts) for d in pred.not_under]
    not_within = [_resolve(d, base, facts) for d in pred.not_within]
    globs = [_resolve(g, base, facts, bare=True) for g in pred.glob]
    not_globs = [_resolve(g, base, facts, bare=True) for g in pred.not_glob]

    def matches(path: PathFact) -> bool:
        if pred.op != "any" and path.op != pred.op:
            return False
        if pred.recursive is not None and path.recursive != pred.recursive:
            return False
        if under and not _under_any(path.path, under, windows):
            return False
        # Where a path with an unresolved variable lies is not known, so only
        # an exception that holds anywhere (``**/name``) can apply to it.
        located = "$" not in path.path
        if _under_any(
            path.path, (d for d in not_under if located or _anywhere(d)), windows
        ):
            return False
        local = [d for d in not_within if located or _anywhere(d)]
        if _within(path.path, facts.cwd, local, windows):
            return False
        if any(
            matches_glob(path.path, glob, windows=windows)
            for glob in not_globs
            if located or _anywhere(glob)
        ):
            return False
        # An operand the shell still has to expand may name a matching file.
        return not globs or any(
            may_match(path.path, glob, windows=windows) for glob in globs
        )

    return any(matches(path) for path in facts.paths)


def _lookup(args: Any, dotted: str) -> Any:
    """Value at a dotted path in a structured tool input, or ``_MISSING``."""
    value = args
    for part in dotted.split("."):
        if isinstance(value, Mapping) and part in value:
            value = value[part]
        elif isinstance(value, list) and part.isdigit() and int(part) < len(value):
            value = value[int(part)]
        else:
            return _MISSING
    return value


def _number(value: Any) -> Fraction | float | None:
    """Exact value of a numeric argument (a float only when not finite).

    Comparisons and sums are exact, so they agree with what lint proves
    about the same rules.
    """
    from fractions import Fraction

    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        try:
            value = float(value)
        except ValueError:
            return None
    if isinstance(value, int) or (isinstance(value, float) and math.isfinite(value)):
        return Fraction(value)
    return value if isinstance(value, float) else None


def _ordered(left: Fraction | float, op: str, right: Fraction | float) -> bool:
    return {
        "<": left < right,
        "<=": left <= right,
        ">": left > right,
        ">=": left >= right,
        "==": left == right,
        "!=": left != right,
    }[op]


def _arg_holds(pred: ArgPred, facts: Facts) -> bool:
    value = _lookup(facts.args, pred.name)
    if value is _MISSING:
        return False
    if pred.op == "matches":
        text = value[:TEXT_LIMIT] if isinstance(value, str) else None
        return text is not None and pred.value.search(text) is not None
    if pred.op == "in":
        return value in pred.value
    left, right = _number(value), _number(pred.value)
    if left is not None and right is not None and not isinstance(pred.value, str):
        return _ordered(left, pred.op, right)
    if pred.op == "==":
        return bool(value == pred.value)
    if pred.op == "!=":
        return bool(value != pred.value)
    return False


def _expr_holds(pred: ExprPred, facts: Facts) -> bool:
    from fractions import Fraction

    total: Fraction | float = Fraction(0)
    for name, coefficient in pred.lhs:
        number = _number(_lookup(facts.args, name))
        if number is None:
            return False
        total += Fraction(coefficient) * number
    return _ordered(total, pred.op, Fraction(pred.rhs))


def _assigns(pred: AssignsPred, facts: Facts) -> bool:
    """True when the call sets a variable named by *pred* (Windows folds case)."""
    if facts.windows:
        names = [name.upper() for name in facts.assigned]
        return any(fnmatchcase(n, glob.upper()) for n in names for glob in pred.name)
    return any(fnmatchcase(n, glob) for n in facts.assigned for glob in pred.name)


def _text_holds(pred: TextRegexPred, facts: Facts) -> bool:
    value = _lookup(facts.args, pred.field)
    if value is _MISSING:
        return False
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    return pred.regex.search(text[:TEXT_LIMIT]) is not None


# ---------------------------------------------------------------------------
# Predicate tree
# ---------------------------------------------------------------------------
def _reads_history(pred: Predicate) -> bool:
    """True when evaluating *pred* may need the session's earlier calls."""
    if isinstance(pred, NotPrecededByPred | CountExceedsPred):
        return True
    if isinstance(pred, AllPred | AnyPred):
        return any(_reads_history(inner) for inner in pred.of)
    return isinstance(pred, NotPred) and _reads_history(pred.of)


def _cheapest_first(parts: tuple[Predicate, ...]) -> list[Predicate]:
    """Order the parts so the history is read only when nothing else decides."""
    return sorted(parts, key=_reads_history)


def _past_matches(pred: Predicate, facts: Facts, ctx: _Context) -> list[PastCall]:
    """Earlier calls of the session on which *pred* holds.

    A call without a session id has no history: unrelated calls must not
    vouch for each other.  A rule with a directory scope sees of an earlier
    call what it would see of this one: the commands that ran in scope.
    """
    if ctx.past is None or not facts.session:
        return []
    inner = replace(ctx, past=None)

    def seen(past: Facts) -> Facts | None:
        # Judge the earlier call with the path flavour and home of this one.
        now = replace(
            past, windows=facts.windows, home=facts.home, variables=facts.variables
        )
        return _view(now, ctx.area, ctx.roots)

    return [
        past
        for past in ctx.past.earlier(facts.session)
        if (view := seen(past.facts)) is not None and _holds(pred, view, inner)
    ]


def _holds(pred: Predicate, facts: Facts, ctx: _Context) -> bool:
    """Truth value of one predicate on the facts of a call."""
    if isinstance(pred, CommandPred):
        return any(
            _command_matches(command, pred, facts.windows)
            for command in facts.commands
            if command.argv
        )
    if isinstance(pred, PathPred):
        return _path_holds(pred, ctx.base, facts)
    if isinstance(pred, ArgPred):
        return _arg_holds(pred, facts)
    if isinstance(pred, ExprPred):
        return _expr_holds(pred, facts)
    if isinstance(pred, TextRegexPred):
        return _text_holds(pred, facts)
    if isinstance(pred, DynamicShellPred):
        if not pred.reason:
            return bool(facts.dynamic)
        return any(reason.kind in pred.reason for reason in facts.dynamic)
    if isinstance(pred, AssignsPred):
        return _assigns(pred, facts)
    if isinstance(pred, AllPred):
        return all(_holds(inner, facts, ctx) for inner in _cheapest_first(pred.of))
    if isinstance(pred, AnyPred):
        return any(_holds(inner, facts, ctx) for inner in _cheapest_first(pred.of))
    if isinstance(pred, NotPred):
        return not _holds(pred.of, facts, ctx)
    if isinstance(pred, NotPrecededByPred):
        return not _past_matches(pred.predicate, facts, ctx)
    if isinstance(pred, CountExceedsPred):
        matches = _past_matches(pred.predicate, facts, ctx)
        if pred.within_seconds is not None:
            oldest = ctx.now - pred.within_seconds
            matches = [past for past in matches if past.time >= oldest]
        return len(matches) > pred.max
    raise TypeError(f"unknown predicate {type(pred).__name__}")


# ---------------------------------------------------------------------------
# Directory scopes
# ---------------------------------------------------------------------------
def _area(
    under: tuple[str, ...],
    not_under: tuple[str, ...],
    roots: tuple[str, ...],
    base: str | None,
    facts: Facts,
    *,
    lenient: bool,
) -> _Area | None:
    """The directory scope with its patterns resolved; ``None`` when empty."""
    if not (under or not_under or roots):
        return None

    def resolved(patterns: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_resolve(pattern, base, facts) for pattern in patterns)

    return _Area(resolved(under), resolved(not_under), resolved(roots), lenient)


def _placed(directory: str, area: _Area, facts: Facts) -> bool:
    """True when *directory* is under the area's directories and no exception."""
    if area.under and not _under_any(directory, area.under, facts.windows):
        return False
    return not _under_any(directory, area.not_under, facts.windows)


def _rooted(path: str, area: _Area, facts: Facts, roots: _Roots) -> bool:
    """True when the nearest repository around *path* is one the area names."""
    root = roots.root(path)
    if root == UNKNOWN_DIR:
        return area.lenient
    return root is not None and any(
        matches_glob(root, wanted, windows=facts.windows) for wanted in area.roots
    )


def _inside(
    directory: str, where: str, area: _Area, facts: Facts, roots: _Roots
) -> bool:
    """True when something done in *directory* is in *area*.

    *where* is what ``repo_root`` is asked about: the same directory for a
    command, the file for a file tool.
    """
    if directory == UNKNOWN_DIR:
        return area.lenient
    if not _placed(directory, area, facts):
        return False
    return not area.roots or _rooted(where, area, facts, roots)


def _view(facts: Facts, area: _Area | None, roots: _Roots) -> Facts | None:
    """The part of a call that lies in *area*; ``None`` when nothing does.

    Of a shell call that is the commands that run in the area and the paths
    they touch.  A call without commands is judged as a whole on its working
    directory, and ``repo_root`` on each path it touches.
    """
    if area is None:
        return facts
    paths: tuple[PathFact, ...]
    if facts.commands:
        verdicts: dict[str, bool] = {}

        def inside(cwd: str) -> bool:
            if cwd not in verdicts:
                here = cwd or facts.cwd
                verdicts[cwd] = _inside(here, here, area, facts, roots)
            return verdicts[cwd]

        commands = tuple(c for c in facts.commands if inside(c.cwd))
        paths = tuple(path for path in facts.paths if inside(path.cwd))
        if not commands and not paths:
            return None
        if len(commands) == len(facts.commands) and len(paths) == len(facts.paths):
            return facts
        return replace(facts, commands=commands, paths=paths)
    if not _placed(facts.cwd, area, facts):
        return None
    if not area.roots:
        return facts
    if not facts.paths:
        return facts if _rooted(facts.cwd, area, facts, roots) else None
    paths = tuple(p for p in facts.paths if _rooted(p.path, area, facts, roots))
    if len(paths) == len(facts.paths):
        return facts
    return replace(facts, paths=paths) if paths else None


# ---------------------------------------------------------------------------
# Owner exceptions
# ---------------------------------------------------------------------------
def _excepted(
    rule: Rule,
    facts: Facts,
    view: Facts,
    exceptions: tuple[RuleException, ...],
    ctx: _Context,
) -> tuple[str, ...]:
    """Reasons of the owner's exceptions that drop *rule* for this call.

    An exception takes the commands it covers out of what the rule sees (for
    a file tool: the paths it covers).  The rule is dropped when it does not
    fire on what is left, and always when nothing is left.  So a rule that
    fired on something no single command owns (``dynamic_shell``, a variable
    that is set, a structured argument) is dropped only when every command
    the rule sees is covered.  Empty when the rule stands.
    """
    if not exceptable(rule.id):
        return ()
    zones = [
        (
            _area(e.cwd_under, (), e.repo_root, _NO_BASE, facts, lenient=False),
            e,
        )
        for e in exceptions
        if fnmatchcase(rule.id, e.rule)
        and (not e.tools or any(fnmatchcase(facts.tool, tool) for tool in e.tools))
    ]
    if not zones:
        return ()
    inner = replace(ctx, base=None, area=None)
    used: dict[str, None] = {}

    def covered(directory: str, where: str, alone: Callable[[], Facts]) -> bool:
        for zone, exception in zones:
            if zone is not None and not _inside(
                directory, where, zone, facts, ctx.roots
            ):
                continue
            when = exception.when
            if when is None or _holds(when, alone(), inner):
                used[exception.reason] = None
                return True
        return False

    commands: tuple[SimpleCommand, ...] = ()
    paths: tuple[PathFact, ...] = ()
    if facts.commands:
        visible = {id(command) for command in view.commands}
        gone = set()
        for index, command in enumerate(facts.commands):
            here = command.cwd or facts.cwd

            def alone(index: int = index, command: SimpleCommand = command) -> Facts:
                own = tuple(path for path in facts.paths if path.source == index)
                return replace(facts, commands=(command,), paths=own)

            if id(command) in visible and covered(here, here, alone):
                gone.add(index)
        if not gone:
            return ()
        commands = tuple(
            command
            for index, command in enumerate(facts.commands)
            if id(command) in visible and index not in gone
        )
        paths = tuple(path for path in view.paths if path.source not in gone)
    elif view.paths:

        def only(path: PathFact) -> Callable[[], Facts]:
            return lambda: replace(facts, paths=(path,))

        paths = tuple(
            path for path in view.paths if not covered(facts.cwd, path.path, only(path))
        )
        if len(paths) == len(view.paths):
            return ()
    elif not covered(facts.cwd, facts.cwd, lambda: facts):
        return ()
    if commands or paths:
        rest = replace(facts, commands=commands, paths=paths)
        if _holds(rule.predicate, rest, ctx) != rule.obligation:
            return ()  # it still fires on what no exception covers
    return tuple(used)


def evaluate(
    rules: Iterable[Rule],
    facts: Facts,
    history: History | None = None,
    *,
    now: float | None = None,
    exceptions: Iterable[RuleException] = (),
    repo_root: RepoFinder | None = None,
) -> Decision:
    """Decide what the ledger says about one call.

    Parameters
    ----------
    rules:
        Active rules (expiry and the unconfirmed cap already applied; see
        :func:`ember_armor.ledger.store.load_rules`).
    facts:
        Facts extracted from the proposed call.
    history:
        Earlier calls of the session, for ``not_preceded_by`` and
        ``count_exceeds``.  ``None`` means no earlier calls.
    now:
        Current time in epoch seconds (for ``within_seconds``).
    exceptions:
        The owner's exceptions in force (``exceptions`` in ``config.json``).
    repo_root:
        ``repo_root(directory)`` giving the root of the nearest enclosing
        git repository of a normalised directory, ``None`` when there is
        none; it may raise :class:`OSError`.  Defaults to a lookup on the
        filesystem (:mod:`ember_armor.ledger.repo`), which runs only when a
        rule or an exception with ``repo_root`` has to be judged.

    Returns
    -------
    Decision
        ``none`` when no rule fired, otherwise the most restrictive effect
        with every rule that fired, strongest first.  ``excepted`` names the
        rules an exception dropped.  ``error`` is set when a repository
        lookup failed; the scope it was needed for then counts as holding
        for a rule and as not holding for an exception.
    """
    moment = time.time() if now is None else now
    past = None if history is None else _Session(history)
    roots = _Roots(repo_root, facts.windows)
    exceptions = tuple(exceptions)
    fired: list[FiredRule] = []
    excepted: list[ExceptedRule] = []
    for rule in rules:
        applies = rule.applies
        if applies.tools and not any(
            fnmatchcase(facts.tool, tool) for tool in applies.tools
        ):
            continue
        area = None
        if applies.directories:
            area = _area(
                applies.cwd_under,
                applies.cwd_not_under,
                applies.repo_root,
                rule.base,
                facts,
                lenient=True,
            )
        view = _view(facts, area, roots)
        if view is None:
            continue
        ctx = _Context(rule.base, past, moment, roots, area)
        if _holds(rule.predicate, view, ctx) == rule.obligation:
            continue
        reasons = _excepted(rule, facts, view, exceptions, ctx) if exceptions else ()
        if reasons:
            excepted += [ExceptedRule(rule.id, reason) for reason in reasons]
            continue
        fired.append(
            FiredRule(rule.id, rule.text, rule.source, rule.effect, rule.origin)
        )
    error = "; ".join(dict.fromkeys(roots.errors)) or None
    fired.sort(key=lambda rule: -SEVERITY[rule.effect])
    effect = fired[0].effect if fired else "none"
    return Decision(effect, tuple(fired), error, tuple(excepted))
