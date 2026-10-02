"""Evaluate ledger rules against the facts of one tool call.

Evaluation is direct: each predicate is computed on the extracted facts.
No solver is involved and no model is called.  When several rules fire the
most restrictive effect wins (``deny`` over ``ask`` over ``warn``).
"""

from __future__ import annotations

import json
import math
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from fnmatch import fnmatchcase
from fractions import Fraction
from typing import Any, Protocol

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
    ExprPred,
    FiredRule,
    NotPrecededByPred,
    NotPred,
    PathPred,
    Predicate,
    Rule,
    TextRegexPred,
)
from ember_armor.ledger.paths import (
    is_under,
    matches_glob,
    may_match,
    resolve_pattern,
)
from ember_armor.ledger.shell import SimpleCommand, program_name
from ember_armor.ledger.shell.argv import has_flag, operand_positions
from ember_armor.ledger.shellpaths import PathFact

TEXT_LIMIT = 20_000
_MISSING = object()

#: Options that take a value and may stand before a program's subcommand.
_GLOBAL_VALUE_FLAGS: dict[str, frozenset[str]] = {
    "git": frozenset({"-C", "-c", "--git-dir", "--work-tree", "--namespace"}),
    "docker": frozenset({"--context", "-c", "--config", "-H", "--host", "-l",
                         "--log-level"}),
    "kubectl": frozenset({"-n", "--namespace", "--context", "--kubeconfig",
                          "--cluster", "--user", "-s", "--server", "--as"}),
    "aws": frozenset({"--profile", "--region", "--endpoint-url", "--output"}),
    "gh": frozenset({"-R", "--repo"}),
    "npm": frozenset({"--prefix", "-w", "--workspace"}),
    "vercel": frozenset({"-t", "--token", "-S", "--scope", "--cwd", "-A",
                         "--local-config", "-Q", "--global-config"}),
}  # fmt: skip
_GLOBAL_VALUE_FLAGS["podman"] = _GLOBAL_VALUE_FLAGS["docker"]
_GLOBAL_VALUE_FLAGS["oc"] = _GLOBAL_VALUE_FLAGS["kubectl"]
_GLOBAL_VALUE_FLAGS["vc"] = _GLOBAL_VALUE_FLAGS["vercel"]
_GLOBAL_VALUE_FLAGS["pnpm"] = frozenset({"-C", "--dir", "-F", "--filter"})


@dataclass(frozen=True)
class PastCall:
    """An earlier call of the session: when it was proposed, and its facts."""

    time: float
    facts: Facts


class History(Protocol):
    """Source of earlier calls for the history predicates."""

    def earlier(self, session: str) -> Iterable[PastCall]:
        """Earlier calls of *session* that were proposed and not denied."""
        ...


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


@dataclass
class _Session:
    """The earlier calls of one session, read from the history at most once."""

    history: History
    calls: list[PastCall] | None = None

    def earlier(self, session: str) -> list[PastCall]:
        if self.calls is None:
            self.calls = list(self.history.earlier(session))
        return self.calls


@dataclass(frozen=True)
class _Context:
    rule: Rule
    past: _Session | None
    now: float


# ---------------------------------------------------------------------------
# Leaf predicates
# ---------------------------------------------------------------------------
def _command_matches(command: SimpleCommand, pred: CommandPred, windows: bool) -> bool:
    if pred.shell != "any" and command.shell != pred.shell:
        return False
    fold = command.shell != "bash"

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


def _resolve(pattern: str, rule: Rule, facts: Facts, *, bare: bool = False) -> str:
    return resolve_pattern(
        pattern,
        rule.base or facts.cwd,
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


def _path_holds(pred: PathPred, rule: Rule, facts: Facts) -> bool:
    """True when one path of the call satisfies every field of *pred*."""
    if not facts.paths:
        return False
    windows = facts.windows
    under = [_resolve(d, rule, facts) for d in pred.under]
    not_under = [_resolve(d, rule, facts) for d in pred.not_under]
    not_within = [_resolve(d, rule, facts) for d in pred.not_within]
    globs = [_resolve(g, rule, facts, bare=True) for g in pred.glob]
    not_globs = [_resolve(g, rule, facts, bare=True) for g in pred.not_glob]

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
    vouch for each other.
    """
    if ctx.past is None or not facts.session:
        return []
    inner = replace(ctx, past=None)

    def as_now(past: Facts) -> Facts:
        # Judge the earlier call with the path flavour and home of this one.
        return replace(
            past, windows=facts.windows, home=facts.home, variables=facts.variables
        )

    return [
        past
        for past in ctx.past.earlier(facts.session)
        if _holds(pred, as_now(past.facts), inner)
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
        return _path_holds(pred, ctx.rule, facts)
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


def _in_scope(rule: Rule, facts: Facts) -> bool:
    tools, directories = rule.applies.tools, rule.applies.cwd_under
    if tools and not any(fnmatchcase(facts.tool, tool) for tool in tools):
        return False
    resolved = [_resolve(directory, rule, facts) for directory in directories]
    return not resolved or _under_any(facts.cwd, resolved, facts.windows)


def evaluate(
    rules: Iterable[Rule],
    facts: Facts,
    history: History | None = None,
    *,
    now: float | None = None,
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

    Returns
    -------
    Decision
        ``none`` when no rule fired, otherwise the most restrictive effect
        with every rule that fired, strongest first.
    """
    moment = time.time() if now is None else now
    past = None if history is None else _Session(history)
    fired: list[FiredRule] = []
    for rule in rules:
        if not _in_scope(rule, facts):
            continue
        holds = _holds(rule.predicate, facts, _Context(rule, past, moment))
        if holds != rule.obligation:
            fired.append(
                FiredRule(rule.id, rule.text, rule.source, rule.effect, rule.origin)
            )
    if not fired:
        return Decision()
    fired.sort(key=lambda rule: -SEVERITY[rule.effect])
    return Decision(effect=fired[0].effect, fired=tuple(fired))
