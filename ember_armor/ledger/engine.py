"""Evaluate ledger rules against the facts of one tool call.

Evaluation is direct: each predicate is computed on the extracted facts.
No solver is involved and no model is called.  When several rules fire the
most restrictive effect wins (``deny`` over ``ask`` over ``warn``).
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from fnmatch import fnmatchcase
from typing import Any, Protocol

from ember_armor.ledger.facts import Facts
from ember_armor.ledger.model import (
    SEVERITY,
    AllPred,
    AnyPred,
    ArgPred,
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
from ember_armor.ledger.paths import is_under, matches_glob, resolve_pattern
from ember_armor.ledger.shell import SimpleCommand, program_name
from ember_armor.ledger.shell.argv import has_flag, operands
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


@dataclass(frozen=True)
class _Context:
    rule: Rule
    history: History | None
    now: float


# ---------------------------------------------------------------------------
# Leaf predicates
# ---------------------------------------------------------------------------
def _command_matches(command: SimpleCommand, pred: CommandPred) -> bool:
    if pred.shell != "any" and command.shell != pred.shell:
        return False
    fold = command.shell != "bash"

    def norm(text: str) -> str:
        return text.lower() if fold else text

    name = program_name(command.argv[0], fold=fold)
    if pred.program and name not in {norm(p) for p in pred.program}:
        return False
    if pred.subcommand:
        value_flags = _GLOBAL_VALUE_FLAGS.get(name.lower(), frozenset())
        leading = operands(command, value_flags, slash_flags=command.shell == "cmd")
        wanted = [norm(part) for part in pred.subcommand]
        if [norm(part) for part in leading[: len(wanted)]] != wanted:
            return False
    if pred.flags_any and not any(has_flag(command, f) for f in pred.flags_any):
        return False
    if not all(has_flag(command, flag) for flag in pred.flags_all):
        return False
    if pred.args_any_glob:
        args = [norm(arg) for arg in command.argv[1:]]
        globs = [norm(glob) for glob in pred.args_any_glob]
        return any(fnmatchcase(arg, glob) for arg in args for glob in globs)
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


def _under_any(path: str, directories: Iterable[str], windows: bool) -> bool:
    """True when *path* is inside one of the resolved *directories*."""
    return any(is_under(path, directory, windows=windows) for directory in directories)


def _path_holds(pred: PathPred, rule: Rule, facts: Facts) -> bool:
    """True when one path of the call satisfies every field of *pred*."""
    windows = facts.windows
    under = [_resolve(d, rule, facts) for d in pred.under]
    not_under = [_resolve(d, rule, facts) for d in pred.not_under]
    globs = [_resolve(g, rule, facts, bare=True) for g in pred.glob]

    def matches(path: PathFact) -> bool:
        if pred.op != "any" and path.op != pred.op:
            return False
        if pred.recursive is not None and path.recursive != pred.recursive:
            return False
        if under and not _under_any(path.path, under, windows):
            return False
        if _under_any(path.path, not_under, windows):
            return False
        return not globs or any(
            matches_glob(path.path, glob, windows=windows) for glob in globs
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


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _ordered(left: float, op: str, right: float) -> bool:
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
    total = 0.0
    for name, coefficient in pred.lhs:
        number = _number(_lookup(facts.args, name))
        if number is None:
            return False
        total += coefficient * number
    return _ordered(total, pred.op, pred.rhs)


def _text_holds(pred: TextRegexPred, facts: Facts) -> bool:
    value = _lookup(facts.args, pred.field)
    if value is _MISSING:
        return False
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    return pred.regex.search(text[:TEXT_LIMIT]) is not None


# ---------------------------------------------------------------------------
# Predicate tree
# ---------------------------------------------------------------------------
def _past_matches(pred: Predicate, facts: Facts, ctx: _Context) -> list[PastCall]:
    """Earlier calls of the session on which *pred* holds."""
    if ctx.history is None:
        return []
    env = {"windows": facts.windows, "home": facts.home, "variables": facts.variables}
    inner = replace(ctx, history=None)
    return [
        past
        for past in ctx.history.earlier(facts.session)
        if _holds(pred, replace(past.facts, **env), inner)
    ]


def _holds(pred: Predicate, facts: Facts, ctx: _Context) -> bool:
    """Truth value of one predicate on the facts of a call."""
    if isinstance(pred, CommandPred):
        return any(_command_matches(c, pred) for c in facts.commands if c.argv)
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
    if isinstance(pred, AllPred):
        return all(_holds(inner, facts, ctx) for inner in pred.of)
    if isinstance(pred, AnyPred):
        return any(_holds(inner, facts, ctx) for inner in pred.of)
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
    fired: list[FiredRule] = []
    for rule in rules:
        if not _in_scope(rule, facts):
            continue
        holds = _holds(rule.predicate, facts, _Context(rule, history, moment))
        if holds != rule.obligation:
            fired.append(FiredRule(rule.id, rule.text, rule.source, rule.effect))
    if not fired:
        return Decision()
    fired.sort(key=lambda rule: -SEVERITY[rule.effect])
    return Decision(effect=fired[0].effect, fired=tuple(fired))
