"""Static checks of a ledger with the Z3 solver (``ember-gate lint``).

The gate never needs a solver: it evaluates one concrete call directly.
Lint asks questions about *every possible* call, so it describes a call
symbolically:

- A numeric argument is a real variable guarded by "present" and "is a
  number" flags.  As in the engine, a comparison on a missing or non-numeric
  argument is false.
- Tool names, working directories, command predicates and path predicates
  are boolean atoms, with implications added only where they are certain
  (see :mod:`ember_armor.ledger.implies`).
- ``text_regex`` and the history predicates are atoms nothing is known about.

Every finding is an "unsatisfiable" answer from the solver.  Because the
atoms allow more calls than can really happen, a finding is certain and a
clean result is not a proof.  Numbers are the exact values of the floats
the rules hold, as in the engine.  Non-finite arguments (``1e999``) are not
modelled.

Z3 is imported lazily inside :func:`lint`; it comes with the optional
``smt`` extra.
"""

from __future__ import annotations

import importlib
import json
import math
import operator
import os
from collections.abc import Hashable, Iterable
from dataclasses import dataclass
from datetime import date
from fnmatch import fnmatchcase
from fractions import Fraction
from itertools import permutations
from typing import Any, TypeVar

from ember_armor.ledger.facts import FILE_TOOLS, SHELL_TOOLS
from ember_armor.ledger.implies import (
    command_implies,
    directory_inside,
    path_implies,
    resolved,
)
from ember_armor.ledger.model import (
    SEVERITY,
    AllPred,
    AnyPred,
    Applies,
    ArgPred,
    AssignsPred,
    CommandPred,
    DynamicShellPred,
    ExprPred,
    NotPred,
    PathPred,
    Predicate,
    Rule,
    TextRegexPred,
)
from ember_armor.ledger.shell.core import DYNAMIC_KINDS

TIMEOUT_MS = 10_000
_COMPARE = {
    "<": operator.lt,
    "<=": operator.le,
    ">": operator.gt,
    ">=": operator.ge,
    "==": operator.eq,
    "!=": operator.ne,
}
_Key = TypeVar("_Key", bound=Hashable)


class SolverUnavailableError(RuntimeError):
    """Z3 is not installed, so the ledger cannot be linted."""


@dataclass(frozen=True)
class Finding:
    """One problem lint found in the ledger.

    ``kind`` is ``dead``, ``blanket``, ``shadowed`` or ``contradiction``.
    ``rules`` holds the rule ids involved, the rule the finding is about
    first.  A contradiction also names the ``scope`` in which every call is
    denied.
    """

    kind: str
    rules: tuple[str, ...]
    message: str
    scope: Applies | None = None


@dataclass(frozen=True, eq=False)
class _Case:
    """A rule as solver terms: its scope, its condition, and both together."""

    rule: Rule
    scope: Any
    fires: Any
    applies: Any


def _is_number(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def _constant_key(value: Any) -> str:
    """Key under which equal constants share one equality atom."""
    if _is_number(value) and math.isfinite(value):
        return f"number:{Fraction(value)}"
    return json.dumps(value, sort_keys=True, default=str)


def _describe(scope: Applies) -> str:
    parts = [f"tool {tool}" for tool in scope.tools]
    parts += [f"working directory under {d}" for d in scope.cwd_under]
    return " and ".join(parts) if parts else "everywhere"


class _Model:
    """Symbolic description of one arbitrary tool call."""

    def __init__(self, z3: Any, windows: bool) -> None:
        self.z3 = z3
        self.windows = windows
        self.tools: dict[str, Any] = {}
        self.directories: dict[tuple[str, str | None], Any] = {}
        self.commands: dict[CommandPred, Any] = {}
        self.paths: dict[tuple[PathPred, str | None], Any] = {}
        self.opaque: dict[Hashable, Any] = {}
        self.kinds = {kind: z3.Bool(f"dynamic:{kind}") for kind in DYNAMIC_KINDS}
        self.values: dict[str, tuple[Any, Any, Any]] = {}
        self.equalities: dict[str, dict[str, tuple[Any, Any]]] = {}
        for name in (*SHELL_TOOLS, *FILE_TOOLS):
            self._atom(self.tools, name, "tool")

    def _atom(self, table: dict[_Key, Any], key: _Key, label: str) -> Any:
        if key not in table:
            table[key] = self.z3.Bool(f"{label}#{len(table)}")
        return table[key]

    def _value(self, name: str) -> tuple[Any, Any, Any]:
        """``(present, is a number, numeric value)`` of one argument."""
        if name not in self.values:
            self.values[name] = (
                self.z3.Bool(f"present:{name}"),
                self.z3.Bool(f"numeric:{name}"),
                self.z3.Real(f"value:{name}"),
            )
        return self.values[name]

    def _real(self, number: float) -> Any:
        fraction = Fraction(number)
        return self.z3.Q(fraction.numerator, fraction.denominator)

    def _equal(self, name: str, constant: Any) -> Any:
        """Atom: the argument is equal to *constant* as Python compares them."""
        table = self.equalities.setdefault(name, {})
        key = _constant_key(constant)
        if key not in table:
            table[key] = (constant, self.z3.Bool(f"equal:{name}#{len(table)}"))
        return table[key][1]

    # -- predicates ----------------------------------------------------------
    def _arg(self, pred: ArgPred) -> Any:
        z3 = self.z3
        present, numeric, value = self._value(pred.name)
        if pred.op == "matches":
            key = ("matches", pred.name, pred.value.pattern)
            return z3.And(present, self._atom(self.opaque, key, "matches"))
        if pred.op == "in":
            return z3.Or([self._equal(pred.name, item) for item in pred.value])
        if not _is_number(pred.value):
            same = self._equal(pred.name, pred.value)
            if pred.op == "==":
                return same
            if pred.op == "!=":
                return z3.And(present, z3.Not(same))
            return z3.BoolVal(False)
        if not math.isfinite(pred.value):
            return self._atom(self.opaque, repr(pred), "arg")
        compared = _COMPARE[pred.op](value, self._real(pred.value))
        if pred.op not in ("==", "!="):
            return z3.And(numeric, compared)
        same = self._equal(pred.name, pred.value)
        other = same if pred.op == "==" else z3.And(present, z3.Not(same))
        return z3.If(numeric, compared, other)

    def _expr(self, pred: ExprPred) -> Any:
        z3 = self.z3
        terms = [self._real(c) * self._value(name)[2] for name, c in pred.lhs]
        numeric = [self._value(name)[1] for name, _ in pred.lhs]
        compared = _COMPARE[pred.op](z3.Sum(terms), self._real(pred.rhs))
        return z3.And(*numeric, compared)

    def predicate(self, pred: Predicate, base: str | None) -> Any:
        """Solver term for *pred* in a rule whose patterns resolve on *base*."""
        z3 = self.z3
        if isinstance(pred, CommandPred):
            return self._atom(self.commands, pred, "command")
        if isinstance(pred, PathPred):
            return self._atom(self.paths, (pred, base), "path")
        if isinstance(pred, ArgPred):
            return self._arg(pred)
        if isinstance(pred, ExprPred):
            return self._expr(pred)
        if isinstance(pred, DynamicShellPred):
            return z3.Or([self.kinds[kind] for kind in pred.reason or DYNAMIC_KINDS])
        if isinstance(pred, AllPred):
            return z3.And([self.predicate(inner, base) for inner in pred.of])
        if isinstance(pred, AnyPred):
            return z3.Or([self.predicate(inner, base) for inner in pred.of])
        if isinstance(pred, NotPred):
            return z3.Not(self.predicate(pred.of, base))
        if isinstance(pred, TextRegexPred):
            return self._atom(self.opaque, repr(pred), "text")
        if isinstance(pred, AssignsPred):
            return self._atom(self.opaque, repr(pred), "assigns")
        return self._atom(self.opaque, (repr(pred), base), "history")

    def scope(self, scope: Applies, base: str | None) -> Any:
        """Term that is true for the calls *scope* covers."""
        z3 = self.z3
        parts = []
        names = [self._atom(self.tools, tool, "tool") for tool in scope.tools]
        if names:
            parts.append(z3.Or(names))
        under = [
            self._atom(self.directories, (directory, base), "cwd")
            for directory in scope.cwd_under
        ]
        if under:
            parts.append(z3.Or(under))
        return z3.And(parts)

    # -- what is certain about any call --------------------------------------
    def _tool_axioms(self) -> list[Any]:
        z3 = self.z3
        known = [atom for name, atom in self.tools.items() if set(name) == {"*"}]
        for (a, atom_a), (b, atom_b) in permutations(self.tools.items(), 2):
            if any(char in a for char in "*?["):
                continue
            if fnmatchcase(a, b):
                known.append(z3.Implies(atom_a, atom_b))
            else:
                known.append(z3.Not(z3.And(atom_a, atom_b)))
        shell = z3.Or([self.tools[name] for name in SHELL_TOOLS])
        files = z3.Or(shell, *[self.tools[name] for name in FILE_TOOLS])
        for atom in (*self.commands.values(), *self.kinds.values()):
            known.append(z3.Implies(atom, shell))
        known += [z3.Implies(atom, files) for atom in self.paths.values()]
        return known

    def _argument_axioms(self) -> list[Any]:
        z3 = self.z3
        known = []
        for name, table in self.equalities.items():
            present, numeric, value = self._value(name)
            for constant, atom in table.values():
                known.append(z3.Implies(atom, present))
                if _is_number(constant) and math.isfinite(constant):
                    same = value == self._real(constant)
                    known.append(z3.Implies(z3.And(atom, numeric), same))
            for (a, atom_a), (b, atom_b) in permutations(table.values(), 2):
                if a != b:
                    known.append(z3.Not(z3.And(atom_a, atom_b)))
        for present, numeric, _ in self.values.values():
            known.append(z3.Implies(numeric, present))
        return known

    def axioms(self) -> list[Any]:
        """Implications that hold for every call (add after all predicates)."""
        z3 = self.z3
        windows = self.windows
        known = self._tool_axioms() + self._argument_axioms()
        for (command, atom), (wider, other) in permutations(self.commands.items(), 2):
            if command_implies(command, wider):
                known.append(z3.Implies(atom, other))
        for (path, atom), (around, other) in permutations(self.paths.items(), 2):
            if path_implies(*path, *around, windows=windows):
                known.append(z3.Implies(atom, other))
        for (inner, atom), (outer, other) in permutations(self.directories.items(), 2):
            inside = resolved(*inner, windows=windows)
            around_it = resolved(*outer, windows=windows)
            if directory_inside(inside, around_it, windows=windows):
                known.append(z3.Implies(atom, other))
        return known


class _Linter:
    """Runs the four checks on the encoded rules."""

    def __init__(self, z3: Any, rules: list[Rule], windows: bool) -> None:
        self.z3 = z3
        self.model = _Model(z3, windows)
        self.cases = [self._case(rule) for rule in rules]
        self.solver = z3.Solver()
        self.solver.set("timeout", TIMEOUT_MS)
        self.solver.add(self.model.axioms())

    def _case(self, rule: Rule) -> _Case:
        z3 = self.z3
        scope = self.model.scope(rule.applies, rule.base)
        holds = self.model.predicate(rule.predicate, rule.base)
        fires = z3.Not(holds) if rule.obligation else holds
        return _Case(rule, scope, fires, z3.And(scope, fires))

    def _impossible(self, *conditions: Any) -> bool:
        """True when no call satisfies every condition."""
        self.solver.push()
        self.solver.add(*conditions)
        verdict = self.solver.check()
        self.solver.pop()
        return bool(verdict == self.z3.unsat)

    def _covers(self, a: _Case, b: _Case) -> bool:
        """True when *a* fires on every call *b* fires on."""
        return self._impossible(b.applies, self.z3.Not(a.applies))

    def run(self) -> list[Finding]:
        """Dead and blanket rules, then shadowed rules, then contradictions."""
        findings: list[Finding] = []
        dead: list[_Case] = []
        blanket: list[_Case] = []
        for case in self.cases:
            if self._impossible(case.applies):
                dead.append(case)
            elif self._impossible(case.scope, self.z3.Not(case.fires)):
                blanket.append(case)
        for case in self.cases:
            rule = case.rule
            if rule.origin == "builtin":
                continue
            if case in dead:
                text = "never fires: no call in its scope can meet its condition"
                findings.append(Finding("dead", (rule.id,), f"{rule.id} {text}"))
                continue
            if case in blanket:
                where = _describe(rule.applies)
                text = f"fires on every call in its scope ({where})"
                findings.append(Finding("blanket", (rule.id,), f"{rule.id} {text}"))
            findings += self._shadowed(case, dead)
        settled = dead + blanket
        return findings + self._contradictions(
            [c for c in self.cases if c.rule.effect == "deny" and c not in settled]
        )

    def _shadowed(self, case: _Case, dead: list[_Case]) -> list[Finding]:
        """The finding for *case* if other rules make it redundant."""
        rule = case.rule
        rank = SEVERITY[rule.effect]
        position = self.cases.index(case)
        stronger = []
        for index, other in enumerate(self.cases):
            if other is case or other in dead or SEVERITY[other.rule.effect] < rank:
                continue
            if not self._covers(other, case):
                continue
            twin = SEVERITY[other.rule.effect] == rank and self._covers(case, other)
            if twin and index > position:
                continue  # equivalent rules: only the later one is reported
            stronger.append(other.rule)
        if not stronger:
            return []
        names = ", ".join(
            f"{r.id} ({r.effect}{'' if r.confirmed else ', unconfirmed'})"
            for r in stronger
        )
        message = f"{rule.id} ({rule.effect}) is shadowed: whenever it fires, so does "
        ids = (rule.id, *(r.id for r in stronger))
        return [Finding("shadowed", ids, message + names)]

    def _scopes(self, cases: list[_Case]) -> list[tuple[Applies, Any]]:
        """Scopes to test for contradictions, widest first.

        One per tool pattern and working directory the deny rules name.
        """
        found: dict[Hashable, tuple[Applies, Any]] = {}
        for case in cases:
            applies, base = case.rule.applies, case.rule.base
            for tool in applies.tools or (None,):
                for directory in applies.cwd_under or (None,):
                    scope = Applies(
                        tools=(tool,) if tool else (),
                        cwd_under=(directory,) if directory else (),
                    )
                    key = (scope, base if directory else None)
                    found.setdefault(key, (scope, self.model.scope(scope, base)))
        return sorted(
            found.values(), key=lambda item: len(item[0].tools + item[0].cwd_under)
        )

    def _contradictions(self, cases: list[_Case]) -> list[Finding]:
        """Sets of deny rules that together deny every call of a scope.

        Each set comes from the solver's unsat core, reduced until no rule
        can be dropped from it.  One set is reported per scope.
        """
        z3 = self.z3
        marks = [z3.Bool(f"deny#{index}") for index in range(len(cases))]
        for mark, case in zip(marks, cases, strict=True):
            self.solver.add(z3.Implies(mark, z3.Not(case.applies)))
        findings: list[Finding] = []
        reported: list[list[Any]] = []
        for scope, term in self._scopes(cases):
            self.solver.push()
            self.solver.add(term)
            core = self._core(marks, reported)
            self.solver.pop()
            if not core:
                continue
            reported.append(core)
            names = {str(mark) for mark in core}
            ids = tuple(
                case.rule.id
                for mark, case in zip(marks, cases, strict=True)
                if str(mark) in names
            )
            where = _describe(scope)
            where = where if where == "everywhere" else f"for {where}"
            subject = (
                f"deny rules {', '.join(ids)} together deny"
                if len(ids) > 1
                else f"deny rule {ids[0]} denies"
            )
            message = f"{subject} every call {where}"
            unconfirmed = [
                case.rule.id
                for case in cases
                if case.rule.id in ids and not case.rule.confirmed
            ]
            if unconfirmed:
                message += (
                    f" (once confirmed: {', '.join(unconfirmed)} "
                    "can only warn until then)"
                )
            findings.append(Finding("contradiction", ids, message, scope))
        return findings

    def _core(self, marks: list[Any], reported: list[list[Any]]) -> list[Any]:
        """Irreducible set of *marks* that leaves no call allowed, if any.

        Empty when some call is allowed, when the scope itself is empty, or
        when a set already reported explains this scope too.
        """
        unsat = self.z3.unsat
        if any(self.solver.check(*known) == unsat for known in reported):
            return []
        if self.solver.check(*marks) != unsat:
            return []
        names = {str(mark) for mark in self.solver.unsat_core()}
        core = [mark for mark in marks if str(mark) in names]
        for mark in list(core):
            rest = [other for other in core if other is not mark]
            if self.solver.check(*rest) == unsat:
                core = rest
        return core


def lint(
    rules: Iterable[Rule], *, windows: bool | None = None, today: date | None = None
) -> list[Finding]:
    """Check a ledger for dead, blanket, shadowed and contradictory rules.

    Parameters
    ----------
    rules:
        The rules as written (:func:`ember_armor.ledger.store.load_all`).
        Declared effects are used whether or not a rule is confirmed.
        Built-in rules take part but are never themselves reported as dead,
        blanket or shadowed.
    windows:
        Path flavour for comparing path patterns; defaults to the platform.
    today:
        Rules that expired before this date are ignored; defaults to today.

    Raises
    ------
    SolverUnavailableError
        If Z3 is not installed (it comes with the ``smt`` extra).
    """
    try:
        z3: Any = importlib.import_module("z3")
    except ImportError as exc:
        raise SolverUnavailableError(
            "Ledger lint needs the Z3 solver, which is not installed. "
            'Install the optional extra: pip install "ember-armor[smt]"'
        ) from exc
    day = today or date.today()
    live = [rule for rule in rules if rule.expires is None or day <= rule.expires]
    flavour = os.name == "nt" if windows is None else windows
    return _Linter(z3, live, flavour).run()
