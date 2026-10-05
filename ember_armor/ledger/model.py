"""Rule, predicate and decision data structures for the constraint ledger.

A ledger is ``{"version": 1, "rules": [...]}``.  :func:`parse_ledger` turns
that JSON into :class:`Rule` objects and rejects anything it does not
understand: the predicate set is closed, so a typo must be an error and never
a rule that silently matches nothing.
"""

from __future__ import annotations

import dataclasses
import math
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime
from fnmatch import fnmatchcase

from ember_armor.ledger.shell.core import DYNAMIC_KINDS

TYPE_CHECKING = False
if TYPE_CHECKING:
    from typing import Any

    from ember_armor.ledger.exceptions import ExceptedRule, RuleException

LEDGER_VERSION = 1
EFFECTS = ("warn", "ask", "deny")
SEVERITY = {"none": 0, "warn": 1, "ask": 2, "deny": 3}
PATH_OPS = ("read", "write", "delete", "any")
ARG_OPS = ("<", "<=", ">", ">=", "==", "!=", "in", "matches")
EXPR_OPS = ("<", "<=", ">", ">=", "==", "!=")
SHELLS = ("bash", "powershell", "any")
BUILTIN_PREFIX = "builtin."
#: Rules no exception can drop: the deny rules of the built-in pack and the
#: rules that guard the gate itself (also any later ``builtin.gate.`` rule).
UNEXCEPTABLE = (
    "builtin.delete.protected",
    "builtin.delete.git-dir",
    "builtin.gate.files",
    "builtin.gate.rules",
    "builtin.gate.environment",
    "builtin.gate.host-settings",
)
GATE_RULES = "builtin.gate."
#: Longest rule text and source quoted to the agent when a rule fires.
REASON_CHARS = 400

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}")


class LedgerError(ValueError):
    """A ledger file or rule is malformed."""


# ---------------------------------------------------------------------------
# Predicates
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class CommandPred:
    """Matches one simple command of the parsed shell input.

    Every field must hold for the same command.  ``flags_none`` and
    ``args_none_glob`` are the exceptions (a dry run, ``--help``).  The
    argument fields look at what follows the subcommand; ``args_regex`` also
    searches the command's here-document and the stage that pipes into it.
    """

    program: tuple[str, ...] = ()
    subcommand: tuple[str, ...] = ()
    flags_any: tuple[str, ...] = ()
    flags_all: tuple[str, ...] = ()
    flags_none: tuple[str, ...] = ()
    args_any_glob: tuple[str, ...] = ()
    args_none_glob: tuple[str, ...] = ()
    args_regex: str | None = None
    shell: str = "any"
    regex: re.Pattern[str] | None = dataclasses.field(
        default=None, compare=False, repr=False
    )


@dataclass(frozen=True)
class PathPred:
    """Matches one path the call reads, writes or deletes.

    Every field must hold for the same path.  ``recursive`` narrows a
    ``delete`` to recursive (``True``) or non-recursive (``False``)
    deletions; ``None`` accepts both.  ``not_within`` is an exception like
    ``not_under``, judged from where the call is made: the directory that
    matches must not be the working directory or a directory above it.
    """

    op: str = "any"
    under: tuple[str, ...] = ()
    not_under: tuple[str, ...] = ()
    not_within: tuple[str, ...] = ()
    glob: tuple[str, ...] = ()
    not_glob: tuple[str, ...] = ()
    recursive: bool | None = None


@dataclass(frozen=True)
class ArgPred:
    """Compares one field of a structured tool input."""

    name: str
    op: str
    value: Any


@dataclass(frozen=True)
class ExprPred:
    """Linear arithmetic over numeric arguments: ``sum(coeff * arg) op rhs``."""

    lhs: tuple[tuple[str, float], ...]
    op: str
    rhs: float


@dataclass(frozen=True)
class TextRegexPred:
    """Regular-expression search on one (truncated) text field."""

    field: str
    pattern: str
    regex: re.Pattern[str] = dataclasses.field(compare=False, repr=False)


@dataclass(frozen=True)
class DynamicShellPred:
    """True when the shell input is not fully literal.

    ``reason`` optionally restricts the match to given reason kinds
    (for example ``download_pipe``).
    """

    reason: tuple[str, ...] = ()


@dataclass(frozen=True)
class AssignsPred:
    """True when the shell input sets a variable with one of these names.

    ``name`` holds names or globs.  What counts as setting is listed on
    ``ParseResult.assigned`` and :func:`ember_armor.ledger.facts.extract`.
    """

    name: tuple[str, ...]


@dataclass(frozen=True)
class AllPred:
    """Every inner predicate is true."""

    of: tuple[Predicate, ...]


@dataclass(frozen=True)
class AnyPred:
    """At least one inner predicate is true."""

    of: tuple[Predicate, ...]


@dataclass(frozen=True)
class NotPred:
    """The inner predicate is false."""

    of: Predicate


@dataclass(frozen=True)
class NotPrecededByPred:
    """No earlier call in the session matches the inner predicate."""

    predicate: Predicate


@dataclass(frozen=True)
class CountExceedsPred:
    """More than ``max`` earlier calls in the session match the inner predicate."""

    predicate: Predicate
    max: int
    within_seconds: float | None = None


Predicate = (
    CommandPred
    | PathPred
    | ArgPred
    | ExprPred
    | TextRegexPred
    | DynamicShellPred
    | AssignsPred
    | AllPred
    | AnyPred
    | NotPred
    | NotPrecededByPred
    | CountExceedsPred
)


# ---------------------------------------------------------------------------
# Rules and decisions
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Applies:
    """Scope of a rule.  Empty tuples mean everywhere.

    The three directory scopes are judged for each command of a shell call
    on the directory in effect when it runs, and the rule then sees only the
    commands in scope and the paths they touch.  ``cwd_not_under`` holds
    exceptions to ``cwd_under``.  ``repo_root`` holds when the nearest
    enclosing git repository of that directory is one of the directories
    listed.  For any other tool the first two look at the working directory
    of the call and ``repo_root`` at each path the call touches.
    """

    tools: tuple[str, ...] = ()
    cwd_under: tuple[str, ...] = ()
    cwd_not_under: tuple[str, ...] = ()
    repo_root: tuple[str, ...] = ()

    @property
    def directories(self) -> bool:
        """True when the scope names a directory in any of the three ways."""
        return bool(self.cwd_under or self.cwd_not_under or self.repo_root)


@dataclass(frozen=True)
class Rule:
    """One constraint of the ledger.

    ``obligation`` is true when the rule was written with ``require``: it
    then fires when ``predicate`` is false.  ``origin`` names the ledger the
    rule came from (``builtin``, ``user``, ``project`` or ``override``) and
    ``base`` is the directory relative path patterns are resolved against
    (``None`` means the working directory of the call).
    """

    id: str
    text: str
    source: str
    effect: str
    predicate: Predicate
    obligation: bool = False
    applies: Applies = Applies()
    confirmed: bool = False
    expires: date | None = None
    origin: str = "user"
    base: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict, compare=False, repr=False)


@dataclass(frozen=True)
class FiredRule:
    """A rule that fired for a call, with the effect it contributed.

    ``origin`` names the ledger the rule came from (see :class:`Rule`).
    ``confirmed`` is true when the owner vouches for the rule: a built-in
    rule, a rule confirmed in the user ledger, or a project rule confirmed
    on this machine.  Only such a rule's words are ever shown to the agent.
    """

    id: str
    text: str
    source: str
    effect: str
    origin: str = "user"
    confirmed: bool = False


@dataclass(frozen=True)
class Decision:
    """Outcome of evaluating one call: ``none``, ``warn``, ``ask`` or ``deny``.

    ``excepted`` lists the rules that an owner's exception dropped for this
    call, with the reason the owner gave.
    """

    effect: str = "none"
    fired: tuple[FiredRule, ...] = ()
    error: str | None = None
    excepted: tuple[ExceptedRule, ...] = ()

    def reason(self) -> str:
        """Human-readable reason quoting each fired rule's text and source.

        The quoted text is capped, and a rule from a project ledger is
        labelled as such: its wording was written in the repository.
        """
        lines = []
        for rule in self.fired:
            where = " from this repository's ledger" if rule.origin == "project" else ""
            lines.append(
                f"EmberArmor ledger rule {rule.id}{where} ({rule.effect}): "
                f'"{rule.text[:REASON_CHARS]}" [source: {rule.source[:REASON_CHARS]}]'
            )
        if self.error:
            lines.append(f"EmberArmor gate failure: {self.error}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------
def _check_keys(
    obj: Mapping[str, Any], where: str, required: Sequence[str], optional: Sequence[str]
) -> None:
    missing = [k for k in required if k not in obj]
    if missing:
        raise LedgerError(f"{where}: missing field(s) {', '.join(missing)}")
    unknown = sorted(set(obj) - set(required) - set(optional))
    if unknown:
        raise LedgerError(f"{where}: unknown field(s) {', '.join(unknown)}")


def _strings(value: Any, where: str) -> tuple[str, ...]:
    """Accept a string or a list of strings; return a tuple of strings."""
    items = [value] if isinstance(value, str) else value
    if not isinstance(items, list) or not all(isinstance(i, str) and i for i in items):
        raise LedgerError(f"{where}: expected a non-empty string or list of strings")
    return tuple(items)


def _string(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LedgerError(f"{where}: expected a non-empty string")
    return value


def _number(value: Any, where: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise LedgerError(f"{where}: expected a number")
    if not math.isfinite(value):
        raise LedgerError(f"{where}: expected a finite number")
    return float(value)


def _one_of(value: Any, allowed: Sequence[str], where: str) -> str:
    if value not in allowed:
        raise LedgerError(f"{where}: {value!r} is not one of {', '.join(allowed)}")
    return str(value)


# ---------------------------------------------------------------------------
# Predicate parsing
# ---------------------------------------------------------------------------
def _parse_command(obj: Mapping[str, Any], where: str) -> CommandPred:
    lists = ("program", "subcommand", "flags_any", "flags_all", "flags_none",
             "args_any_glob", "args_none_glob")  # fmt: skip
    _check_keys(obj, where, ("type",), (*lists, "args_regex", "shell"))
    values = {k: _strings(obj[k], f"{where}.{k}") for k in lists if k in obj}
    shell = _one_of(obj.get("shell", "any"), SHELLS, f"{where}.shell")
    regex = None
    if "args_regex" in obj:
        regex = _compile(obj["args_regex"], f"{where}.args_regex")
    pattern = regex.pattern if regex else None
    return CommandPred(shell=shell, args_regex=pattern, regex=regex, **values)


def _parse_path(obj: Mapping[str, Any], where: str) -> PathPred:
    lists = ("under", "not_under", "not_within", "glob", "not_glob")
    _check_keys(obj, where, ("type",), (*lists, "op", "recursive"))
    values = {k: _strings(obj[k], f"{where}.{k}") for k in lists if k in obj}
    recursive = obj.get("recursive")
    if recursive is not None and not isinstance(recursive, bool):
        raise LedgerError(f"{where}.recursive: expected true or false")
    op = _one_of(obj.get("op", "any"), PATH_OPS, f"{where}.op")
    return PathPred(op=op, recursive=recursive, **values)


def _parse_arg(obj: Mapping[str, Any], where: str) -> ArgPred:
    _check_keys(obj, where, ("type", "name", "op", "value"), ())
    op = _one_of(obj["op"], ARG_OPS, f"{where}.op")
    value = obj["value"]
    if op == "in" and not isinstance(value, list):
        raise LedgerError(f"{where}.value: 'in' needs a list")
    if op == "matches":
        value = _compile(value, f"{where}.value")
    if op in ("<", "<=", ">", ">="):
        # A threshold that is not a number could never match: a typo.
        _number(value, f"{where}.value")
    return ArgPred(name=_string(obj["name"], f"{where}.name"), op=op, value=value)


def _parse_expr(obj: Mapping[str, Any], where: str) -> ExprPred:
    _check_keys(obj, where, ("type", "lhs", "op", "rhs"), ())
    lhs = obj["lhs"]
    if not isinstance(lhs, dict) or not lhs:
        raise LedgerError(f"{where}.lhs: expected a map of argument name to number")
    terms = tuple(
        (_string(k, f"{where}.lhs"), _number(v, f"{where}.lhs.{k}"))
        for k, v in lhs.items()
    )
    op = _one_of(obj["op"], EXPR_OPS, f"{where}.op")
    return ExprPred(lhs=terms, op=op, rhs=_number(obj["rhs"], f"{where}.rhs"))


def _compile(pattern: Any, where: str) -> re.Pattern[str]:
    try:
        return re.compile(_string(pattern, where))
    except re.error as exc:
        raise LedgerError(f"{where}: invalid regular expression ({exc})") from exc


def _parse_text_regex(obj: Mapping[str, Any], where: str) -> TextRegexPred:
    _check_keys(obj, where, ("type", "field", "pattern"), ())
    regex = _compile(obj["pattern"], f"{where}.pattern")
    return TextRegexPred(
        field=_string(obj["field"], f"{where}.field"),
        pattern=regex.pattern,
        regex=regex,
    )


def _parse_dynamic(obj: Mapping[str, Any], where: str) -> DynamicShellPred:
    _check_keys(obj, where, ("type",), ("reason",))
    reason = _strings(obj["reason"], f"{where}.reason") if "reason" in obj else ()
    for kind in reason:
        _one_of(kind, DYNAMIC_KINDS, f"{where}.reason")
    return DynamicShellPred(reason=reason)


def _parse_assigns(obj: Mapping[str, Any], where: str) -> AssignsPred:
    _check_keys(obj, where, ("type", "name"), ())
    names = _strings(obj["name"], f"{where}.name")
    if not names:
        raise LedgerError(f"{where}.name: expected at least one variable name")
    return AssignsPred(name=names)


def _parse_group(obj: Mapping[str, Any], where: str, history: bool) -> Predicate:
    _check_keys(obj, where, ("type", "of"), ())
    kind, inner = obj["type"], obj["of"]
    if kind == "not":
        return NotPred(of=parse_predicate(inner, f"{where}.of", history=history))
    if not isinstance(inner, list) or not inner:
        raise LedgerError(f"{where}.of: expected a non-empty list of predicates")
    parts = tuple(
        parse_predicate(p, f"{where}.of[{i}]", history=history)
        for i, p in enumerate(inner)
    )
    return AllPred(of=parts) if kind == "all" else AnyPred(of=parts)


def _parse_history(obj: Mapping[str, Any], where: str, history: bool) -> Predicate:
    kind = obj["type"]
    if history:
        raise LedgerError(f"{where}: {kind} cannot be nested in a history predicate")
    if kind == "not_preceded_by":
        _check_keys(obj, where, ("type", "predicate"), ())
        inner = parse_predicate(obj["predicate"], f"{where}.predicate", history=True)
        return NotPrecededByPred(predicate=inner)
    _check_keys(obj, where, ("type", "predicate", "max"), ("within_seconds",))
    limit = obj["max"]
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
        raise LedgerError(f"{where}.max: expected a non-negative integer")
    within = obj.get("within_seconds")
    if within is not None and _number(within, f"{where}.within_seconds") <= 0:
        raise LedgerError(f"{where}.within_seconds: expected a positive number")
    inner = parse_predicate(obj["predicate"], f"{where}.predicate", history=True)
    return CountExceedsPred(predicate=inner, max=limit, within_seconds=within)


_LEAF_PARSERS: dict[str, Callable[[Mapping[str, Any], str], Predicate]] = {
    "command": _parse_command,
    "path": _parse_path,
    "arg": _parse_arg,
    "expr": _parse_expr,
    "text_regex": _parse_text_regex,
    "dynamic_shell": _parse_dynamic,
    "assigns": _parse_assigns,
}
PREDICATE_TYPES = (
    *_LEAF_PARSERS,
    "all",
    "any",
    "not",
    "not_preceded_by",
    "count_exceeds",
)


def parse_predicate(obj: Any, where: str, *, history: bool = False) -> Predicate:
    """Validate one predicate object and return its dataclass.

    Parameters
    ----------
    obj:
        The JSON object, which must carry a ``type``.
    where:
        Location used in error messages (for example ``rules[2].when``).
    history:
        True while parsing the inside of a history predicate, where another
        history predicate is not allowed.
    """
    if not isinstance(obj, dict):
        raise LedgerError(f"{where}: expected a predicate object")
    kind = obj.get("type")
    if kind in _LEAF_PARSERS:
        return _LEAF_PARSERS[kind](obj, where)
    if kind in ("all", "any", "not"):
        return _parse_group(obj, where, history)
    if kind in ("not_preceded_by", "count_exceeds"):
        return _parse_history(obj, where, history)
    raise LedgerError(
        f"{where}: unknown predicate type {kind!r} "
        f"(known: {', '.join(PREDICATE_TYPES)})"
    )


# ---------------------------------------------------------------------------
# Rule and ledger parsing
# ---------------------------------------------------------------------------
_RULE_REQUIRED = ("id", "text", "source", "effect")
_RULE_OPTIONAL = ("applies", "when", "require", "confirmed", "expires")
_EXCEPTION_REQUIRED = ("rule", "reason")
_EXCEPTION_OPTIONAL = ("cwd_under", "repo_root", "tools", "when", "expires")
#: An absolute directory, or one that starts with ``~`` or a variable.
_ROOTED_RE = re.compile(r"[/\\~$%]|[A-Za-z]:[/\\]")
#: The variable that names the drive of the home directory, on its own.
_DRIVE_VARIABLE_RE = re.compile(r"(?:\$\{?(?:env:)?|%)HOMEDRIVE[}%]?", re.IGNORECASE)
_WILDCARD_RE = re.compile(r"\[[^\]]*\]|[*?]")


def _no_place(directory: str) -> str | None:
    """Why *directory* is no place for an exception (``None``: it is one).

    An exception holds in a place.  A whole filesystem, a whole drive or a
    pattern that is only wildcards below one is everywhere, and where a
    directory with ``..`` in it ends depends on what stands in front.
    """
    segments = [part for part in directory.replace("\\", "/").split("/") if part]
    if ".." in segments:
        return "holds '..' (write the directory it leads to)"
    if directory.replace("\\", "/").startswith("//"):
        segments = segments[2:]  # //host/share
    elif segments and not directory.startswith(("/", "\\")):
        if segments[0][0] in "~$%" and not _DRIVE_VARIABLE_RE.fullmatch(segments[0]):
            return None  # a home directory, or what a variable names
        segments = segments[1:]  # a drive
    if any(_WILDCARD_RE.sub("", part) for part in segments):
        return None
    return "is a whole filesystem, not a place in one"


def _parse_applies(obj: Any, where: str) -> Applies:
    if not isinstance(obj, dict):
        raise LedgerError(f"{where}: expected an object")
    _check_keys(obj, where, (), ("tools", "cwd_under", "cwd_not_under", "repo_root"))
    values = {k: _strings(v, f"{where}.{k}") for k, v in obj.items()}
    return Applies(**values)


def _parse_expires(value: Any, where: str) -> date:
    try:
        return datetime.fromisoformat(_string(value, where)).date()
    except ValueError as exc:
        raise LedgerError(f"{where}: expected an ISO date (YYYY-MM-DD)") from exc


def parse_rule(
    obj: Any, where: str = "rule", *, origin: str = "user", base: str | None = None
) -> Rule:
    """Validate one rule object and return a :class:`Rule`."""
    if not isinstance(obj, dict):
        raise LedgerError(f"{where}: expected a rule object")
    rule_id = obj.get("id")
    if isinstance(rule_id, str) and rule_id:
        where = f"{where} (id {rule_id!r})"
    _check_keys(obj, where, _RULE_REQUIRED, _RULE_OPTIONAL)
    if not isinstance(rule_id, str) or not _ID_RE.fullmatch(rule_id):
        raise LedgerError(
            f"{where}: id must be 1-80 characters of letters, digits, '.', '_' or '-'"
        )
    if rule_id.startswith(BUILTIN_PREFIX) and origin != "builtin":
        raise LedgerError(f"{where}: ids starting with 'builtin.' are reserved")
    if obj["effect"] not in EFFECTS:
        raise LedgerError(
            f"{where}: effect {obj['effect']!r} is not one of {', '.join(EFFECTS)} "
            "(there is no 'allow' effect; write exceptions into the predicate)"
        )
    has_when, has_require = "when" in obj, "require" in obj
    if has_when == has_require:
        problem = "both" if has_when else "neither"
        raise LedgerError(
            f"{where}: exactly one of 'when' and 'require' is needed, found {problem}"
        )
    key = "when" if has_when else "require"
    confirmed = obj.get("confirmed", False)
    if not isinstance(confirmed, bool):
        raise LedgerError(f"{where}.confirmed: expected true or false")
    expires = obj.get("expires")
    if expires is not None:
        expires = _parse_expires(expires, f"{where}.expires")
    return Rule(
        id=rule_id,
        text=_string(obj["text"], f"{where}.text"),
        source=_string(obj["source"], f"{where}.source"),
        effect=obj["effect"],
        predicate=parse_predicate(obj[key], f"{where}.{key}"),
        obligation=has_require,
        applies=_parse_applies(obj.get("applies", {}), f"{where}.applies"),
        confirmed=confirmed,
        expires=expires,
        origin=origin,
        base=base,
        raw=obj,
    )


def exceptable(rule_id: str) -> bool:
    """False for a rule that no exception can drop (see :data:`UNEXCEPTABLE`)."""
    return rule_id not in UNEXCEPTABLE and not rule_id.startswith(GATE_RULES)


def parse_exception(obj: Any, where: str = "exception") -> RuleException:
    """Validate one exception object of ``config.json``.

    An exception must say where it holds (``cwd_under``, ``repo_root`` or
    ``when``) and why (``reason``).  Its directories are absolute, or start
    with ``~`` or a variable: the working directory of a call never decides
    where an exception holds.  It cannot name a rule of
    :data:`UNEXCEPTABLE`, alone or through a glob.

    Raises
    ------
    LedgerError
        If the object is malformed.
    """
    from ember_armor.ledger.exceptions import RuleException

    if not isinstance(obj, dict):
        raise LedgerError(f"{where}: expected an exception object")
    _check_keys(obj, where, _EXCEPTION_REQUIRED, _EXCEPTION_OPTIONAL)
    glob = _string(obj["rule"], f"{where}.rule")
    if glob.startswith(GATE_RULES) or any(fnmatchcase(i, glob) for i in UNEXCEPTABLE):
        raise LedgerError(
            f"{where}.rule: {glob!r} covers a rule that takes no exception "
            f"({', '.join(UNEXCEPTABLE[:2])} and every {GATE_RULES}* rule); "
            "name the rules it is meant for"
        )
    lists = {
        key: _strings(obj[key], f"{where}.{key}")
        for key in ("cwd_under", "repo_root", "tools")
        if key in obj
    }
    for key in ("cwd_under", "repo_root"):
        for directory in lists.get(key, ()):
            if not _ROOTED_RE.match(directory):
                raise LedgerError(
                    f"{where}.{key}: {directory!r} is not an absolute directory "
                    "(it may start with ~ or a variable)"
                )
            problem = _no_place(directory)
            if problem is not None:
                raise LedgerError(
                    f"{where}.{key}: {directory!r} {problem}; an exception "
                    "that holds everywhere is the rule switched off"
                )
    when = parse_predicate(obj["when"], f"{where}.when") if "when" in obj else None
    if when is None and not (lists.get("cwd_under") or lists.get("repo_root")):
        raise LedgerError(
            f"{where}: needs at least one of cwd_under, repo_root and when; an "
            "exception that holds everywhere is the rule switched off"
        )
    expires = obj.get("expires")
    if expires is not None:
        expires = _parse_expires(expires, f"{where}.expires")
    return RuleException(
        rule=glob,
        reason=_string(obj["reason"], f"{where}.reason"),
        when=when,
        expires=expires,
        raw=obj,
        **lists,
    )


def parse_ledger(
    doc: Any, *, origin: str = "user", base: str | None = None, name: str = "ledger"
) -> list[Rule]:
    """Validate a whole ledger document and return its rules.

    Parameters
    ----------
    doc:
        The decoded JSON document.
    origin:
        Which ledger this is (``builtin``, ``user``, ``project``, ``override``).
    base:
        Directory that relative path patterns in the rules resolve against.
    name:
        File name or label used in error messages.
    """
    if not isinstance(doc, dict):
        raise LedgerError(f"{name}: expected an object with 'version' and 'rules'")
    _check_keys(doc, name, ("version", "rules"), ())
    if doc["version"] != LEDGER_VERSION:
        raise LedgerError(
            f"{name}: unsupported version {doc['version']!r} "
            f"(expected {LEDGER_VERSION})"
        )
    if not isinstance(doc["rules"], list):
        raise LedgerError(f"{name}: 'rules' must be a list")
    rules: list[Rule] = []
    seen: set[str] = set()
    for index, obj in enumerate(doc["rules"]):
        rule = parse_rule(obj, f"{name}: rules[{index}]", origin=origin, base=base)
        if rule.id in seen:
            raise LedgerError(f"{name}: rules[{index}]: duplicate id {rule.id!r}")
        seen.add(rule.id)
        rules.append(rule)
    return rules
