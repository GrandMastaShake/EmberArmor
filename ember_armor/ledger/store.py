"""Loading, merging and editing ledger files.

Rules come from three places: the built-in pack, the user ledger
(``~/.ember/ledger.json``, or under ``EMBER_HOME``) and the project ledger
(``.ember/ledger.json``, found by walking up from the working directory).
``EMBER_LEDGER`` replaces the user and project ledgers with one file.
Ledgers only ever add rules, and rules can only restrict.

A project ledger travels with a repository, so nothing in it is trusted as
written.  Whether one of its rules is confirmed is recorded on this machine
(``project-confirmed.json`` in the Ember home, by rule id and content hash),
never in the repository, and a rule nobody here confirmed is not allowed to
run a regular expression.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterable, Mapping
from dataclasses import replace
from datetime import date
from pathlib import Path
from typing import Any

from ember_armor.ledger.builtin import builtin_rules
from ember_armor.ledger.config import (
    ConfigError,
    builtin_enabled,
    disposable_patterns,
    ember_home,
)
from ember_armor.ledger.model import (
    LEDGER_VERSION,
    AllPred,
    AnyPred,
    ArgPred,
    CommandPred,
    CountExceedsPred,
    LedgerError,
    NotPrecededByPred,
    NotPred,
    Predicate,
    Rule,
    TextRegexPred,
    parse_ledger,
    parse_rule,
)
from ember_armor.ledger.paths import normalize

LEDGER_NAME = "ledger.json"
CONFIRMED_NAME = "project-confirmed.json"


def user_ledger_path(env: Mapping[str, str]) -> Path:
    """Path of the user ledger (it may not exist)."""
    return ember_home(env) / LEDGER_NAME


def find_project_ledger(cwd: str) -> Path | None:
    """Nearest ``.ember/ledger.json`` at or above *cwd*, if any.

    A network or device path (one that starts with two separators) is never
    searched: looking there would contact a host named by the call.
    """
    if not cwd or cwd.replace("\\", "/").startswith("//"):
        return None
    start = Path(normalize(cwd, "/", windows=os.name == "nt"))
    for directory in (start, *start.parents):
        candidate = directory / ".ember" / LEDGER_NAME
        if candidate.is_file():
            return candidate
    return None


def _read_json(path: Path, what: str) -> Any:
    """Decoded JSON of *path* (a UTF-8 byte order mark is accepted)."""
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise LedgerError(f"cannot read {what} {path}: {exc}") from exc
    except (ValueError, RecursionError) as exc:
        raise LedgerError(f"{what} {path} is not valid JSON: {exc}") from exc


def read_document(path: Path, *, missing_ok: bool = True) -> dict[str, Any]:
    """Decode a ledger file.

    Parameters
    ----------
    path:
        The ledger file.
    missing_ok:
        Treat a missing file as an empty ledger.  That is right for the
        default user ledger and wrong for a file somebody named explicitly.

    Raises
    ------
    LedgerError
        If the file cannot be read or is not valid JSON.
    """
    try:
        document = _read_json(path, "ledger")
    except FileNotFoundError as exc:
        if missing_ok:
            return {"version": LEDGER_VERSION, "rules": []}
        raise LedgerError(f"ledger {path} does not exist") from exc
    if not isinstance(document, dict):
        raise LedgerError(f"ledger {path}: expected a JSON object")
    return document


def load_file(
    path: Path, *, origin: str, base: str | None = None, missing_ok: bool = True
) -> list[Rule]:
    """Load and validate one ledger file."""
    document = read_document(path, missing_ok=missing_ok)
    return parse_ledger(document, origin=origin, base=base, name=str(path))


# ---------------------------------------------------------------------------
# Project ledgers: confirmation is kept on this machine
# ---------------------------------------------------------------------------
def rule_digest(raw: Mapping[str, Any]) -> str:
    """Content hash of a rule as written, without its ``confirmed`` field."""
    body = {key: value for key, value in raw.items() if key != "confirmed"}
    text = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _project_key(ledger: Path) -> str:
    return os.path.normcase(str(ledger.resolve()))


def _confirmed_path(env: Mapping[str, str]) -> Path:
    return ember_home(env) / CONFIRMED_NAME


def _read_confirmed(env: Mapping[str, str]) -> dict[str, dict[str, str]]:
    """Confirmed project rules: ledger path to rule id to content hash."""
    path = _confirmed_path(env)
    try:
        document = _read_json(path, "confirmation record")
    except FileNotFoundError:
        return {}
    projects = document.get("projects") if isinstance(document, dict) else None
    if not isinstance(projects, dict) or not all(
        isinstance(rules, dict) for rules in projects.values()
    ):
        raise LedgerError(f"confirmation record {path} is malformed")
    return projects


def _load_project(ledger: Path, env: Mapping[str, str]) -> list[Rule]:
    """Rules of a project ledger, confirmed only where this machine says so."""
    base = str(ledger.parent.parent)
    rules = load_file(ledger, origin="project", base=base)
    confirmed = _read_confirmed(env).get(_project_key(ledger), {})
    return [
        replace(rule, confirmed=confirmed.get(rule.id) == rule_digest(rule.raw))
        for rule in rules
    ]


def confirm_project_rule(env: Mapping[str, str], ledger: Path, rule_id: str) -> None:
    """Record on this machine that a human approved a project rule.

    The approval is tied to the rule's content: if the repository changes
    the rule, it is unconfirmed again.
    """
    document = read_document(ledger, missing_ok=False)
    parse_ledger(document, origin="project", name=str(ledger))
    raw = document["rules"][_index(document, rule_id, ledger)]
    projects = _read_confirmed(env)
    projects.setdefault(_project_key(ledger), {})[rule_id] = rule_digest(raw)
    _write_json(_confirmed_path(env), {"version": 1, "projects": projects})


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------
def load_sources(
    cwd: str, env: Mapping[str, str], *, project: bool = True
) -> tuple[list[Rule], list[str]]:
    """Every rule that applies in *cwd*, and what could not be loaded.

    Each source is read on its own, so a broken project ledger (or user
    ledger, or configuration) never takes the rules of the others with it.
    Order: built-in pack, then the ``EMBER_LEDGER`` override or the user
    ledger followed by the project ledger.

    Parameters
    ----------
    cwd:
        Working directory whose project ledger to look for.
    env:
        Environment mapping (Ember home, ``EMBER_LEDGER``, built-in switch).
    project:
        ``False`` never looks for a project ledger (the HTTP server, where
        the directory comes from the request).

    Returns
    -------
    tuple[list[Rule], list[str]]
        The rules as written (expired ones included) and one message per
        source that failed.
    """
    rules: list[Rule] = []
    problems: list[str] = []
    try:
        if builtin_enabled(env):
            rules += builtin_rules(disposable_patterns(env))
    except ConfigError as exc:
        # The pack stays on when the configuration cannot say otherwise.
        problems.append(str(exc))
        rules += builtin_rules()
    override = env.get("EMBER_LEDGER")
    user = user_ledger_path(env)
    sources = [("override", Path(override))] if override else [("user", user)]
    found = find_project_ledger(cwd) if project and not override else None
    if found is not None and found.resolve() != user.resolve():
        sources.append(("project", found))
    for origin, path in sources:
        try:
            if origin == "project":
                rules += _load_project(path, env)
            else:
                rules += load_file(path, origin=origin, missing_ok=origin == "user")
        except LedgerError as exc:
            problems.append(str(exc))
    return rules, problems


def load_all(cwd: str, env: Mapping[str, str], *, project: bool = True) -> list[Rule]:
    """Every rule that applies in *cwd*, as written (expired ones included).

    Raises
    ------
    LedgerError
        If any source could not be loaded (see :func:`load_sources`).
    """
    rules, problems = load_sources(cwd, env, project=project)
    if problems:
        raise LedgerError("; ".join(problems))
    return rules


def uses_regex(pred: Predicate) -> bool:
    """True when evaluating *pred* runs a regular expression."""
    if isinstance(pred, TextRegexPred):
        return True
    if isinstance(pred, ArgPred):
        return pred.op == "matches"
    if isinstance(pred, CommandPred):
        return pred.regex is not None
    if isinstance(pred, AllPred | AnyPred):
        return any(uses_regex(inner) for inner in pred.of)
    if isinstance(pred, NotPred):
        return uses_regex(pred.of)
    if isinstance(pred, NotPrecededByPred | CountExceedsPred):
        return uses_regex(pred.predicate)
    return False


def evaluated(rule: Rule) -> bool:
    """False for a rule the gate will not run.

    An unconfirmed rule from a project ledger never runs a regular
    expression: a pattern that takes minutes to match would stall every
    call made in that repository.
    """
    untrusted = rule.origin == "project" and not rule.confirmed
    return not (untrusted and uses_regex(rule.predicate))


def active_rules(rules: Iterable[Rule], today: date) -> list[Rule]:
    """Rules in force on *today*, with their effective effect.

    Expired rules are dropped, and so are rules that are not evaluated (see
    :func:`evaluated`).  A rule no human has confirmed can do no more than
    ``warn``, whatever effect it declares.
    """
    active: list[Rule] = []
    for rule in rules:
        if (rule.expires is not None and today > rule.expires) or not evaluated(rule):
            continue
        active.append(rule if rule.confirmed else replace(rule, effect="warn"))
    return active


def load_rules(
    cwd: str, env: Mapping[str, str], today: date | None = None
) -> list[Rule]:
    """The rules the gate evaluates for a call made in *cwd*."""
    return active_rules(load_all(cwd, env), today or date.today())


# ---------------------------------------------------------------------------
# Editing (used by ``ember-gate rules add|confirm|remove``)
# ---------------------------------------------------------------------------
def _write_json(path: Path, document: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def write_document(path: Path, document: Mapping[str, Any]) -> None:
    """Validate *document* and write it to *path* atomically."""
    parse_ledger(document, name=str(path))
    _write_json(path, document)


def _index(document: Mapping[str, Any], rule_id: str, path: Path) -> int:
    for index, rule in enumerate(document.get("rules", [])):
        if isinstance(rule, dict) and rule.get("id") == rule_id:
            return index
    raise LedgerError(f"no rule with id {rule_id!r} in {path}")


def add_rule(path: Path, rule: Mapping[str, Any]) -> Rule:
    """Append *rule* to the ledger at *path*.

    The rule is stored unconfirmed whatever it says: confirming is a separate,
    deliberate step (``ember-gate rules confirm``).
    """
    stored = {**rule, "confirmed": False}
    parsed = parse_rule(stored)
    document = read_document(path)
    document.setdefault("version", LEDGER_VERSION)
    document.setdefault("rules", []).append(stored)
    write_document(path, document)
    return parsed


def confirm_rule(path: Path, rule_id: str) -> None:
    """Mark the rule as approved by a human."""
    document = read_document(path)
    document["rules"][_index(document, rule_id, path)]["confirmed"] = True
    write_document(path, document)


def remove_rule(path: Path, rule_id: str) -> None:
    """Delete the rule from the ledger at *path*."""
    document = read_document(path)
    del document["rules"][_index(document, rule_id, path)]
    write_document(path, document)
