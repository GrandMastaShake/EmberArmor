"""Loading, merging and editing ledger files.

Rules come from three places: the built-in pack, the user ledger
(``~/.ember/ledger.json``, or under ``EMBER_HOME``) and the project ledger
(``.ember/ledger.json``, found by walking up from the working directory).
``EMBER_LEDGER`` replaces the user and project ledgers with one file.
Ledgers only ever add rules, and rules can only restrict.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Mapping
from dataclasses import replace
from datetime import date
from pathlib import Path
from typing import Any

from ember_armor.ledger.builtin import builtin_rules
from ember_armor.ledger.config import builtin_enabled, ember_home
from ember_armor.ledger.model import (
    LEDGER_VERSION,
    LedgerError,
    Rule,
    parse_ledger,
    parse_rule,
)
from ember_armor.ledger.paths import normalize

LEDGER_NAME = "ledger.json"


def user_ledger_path(env: Mapping[str, str]) -> Path:
    """Path of the user ledger (it may not exist)."""
    return ember_home(env) / LEDGER_NAME


def find_project_ledger(cwd: str) -> Path | None:
    """Nearest ``.ember/ledger.json`` at or above *cwd*, if any."""
    if not cwd:
        return None
    start = Path(normalize(cwd, "/", windows=os.name == "nt"))
    for directory in (start, *start.parents):
        candidate = directory / ".ember" / LEDGER_NAME
        if candidate.is_file():
            return candidate
    return None


def read_document(path: Path) -> dict[str, Any]:
    """Decode a ledger file; a missing file is an empty ledger.

    Raises
    ------
    LedgerError
        If the file cannot be read or is not valid JSON.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {"version": LEDGER_VERSION, "rules": []}
    except OSError as exc:
        raise LedgerError(f"cannot read ledger {path}: {exc}") from exc
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LedgerError(f"ledger {path} is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise LedgerError(f"ledger {path}: expected a JSON object")
    return document


def load_file(path: Path, *, origin: str, base: str | None = None) -> list[Rule]:
    """Load and validate one ledger file."""
    return parse_ledger(read_document(path), origin=origin, base=base, name=str(path))


def load_all(cwd: str, env: Mapping[str, str]) -> list[Rule]:
    """Every rule that applies in *cwd*, as written (expired ones included).

    Order: built-in pack, then the ``EMBER_LEDGER`` override or the user
    ledger followed by the project ledger.
    """
    rules: list[Rule] = list(builtin_rules()) if builtin_enabled(env) else []
    override = env.get("EMBER_LEDGER")
    if override:
        return rules + load_file(Path(override), origin="override")
    user = user_ledger_path(env)
    rules += load_file(user, origin="user")
    project = find_project_ledger(cwd)
    if project is not None and project.resolve() != user.resolve():
        base = str(project.parent.parent)
        rules += load_file(project, origin="project", base=base)
    return rules


def active_rules(rules: Iterable[Rule], today: date) -> list[Rule]:
    """Rules in force on *today*, with their effective effect.

    Expired rules are dropped.  A rule no human has confirmed can do no more
    than ``warn``, whatever effect it declares.
    """
    active: list[Rule] = []
    for rule in rules:
        if rule.expires is not None and today > rule.expires:
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
def write_document(path: Path, document: Mapping[str, Any]) -> None:
    """Validate *document* and write it to *path* atomically."""
    parse_ledger(document, name=str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


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
