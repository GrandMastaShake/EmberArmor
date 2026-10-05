"""Classification corpora for the built-in pack.

``corpus/must_flag.json`` lists calls the built-in rules must catch, with the
expected effect and rule id.  ``corpus/must_not_flag.json`` lists harmless
developer calls that must pass untouched.  Each entry is evaluated for the
path flavour(s) it names; an entry without ``platform`` runs for both.

The command strings are only parsed.  They are never executed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ember_armor.ledger.builtin import builtin_rules
from ember_armor.ledger.engine import evaluate
from ember_armor.ledger.model import Decision
from tests.ledger.helpers import facts_for

CORPUS = Path(__file__).parent / "corpus"
MUST_FLAG = json.loads((CORPUS / "must_flag.json").read_text(encoding="utf-8"))
MUST_NOT_FLAG = json.loads((CORPUS / "must_not_flag.json").read_text(encoding="utf-8"))


def _cases(entries: list[dict[str, Any]]) -> list[Any]:
    cases = []
    for entry in entries:
        payload = entry.get("command", entry.get("input"))
        for platform in (
            [entry["platform"]] if "platform" in entry else ["posix", "windows"]
        ):
            label = payload if isinstance(payload, str) else json.dumps(payload)
            cases.append(
                pytest.param(
                    entry, platform, id=f"{entry['tool']}/{platform}: {label[:70]}"
                )
            )
    return cases


def _decide(entry: dict[str, Any], platform: str) -> Decision:
    payload = entry.get("command", entry.get("input"))
    return evaluate(builtin_rules(), facts_for(entry["tool"], payload, platform))


def test_corpus_sizes() -> None:
    assert len(MUST_FLAG) >= 80
    assert len(MUST_NOT_FLAG) >= 120


def test_every_builtin_rule_has_a_must_flag_entry() -> None:
    covered = {entry["rule"] for entry in MUST_FLAG}
    assert {rule.id for rule in builtin_rules()} <= covered


def test_corpus_covers_both_shells() -> None:
    for entries in (MUST_FLAG, MUST_NOT_FLAG):
        tools = {entry["tool"] for entry in entries}
        assert {"Bash", "PowerShell"} <= tools


@pytest.mark.parametrize(("entry", "platform"), _cases(MUST_FLAG))
def test_must_flag(entry: dict[str, Any], platform: str) -> None:
    decision = _decide(entry, platform)
    assert decision.effect == entry["effect"]
    assert entry["rule"] in [fired.id for fired in decision.fired]


@pytest.mark.parametrize(("entry", "platform"), _cases(MUST_NOT_FLAG))
def test_must_not_flag(entry: dict[str, Any], platform: str) -> None:
    decision = _decide(entry, platform)
    assert decision.effect == "none", [fired.id for fired in decision.fired]
