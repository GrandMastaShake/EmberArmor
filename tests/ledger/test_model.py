"""Validation of ledger JSON: rules, predicates and error messages."""

from __future__ import annotations

import copy
from datetime import date
from typing import Any

import pytest

from ember_armor.ledger.builtin import builtin_document, builtin_rules
from ember_armor.ledger.model import (
    CommandPred,
    CountExceedsPred,
    Decision,
    FiredRule,
    LedgerError,
    NotPrecededByPred,
    PathPred,
    parse_ledger,
    parse_predicate,
    parse_rule,
)
from tests.ledger.helpers import rule

COMMAND = {"type": "command", "program": "git"}


def test_valid_rule_round_trip() -> None:
    parsed = parse_rule(
        rule(
            "no-force",
            applies={"tools": ["Bash", "mcp__*"], "cwd_under": "/work"},
            expires="2031-01-31",
        )
    )
    assert parsed.id == "no-force"
    assert parsed.effect == "deny"
    assert parsed.confirmed is True
    assert parsed.obligation is False
    assert parsed.expires == date(2031, 1, 31)
    assert parsed.applies.tools == ("Bash", "mcp__*")
    assert parsed.applies.cwd_under == ("/work",)
    assert parsed.predicate == CommandPred(
        program=("git",), subcommand=("push",), flags_any=("--force",)
    )


def test_defaults() -> None:
    item = rule()
    del item["confirmed"]
    parsed = parse_rule(item)
    assert parsed.confirmed is False
    assert parsed.expires is None
    assert parsed.applies.tools == ()
    assert parsed.origin == "user"


def test_require_marks_an_obligation() -> None:
    item = rule()
    item["require"] = item.pop("when")
    assert parse_rule(item).obligation is True


def _without(key: str) -> dict[str, Any]:
    item = rule()
    del item[key]
    return item


RULE_ERRORS = [
    (rule(when={"type": "comand"}), "unknown predicate type 'comand'"),
    (
        rule(require=COMMAND),
        "exactly one of 'when' and 'require' is needed, found both",
    ),
    (_without("when"), "found neither"),
    (rule(effect="allow"), "effect 'allow' is not one of warn, ask, deny"),
    (rule(effect="block"), "effect 'block'"),
    (rule(surprise=1), "unknown field(s) surprise"),
    (_without("text"), "missing field(s) text"),
    (_without("source"), "missing field(s) source"),
    (rule(""), "id must be"),
    (rule("has space"), "id must be"),
    (rule("builtin.mine"), "reserved"),
    (rule(confirmed="yes"), "confirmed: expected true or false"),
    (rule(expires="next week"), "expected an ISO date"),
    (rule(text="  "), "text: expected a non-empty string"),
    (rule(applies={"tool": ["Bash"]}), "applies: unknown field(s) tool"),
    (rule(applies={"tools": [1]}), "applies.tools"),
    (rule(when={**COMMAND, "flag": ["-f"]}), "when: unknown field(s) flag"),
    (rule(when={**COMMAND, "shell": "fish"}), "'fish' is not one of bash"),
    (rule(when={"type": "path", "op": "exec"}), "'exec' is not one of read"),
    (rule(when={"type": "path", "recursive": "yes"}), "recursive: expected true"),
    (rule(when={"type": "arg", "name": "n", "op": "~", "value": 1}), "'~' is not one"),
    (
        rule(when={"type": "arg", "name": "n", "op": "in", "value": 1}),
        "'in' needs a list",
    ),
    (
        rule(when={"type": "arg", "name": "n", "op": "matches", "value": "("}),
        "invalid regular expression",
    ),
    (
        rule(when={"type": "expr", "lhs": {"a": "x"}, "op": "<", "rhs": 1}),
        "expected a number",
    ),
    (
        rule(when={"type": "expr", "lhs": {}, "op": "<", "rhs": 1}),
        "lhs: expected a map",
    ),
    (
        rule(when={"type": "text_regex", "field": "command", "pattern": "["}),
        "invalid regular expression",
    ),
    (rule(when={"type": "all", "of": []}), "expected a non-empty list"),
    (rule(when={"type": "not", "of": [COMMAND]}), "expected a predicate object"),
    (
        rule(when={"type": "count_exceeds", "predicate": COMMAND, "max": -1}),
        "max: expected a non-negative integer",
    ),
    (
        rule(
            when={
                "type": "count_exceeds",
                "predicate": COMMAND,
                "max": 1,
                "within_seconds": 0,
            }
        ),
        "within_seconds",
    ),
    (
        rule(
            when={
                "type": "not_preceded_by",
                "predicate": {"type": "not_preceded_by", "predicate": COMMAND},
            }
        ),
        "cannot be nested in a history predicate",
    ),
    (rule(when="git push"), "expected a predicate object"),
]


@pytest.mark.parametrize(("item", "message"), RULE_ERRORS)
def test_rule_errors_are_specific(item: dict[str, Any], message: str) -> None:
    with pytest.raises(LedgerError) as caught:
        parse_rule(item)
    assert message in str(caught.value)


def test_error_names_the_rule_and_location() -> None:
    document = {"version": 1, "rules": [rule("ok"), rule("broken", when={"type": "x"})]}
    with pytest.raises(LedgerError) as caught:
        parse_ledger(document, name="my-ledger.json")
    text = str(caught.value)
    assert "my-ledger.json" in text
    assert "rules[1]" in text
    assert "'broken'" in text


LEDGER_ERRORS = [
    ([], "expected an object"),
    ({"rules": []}, "missing field(s) version"),
    ({"version": 2, "rules": []}, "unsupported version 2"),
    ({"version": 1, "rules": {}}, "'rules' must be a list"),
    ({"version": 1, "rules": [], "extra": True}, "unknown field(s) extra"),
    ({"version": 1, "rules": [rule("a"), rule("a")]}, "duplicate id 'a'"),
    ({"version": 1, "rules": ["nope"]}, "expected a rule object"),
]


@pytest.mark.parametrize(("document", "message"), LEDGER_ERRORS)
def test_ledger_errors(document: Any, message: str) -> None:
    with pytest.raises(LedgerError) as caught:
        parse_ledger(document)
    assert message in str(caught.value)


def test_string_or_list_fields_normalise_to_tuples() -> None:
    pred = parse_predicate(
        {"type": "path", "op": "delete", "under": "/data", "glob": ["*.db", "*.bak"]},
        "p",
    )
    assert pred == PathPred(op="delete", under=("/data",), glob=("*.db", "*.bak"))


def test_history_predicates_parse() -> None:
    inner = {"type": "command", "program": "pytest"}
    first = parse_predicate({"type": "not_preceded_by", "predicate": inner}, "p")
    assert isinstance(first, NotPrecededByPred)
    second = parse_predicate(
        {"type": "count_exceeds", "predicate": inner, "max": 3, "within_seconds": 60},
        "p",
    )
    assert second == CountExceedsPred(
        predicate=CommandPred(program=("pytest",)), max=3, within_seconds=60
    )


def test_decision_reason_quotes_text_and_source() -> None:
    decision = Decision(
        effect="deny",
        fired=(FiredRule("r1", "Never touch prod.", "Alexander, 2026-10-02", "deny"),),
    )
    reason = decision.reason()
    assert "r1" in reason
    assert '"Never touch prod."' in reason
    assert "Alexander, 2026-10-02" in reason


def test_decision_reason_includes_gate_failure() -> None:
    assert "ledger unreadable" in Decision("ask", error="ledger unreadable").reason()


def test_builtin_pack_is_plain_ledger_data() -> None:
    document = copy.deepcopy(builtin_document())
    rules = parse_ledger(document, origin="builtin")
    assert [r.id for r in rules] == [r.id for r in builtin_rules()]
    assert all(r.id.startswith("builtin.") for r in rules)
    assert all(r.confirmed for r in rules)
    assert {r.effect for r in rules} == {"ask", "deny"}
    assert all(r.source and r.text for r in rules)


def test_builtin_ids_are_rejected_outside_the_pack() -> None:
    with pytest.raises(LedgerError):
        parse_ledger(builtin_document(), origin="project")
