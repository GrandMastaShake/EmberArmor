"""``ember-gate lint``: dead, blanket, shadowed and contradictory rules.

Every test here calls the real Z3 solver.  Nothing is mocked; the two tests
about a missing solver only block the import.
"""

from __future__ import annotations

import json
import sys
from datetime import date
from typing import Any

import pytest

from ember_armor.ledger import cli
from ember_armor.ledger.builtin import builtin_rules
from ember_armor.ledger.lint import Finding, SolverUnavailableError, lint
from ember_armor.ledger.model import Rule, parse_rule
from tests.ledger.helpers import rule, write_ledger

pytest.importorskip("z3")


def arg(name: str, op: str, value: Any) -> dict[str, Any]:
    return {"type": "arg", "name": name, "op": op, "value": value}


def path(**fields: Any) -> dict[str, Any]:
    return {"type": "path", **fields}


def make(rule_id: str, when: dict[str, Any] | None = None, **fields: Any) -> Rule:
    """A confirmed deny rule; ``require=`` replaces the ``when`` predicate."""
    origin = fields.pop("origin", "user")
    base = fields.pop("base", None)
    if "require" in fields:
        raw = rule(rule_id, **fields)
        del raw["when"]
    else:
        raw = rule(rule_id, when=when, **fields)
    return parse_rule(raw, origin=origin, base=base)


def kinds(findings: list[Finding]) -> list[tuple[str, tuple[str, ...]]]:
    return [(finding.kind, finding.rules) for finding in findings]


TRANSFER = {"tools": ["transfer"]}
CAP = arg("amount", ">", 5_000_000)
FLOOR = arg("amount", ">=", 10_000_000)


# ---------------------------------------------------------------------------
# Contradictions
# ---------------------------------------------------------------------------
def test_cap_and_floor_on_the_same_tool_contradict() -> None:
    rules = [
        make("cap", CAP, applies=TRANSFER),
        make("floor", require=FLOOR, applies=TRANSFER),
    ]
    findings = lint(rules)
    assert kinds(findings) == [("contradiction", ("cap", "floor"))]
    assert "cap" in findings[0].message
    assert "floor" in findings[0].message
    assert "tool transfer" in findings[0].message


def test_cap_and_floor_on_different_tools_do_not_contradict() -> None:
    rules = [
        make("cap", CAP, applies={"tools": ["transfer"]}),
        make("floor", require=FLOOR, applies={"tools": ["refund"]}),
    ]
    assert lint(rules) == []


def test_contradiction_needs_deny_rules() -> None:
    rules = [
        make("cap", CAP, applies=TRANSFER),
        make("floor", require=FLOOR, applies=TRANSFER, effect="ask"),
    ]
    assert lint(rules) == []


def test_a_missing_argument_is_not_denied_by_two_one_sided_rules() -> None:
    # A call without "amount" meets neither condition, so some call is allowed.
    rules = [make("high", arg("amount", ">", 5)), make("low", arg("amount", "<=", 5))]
    assert lint(rules) == []


def test_a_condition_and_its_negation_deny_everything() -> None:
    high = arg("amount", ">", 5)
    rules = [make("high", high), make("rest", {"type": "not", "of": high})]
    findings = lint(rules)
    assert kinds(findings) == [("contradiction", ("high", "rest"))]
    assert findings[0].message.endswith("every call everywhere")


def test_contradiction_names_only_the_rules_that_are_needed() -> None:
    rules = [
        make("unrelated", arg("currency", "==", "XXX"), applies=TRANSFER),
        make("cap", CAP, applies=TRANSFER),
        make("other-tool", arg("amount", "<", 0), applies={"tools": ["refund"]}),
        make("floor", require=FLOOR, applies=TRANSFER),
    ]
    assert kinds(lint(rules)) == [("contradiction", ("cap", "floor"))]


def test_contradiction_is_found_on_the_tool_two_scopes_share() -> None:
    rules = [
        make("cap", CAP, applies={"tools": ["transfer", "refund"]}),
        make("floor", require=FLOOR, applies={"tools": ["transfer", "payout"]}),
    ]
    findings = lint(rules)
    assert kinds(findings) == [("contradiction", ("cap", "floor"))]
    assert "tool transfer" in findings[0].message


def test_linear_expressions_contradict() -> None:
    total = {"amount": 1, "fee": 1}
    rules = [
        make("cap", {"type": "expr", "lhs": total, "op": ">", "rhs": 100}),
        make("floor", require={"type": "expr", "lhs": total, "op": ">=", "rhs": 200}),
    ]
    assert kinds(lint(rules)) == [("contradiction", ("cap", "floor"))]


def test_a_global_contradiction_is_reported_once() -> None:
    high = arg("amount", ">", 5)
    rules = [
        make("high", high),
        make("rest", {"type": "not", "of": high}),
        make("narrow", arg("amount", "==", 7), applies=TRANSFER),
    ]
    assert [f.rules for f in lint(rules) if f.kind == "contradiction"] == [
        ("high", "rest")
    ]


# ---------------------------------------------------------------------------
# Dead rules
# ---------------------------------------------------------------------------
DEAD_CASES = [
    {"type": "all", "of": [arg("amount", ">", 10), arg("amount", "<", 5)]},
    {"type": "all", "of": [arg("env", "==", "prod"), arg("env", "==", "dev")]},
    {"type": "all", "of": [arg("env", "in", ["a", "b"]), arg("env", "==", "c")]},
    {"type": "all", "of": [arg("n", "in", [1, 2]), arg("n", ">", 2)]},
    arg("amount", ">", "5"),
    arg("env", "in", []),
    {
        "type": "all",
        "of": [
            {"type": "expr", "lhs": {"a": 2, "b": -1}, "op": ">", "rhs": 0},
            {"type": "expr", "lhs": {"a": 2, "b": -1}, "op": "<", "rhs": -1.5},
        ],
    },
]


@pytest.mark.parametrize("when", DEAD_CASES)
def test_condition_that_cannot_be_true_is_dead(when: dict[str, Any]) -> None:
    findings = lint([make("r", when, effect="ask")])
    assert kinds(findings) == [("dead", ("r",))]
    assert "never fires" in findings[0].message


LIVE_CASES = [
    {"type": "all", "of": [arg("amount", ">", 5), arg("amount", "<", 10)]},
    {"type": "all", "of": [arg("env", "!=", "prod"), arg("env", "!=", "dev")]},
    {"type": "all", "of": [arg("n", "in", [1, 2]), arg("n", ">=", 2)]},
    {"type": "all", "of": [arg("n", "==", 1), arg("n", "==", True)]},
    arg("amount", "!=", "5"),
    {"type": "text_regex", "field": "command", "pattern": "x"},
    {"type": "not_preceded_by", "predicate": {"type": "command", "program": "pytest"}},
]


@pytest.mark.parametrize("when", LIVE_CASES)
def test_condition_that_can_be_true_is_not_reported(when: dict[str, Any]) -> None:
    assert lint([make("r", when, effect="ask")]) == []


def test_command_rule_scoped_to_a_file_tool_is_dead() -> None:
    when = {"type": "command", "program": "git"}
    assert kinds(lint([make("r", when, applies={"tools": ["Read"]})])) == [
        ("dead", ("r",))
    ]
    assert lint([make("r", when, applies={"tools": ["Bash", "Read"]})]) == []
    assert lint([make("r", when, applies={"tools": ["B*"]})]) == []


def test_path_rule_scoped_to_a_tool_without_paths_is_dead() -> None:
    when = path(op="write", under=["src"])
    assert kinds(lint([make("r", when, applies={"tools": ["mcp__db__query"]})])) == [
        ("dead", ("r",))
    ]
    assert lint([make("r", when, applies={"tools": ["Write", "Edit"]})]) == []


# ---------------------------------------------------------------------------
# Blanket rules
# ---------------------------------------------------------------------------
def test_condition_that_is_always_true_is_blanket() -> None:
    high = arg("amount", ">", 5)
    when = {"type": "any", "of": [high, {"type": "not", "of": high}]}
    findings = lint([make("r", when, effect="warn", applies=TRANSFER)])
    assert kinds(findings) == [("blanket", ("r",))]
    assert "tool transfer" in findings[0].message


def test_requiring_the_impossible_is_blanket() -> None:
    never = {"type": "all", "of": [arg("amount", ">", 10), arg("amount", "<", 5)]}
    findings = lint([make("r", require=never)])
    assert kinds(findings) == [("blanket", ("r",))]
    assert "everywhere" in findings[0].message


def test_tool_scope_of_every_tool_is_blanket_only_with_a_true_condition() -> None:
    assert lint([make("r", arg("amount", ">", 5), applies={"tools": ["*"]})]) == []


# ---------------------------------------------------------------------------
# Shadowed rules
# ---------------------------------------------------------------------------
def test_path_scope_inside_another_deny_rules_path_scope_is_shadowed() -> None:
    rules = [
        make("src", path(op="write", under=["src"])),
        make("generated", path(op="write", under=["src/generated"])),
    ]
    findings = lint(rules)
    assert kinds(findings) == [("shadowed", ("generated", "src"))]
    assert "src (deny)" in findings[0].message


def test_working_directory_scope_inside_another_is_shadowed() -> None:
    when = {"type": "command", "program": "npm", "subcommand": ["publish"]}
    rules = [
        make("wide", when, applies={"cwd_under": ["/work"]}),
        make("narrow", when, applies={"cwd_under": ["/work/app"]}),
    ]
    assert kinds(lint(rules, windows=False)) == [("shadowed", ("narrow", "wide"))]


def test_a_weaker_rule_does_not_shadow_a_stronger_one() -> None:
    rules = [
        make("src", path(op="write", under=["src"]), effect="ask"),
        make("generated", path(op="write", under=["src/generated"])),
    ]
    assert lint(rules) == []


def test_a_wider_operation_shadows_and_a_different_one_does_not() -> None:
    inner = path(op="write", under=["src/generated"])
    assert kinds(lint([make("a", path(under=["src"])), make("b", inner)])) == [
        ("shadowed", ("b", "a"))
    ]
    reads = path(op="read", under=["src"])
    assert lint([make("a", reads), make("b", inner)]) == []


def test_an_exception_keeps_a_rule_from_shadowing() -> None:
    outer = path(op="write", under=["src"], not_under=["src/generated"])
    inner = path(op="write", under=["src/generated/api"])
    assert lint([make("a", outer), make("b", inner)]) == []
    outer = path(op="write", under=["src"], not_under=["src/vendor"])
    inner = path(op="write", under=["src/app"], not_under=["src/vendor", "src/x"])
    assert kinds(lint([make("a", outer), make("b", inner)])) == [
        ("shadowed", ("b", "a"))
    ]


def test_windows_paths_compare_without_case_and_separator() -> None:
    rules = [
        make("src", path(op="write", under=["c:/work/app/src"])),
        make("generated", path(op="write", under=[r"C:\Work\App\SRC\generated"])),
    ]
    assert kinds(lint(rules, windows=True)) == [("shadowed", ("generated", "src"))]
    assert lint(rules, windows=False) == []


def test_relative_patterns_of_different_ledgers_are_not_compared() -> None:
    rules = [
        make("user", path(op="write", under=["src"])),
        make("project", path(op="write", under=["src/generated"]), base="/work/app"),
    ]
    assert lint(rules, windows=False) == []
    same_base = [
        make("a", path(op="write", under=["src"]), base="/work/app"),
        make("b", path(op="write", under=["/work/app/src/generated"])),
    ]
    assert kinds(lint(same_base, windows=False)) == [("shadowed", ("b", "a"))]


def test_command_refinement_is_shadowed_by_a_built_in_rule() -> None:
    when = {
        "type": "command",
        "program": "git",
        "subcommand": ["push", "origin"],
        "flags_any": ["--force"],
    }
    findings = lint([*builtin_rules(), make("mine", when, effect="ask")])
    assert kinds(findings) == [("shadowed", ("mine", "builtin.git.force-push"))]
    assert lint([*builtin_rules(), make("mine", when, effect="deny")]) == []


def test_of_two_equivalent_rules_only_the_later_one_is_reported() -> None:
    when = arg("amount", ">", 5)
    rules = [make("first", when), make("second", when), make("third", when)]
    assert kinds(lint(rules)) == [
        ("shadowed", ("second", "first")),
        ("shadowed", ("third", "first", "second")),
    ]


def test_numeric_range_inside_another_is_shadowed() -> None:
    rules = [
        make("big", arg("amount", ">", 100), effect="ask"),
        make("huge", arg("amount", ">=", 1000.5), effect="warn"),
    ]
    assert kinds(lint(rules)) == [("shadowed", ("huge", "big"))]


def test_an_unconfirmed_shadowing_rule_is_called_out() -> None:
    rules = [
        make("src", path(op="write", under=["src"]), confirmed=False),
        make("generated", path(op="write", under=["src/generated"])),
    ]
    findings = lint(rules)
    assert kinds(findings) == [("shadowed", ("generated", "src"))]
    assert "src (deny, unconfirmed)" in findings[0].message


# ---------------------------------------------------------------------------
# What lint leaves alone
# ---------------------------------------------------------------------------
def test_the_built_in_pack_is_clean() -> None:
    assert lint(builtin_rules(), windows=True) == []
    assert lint(builtin_rules(), windows=False) == []


def test_built_in_rules_are_not_reported_as_shadowed() -> None:
    everything = {"type": "command", "program": "git"}
    findings = lint([*builtin_rules(), make("all-git", everything)])
    assert findings == []


def test_expired_rules_are_ignored() -> None:
    never = {"type": "all", "of": [arg("amount", ">", 10), arg("amount", "<", 5)]}
    expired = make("r", never, expires="2026-01-31")
    assert lint([expired], today=date(2026, 2, 1)) == []
    assert kinds(lint([expired], today=date(2026, 1, 31))) == [("dead", ("r",))]


def test_a_dead_rule_is_not_also_reported_as_shadowed() -> None:
    never = {"type": "all", "of": [arg("amount", ">", 10), arg("amount", "<", 5)]}
    rules = [make("live", arg("amount", ">", 1)), make("dead", never)]
    assert kinds(lint(rules)) == [("dead", ("dead",))]


# ---------------------------------------------------------------------------
# Missing solver, and the command line
# ---------------------------------------------------------------------------
def test_missing_solver_is_an_error_not_a_clean_result(monkeypatch) -> None:
    monkeypatch.setitem(sys.modules, "z3", None)
    with pytest.raises(SolverUnavailableError, match="smt"):
        lint([])


@pytest.fixture
def cli_env(gate_env: dict[str, str], monkeypatch, tmp_path):
    for name in ("EMBER_GATE_MODE", "EMBER_GATE_BUILTIN"):
        monkeypatch.delenv(name, raising=False)
    for name, value in gate_env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.chdir(tmp_path)
    return gate_env


def test_cli_exits_zero_on_a_clean_ledger(cli_env, capsys) -> None:
    assert cli.main(["lint"]) == 0
    assert "no findings" in capsys.readouterr().out


def test_cli_prints_findings_and_exits_one(cli_env, capsys, tmp_path) -> None:
    floor = rule("floor", require=FLOOR, applies=TRANSFER)
    del floor["when"]
    write_ledger(
        tmp_path / "ledger.json", rule("cap", when=CAP, applies=TRANSFER), floor
    )
    assert cli.main(["lint"]) == 1
    out = capsys.readouterr().out
    assert "contradiction: deny rules cap, floor together deny every call" in out
    assert "1 finding" in out
    assert cli.main(["lint", "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["findings"][0]["kind"] == "contradiction"
    assert report["findings"][0]["rules"] == ["cap", "floor"]
    assert report["rules"] == len(builtin_rules()) + 2


def test_cli_exits_three_without_the_solver(cli_env, capsys, monkeypatch) -> None:
    monkeypatch.setitem(sys.modules, "z3", None)
    assert cli.main(["lint"]) == 3
    captured = capsys.readouterr()
    assert "not installed" in captured.err
    assert "no findings" not in captured.out


def test_cli_reports_a_malformed_ledger(cli_env, capsys, tmp_path) -> None:
    (tmp_path / "ledger.json").write_text("{not json", encoding="utf-8")
    assert cli.main(["lint"]) == 1
    assert "not valid JSON" in capsys.readouterr().err
