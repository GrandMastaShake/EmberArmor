"""The gate asks before its own files, rules, variables and hook are changed.

Covers the ``assigns`` predicate, the ``gate.*`` rules of the built-in pack
and the hook end to end.  Command strings are data; the only processes
started are the gate's own hook.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ember_armor.ledger.audit import restore, summarise
from ember_armor.ledger.builtin import builtin_rules
from ember_armor.ledger.engine import evaluate
from ember_armor.ledger.facts import extract
from ember_armor.ledger.model import AssignsPred, LedgerError, parse_ledger, parse_rule
from tests.ledger.helpers import facts_for, make_call, rule, run_gate

HOOK = "ember_armor.ledger.hook"
GATE_VARIABLES = {"type": "assigns", "name": ["EMBER_*", "CI"]}


def fired(tool: str, payload: Any, platform: str = "posix") -> list[str]:
    decision = evaluate(builtin_rules(), facts_for(tool, payload, platform))
    return [rule.id.removeprefix("builtin.") for rule in decision.fired]


# ---------------------------------------------------------------------------
# the assigns predicate
# ---------------------------------------------------------------------------
def test_assigns_is_parsed_and_validated() -> None:
    parsed = parse_rule(rule(when=GATE_VARIABLES))
    assert parsed.predicate == AssignsPred(name=("EMBER_*", "CI"))
    for broken in ({"type": "assigns"}, {"type": "assigns", "name": []},
                   {"type": "assigns", "name": ["A"], "value": "x"}):  # fmt: skip
        with pytest.raises(LedgerError):
            parse_rule(rule(when=broken))


ASSIGNS = [
    ("Bash", "EMBER_GATE_MODE=observe make", True),
    ("Bash", "CI=1 npm test", True),
    ("Bash", "export EMBER_HOME=/tmp/x", True),
    ("Bash", "env -u EMBER_LEDGER make", True),
    ("Bash", "sudo env CI=1 make", True),
    ("Bash", "x=$(EMBER_HOME=/tmp/x ember-gate lint)", True),
    ("Bash", "echo EMBER_GATE_MODE=observe", False),
    ("Bash", "echo $CI; printenv EMBER_HOME", False),
    ("Bash", "ci=1 make", False),
    ("Bash", "MY_EMBER_HOME=1 make", False),
    ("PowerShell", "$env:EMBER_HOME = 'C:\\x'", True),
    ("PowerShell", "$env:ci = 'true'", True),
    ("PowerShell", "$CI = 'true'", False),
    ("PowerShell", "Write-Host $env:CI", False),
    ("Read", {"file_path": "EMBER_HOME=x"}, False),
]


@pytest.mark.parametrize(("tool", "payload", "expected"), ASSIGNS)
def test_assigns_holds_for_what_the_shell_input_sets(
    tool: str, payload: Any, expected: bool
) -> None:
    rules = parse_ledger({"version": 1, "rules": [rule(when=GATE_VARIABLES)]})
    assert (evaluate(rules, facts_for(tool, payload)).effect == "deny") is expected


def test_names_fold_case_on_windows_only() -> None:
    rules = parse_ledger({"version": 1, "rules": [rule(when=GATE_VARIABLES)]})
    assert evaluate(rules, facts_for("Bash", "ci=1 make", "windows")).effect == "deny"
    assert evaluate(rules, facts_for("Bash", "ci=1 make", "posix")).effect == "none"


def test_assigned_names_survive_the_audit_summary() -> None:
    facts = facts_for("Bash", "EMBER_GATE_MODE=observe TOKEN=hunter2secret make")
    assert facts.assigned == ("EMBER_GATE_MODE", "TOKEN")
    summary = summarise(facts)
    assert summary["assigned"] == ["EMBER_GATE_MODE", "TOKEN"]
    assert "hunter2secret" not in json.dumps(summary)
    entry = {"tool": "Bash", "cwd": facts.cwd, "session": "s1", "call": summary}
    assert restore(entry).assigned == facts.assigned


def test_lint_treats_assigns_as_an_atom() -> None:
    pytest.importorskip("z3")
    from ember_armor.ledger.lint import lint

    rules = parse_ledger(
        {
            "version": 1,
            "rules": [
                rule("a", when=GATE_VARIABLES),
                rule("b", when=GATE_VARIABLES, effect="ask"),
                rule("c", when={"type": "assigns", "name": ["OTHER"]}),
            ],
        }
    )
    findings = [(finding.kind, finding.rules) for finding in lint(rules)]
    assert findings == [("shadowed", ("b", "a"))]


# ---------------------------------------------------------------------------
# the gate.* rules
# ---------------------------------------------------------------------------
def test_the_ember_home_named_by_the_environment_is_covered(tmp_path: Path) -> None:
    home = tmp_path / "elsewhere"
    env = {"HOME": "/home/dev", "EMBER_HOME": str(home)}

    def decide(tool: str, payload: Any) -> list[str]:
        call = make_call(tool, payload, cwd=str(tmp_path))
        decision = evaluate(builtin_rules(), extract(call, env=env))
        return [rule.id for rule in decision.fired]

    target = str(home / "config.json")
    assert decide("Write", {"file_path": target, "content": "{}"}) == [
        "builtin.gate.files"
    ]
    assert decide("Read", {"file_path": target}) == []
    assert decide("Bash", "echo x > $EMBER_HOME/config.json") == ["builtin.gate.files"]
    assert decide("Write", {"file_path": str(tmp_path / "other.json")}) == []


def test_reads_of_the_gates_files_are_not_restricted() -> None:
    assert fired("Bash", "cat ~/.ember/config.json; ls ~/.ember/audit") == []
    assert fired("Read", {"file_path": "~/.ember/ledger.json"}) == []
    assert fired("Grep", {"path": "~/.ember", "pattern": "mode"}) == []


def test_only_the_editing_subcommands_are_asked_about() -> None:
    for harmless in ("list", "list --json"):
        assert fired("Bash", f"ember-gate rules {harmless}") == []
    for edit in ("add --file r.json", "confirm x", "remove x"):
        assert fired("Bash", f"ember-gate rules {edit}") == ["gate.rules"]
        module = f"python -m ember_armor.ledger.cli rules {edit}"
        assert fired("Bash", module) == ["gate.rules"]
        assert fired("PowerShell", f"ember-gate.exe rules {edit}") == ["gate.rules"]


SETTINGS = [
    ("~/.claude/settings.json", True),
    (".claude/settings.json", True),
    (".claude/settings.local.json", True),
    ("sub/project/.claude/settings.json", True),
    (".claude/commands/x.md", False),
    ("settings.json", False),
    (".vscode/settings.json", False),
]


@pytest.mark.parametrize(("path", "asked"), SETTINGS)
def test_claude_code_settings_files(path: str, asked: bool) -> None:
    expected = ["gate.host-settings"] if asked else []
    for platform in ("posix", "windows"):
        call = {"file_path": path, "content": "{}"}
        assert fired("Write", call, platform) == expected
        assert fired("Bash", f"echo '{{}}' > {path}", platform) == expected
        assert fired("Read", {"file_path": path}, platform) == []


# ---------------------------------------------------------------------------
# through the hook
# ---------------------------------------------------------------------------
HOOKED = [
    ("Write", {"file_path": "{home}/config.json", "content": "{{}}"}, "gate.files"),
    ("Bash", "rm {home}/ledger.json", "gate.files"),
    ("Bash", "EMBER_GATE_MODE=observe git status", "gate.environment"),
    ("Bash", "ember-gate rules confirm x", "gate.rules"),
    ("Edit", {"file_path": ".claude/settings.json"}, "gate.host-settings"),
]


@pytest.mark.parametrize(("tool", "payload", "rule_id"), HOOKED)
def test_the_hook_asks_in_enforce_mode(
    gate_env: dict[str, str], tmp_path: Path, tool: str, payload: Any, rule_id: str
) -> None:
    home = Path(gate_env["EMBER_HOME"]).as_posix()
    if isinstance(payload, dict):
        payload = {k: v.format(home=home) for k, v in payload.items()}
    else:
        payload = payload.format(home=home)
    call = json.dumps(make_call(tool, payload, cwd=str(tmp_path)))
    done = run_gate([], gate_env, stdin=call, mode="enforce", module=HOOK)
    assert done.returncode == 0
    specific = json.loads(done.stdout)["hookSpecificOutput"]
    assert specific["permissionDecision"] == "ask"
    assert f"builtin.{rule_id}" in specific["permissionDecisionReason"]
    quiet = run_gate([], gate_env, stdin=call, mode="observe", module=HOOK)
    assert quiet.stdout == b""
