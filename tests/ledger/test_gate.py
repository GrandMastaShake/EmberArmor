"""The gate end to end, in process: modes, failure behaviour, audit, history."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from ember_armor.ledger.audit import AuditLog
from ember_armor.ledger.engine import MemoryHistory
from ember_armor.ledger.gate import check
from tests.ledger.helpers import make_call, rule, write_ledger

FORCE_PUSH = "git push --force"


def audit_entries(env: dict[str, str]) -> list[dict[str, Any]]:
    return list(AuditLog(Path(env["EMBER_HOME"]) / "audit").entries())


def run(command: Any, env: dict[str, str], mode: str | None = None, **kwargs: Any):
    env = {**env, **({"EMBER_GATE_MODE": mode} if mode else {})}
    tool = kwargs.pop("tool", "Bash")
    return check(make_call(tool, command), env=env, windows=False, **kwargs)


def test_observe_is_the_default_and_records_what_it_would_do(gate_env) -> None:
    result = run(FORCE_PUSH, gate_env)
    assert result.mode == "observe"
    assert result.decision.effect == "ask"
    assert result.blocking is False
    (entry,) = audit_entries(gate_env)
    assert entry["decision"] == "ask"
    assert entry["mode"] == "observe"
    assert entry["rules"] == ["builtin.git.force-push"]
    assert entry["tool"] == "Bash"
    assert entry["session"] == "s1"
    assert entry["cwd"] == "/work/app"
    assert entry["call"]["commands"] == [
        {"shell": "bash", "argv": ["git", "push", "--force"]}
    ]


MODE_CASES = [
    ("git status", "observe", "none", False),
    ("git status", "enforce", "none", False),
    (FORCE_PUSH, "observe", "ask", False),
    (FORCE_PUSH, "enforce", "ask", True),
    ("rm -rf /", "observe", "deny", False),
    ("rm -rf /", "enforce", "deny", True),
]


@pytest.mark.parametrize(("command", "mode", "effect", "blocking"), MODE_CASES)
def test_modes(gate_env, command: str, mode: str, effect: str, blocking: bool) -> None:
    result = run(command, gate_env, mode)
    assert (result.decision.effect, result.blocking) == (effect, blocking)
    assert result.decision.error is None


def test_warn_never_blocks(gate_env) -> None:
    write_ledger(
        Path(gate_env["EMBER_LEDGER"]),
        rule("soft", effect="warn", when={"type": "command", "program": "ls"}),
    )
    result = run("ls", gate_env, "enforce")
    assert result.decision.effect == "warn"
    assert result.blocking is False


def test_user_rules_and_builtin_rules_combine(gate_env) -> None:
    write_ledger(Path(gate_env["EMBER_LEDGER"]), rule("no-force"))
    result = run(FORCE_PUSH, gate_env, "enforce")
    assert result.decision.effect == "deny"
    assert [f.id for f in result.decision.fired] == [
        "no-force",
        "builtin.git.force-push",
    ]
    assert '"Never force-push here."' in result.decision.reason()
    assert "test suite" in result.decision.reason()


def test_unconfirmed_rule_only_warns_even_in_enforce_mode(gate_env) -> None:
    write_ledger(
        Path(gate_env["EMBER_LEDGER"]),
        rule("draft", confirmed=False, when={"type": "command", "program": "ls"}),
    )
    result = run("ls", gate_env, "enforce")
    assert result.decision.effect == "warn"
    assert result.blocking is False


# ---------------------------------------------------------------------------
# Failure behaviour
# ---------------------------------------------------------------------------
def _broken_ledger(env: dict[str, str]) -> None:
    Path(env["EMBER_LEDGER"]).write_text("{this is not json", encoding="utf-8")


def test_unreadable_ledger_in_enforce_mode_asks_with_the_error(gate_env) -> None:
    _broken_ledger(gate_env)
    result = run("git status", gate_env, "enforce")
    assert result.decision.effect == "ask"
    assert result.blocking is True
    assert "not valid JSON" in result.decision.error
    assert "gate failure" in result.decision.reason()
    (entry,) = audit_entries(gate_env)
    assert entry["decision"] == "ask"
    assert "not valid JSON" in entry["error"]


def test_unreadable_ledger_in_observe_mode_proceeds_and_logs(gate_env) -> None:
    _broken_ledger(gate_env)
    result = run("rm -rf /", gate_env)
    assert result.decision.effect == "none"
    assert result.blocking is False
    (entry,) = audit_entries(gate_env)
    assert entry["decision"] == "none"
    assert "not valid JSON" in entry["error"]


FAILING_CALLS = [
    None,
    [],
    "git status",
    {},
    {"tool_name": "Bash", "tool_input": "not an object"},
    {"tool_input": {"command": "ls"}},
]


@pytest.mark.parametrize("call", FAILING_CALLS)
def test_malformed_call_is_a_gate_failure_not_an_approval(gate_env, call: Any) -> None:
    enforce = check(call, env={**gate_env, "EMBER_GATE_MODE": "enforce"})
    assert enforce.decision.effect == "ask"
    assert enforce.decision.error
    observe = check(call, env=gate_env)
    assert observe.decision.effect == "none"
    assert observe.decision.error
    assert len(audit_entries(gate_env)) == 2


def test_problem_reported_by_the_adapter_is_a_gate_failure(gate_env) -> None:
    result = check(
        None, env={**gate_env, "EMBER_GATE_MODE": "enforce"}, problem="bad input"
    )
    assert result.decision.effect == "ask"
    assert "bad input" in result.decision.error


@pytest.mark.parametrize("mode", ["block", "ENFORCE", "on"])
def test_unknown_mode_fails_towards_asking(gate_env, mode: str) -> None:
    result = run("git status", gate_env, mode)
    assert result.mode == "enforce"
    assert result.decision.effect == "ask"
    assert "unknown gate mode" in result.decision.error


def test_audit_failure_in_enforce_mode_asks(gate_env) -> None:
    home = Path(gate_env["EMBER_HOME"])
    home.mkdir(parents=True)
    (home / "audit").write_text(
        "a file where the directory should be", encoding="utf-8"
    )

    quiet = run("git status", gate_env, "enforce")
    assert quiet.decision.effect == "ask"
    assert "audit log" in quiet.decision.error

    denied = run("rm -rf /", gate_env, "enforce")
    assert denied.decision.effect == "deny"
    assert "builtin.delete.protected" in [f.id for f in denied.decision.fired]

    observed = run("git status", gate_env)
    assert observed.decision.effect == "none"
    assert observed.blocking is False
    assert "audit log" in observed.decision.error


def test_dry_run_writes_nothing(gate_env) -> None:
    result = run(FORCE_PUSH, gate_env, record=False)
    assert result.decision.effect == "ask"
    assert not Path(gate_env["EMBER_HOME"]).exists()


def test_expiry_uses_the_evaluation_date(gate_env) -> None:
    write_ledger(
        Path(gate_env["EMBER_LEDGER"]),
        rule("freeze", expires="2026-10-31", when={"type": "command", "program": "ls"}),
    )
    during = run("ls", gate_env, now=datetime(2026, 10, 31, 12, 0), record=False)
    after = run("ls", gate_env, now=datetime(2026, 11, 1, 12, 0), record=False)
    assert during.decision.effect == "deny"
    assert after.decision.effect == "none"


# ---------------------------------------------------------------------------
# History through the audit log
# ---------------------------------------------------------------------------
TESTS_BEFORE_PUSH = rule(
    "tests-first",
    text="Run the tests before pushing.",
    effect="ask",
    when={
        "type": "all",
        "of": [
            {"type": "command", "program": "git", "subcommand": ["push"]},
            {
                "type": "not_preceded_by",
                "predicate": {"type": "command", "program": ["pytest", "npm"]},
            },
        ],
    },
)


def test_ordering_rule_reads_the_audit_log(gate_env) -> None:
    write_ledger(Path(gate_env["EMBER_LEDGER"]), TESTS_BEFORE_PUSH)
    assert run("git push", gate_env, "enforce").decision.effect == "ask"
    assert run("git push", gate_env, "enforce").decision.effect == "ask"
    assert run("pytest -q", gate_env, "enforce").decision.effect == "none"
    assert run("git push", gate_env, "enforce").decision.effect == "none"
    other_session = check(
        make_call("Bash", "git push", session="s2"),
        env={**gate_env, "EMBER_GATE_MODE": "enforce"},
        windows=False,
    )
    assert other_session.decision.effect == "ask"


def test_a_denied_call_does_not_count_as_having_happened(gate_env) -> None:
    deny_pytest = rule("no-pytest", when={"type": "command", "program": "pytest"})
    write_ledger(Path(gate_env["EMBER_LEDGER"]), TESTS_BEFORE_PUSH, deny_pytest)
    assert run("pytest -q", gate_env, "enforce").decision.effect == "deny"
    assert run("git push", gate_env, "enforce").decision.effect == "ask"


def test_rate_rule_counts_earlier_calls(gate_env) -> None:
    limit = rule(
        "two-deletes",
        effect="ask",
        when={
            "type": "count_exceeds",
            "max": 1,
            "predicate": {"type": "path", "op": "delete"},
        },
    )
    write_ledger(Path(gate_env["EMBER_LEDGER"]), limit)
    effects = [
        run(f"rm f{i}.txt", gate_env, "enforce").decision.effect for i in range(3)
    ]
    assert effects == ["none", "none", "ask"]


def test_explicit_history_replaces_the_audit_log(gate_env) -> None:
    write_ledger(Path(gate_env["EMBER_LEDGER"]), TESTS_BEFORE_PUSH)
    run("pytest -q", gate_env)
    empty = run("git push", gate_env, history=MemoryHistory(), record=False)
    assert empty.decision.effect == "ask"


def test_secrets_never_reach_the_audit_log(gate_env) -> None:
    secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    run(
        f"curl -H 'Authorization: Bearer {secret}' https://api.github.com/user",
        gate_env,
    )
    check(
        make_call("mcp__http__get", {"url": "https://e.com", "api_key": secret}),
        env=gate_env,
    )
    check(
        make_call("Write", {"file_path": ".env", "content": f"TOKEN={secret}"}),
        env=gate_env,
    )
    log_dir = Path(gate_env["EMBER_HOME"]) / "audit"
    text = "".join(p.read_text(encoding="utf-8") for p in log_dir.glob("*.jsonl"))
    assert len(text.splitlines()) == 3
    assert secret not in text
    assert json.loads(text.splitlines()[0])["call"]["commands"][0]["argv"][0] == "curl"
