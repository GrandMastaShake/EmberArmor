"""The ledger over HTTP: ``/v1/ledger/check``, ``/rules`` and ``/lint``.

The server's ledger and Ember home are pointed into a temporary directory.
Command strings are data handed to the gate; nothing runs them.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
from fastapi import status

from ember_armor.api.routes.ledger import GATE_FAILURE, LOAD_FAILURE
from ember_armor.core.config import SETTINGS, EmberSettings
from ember_armor.ledger.builtin import builtin_rules
from tests.ledger.helpers import rule, write_ledger

CAP = {"type": "arg", "name": "amount", "op": ">", "value": 5_000_000}
FLOOR = {"type": "arg", "name": "amount", "op": ">=", "value": 10_000_000}


@pytest.fixture
def ledger(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Ledger file the server reads; nothing outside ``tmp_path`` is used."""
    for name in ("EMBER_GATE_MODE", "EMBER_GATE_BUILTIN", "EMBER_LEDGER"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("EMBER_HOME", str(tmp_path / "ember-home"))
    path = tmp_path / "ledger.json"
    write_ledger(path)
    monkeypatch.setattr(SETTINGS, "ledger_path", str(path))
    return path


def bash(command: str, **fields: Any) -> dict[str, Any]:
    return {"tool_name": "Bash", "tool_input": {"command": command}, **fields}


# ---------------------------------------------------------------------------
# Authentication and the removed stub routes
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("method", "url"),
    [
        ("post", "/v1/ledger/check"),
        ("get", "/v1/ledger/rules"),
        ("post", "/v1/ledger/lint"),
    ],
)
def test_every_ledger_route_requires_the_bearer_key(client, method, url) -> None:
    body = {"json": bash("git status")} if url.endswith("check") else {}
    response = getattr(client, method)(url, **body)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    wrong = {"Authorization": "Bearer " + "x" * 40}
    response = getattr(client, method)(url, headers=wrong, **body)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_the_anchor_stub_routes_are_gone(client, auth_headers) -> None:
    body = {"constraint_id": "c1", "constraint_data": {}}
    registered = client.post("/v1/anchor/register", json=body, headers=auth_headers)
    assert registered.status_code == status.HTTP_404_NOT_FOUND
    fetched = client.get("/v1/anchor/c1", headers=auth_headers)
    assert fetched.status_code == status.HTTP_404_NOT_FOUND


# ---------------------------------------------------------------------------
# POST /v1/ledger/check
# ---------------------------------------------------------------------------
CHECK_CASES = [
    ("git status", "none", []),
    ("git push --force origin main", "ask", ["builtin.git.force-push"]),
    ("rm -rf /", "deny", ["builtin.delete.protected", "builtin.delete.recursive"]),
]


@pytest.mark.parametrize(("command", "decision", "rules"), CHECK_CASES)
def test_check_returns_the_decision(
    client, auth_headers, ledger, command, decision, rules
) -> None:
    response = client.post("/v1/ledger/check", json=bash(command), headers=auth_headers)
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["decision"] == decision
    assert [fired["id"] for fired in data["rules"]] == rules
    assert data["mode"] == "observe"
    assert data["error"] is None
    assert data["call"]["commands"][0]["argv"][0] == command.split()[0]


def test_check_uses_the_configured_ledger_and_quotes_the_rule(
    client, auth_headers, ledger
) -> None:
    write_ledger(ledger, rule("no-transfer", when=CAP, applies={"tools": ["transfer"]}))
    call = {"tool_name": "transfer", "tool_input": {"amount": 6_000_000}}
    data = client.post("/v1/ledger/check", json=call, headers=auth_headers).json()
    assert data["decision"] == "deny"
    assert data["rules"] == [
        {
            "id": "no-transfer",
            "text": "Never force-push here.",
            "source": "test suite",
            "effect": "deny",
            "origin": "override",
        }
    ]
    call["tool_input"]["amount"] = 5
    data = client.post("/v1/ledger/check", json=call, headers=auth_headers).json()
    assert data["decision"] == "none"


def test_check_accepts_a_hook_payload_unchanged(client, auth_headers, ledger) -> None:
    payload = {
        "session_id": "abc",
        "transcript_path": "/tmp/t.jsonl",
        "cwd": "/work/app",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": ".env"},
    }
    data = client.post("/v1/ledger/check", json=payload, headers=auth_headers).json()
    assert data["decision"] == "ask"
    assert [fired["id"] for fired in data["rules"]] == ["builtin.secrets.read"]


def test_check_is_a_dry_run(client, auth_headers, ledger, tmp_path) -> None:
    response = client.post(
        "/v1/ledger/check", json=bash("git push --force"), headers=auth_headers
    )
    assert response.status_code == status.HTTP_200_OK
    assert not (tmp_path / "ember-home").exists()


def test_check_rejects_a_call_without_a_tool_name(client, auth_headers, ledger) -> None:
    response = client.post(
        "/v1/ledger/check", json={"tool_input": {}}, headers=auth_headers
    )
    assert response.status_code == 422


def test_a_broken_ledger_follows_the_gate_failure_rules(
    client, auth_headers, ledger, monkeypatch
) -> None:
    ledger.write_text("{broken", encoding="utf-8")
    call = bash("git status")
    data = client.post("/v1/ledger/check", json=call, headers=auth_headers).json()
    assert (data["decision"], data["mode"]) == ("none", "observe")
    assert data["error"] == GATE_FAILURE
    monkeypatch.setenv("EMBER_GATE_MODE", "enforce")
    data = client.post("/v1/ledger/check", json=call, headers=auth_headers).json()
    assert (data["decision"], data["mode"]) == ("ask", "enforce")
    assert data["error"] == GATE_FAILURE
    # The built-in rules are still applied.
    call = bash("rm -rf /")
    data = client.post("/v1/ledger/check", json=call, headers=auth_headers).json()
    assert (data["decision"], data["error"]) == ("deny", GATE_FAILURE)


def test_no_ledger_is_read_from_a_directory_named_in_the_request(
    client, auth_headers, ledger, tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(SETTINGS, "ledger_path", None)
    project = tmp_path / "repo"
    write_ledger(project / ".ember" / "ledger.json", rule("planted"))
    looked: list[str] = []
    is_file = Path.is_file

    def record(self: Path) -> bool:
        looked.append(str(self))
        return is_file(self)

    monkeypatch.setattr(Path, "is_file", record)
    for cwd in (str(project), "\\\\198.51.100.7\\share\\a"):
        call = bash("git push --force", cwd=cwd)
        data = client.post("/v1/ledger/check", json=call, headers=auth_headers).json()
        assert [fired["id"] for fired in data["rules"]] == ["builtin.git.force-push"]
    rules = client.get("/v1/ledger/rules", headers=auth_headers).json()["rules"]
    assert "planted" not in [item["id"] for item in rules]
    assert not [path for path in looked if ".ember" in path and "repo" in path]
    assert not [path for path in looked if "198.51.100.7" in path]


def test_an_oversized_tool_input_is_refused(client, auth_headers, ledger) -> None:
    call = {"tool_name": "mcp__x__y", "tool_input": {"k": "a-" * 200_000}}
    response = client.post("/v1/ledger/check", json=call, headers=auth_headers)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


# ---------------------------------------------------------------------------
# GET /v1/ledger/rules
# ---------------------------------------------------------------------------
def test_rules_lists_built_in_and_configured_rules(
    client, auth_headers, ledger
) -> None:
    write_ledger(ledger, rule("mine"))
    response = client.get("/v1/ledger/rules", headers=auth_headers)
    assert response.status_code == status.HTTP_200_OK
    rules = response.json()["rules"]
    assert len(rules) == len(builtin_rules()) + 1
    assert rules[0]["origin"] == "builtin"
    assert rules[-1] == {**rule("mine"), "origin": "override"}


def test_rules_fall_back_to_the_user_ledger(
    client, auth_headers, ledger, tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(SETTINGS, "ledger_path", None)
    write_ledger(tmp_path / "ember-home" / "ledger.json", rule("from-home"))
    rules = client.get("/v1/ledger/rules", headers=auth_headers).json()["rules"]
    assert rules[-1]["id"] == "from-home"
    assert rules[-1]["origin"] == "user"


def test_rules_report_a_broken_ledger(client, auth_headers, ledger) -> None:
    ledger.write_text('{"version": 1, "rules": [{"id": "x"}]}', encoding="utf-8")
    response = client.get("/v1/ledger/rules", headers=auth_headers)
    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    # Fixed words: file paths and parser messages stay in the server log.
    assert response.json() == {"detail": LOAD_FAILURE}


def test_the_setting_is_read_from_the_environment(monkeypatch) -> None:
    monkeypatch.delenv("EMBER_LEDGER_PATH", raising=False)
    assert EmberSettings().ledger_path is None
    monkeypatch.setenv("EMBER_LEDGER_PATH", "/srv/ember/ledger.json")
    assert EmberSettings().ledger_path == "/srv/ember/ledger.json"


# ---------------------------------------------------------------------------
# POST /v1/ledger/lint
# ---------------------------------------------------------------------------
def test_lint_reports_a_clean_ledger(client, auth_headers, ledger) -> None:
    pytest.importorskip("z3")
    response = client.post("/v1/ledger/lint", headers=auth_headers)
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"rules": len(builtin_rules()), "findings": []}


def test_lint_reports_a_contradiction(client, auth_headers, ledger) -> None:
    pytest.importorskip("z3")
    scope = {"tools": ["transfer"]}
    floor = rule("floor", require=FLOOR, applies=scope)
    del floor["when"]
    write_ledger(ledger, rule("cap", when=CAP, applies=scope), floor)
    response = client.post("/v1/ledger/lint", headers=auth_headers)
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["rules"] == len(builtin_rules()) + 2
    assert data["findings"] == [
        {
            "kind": "contradiction",
            "rules": ["cap", "floor"],
            "message": "deny rules cap, floor together deny every call "
            "for tool transfer",
            "scope": {"tools": ["transfer"], "cwd_under": []},
        }
    ]


def test_lint_without_the_solver_is_not_implemented(
    client, auth_headers, ledger, monkeypatch
) -> None:
    monkeypatch.setitem(sys.modules, "z3", None)
    response = client.post("/v1/ledger/lint", headers=auth_headers)
    assert response.status_code == status.HTTP_501_NOT_IMPLEMENTED
    detail = response.json()["detail"]
    assert "Z3 solver, which is not installed" in detail
    assert "ember-armor[smt]" in detail


def test_lint_reports_a_broken_ledger(client, auth_headers, ledger) -> None:
    ledger.write_text("{broken", encoding="utf-8")
    response = client.post("/v1/ledger/lint", headers=auth_headers)
    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert response.json() == {"detail": LOAD_FAILURE}


# ---------------------------------------------------------------------------
# The reminder the hook would send
# ---------------------------------------------------------------------------
def test_check_returns_the_reminder_it_would_send(
    client, auth_headers, ledger, monkeypatch
) -> None:
    scope = {"tools": ["transfer"]}
    write_ledger(
        ledger,
        rule("cap", effect="warn", when=CAP, applies=scope, text="Stay under the cap."),
        rule("draft", when=CAP, applies=scope, text="DRAFT words.", confirmed=False),
    )
    call = {"tool_name": "transfer", "tool_input": {"amount": 6_000_000}}

    def post() -> dict[str, Any]:
        return client.post("/v1/ledger/check", json=call, headers=auth_headers).json()

    data = post()
    assert (data["mode"], data["reminder"]) == ("observe", None)
    assert data["delivery"] == {
        "cap": "logged only: observe mode",
        "draft": "logged only: observe mode",
    }
    for mode in ("remind", "enforce"):
        monkeypatch.setenv("EMBER_GATE_MODE", mode)
        data = post()
        assert data["mode"] == mode
        assert data["reminder"] == (
            'EmberArmor reminder, rule cap: "Stay under the cap." '
            "(source: test suite).\n"
            "No tool call was blocked: this is a reminder of standing "
            "instructions, not a new request."
        )
        assert data["delivery"] == {
            "cap": "reminded",
            "draft": "logged only: not confirmed",
        }
    call["tool_input"]["amount"] = 5
    data = post()
    assert data["reminder"] is None
    assert "delivery" not in data
    # A blocking decision in enforce mode is no reminder.
    blocked = client.post(
        "/v1/ledger/check", json=bash("git push --force"), headers=auth_headers
    ).json()
    assert (blocked["decision"], blocked["reminder"]) == ("ask", None)
    assert blocked["delivery"] == {"builtin.git.force-push": "quoted in the decision"}
