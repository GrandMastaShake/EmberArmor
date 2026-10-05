"""Directory scopes and owner exceptions over ``POST /v1/ledger/check``.

The directories of a call over HTTP come from the request, so the server
judges them as text and never asks its own disk about them.  The server's
ledger and Ember home are pointed into a temporary directory.  Command
strings are data handed to the gate; nothing runs them.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ember_armor.core.config import SETTINGS
from ember_armor.ledger import repo
from tests.ledger.helpers import rule, write_ledger

COMMIT = {"type": "command", "program": "git", "subcommand": ["commit"]}
RESET = "builtin.git.reset-hard"


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


def decide(client, headers, command: str, cwd: str) -> dict[str, Any]:
    call = {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": cwd}
    response = client.post("/v1/ledger/check", json=call, headers=headers)
    assert response.status_code == 200
    return response.json()


def test_a_directory_scope_is_judged_for_each_command(
    client, auth_headers, ledger
) -> None:
    write_ledger(
        ledger, rule("here", when=COMMIT, applies={"cwd_under": ["/srv/repo"]})
    )
    cases = [
        ("/srv/repo", "git commit", "deny"),
        ("/work", "cd /srv/repo && git commit", "deny"),
        ("/work", "git -C /srv/repo commit", "deny"),
        ("/srv/repo", "cd /work && git commit", "none"),
        ("/srv/repo", "git -C /work commit", "none"),
    ]
    for cwd, command, expected in cases:
        data = decide(client, auth_headers, command, cwd)
        assert data["decision"] == expected, (cwd, command)


def test_a_request_that_names_no_directory_is_in_scope(
    client, auth_headers, ledger
) -> None:
    write_ledger(
        ledger, rule("here", when=COMMIT, applies={"cwd_under": ["/srv/repo"]})
    )
    call = {"tool_name": "Bash", "tool_input": {"command": "git commit"}}
    response = client.post("/v1/ledger/check", json=call, headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "deny"
    assert data["call"]["located"] is False
    assert data["call"]["commands"][0]["cwd"] == "?"
    assert decide(client, auth_headers, "git commit", "")["decision"] == "deny"
    assert (
        decide(client, auth_headers, "git commit", "some/where")["decision"] == "deny"
    )
    # A command that names its directory is placed again.
    data = decide(client, auth_headers, "cd /work && git commit", "")
    assert data["decision"] == "none"


def test_no_repository_is_looked_up_for_a_request(
    client, auth_headers, ledger, tmp_path: Path, monkeypatch
) -> None:
    def refuse(*args: Any) -> None:
        raise AssertionError("the server asked its disk about a request's directory")

    monkeypatch.setattr(repo, "finder", refuse)
    monkeypatch.setattr(repo, "find_root", refuse)
    monkeypatch.setattr(repo, "has_git", refuse)
    top = tmp_path / "top"
    (top / ".git").mkdir(parents=True)
    write_ledger(ledger, rule("top", when=COMMIT, applies={"repo_root": [str(top)]}))
    # Not known, so in scope: the rule fires wherever the request says it is.
    for cwd in (str(top), str(tmp_path), "/nowhere/at/all"):
        data = decide(client, auth_headers, "git commit", cwd)
        assert data["decision"] == "deny", cwd
        assert data["error"] is None
    assert decide(client, auth_headers, "git status", str(top))["decision"] == "none"


def test_exceptions_of_the_server_configuration_apply(
    client, auth_headers, ledger, tmp_path: Path
) -> None:
    home = tmp_path / "ember-home"
    home.mkdir()
    exceptions = [
        {"rule": RESET, "cwd_under": ["/srv/jobs"], "reason": "the nightly job"},
        {"rule": "builtin.git.clean", "repo_root": ["/srv/jobs/site"], "reason": "x"},
    ]
    (home / "config.json").write_text(json.dumps({"exceptions": exceptions}))
    data = decide(client, auth_headers, "git -C /srv/jobs/site reset --hard", "/work")
    assert data["decision"] == "none"
    assert data["excepted"] == [{"rule": RESET, "reason": "the nightly job"}]
    data = decide(client, auth_headers, "git reset --hard", "/work")
    assert data["decision"] == "ask"
    assert "excepted" not in data
    # A repository is not looked up, so an exception tied to one never holds.
    data = decide(client, auth_headers, "git clean -fd", "/srv/jobs/site")
    assert data["decision"] == "ask"
    assert "excepted" not in data
