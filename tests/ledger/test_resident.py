"""The resident gate: the hook as a local HTTP server.

The server is run in a thread of the test with a temporary Ember home, and
once as a real detached process started the way the SessionStart hook
starts it.  The command strings in the calls are data for the gate;
nothing executes them.
"""

from __future__ import annotations

import io
import json
import os
import sys
import threading
import time
from collections.abc import Iterator
from http.client import HTTPConnection
from pathlib import Path
from typing import Any

import pytest

from ember_armor.ledger import cli, hook
from ember_armor.ledger.resident import (
    TOKEN_HEADER,
    Address,
    address,
    ensure,
    health,
    serve,
    stop,
)
from tests.ledger.helpers import make_call, rule, write_ledger

QUIET = json.dumps(make_call("Bash", "git status")).encode("utf-8")
FORCE = json.dumps(make_call("Bash", "git push --force origin main")).encode("utf-8")
#: The same call from another session: a reminder is sent once per session.
FORCE_S2 = json.dumps(
    make_call("Bash", "git push --force origin main", session="s2")
).encode("utf-8")
START = json.dumps(
    {"session_id": "s1", "cwd": "/work/app", "source": "compact"}
).encode()


@pytest.fixture
def home_env(gate_env: dict[str, str], tmp_path: Path) -> dict[str, str]:
    """A home with one confirmed rule, in remind mode."""
    write_ledger(tmp_path / "ledger.json", rule("force"))
    return {**gate_env, "EMBER_GATE_MODE": "remind"}


def run(server: Any) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


@pytest.fixture
def gate(home_env: dict[str, str]) -> Iterator[Any]:
    server = serve(home_env, idle_minutes=60, respawn=False, block=False)
    thread = run(server)
    yield server
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def post(
    where: Address, route: str, body: bytes, token: str | None = None
) -> tuple[int, bytes]:
    connection = HTTPConnection("127.0.0.1", where.port, timeout=5)
    headers = {
        TOKEN_HEADER: where.token if token is None else token,
        "Content-Type": "application/json",
    }
    connection.request("POST", route, body=body, headers=headers)
    response = connection.getresponse()
    return response.status, response.read()


def audit_lines(env: dict[str, str]) -> int:
    directory = Path(env["EMBER_HOME"]) / "audit"
    if not directory.exists():
        return 0
    return sum(
        len(path.read_text(encoding="utf-8").splitlines())
        for path in directory.glob("*.jsonl")
    )


# ---------------------------------------------------------------------------
# The address
# ---------------------------------------------------------------------------
def test_the_address_is_written_once_for_the_owner(home_env: dict[str, str]) -> None:
    assert address(home_env) is None
    first = address(home_env, create=True)
    assert first is not None
    assert address(home_env, create=True) == first
    assert address(home_env) == first
    assert first.port > 0 and len(first.token) == 32
    assert first.url == f"http://127.0.0.1:{first.port}"
    path = Path(home_env["EMBER_HOME"]) / "resident.json"
    if os.name != "nt":
        assert oct(path.stat().st_mode & 0o777) == "0o600"


def test_a_broken_address_file_is_an_error(home_env: dict[str, str]) -> None:
    path = Path(home_env["EMBER_HOME"]) / "resident.json"
    path.parent.mkdir(parents=True)
    path.write_text('{"port": "x"}', encoding="utf-8")
    with pytest.raises(ValueError, match="port and a token"):
        address(home_env)


# ---------------------------------------------------------------------------
# What the server answers
# ---------------------------------------------------------------------------
def test_the_resident_gate_answers_like_the_command_hook(
    gate: Any, home_env: dict[str, str]
) -> None:
    expected, _ = hook.respond((), FORCE_S2, home_env)
    assert "additionalContext" in expected
    status, body = post(gate.where, "/hook", FORCE)
    assert status == 200
    assert body.decode("utf-8") == expected
    reminder = json.loads(body)["hookSpecificOutput"]["additionalContext"]
    assert reminder.startswith("EmberArmor reminder, rule force")
    assert post(gate.where, "/hook", QUIET) == (200, b"")
    assert gate.served == 2
    assert audit_lines(home_env) == 3  # hook.respond above logged one too


def test_a_wrong_token_is_refused_and_nothing_is_logged(
    gate: Any, home_env: dict[str, str]
) -> None:
    assert post(gate.where, "/hook", FORCE, token="nope")[0] == 401
    assert post(gate.where, "/hook", FORCE, token="")[0] == 401
    assert gate.served == 0
    assert audit_lines(home_env) == 0
    assert health(Address(gate.where.port, "nope")) is None


def test_health_describes_the_server(gate: Any) -> None:
    state = health(gate.where)
    assert state is not None
    assert state["ok"] is True
    assert state["served"] == 0
    assert state["stale"] is False
    assert state["pid"] == os.getpid()
    assert state["marker"] == gate.started_marker


def test_unknown_routes_are_not_found(gate: Any) -> None:
    assert post(gate.where, "/elsewhere", QUIET)[0] == 404


def test_the_session_start_summary_over_http(
    gate: Any, home_env: dict[str, str]
) -> None:
    expected, _ = hook.respond(("--event", "session-start"), START, home_env)
    status, body = post(gate.where, "/session-start", START)
    assert status == 200
    assert body.decode("utf-8") == expected


def test_an_error_goes_to_the_log_not_to_the_response(
    gate: Any, home_env: dict[str, str]
) -> None:
    status, body = post(gate.where, "/hook", b"{not json")
    assert (status, body) == (200, b"")  # remind mode: a gate failure passes
    log = (Path(home_env["EMBER_HOME"]) / "resident.log").read_text(encoding="utf-8")
    assert "malformed hook input" in log


# ---------------------------------------------------------------------------
# How the server comes and goes
# ---------------------------------------------------------------------------
def test_stop_shuts_the_server_down(home_env: dict[str, str]) -> None:
    server = serve(home_env, idle_minutes=60, respawn=False, block=False)
    thread = run(server)
    assert stop(server.where)
    thread.join(timeout=5)
    assert not thread.is_alive()
    server.server_close()
    assert health(server.where) is None
    assert not stop(server.where)


def test_the_server_exits_when_idle(home_env: dict[str, str]) -> None:
    server = serve(home_env, idle_minutes=0.002, respawn=False, block=False)
    thread = run(server)
    thread.join(timeout=10)
    assert not thread.is_alive()
    server.server_close()
    log = (Path(home_env["EMBER_HOME"]) / "resident.log").read_text(encoding="utf-8")
    assert "exit: idle" in log


def test_a_reinstalled_package_makes_the_server_leave_after_answering(
    home_env: dict[str, str],
) -> None:
    stamps = ["installed"]
    server = serve(
        home_env,
        idle_minutes=60,
        respawn=False,
        block=False,
        marker_of=lambda: stamps[-1],
    )
    thread = run(server)
    assert health(server.where) is not None
    stamps.append("reinstalled")
    assert post(server.where, "/hook", QUIET) == (200, b"")  # answered first
    thread.join(timeout=5)
    assert not thread.is_alive()
    server.server_close()
    log = (Path(home_env["EMBER_HOME"]) / "resident.log").read_text(encoding="utf-8")
    assert "exit: the installed package changed" in log


def test_a_second_server_on_the_same_home_steps_aside(
    gate: Any, home_env: dict[str, str]
) -> None:
    with pytest.raises(SystemExit) as stopped:
        serve(home_env, idle_minutes=60, respawn=False, block=False)
    assert stopped.value.code == 0
    assert address(home_env) == gate.where  # the address file is untouched


def test_ensure_starts_a_real_server_and_finds_it_again(
    home_env: dict[str, str],
) -> None:
    assert ensure(home_env) == "not configured"
    where = address(home_env, create=True)
    assert where is not None
    assert ensure(home_env, wait=20.0) == "running"
    state = health(where)
    assert state is not None
    assert state["pid"] != os.getpid()
    assert ensure(home_env) == "running"
    assert post(where, "/hook", QUIET) == (200, b"")
    assert stop(where)
    deadline = time.monotonic() + 10
    while health(where) is not None and time.monotonic() < deadline:
        time.sleep(0.1)
    assert health(where) is None


# ---------------------------------------------------------------------------
# The command line and the hook
# ---------------------------------------------------------------------------
@pytest.fixture
def cli_env(
    home_env: dict[str, str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> dict[str, str]:
    for name in ("EMBER_GATE_MODE", "EMBER_GATE_BUILTIN"):
        monkeypatch.delenv(name, raising=False)
    for name, value in home_env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.chdir(tmp_path)
    return home_env


def test_install_prints_the_http_form(
    cli_env: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["install", "claude-code", "--print", "--resident"]) == 0
    snippet = json.loads(capsys.readouterr().out)
    where = address(cli_env)
    assert where is not None
    [pre] = snippet["hooks"]["PreToolUse"][0]["hooks"]
    assert pre == {
        "type": "http",
        "url": f"{where.url}/hook",
        "headers": {TOKEN_HEADER: where.token},
        "timeout": 20,
    }
    [start] = snippet["hooks"]["SessionStart"][0]["hooks"]
    assert start["type"] == "command"
    assert start["args"][-2:] == ["--event", "session-start"]
    assert cli.main(["install", "claude-code", "--print"]) == 0
    plain = json.loads(capsys.readouterr().out)
    assert plain["hooks"]["PreToolUse"][0]["hooks"][0]["type"] == "command"


def test_resident_status_and_stop_from_the_command_line(
    cli_env: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["resident", "status"]) == 1
    assert "not configured" in capsys.readouterr().out
    address(cli_env, create=True)
    assert cli.main(["resident", "status"]) == 1
    assert "not running" in capsys.readouterr().out
    server = serve(cli_env, idle_minutes=60, respawn=False, block=False)
    thread = run(server)
    assert cli.main(["resident", "status"]) == 0
    state = json.loads(capsys.readouterr().out)
    assert state["pid"] == os.getpid() and state["port"] == server.where.port
    assert cli.main(["resident", "stop"]) == 0
    assert "stopped" in capsys.readouterr().out
    thread.join(timeout=5)
    server.server_close()


def test_the_session_start_hook_sees_to_the_resident_gate(
    cli_env: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from ember_armor.ledger import resident

    seen: list[str] = []
    monkeypatch.setattr(resident, "ensure", lambda env: seen.append(env["EMBER_HOME"]))
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(START)))
    assert hook.main(["--event", "session-start"]) == 0
    assert seen == [cli_env["EMBER_HOME"]]
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(QUIET)))
    assert hook.main([]) == 0
    assert seen == [cli_env["EMBER_HOME"]]  # a tool call does not


def test_respond_is_what_main_prints(
    home_env: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    for name, value in home_env.items():
        monkeypatch.setenv(name, value)
    output, error = hook.respond((), FORCE_S2, home_env)  # another session: see above
    assert error == ""
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(FORCE)))
    assert hook.main([]) == 0
    assert capsys.readouterr().out == output + "\n"
    output, error = hook.respond((), None, home_env)
    assert output == "" and "standard input could not be read" in error
