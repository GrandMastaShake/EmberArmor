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

from ember_armor.ledger import cli, hook, resident
from ember_armor.ledger.config import resident_idle
from ember_armor.ledger.resident import (
    PORT_RANGE,
    TOKEN_HEADER,
    Address,
    address,
    attend,
    check,
    configured,
    ensure,
    health,
    move,
    serve,
    state,
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
    seen: list[str] = []

    def attended(env: Any) -> str:
        seen.append(env["EMBER_HOME"])
        return ""

    monkeypatch.setattr(resident, "attend", attended)
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


# ---------------------------------------------------------------------------
# The address never moves by itself (the outage of 2026-10-28 to 2026-11-20)
# ---------------------------------------------------------------------------
def held(port: int, *, answer: bytes | None = None) -> Any:
    """Something that is not the gate, listening on *port*.

    It accepts connections and, with *answer*, sends that; without, it
    says nothing, like a gate too busy to answer in time.
    """
    import socket

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", port))
    listener.listen(8)
    kept: list[Any] = []

    def accept() -> None:
        while True:
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            kept.append(connection)
            if answer is not None:
                connection.recv(4096)
                connection.sendall(answer)
                connection.close()

    threading.Thread(target=accept, daemon=True).start()
    return listener


NOT_FOUND = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"


def log_of(env: dict[str, str]) -> str:
    path = Path(env["EMBER_HOME"]) / "resident.log"
    return path.read_text(encoding="utf-8") if path.exists() else ""


def test_ports_come_from_below_the_range_systems_hand_out(
    home_env: dict[str, str],
) -> None:
    where = address(home_env, create=True)
    assert where is not None
    assert PORT_RANGE[0] <= where.port < PORT_RANGE[1] <= 32768


def test_state_tells_down_running_foreign_and_busy(
    gate: Any, home_env: dict[str, str]
) -> None:
    assert state(gate.where)[0] == "running"
    assert state(Address(gate.where.port, "another token"))[0] == "foreign"
    free = resident.free_port()
    assert state(Address(free, "t"), timeout=3.0) == ("down", None)
    silent = held(free)
    try:
        assert state(Address(free, "t"), timeout=0.5) == ("busy", None)
    finally:
        silent.close()
    other = resident.free_port()
    talking = held(other, answer=NOT_FOUND)
    try:
        assert state(Address(other, "t"), timeout=3.0) == ("foreign", None)
    finally:
        talking.close()


def test_a_server_that_cannot_bind_keeps_the_address_and_says_so(
    home_env: dict[str, str],
) -> None:
    where = address(home_env, create=True)
    assert where is not None
    squatter = held(where.port, answer=NOT_FOUND)
    try:
        with pytest.raises(SystemExit) as stopped:
            serve(home_env, idle_minutes=60, respawn=False, block=False, patience=1.0)
    finally:
        squatter.close()
    assert stopped.value.code == 1
    assert address(home_env) == where  # the outage: this used to be a new port
    log = log_of(home_env)
    assert f"not started: port {where.port} cannot be bound" in log
    assert "ember-gate resident move" in log


def test_a_slow_gate_is_not_taken_for_an_absent_one(
    home_env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    where = address(home_env, create=True)
    assert where is not None
    started: list[Any] = []
    monkeypatch.setattr(resident, "spawn", lambda env, python=None: started.append(1))
    monkeypatch.setattr(resident, "state", lambda where, timeout=5.0: ("busy", None))
    assert ensure(home_env) == "not answering"
    assert started == []  # no second server, and so no fight over the port
    monkeypatch.setattr(resident, "state", lambda where, timeout=5.0: ("down", None))
    assert ensure(home_env) == "started"
    assert started == [1]
    assert address(home_env) == where


def test_a_server_waits_for_its_port_to_come_free(home_env: dict[str, str]) -> None:
    where = address(home_env, create=True)
    assert where is not None
    squatter = held(where.port, answer=NOT_FOUND)
    threading.Timer(0.8, squatter.close).start()
    server = serve(home_env, idle_minutes=60, respawn=False, block=False, patience=10)
    thread = run(server)
    try:
        assert server.where == where
        assert state(where)[0] == "running"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_the_address_file_is_never_overwritten(home_env: dict[str, str]) -> None:
    first = address(home_env, create=True)
    assert first is not None
    path = Path(home_env["EMBER_HOME"]) / "resident.json"
    assert resident._write(path, Address(1, "x"), replace=False) is False
    assert address(home_env) == first
    assert [p.name for p in path.parent.iterdir() if "resident.json" in p.name] == [
        "resident.json"
    ]


def test_only_the_owners_command_moves_the_address(home_env: dict[str, str]) -> None:
    first = address(home_env, create=True)
    assert first is not None
    moved = move(home_env)
    assert moved.token == first.token
    assert moved.port != first.port
    assert address(home_env) == moved
    assert f"moved: port {first.port} to port {moved.port}" in log_of(home_env)
    with pytest.raises(ValueError, match="no resident address"):
        move({**home_env, "EMBER_HOME": home_env["EMBER_HOME"] + "-other"})


def test_the_gate_stays_up_unless_told_an_idle_period(
    home_env: dict[str, str],
) -> None:
    assert resident_idle(home_env) == float("inf")
    home = Path(home_env["EMBER_HOME"])
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.json").write_text('{"resident_idle_minutes": 3}', encoding="utf-8")
    assert resident_idle(home_env) == 180.0


# ---------------------------------------------------------------------------
# A gate that is not checking calls says so
# ---------------------------------------------------------------------------
def settings_with(tmp_path: Path, *hooks: dict[str, Any]) -> Path:
    path = tmp_path / "claude" / "settings.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": list(hooks)}]}}
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def http_hook(where: Address) -> dict[str, Any]:
    return {
        "type": "http",
        "url": f"{where.url}/hook",
        "headers": {TOKEN_HEADER: where.token},
    }


def test_configured_reads_the_loopback_http_hooks(tmp_path: Path) -> None:
    where = Address(21000, "abc")
    path = settings_with(
        tmp_path,
        http_hook(where),
        {"type": "command", "command": "python"},
        {"type": "http", "url": "https://example.com/hook"},
        {"type": "http", "url": "http://127.0.0.1:x/hook"},
    )
    assert configured(path) == [where]
    assert configured(tmp_path / "nowhere.json") == []
    path.write_text("{not json", encoding="utf-8")
    assert configured(path) == []


def test_check_is_quiet_when_the_gate_is_where_the_host_calls_it(
    gate: Any, home_env: dict[str, str], tmp_path: Path
) -> None:
    assert check(home_env, settings_with(tmp_path, http_hook(gate.where))) == []
    command_only = settings_with(tmp_path, {"type": "command", "command": "python"})
    assert check(home_env, command_only) == []  # not this module's business
    assert (
        attend(home_env, settings=settings_with(tmp_path, http_hook(gate.where))) == ""
    )


def test_check_names_a_port_or_token_the_settings_got_wrong(
    gate: Any, home_env: dict[str, str], tmp_path: Path
) -> None:
    elsewhere = Address(gate.where.port + 1, gate.where.token)
    [problem] = check(home_env, settings_with(tmp_path, http_hook(elsewhere)))
    assert problem == (
        f"the settings post to port {elsewhere.port}, the gate's address is "
        f"port {gate.where.port}"
    )
    stale = Address(gate.where.port, "an older token")
    assert check(home_env, settings_with(tmp_path, http_hook(stale))) == [
        "the settings carry another token than the gate's"
    ]


def test_attend_warns_the_session_in_fixed_words(
    gate: Any, home_env: dict[str, str], tmp_path: Path
) -> None:
    elsewhere = Address(gate.where.port + 1, gate.where.token)
    said = attend(home_env, settings=settings_with(tmp_path, http_hook(elsewhere)))
    assert said.startswith(
        "EmberArmor gate warning: the gate is NOT checking this session's tool calls"
    )
    assert f"the settings post to port {elsewhere.port}" in said
    assert "Tell the user now." in said
    assert "warning: the settings post to port" in log_of(home_env)


def test_attend_says_nothing_when_the_resident_gate_is_not_in_use(
    home_env: dict[str, str], tmp_path: Path
) -> None:
    assert attend(home_env, settings=tmp_path / "nowhere.json") == ""
    assert not (Path(home_env["EMBER_HOME"]) / "resident.json").exists()


def test_check_names_a_gate_that_is_down(
    home_env: dict[str, str], tmp_path: Path
) -> None:
    where = address(home_env, create=True)
    assert where is not None
    assert check(home_env, tmp_path / "nowhere.json") == [
        f"no gate is running on port {where.port}"
    ]


def test_the_session_start_hook_prints_the_warning_in_front(
    cli_env: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(resident, "attend", lambda env: "EmberArmor gate warning: X.")
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(START)))
    assert hook.main(["--event", "session-start"]) == 0
    captured = capsys.readouterr()
    context = json.loads(captured.out)["hookSpecificOutput"]
    assert context["hookEventName"] == "SessionStart"
    assert context["additionalContext"].startswith("EmberArmor gate warning: X.")
    assert "EmberArmor gate warning: X." in captured.err


def test_a_failure_to_attend_is_itself_a_warning(
    cli_env: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def broken(env: Any) -> str:
        raise RuntimeError("boom")

    monkeypatch.setattr(resident, "attend", broken)
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(START)))
    assert hook.main(["--event", "session-start"]) == 0
    assert "could not be seen to (RuntimeError: boom)" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# What a server leaves behind
# ---------------------------------------------------------------------------
def test_a_server_that_ended_without_a_word_is_named_by_the_next(
    home_env: dict[str, str],
) -> None:
    first = serve(home_env, idle_minutes=60, respawn=False, block=False)
    first.server_close()  # gone, as if killed: no exit line, no ended state
    second = serve(home_env, idle_minutes=60, respawn=False, block=False)
    second.server_close()
    log = log_of(home_env)
    assert f"previous: pid {os.getpid()} started" in log
    assert "ended without a word" in log
    thread = run(third := serve(home_env, idle_minutes=60, respawn=False, block=False))
    assert stop(third.where)
    thread.join(timeout=5)
    third.server_close()
    fourth = serve(home_env, idle_minutes=60, respawn=False, block=False)
    fourth.server_close()
    assert log_of(home_env).count("ended without a word") == 2  # not a third time


def test_a_started_server_has_no_window(home_env: dict[str, str]) -> None:
    where = address(home_env, create=True)
    assert where is not None
    assert ensure(home_env, wait=20.0) == "running"
    try:
        said = health(where)
        assert said is not None
        assert said["console"] in ("none", "hidden")
        assert "console " + said["console"] in log_of(home_env)
    finally:
        stop(where)


def test_check_and_move_from_the_command_line(
    cli_env: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    where = address(cli_env, create=True)
    assert where is not None
    assert cli.main(["resident", "check"]) == 1
    assert (
        f"problem: no gate is running on port {where.port}" in capsys.readouterr().out
    )
    assert cli.main(["resident", "move"]) == 0
    assert "Print the settings again" in capsys.readouterr().out
    moved = address(cli_env)
    assert moved is not None and moved.token == where.token and moved.port != where.port
