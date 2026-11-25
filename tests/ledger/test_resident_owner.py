"""The gate of a home runs from one installation, and the home names it.

Every ``ember-gate`` on a machine reads the same Ember home.  On
2026-11-22 a development checkout found the owner's gate down and started
it from its own working tree; that server answered every tool call for
four days, and nothing said so, because a server judged itself only
against its own package.  These tests hold the repair: the address file
names the installation, any installation starts the gate from there, a
server of another installation does not serve, and ``check`` and
``ensure`` name and replace one that does.

"Another installation" here is a file named like an interpreter in
another directory; nothing runs it.
"""

from __future__ import annotations

import json
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

from ember_armor.ledger import cli, resident
from ember_armor.ledger.resident import (
    address,
    check,
    ensure,
    health,
    move,
    own,
    owner,
    same_installation,
    serve,
    spawn,
    state,
)
from tests.ledger.helpers import rule, write_ledger


@pytest.fixture
def home_env(gate_env: dict[str, str], tmp_path: Path) -> dict[str, str]:
    """A home with one confirmed rule, in remind mode."""
    write_ledger(tmp_path / "ledger.json", rule("force"))
    return {**gate_env, "EMBER_GATE_MODE": "remind"}


@pytest.fixture
def elsewhere(tmp_path: Path) -> str:
    """An interpreter of another installation: a file, never run."""
    folder = tmp_path / "another-installation" / "Scripts"
    folder.mkdir(parents=True)
    path = folder / Path(sys.executable).name
    path.write_bytes(b"")
    return str(path)


def log_of(env: dict[str, str]) -> str:
    path = Path(env["EMBER_HOME"]) / "resident.log"
    return path.read_text(encoding="utf-8") if path.exists() else ""


def start(env: dict[str, str]) -> tuple[Any, threading.Thread]:
    server = serve(env, idle_minutes=60, respawn=False, block=False)

    def work() -> None:
        # As a detached server does: the port is closed when serving ends.
        try:
            server.serve_forever()
        finally:
            server.server_close()

    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    return server, thread


def end(server: Any, thread: threading.Thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def test_the_address_names_the_installation_that_wrote_it(
    home_env: dict[str, str],
) -> None:
    assert owner(home_env) == ""  # no address yet
    address(home_env, create=True)
    assert owner(home_env) == sys.executable
    stored = json.loads(
        (Path(home_env["EMBER_HOME"]) / "resident.json").read_text(encoding="utf-8")
    )
    assert sorted(stored) == ["port", "python", "token"]


def test_one_installation_is_one_directory_of_interpreters(tmp_path: Path) -> None:
    here = tmp_path / "venv" / "Scripts"
    assert same_installation(str(here / "python.exe"), str(here / "pythonw.exe"))
    assert same_installation(str(here / "python.exe"), str(here / "." / "python.exe"))
    assert not same_installation(
        str(here / "python.exe"), str(tmp_path / "checkout" / "python.exe")
    )
    assert not same_installation("", str(here / "python.exe"))
    assert not same_installation("", "")


def test_a_home_that_names_no_installation_is_served_as_before(
    home_env: dict[str, str], tmp_path: Path
) -> None:
    home = Path(home_env["EMBER_HOME"])
    home.mkdir(parents=True)
    port = resident.free_port()
    (home / "resident.json").write_text(
        json.dumps({"port": port, "token": "t" * 32}), encoding="utf-8"
    )
    assert owner(home_env) == ""
    server, thread = start(home_env)
    try:
        assert state(server.where)[0] == "running"
        assert check(home_env, tmp_path / "nowhere.json") == []
        assert ensure(home_env) == "running"
    finally:
        end(server, thread)


def test_a_server_of_another_installation_does_not_serve(
    home_env: dict[str, str], elsewhere: str
) -> None:
    where = address(home_env, create=True)
    assert where is not None
    own(home_env, python=elsewhere)
    with pytest.raises(SystemExit) as refused:
        serve(home_env, idle_minutes=60, respawn=False, block=False)
    assert refused.value.code == 1
    assert state(where)[0] == "down"
    said = log_of(home_env)
    assert f"not started: this home's gate runs from {elsewhere}" in said
    assert "ember-gate resident own" in said
    assert address(home_env) == where  # port and token as they were


def test_the_gate_is_started_from_the_homes_installation(
    home_env: dict[str, str], elsewhere: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    address(home_env, create=True)
    own(home_env, python=elsewhere)
    started: list[list[str]] = []
    monkeypatch.setattr(
        resident.subprocess, "Popen", lambda command, **kwargs: started.append(command)
    )
    spawn(home_env)
    [command] = started
    assert same_installation(command[0], elsewhere)
    assert not same_installation(command[0], sys.executable)
    assert command[1:] == list(resident.SERVER_ARGS)


def test_an_installation_that_is_gone_starts_nothing_and_check_says_so(
    home_env: dict[str, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    where = address(home_env, create=True)
    assert where is not None
    gone = str(tmp_path / "removed" / "python.exe")
    own(home_env, python=gone)
    started: list[Any] = []
    monkeypatch.setattr(
        resident.subprocess, "Popen", lambda command, **kwargs: started.append(command)
    )
    with pytest.raises(OSError, match="is gone"):
        spawn(home_env)
    assert ensure(home_env) == "not answering"
    assert started == []  # never under whatever interpreter asked
    assert "not started: the installation this home's gate runs from is gone" in (
        log_of(home_env)
    )
    problems = check(home_env, tmp_path / "nowhere.json")
    assert problems[0] == f"no gate is running on port {where.port}"
    assert problems[1].startswith(
        f"the installation this home's gate runs from is gone ({gone})"
    )
    assert "ember-gate resident own" in problems[1]


def test_check_names_a_gate_that_runs_from_another_installation(
    home_env: dict[str, str], elsewhere: str, tmp_path: Path
) -> None:
    server, thread = start(home_env)  # runs from this installation
    try:
        assert check(home_env, tmp_path / "nowhere.json") == []
        said = health(server.where)
        assert said is not None and said["python"] == sys.executable
        own(home_env, python=elsewhere)  # the home's gate is another's now
        [problem] = check(home_env, tmp_path / "nowhere.json")
        assert problem == (
            f"the gate on port {server.where.port} runs from {sys.executable}, "
            f"not from this home's installation ({elsewhere}): its code is not "
            "the installed gate's"
        )
    finally:
        end(server, thread)


def test_ensure_replaces_a_gate_of_another_installation(
    home_env: dict[str, str], elsewhere: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, thread = start(home_env)
    where = server.where
    try:
        own(home_env, python=elsewhere)
        started: list[list[str]] = []
        monkeypatch.setattr(
            resident.subprocess,
            "Popen",
            lambda command, **kwargs: started.append(command),
        )
        assert ensure(home_env) == "started"
        thread.join(timeout=5)
        assert state(where)[0] == "down"  # the stranger was asked to stop
        [command] = started
        assert same_installation(command[0], elsewhere)
        said = log_of(home_env)
        assert f"replace: the gate on port {where.port} runs from" in said
        assert "exit: asked to stop" in said
    finally:
        server.server_close()


def test_a_gate_that_does_not_say_where_it_runs_from_is_a_stranger(
    home_env: dict[str, str],
) -> None:
    address(home_env, create=True)
    assert resident._stranger(home_env, {"ok": True})  # a server from before
    assert resident._stranger(home_env, None)
    assert not resident._stranger(home_env, {"python": sys.executable})


def test_moving_the_address_keeps_the_installation(
    home_env: dict[str, str], elsewhere: str
) -> None:
    address(home_env, create=True)
    own(home_env, python=elsewhere)
    move(home_env)
    assert owner(home_env) == elsewhere


def test_own_names_this_installation_and_keeps_the_address(
    home_env: dict[str, str], elsewhere: str
) -> None:
    with pytest.raises(ValueError, match="no resident address"):
        own(home_env)
    where = address(home_env, create=True)
    own(home_env, python=elsewhere)
    assert owner(home_env) == elsewhere
    assert address(home_env) == where
    assert own(home_env) == sys.executable
    assert owner(home_env) == sys.executable
    assert address(home_env) == where
    said = log_of(home_env)
    assert f"owned: the gate of this home runs from {elsewhere}" in said
    assert f"(before: {elsewhere}), by the owner's command" in said


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


def test_own_from_the_command_line(
    cli_env: dict[str, str], elsewhere: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["resident", "own"]) == 1
    assert "not configured" in capsys.readouterr().out
    address(cli_env, create=True)
    own(cli_env, python=elsewhere)
    assert cli.main(["resident", "own"]) == 0
    assert f"this home's gate now runs from {sys.executable}" in capsys.readouterr().out
    assert owner(cli_env) == sys.executable


def test_printing_the_settings_names_an_installation_where_none_is_named(
    cli_env: dict[str, str], elsewhere: str, capsys: pytest.CaptureFixture[str]
) -> None:
    home = Path(cli_env["EMBER_HOME"])
    home.mkdir(parents=True)
    old = {"port": resident.free_port(), "token": "t" * 32}
    (home / "resident.json").write_text(json.dumps(old), encoding="utf-8")
    assert cli.main(["install", "claude-code", "--print", "--resident"]) == 0
    capsys.readouterr()
    assert owner(cli_env) == sys.executable
    where = address(cli_env)
    assert where is not None
    assert (where.port, where.token) == (old["port"], old["token"])
    # One that is named is left alone: naming another is the owner's command.
    own(cli_env, python=elsewhere)
    assert cli.main(["install", "claude-code", "--print", "--resident"]) == 0
    capsys.readouterr()
    assert owner(cli_env) == elsewhere
