"""The resident gate replaces itself when any module of the package changes.

The marker the server compares covered only ``resident.py``, so with an
editable install a ``git pull`` that changed ``gate.py`` or ``builtin.py``
left the gate on the old code until it idled out.  And when the marker did
change, the fresh copy was started from a thread the interpreter does not
wait for, so it was lost whenever the process exited first: the gate went
away and nothing came back.  Here the marker covers the package, a look at it
is reused for a short while, and the copy is started by :func:`serve` once the
port is closed.  The last test runs a real server from a copy of the package
and changes a module under it.  The command strings are data for the gate.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from http.client import HTTPConnection
from pathlib import Path
from typing import Any

import pytest

from ember_armor.ledger import resident
from ember_armor.ledger.resident import (
    TOKEN_HEADER,
    Address,
    address,
    health,
    look,
    marker,
    serve,
    stop,
)
from tests.ledger.helpers import make_call

QUIET = json.dumps(make_call("Bash", "git status")).encode("utf-8")


def post(where: Address, body: bytes = QUIET) -> tuple[int, bytes]:
    connection = HTTPConnection("127.0.0.1", where.port, timeout=5)
    headers = {TOKEN_HEADER: where.token, "Content-Type": "application/json"}
    connection.request("POST", "/hook", body=body, headers=headers)
    response = connection.getresponse()
    return response.status, response.read()


def later(path: Path, seconds: float = 2.0) -> None:
    """Move *path*'s modification time on, as a checkout that rewrites it does."""
    stat = path.stat()
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + int(seconds * 1e9)))


def listening(port: int) -> bool:
    """True while something on the loopback interface accepts on *port*."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(1.0)
        return probe.connect_ex(("127.0.0.1", port)) == 0


def wait_for(check: Any, seconds: float) -> Any:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        found = check()
        if found:
            return found
        time.sleep(0.2)
    return None


@pytest.fixture
def package(tmp_path: Path) -> Path:
    root = tmp_path / "pkg"
    (root / "sub").mkdir(parents=True)
    (root / "a.py").write_text("A = 1\n", encoding="utf-8")
    (root / "sub" / "b.py").write_text("B = 1\n", encoding="utf-8")
    return root


# ---------------------------------------------------------------------------
# The marker
# ---------------------------------------------------------------------------
def test_a_look_sees_any_module_change(package: Path) -> None:
    first = look(package)
    assert look(package) == first
    later(package / "sub" / "b.py")
    second = look(package)
    assert second != first
    (package / "c.py").write_text("", encoding="utf-8")
    third = look(package)
    assert third != second
    (package / "c.py").rename(package / "d.py")
    assert look(package) != third
    fourth = look(package)
    (package / "notes.txt").write_text("not a module", encoding="utf-8")
    assert look(package) == fourth  # only modules count
    assert look(package / "a.py").startswith("1:")  # one file


def test_a_look_is_reused_for_a_while(
    package: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(resident, "_looked", {})
    monkeypatch.setattr(resident, "MARKER_SECONDS", 3600.0)
    first = marker(str(package))
    later(package / "a.py")
    assert marker(str(package)) == first
    monkeypatch.setattr(resident, "MARKER_SECONDS", 0.0)
    assert marker(str(package)) == look(package) != first


def test_the_marker_covers_the_whole_package(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(resident, "_looked", {})
    monkeypatch.setattr(resident, "MARKER_SECONDS", 0.0)
    root = Path(resident.__file__).parent.parent
    assert (root / "ledger" / "gate.py").is_file()
    assert (root / "ledger" / "builtin.py").is_file()
    assert marker() == look(root)


# ---------------------------------------------------------------------------
# Leaving for a fresh copy
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("respawn", [True, False])
def test_the_fresh_copy_is_started_once_the_port_is_closed(
    gate_env: dict[str, str], monkeypatch: pytest.MonkeyPatch, respawn: bool
) -> None:
    env = {**gate_env, "EMBER_GATE_MODE": "remind"}
    where = address(env, create=True)
    assert where is not None
    started: list[str] = []

    def spawn(given: Any, python: Any = None) -> None:
        started.append("closed" if not listening(where.port) else "still listening")

    monkeypatch.setattr(resident, "spawn", spawn)
    stamps = ["installed"]

    def run() -> None:
        serve(env, idle_minutes=60, respawn=respawn, marker_of=lambda: stamps[-1])

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    assert wait_for(lambda: health(where), 10)
    stamps.append("changed")
    assert post(where) == (200, b"")  # answered first
    thread.join(timeout=10)
    assert not thread.is_alive()
    assert started == (["closed"] if respawn else [])
    log = (Path(env["EMBER_HOME"]) / "resident.log").read_text(encoding="utf-8")
    assert "exit: the installed package changed" in log
    assert ("replace: a fresh copy was started" in log) == respawn


def test_being_asked_to_stop_starts_no_copy(
    gate_env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    started: list[Any] = []
    monkeypatch.setattr(resident, "spawn", lambda *args: started.append(args))
    where = address(gate_env, create=True)
    assert where is not None
    thread = threading.Thread(
        target=lambda: serve(gate_env, idle_minutes=60), daemon=True
    )
    thread.start()
    assert wait_for(lambda: health(where), 10)
    assert stop(where)
    thread.join(timeout=10)
    assert not thread.is_alive() and started == []


def test_a_real_server_is_replaced_when_a_module_changes(
    gate_env: dict[str, str], tmp_path: Path
) -> None:
    """A server run from a copy of the package, and ``gate.py`` changed under it.

    The copy it starts runs as the SessionStart hook would start it, from the
    installed package, so this needs the package installed (as CI installs it).
    """
    copy = tmp_path / "copy"
    shutil.copytree(
        Path(resident.__file__).parent.parent,
        copy / "ember_armor",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    env = {**os.environ, **gate_env, "EMBER_GATE_MODE": "remind"}
    where = address(env, create=True)
    assert where is not None
    home = Path(gate_env["EMBER_HOME"])
    # A server this test leaves behind by failing exits on its own.
    (home / "config.json").write_text('{"resident_idle_minutes": 3}', encoding="utf-8")
    entry = (
        f"import sys; sys.path.insert(0, {str(copy)!r}); "
        "from ember_armor.ledger.resident import serve; serve()"
    )
    first = subprocess.Popen(
        [sys.executable, "-c", entry],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        state = wait_for(lambda: health(where, timeout=0.5), 20)
        assert state, "the server run from the copy did not answer"
        # Not ``first.pid``: on Windows a venv's python.exe is a launcher that
        # runs the interpreter as a child process.
        started = state["pid"]
        later(copy / "ember_armor" / "ledger" / "gate.py")

        def replaced() -> Any:
            # The change is looked for after a request.  OSError: the first
            # server has gone and the copy is not up yet.
            with contextlib.suppress(OSError):
                post(where)
            now = health(where, timeout=0.5)
            return now if now and now["pid"] != started else None

        fresh = wait_for(replaced, 30)
        if not fresh:
            log = (home / "resident.log").read_text(encoding="utf-8")
            pytest.fail(
                f"no fresh copy answered on port {where.port}; address now "
                f"{address(env)}; resident.log:\n{log}"
            )
        assert first.wait(timeout=10) == 0
        log = (home / "resident.log").read_text(encoding="utf-8")
        assert "exit: the installed package changed" in log
        assert "replace: a fresh copy was started" in log
        assert sum("start: pid" in line for line in log.splitlines()) == 2
        assert address(env) == where  # same port, same token
    finally:
        stop(where)
        if first.poll() is None:
            first.kill()
