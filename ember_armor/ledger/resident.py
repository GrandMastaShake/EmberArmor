"""The resident gate: the hook kept warm as a local HTTP server.

A command hook pays a Python start and the gate's imports on every tool
call, about 580 ms on the machine this was written on (2026-10-20), while
the gate's own work is about 20 ms.  Claude Code can also call a hook over
HTTP: it posts the event JSON to a URL and reads the same JSON output a
command hook would print.  So the gate can stay resident: one process per
Ember home, bound to the loopback interface, holding the imported modules,
answering each call from memory.

What the server does per request is exactly what the hook does per call:
:func:`ember_armor.ledger.hook.respond` on the posted body, with the
server's own environment.  The ledger, the configuration and the audit log
are read and written on every request as before, so a rule confirmed or a
mode changed while the server runs takes effect on the next call; only the
imports are kept.  What a command hook would print on standard error goes
to ``resident.log`` in the Ember home.

The address lives in ``resident.json`` in the Ember home: a port, chosen
free once and then fixed so the settings file can name it, and a token the
caller must present in the ``X-Ember-Token`` header.  On POSIX the file is
written for the owner only (mode 0600).  On Windows the mode is ignored and
the file has the permissions of the Ember home, which in a default profile
are the owner's, SYSTEM's and the Administrators'; whoever can read it can
ask the gate to stop.  The server exits after an idle period
(``resident_idle_minutes`` in ``config.json``, eight hours by default),
and after answering a request when any module of the installed package has
changed under it (an editable install that a ``git pull`` updates, say), in
which case it closes its port and then starts a fresh copy of itself.  The
SessionStart
hook starts the server when none answers, so a session never begins
without one for long; ``ember-gate resident ensure|start|stop|status`` do
the same by hand.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from ember_armor.ledger.config import ember_home, resident_idle

RESIDENT_FILE = "resident.json"
LOG_FILE = "resident.log"
TOKEN_HEADER = "X-Ember-Token"  # noqa: S105 - a header name, not a secret
HOST = "127.0.0.1"
#: Seconds between the idle watchdog's looks.
_WATCH_SECONDS = 30.0
#: The log is cut back to its last lines when it grows past this.
_LOG_LIMIT = 1_000_000
#: Interpreter arguments of a detached server.
SERVER_ARGS = (
    "-I",
    "-c",
    "from ember_armor.ledger.resident import serve; serve()",
)


@dataclass(frozen=True)
class Address:
    """Where the resident gate of one Ember home answers."""

    port: int
    token: str

    @property
    def url(self) -> str:
        return f"http://{HOST}:{self.port}"


def free_port() -> int:
    """A port the loopback interface can bind right now."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind((HOST, 0))
        return int(probe.getsockname()[1])


def address(env: Mapping[str, str], *, create: bool = False) -> Address | None:
    """The address in ``resident.json``; with *create*, written if missing.

    Raises
    ------
    ValueError
        If the file exists and does not hold a port and a token.
    """
    path = ember_home(env) / RESIDENT_FILE
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        port, token = data.get("port"), data.get("token")
        if not isinstance(port, int) or not isinstance(token, str) or not token:
            raise ValueError(f"{path} does not hold a port and a token")
        return Address(port, token)
    if not create:
        return None
    found = Address(free_port(), secrets.token_hex(16))
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    handle = os.open(path, flags, 0o600)
    with os.fdopen(handle, "w", encoding="utf-8") as out:
        json.dump({"port": found.port, "token": found.token}, out)
    return found


#: Seconds a look at the package is reused.  Looking at every module costs a
#: stat per file; reused for this long, a change is seen at the first request
#: after it, at most this many seconds late.
MARKER_SECONDS = 2.0
_looked: dict[str, tuple[float, str]] = {}


def look(root: Path) -> str:
    """The files under *root*, or the one file *root*, as a string.

    Each ``.py`` file's name, time and size go into it, so it changes when
    any of them is changed, added, removed or renamed.

    Raises
    ------
    OSError
        If a file cannot be looked at.
    """
    files = [root] if root.is_file() else sorted(root.rglob("*.py"))
    digest = hashlib.sha256()
    for file in files:
        stat = file.stat()
        name = file.name if file == root else file.relative_to(root).as_posix()
        digest.update(f"{name}:{stat.st_mtime_ns}:{stat.st_size}\n".encode())
    return f"{len(files)}:{digest.hexdigest()[:16]}"


def marker(path: str | None = None) -> str:
    """The installed package as a string: it changes when any module does.

    The whole ``ember_armor`` package is looked at, so a change to
    ``gate.py`` or ``builtin.py`` counts, not only one to this file (an
    editable install that a ``git pull`` updates, say).  With *path*, the
    files under that directory, or that one file.  A look is reused for
    :data:`MARKER_SECONDS`.

    Raises
    ------
    OSError
        If a file cannot be looked at (the server then counts as stale).
    """
    root = Path(path) if path else Path(__file__).parent.parent
    key, now = str(root), time.monotonic()
    seen = _looked.get(key)
    if seen is not None and now - seen[0] < MARKER_SECONDS:
        return seen[1]
    found = look(root)
    _looked[key] = (now, found)
    return found


def _request(
    where: Address, method: str, route: str, body: bytes = b"", timeout: float = 2.0
) -> tuple[int, bytes]:
    connection = HTTPConnection(HOST, where.port, timeout=timeout)
    try:
        headers = {TOKEN_HEADER: where.token, "Content-Type": "application/json"}
        connection.request(method, route, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def health(where: Address, timeout: float = 2.0) -> dict[str, Any] | None:
    """What a resident gate at *where* says about itself, or ``None``."""
    try:
        status, body = _request(where, "GET", "/health", timeout=timeout)
    except OSError:
        return None
    if status != 200:
        return None
    try:
        data = json.loads(body)
    except ValueError:
        return None
    return data if isinstance(data, dict) and data.get("ok") else None


def stop(where: Address, timeout: float = 2.0) -> bool:
    """Ask the resident gate at *where* to exit; true when it answered."""
    try:
        status, _ = _request(where, "POST", "/stop", timeout=timeout)
    except OSError:
        return False
    return status == 200


def spawn(env: Mapping[str, str], python: str | None = None) -> None:
    """Start a resident gate for the Ember home of *env*, detached."""
    command = [python or sys.executable, *SERVER_ARGS]
    # The process environment underneath, so the interpreter finds what it
    # needs (SystemRoot on Windows, PATH); the given variables on top.
    kwargs: dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
        "env": {**os.environ, **env},
    }
    if os.name == "nt":
        flags = (
            subprocess.DETACHED_PROCESS
            | subprocess.CREATE_NEW_PROCESS_GROUP
            | subprocess.CREATE_NO_WINDOW
        )
        kwargs["creationflags"] = flags
    else:
        kwargs["start_new_session"] = True
    subprocess.Popen(command, **kwargs)  # noqa: S603 - the gate's own interpreter


def ensure(
    env: Mapping[str, str] | None = None,
    *,
    python: str | None = None,
    wait: float = 0.0,
) -> str:
    """See that a resident gate answers for the Ember home of *env*.

    Returns ``not configured`` when ``resident.json`` is absent (the
    command hook is in use), ``running`` when one answers, and ``started``
    after spawning one.  With *wait*, polls up to that many seconds for the
    new server to answer and returns ``running`` once it does.
    """
    given = os.environ if env is None else env
    where = address(given)
    if where is None:
        return "not configured"
    if health(where) is not None:
        return "running"
    spawn(given, python)
    deadline = time.monotonic() + wait
    while wait and time.monotonic() < deadline:
        time.sleep(0.1)
        if health(where) is not None:
            return "running"
    return "started"


# ---------------------------------------------------------------------------
# The server
# ---------------------------------------------------------------------------
class _Gate(ThreadingHTTPServer):
    """The server, with the state its handlers share."""

    daemon_threads = True
    #: On POSIX the port a server just closed is still held by the connections
    #: it closed, in TIME_WAIT, and its fresh copy cannot bind it again without
    #: SO_REUSEADDR, which there does not let two servers listen on one port.
    #: On Windows SO_REUSEADDR would let a second server take a port in use,
    #: so it stays off there.
    allow_reuse_address = os.name != "nt"

    def __init__(
        self,
        where: Address,
        env: Mapping[str, str],
        *,
        idle_seconds: float,
        respawn: bool,
        marker_of: Any,
    ) -> None:
        super().__init__((HOST, where.port), _Handler)
        self.where = where
        self.env: dict[str, str] = dict(env)
        self.idle_seconds = idle_seconds
        self.respawn = respawn
        self.marker_of = marker_of
        self.started_marker = str(marker_of())
        self.started = time.monotonic()
        self.last_request = self.started
        self.served = 0
        #: Set when the server leaves for a fresh copy of itself.
        self.replace = False
        self.lock = threading.Lock()
        self.log_path = ember_home(env) / LOG_FILE

    def note(self, text: str) -> None:
        """Append a line to ``resident.log``, cutting it back when large."""
        try:
            stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
            with self.lock:
                if self.log_path.exists() and self.log_path.stat().st_size > _LOG_LIMIT:
                    lines = self.log_path.read_text(encoding="utf-8").splitlines()
                    tail = "\n".join(lines[-200:]) + "\n"
                    self.log_path.write_text(tail, encoding="utf-8")
                with self.log_path.open("a", encoding="utf-8") as out:
                    out.write(f"{stamp} {text}\n")
        except OSError:
            pass

    def stale(self) -> bool:
        """True when the package was reinstalled under the running server."""
        try:
            return str(self.marker_of()) != self.started_marker
        except OSError:
            return True

    def leave(self, reason: str, *, replace: bool = False) -> None:
        """Shut down from a handler thread, after the response is sent.

        With *replace*, :func:`serve` starts a fresh copy once the port is
        closed.  It is not started here: this thread is not waited for, so
        the copy was lost whenever the process exited first, and before the
        port is closed a copy would find it taken.
        """
        self.note(f"exit: {reason}")
        self.replace = replace and self.respawn

        def go() -> None:
            time.sleep(0.2)
            self.shutdown()

        threading.Thread(target=go, daemon=True).start()

    def replace_self(self) -> None:
        """Start the fresh copy :meth:`leave` asked for; the port is closed."""
        if not self.replace:
            return
        try:
            spawn(self.env)
        except OSError as exc:
            self.note(f"replace: the fresh copy did not start: {exc}")
            return
        self.note("replace: a fresh copy was started")

    def watch(self) -> None:
        """Exit after ``idle_seconds`` without a request."""
        while True:
            time.sleep(min(_WATCH_SECONDS, max(self.idle_seconds / 4, 0.01)))
            if time.monotonic() - self.last_request > self.idle_seconds:
                self.note("exit: idle")
                self.shutdown()
                return


class _Handler(BaseHTTPRequestHandler):
    server: _Gate
    server_version = "ember-gate"
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return  # Requests are not logged; the audit log is the record.

    def _reply(self, status: int, body: bytes = b"") -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _authorised(self) -> bool:
        given = self.headers.get(TOKEN_HEADER, "")
        return secrets.compare_digest(given, self.server.where.token)

    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length > 0 else b""

    def do_GET(self) -> None:  # noqa: N802 - the http.server contract
        if not self._authorised():
            self._reply(401)
            return
        if self.path != "/health":
            self._reply(404)
            return
        gate = self.server
        data = {
            "ok": True,
            "served": gate.served,
            "idle_seconds": round(time.monotonic() - gate.last_request, 1),
            "uptime_seconds": round(time.monotonic() - gate.started, 1),
            "marker": gate.started_marker,
            "stale": gate.stale(),
            "pid": os.getpid(),
        }
        self._reply(200, json.dumps(data).encode("utf-8"))

    def do_POST(self) -> None:  # noqa: N802 - the http.server contract
        gate = self.server
        if not self._authorised():
            self._body()
            self._reply(401)
            return
        body = self._body()
        gate.last_request = time.monotonic()
        if self.path == "/stop":
            self._reply(200, b'{"ok": true}')
            gate.leave("asked to stop")
            return
        if self.path == "/hook":
            argv: tuple[str, ...] = ()
        elif self.path == "/session-start":
            argv = ("--event", "session-start")
        else:
            self._reply(404)
            return
        from ember_armor.ledger import hook

        output, error = hook.respond(argv, body, gate.env)
        gate.served += 1
        if error:
            gate.note(f"{self.path}: {error}")
        self._reply(200, output.encode("utf-8"))
        if gate.stale():
            gate.leave("the installed package changed", replace=True)


def serve(
    env: Mapping[str, str] | None = None,
    *,
    idle_minutes: float | None = None,
    respawn: bool = True,
    marker_of: Any = marker,
    block: bool = True,
) -> _Gate:
    """Run the resident gate for the Ember home of *env*.

    Creates ``resident.json`` when there is none.  When the port in it is
    taken by a resident gate that answers with the same token, the process
    exits with status 0, since the work is done; when it is taken by
    something else, a new free port is chosen and written, and the
    settings file has to be printed again.  With *block* false the server
    is returned unstarted, for a thread of the caller's; the idle watchdog
    runs either way.
    """
    given = dict(os.environ if env is None else env)
    where = address(given, create=True)
    assert where is not None
    idle = resident_idle(given) if idle_minutes is None else idle_minutes * 60
    try:
        gate = _Gate(
            where, given, idle_seconds=idle, respawn=respawn, marker_of=marker_of
        )
    except OSError:
        if health(where) is not None:
            raise SystemExit(0) from None  # Another resident gate answers already.
        path = ember_home(given) / RESIDENT_FILE
        path.unlink(missing_ok=True)
        where = address(given, create=True)
        assert where is not None
        sys.stderr.write(
            f"ember-gate: port taken; the resident gate moved to {where.port}. "
            "Print the settings again: "
            "ember-gate install claude-code --print --resident\n"
        )
        gate = _Gate(
            where, given, idle_seconds=idle, respawn=respawn, marker_of=marker_of
        )
    gate.note(
        f"start: pid {os.getpid()}, port {where.port}, marker {gate.started_marker}"
    )
    threading.Thread(target=gate.watch, daemon=True).start()
    if block:
        try:
            gate.serve_forever()
        finally:
            gate.server_close()
        gate.replace_self()
    return gate


def main(argv: list[str]) -> int:
    """``ember-gate resident start|ensure|stop|status``."""
    action = argv[0] if argv else "status"
    env = os.environ
    if action == "start":
        serve(env)
        return 0
    if action == "ensure":
        print(ensure(env, wait=5.0))
        return 0
    where = address(env)
    if where is None:
        print("not configured: run ember-gate install claude-code --print --resident")
        return 1
    if action == "stop":
        print("stopped" if stop(where) else "not running")
        return 0
    if action == "status":
        state = health(where)
        if state is None:
            print(f"not running (port {where.port})")
            return 1
        print(json.dumps({"port": where.port, **state}, indent=2))
        return 0
    print(f"ember-gate resident: unknown action {action!r}", file=sys.stderr)
    return 2
