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

The address lives in ``resident.json`` in the Ember home: a port and a
token the caller must present in the ``X-Ember-Token`` header.  The file is
written once, for the owner only, and **nothing but the owner's own command
changes it afterwards** (``ember-gate resident move``): the settings file
of the host names this address, and a gate that answers anywhere else
checks nothing.  The first version of this module gave the port up when a
new server could not bind it and got no answer from the old one within two
seconds; on a busy machine that happened about a hundred times in four
weeks, each time leaving the host posting to a dead address and letting
every call pass (2026-10-28 to 2026-11-20 on the machine it was written
on).  Now a server that cannot bind its port waits for the one that holds
it, steps aside when that one answers as this gate, and otherwise says so
in the log and exits; a slow answer is never taken for an absent server.

The server stays up until it is stopped, unless ``resident_idle_minutes``
in ``config.json`` names an idle period.  After answering a request it
leaves when the installed package has changed under it, closing its port
and then starting a fresh copy of itself.  The SessionStart hook sees to
the gate (:func:`attend`): it starts the server when none answers and
compares the address with the one the host's settings call; when the gate
is not answering there, it tells the session so in plain words instead of
letting it run unchecked in silence.  ``ember-gate resident
ensure|start|stop|status|check|move`` do the same by hand.

On Windows the server is started without a console (``pythonw.exe`` where
the environment has one, and never ``DETACHED_PROCESS``, which made the
real interpreter behind a virtual-environment launcher open a console
window of its own at every start).
"""

from __future__ import annotations

import contextlib
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
from http.client import HTTPConnection, HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from ember_armor.ledger.config import ember_home, resident_idle

RESIDENT_FILE = "resident.json"
LOG_FILE = "resident.log"
STATE_FILE = "resident.state"
ERROR_FILE = "resident.err"
TOKEN_HEADER = "X-Ember-Token"  # noqa: S105 - a header name, not a secret
HOST = "127.0.0.1"
#: Ports the gate picks from.  Below the range operating systems hand out
#: for outgoing connections (49152 up on Windows, 32768 up on Linux), so no
#: other program is given the gate's port by chance while the gate is down.
PORT_RANGE = (20000, 32000)
#: Seconds between the watchdog's looks.
_WATCH_SECONDS = 30.0
#: The log is cut back to its last lines when it grows past this.
_LOG_LIMIT = 1_000_000
#: Seconds a server that cannot bind its port waits for the holder.
PATIENCE_SECONDS = 15.0
#: Interpreter arguments of a detached server.
SERVER_ARGS = (
    "-I",
    "-c",
    "from ember_armor.ledger.resident import run; run()",
)
_LOG_LOCK = threading.Lock()


@dataclass(frozen=True)
class Address:
    """Where the resident gate of one Ember home answers."""

    port: int
    token: str

    @property
    def url(self) -> str:
        return f"http://{HOST}:{self.port}"


def note(env: Mapping[str, str], text: str) -> None:
    """Append a line to ``resident.log``, cutting it back when large."""
    path = ember_home(env) / LOG_FILE
    try:
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
        with _LOG_LOCK:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists() and path.stat().st_size > _LOG_LIMIT:
                lines = path.read_text(encoding="utf-8").splitlines()
                path.write_text("\n".join(lines[-200:]) + "\n", encoding="utf-8")
            with path.open("a", encoding="utf-8") as out:
                out.write(f"{stamp} {text}\n")
    except OSError:
        pass


def free_port() -> int:
    """A port of :data:`PORT_RANGE` the loopback interface can bind right now.

    Raises
    ------
    OSError
        If none of two hundred tries could be bound.
    """
    low, high = PORT_RANGE
    for _ in range(200):
        port = low + secrets.randbelow(high - low)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind((HOST, port))
            except OSError:
                continue
            return port
    raise OSError("no free port for the resident gate")


def _read(path: Path) -> Address:
    data = json.loads(path.read_text(encoding="utf-8"))
    port, token = data.get("port"), data.get("token")
    if not isinstance(port, int) or not isinstance(token, str) or not token:
        raise ValueError(f"{path} does not hold a port and a token")
    return Address(port, token)


def _write(path: Path, where: Address, *, replace: bool, python: str = "") -> bool:
    """Write the address whole or not at all; false when one is there already.

    *python* is the interpreter of the installation the gate of this home
    runs from (see :func:`owner`); empty when none is named.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    draft = path.with_name(f"{path.name}.{os.getpid()}.{secrets.token_hex(4)}")
    handle = os.open(draft, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    data: dict[str, Any] = {"port": where.port, "token": where.token}
    if python:
        data["python"] = python
    with os.fdopen(handle, "w", encoding="utf-8") as out:
        json.dump(data, out)
    try:
        if replace:
            os.replace(draft, path)
        else:
            os.link(draft, path)  # fails when the address exists: never overwritten
    except FileExistsError:
        return False
    finally:
        with contextlib.suppress(OSError):
            os.unlink(draft)
    return True


def address(env: Mapping[str, str], *, create: bool = False) -> Address | None:
    """The address in ``resident.json``; with *create*, written if missing.

    An address that exists is never changed here: two processes that both
    find none write one between them, and both read the same.

    Raises
    ------
    ValueError
        If the file exists and does not hold a port and a token.
    """
    path = ember_home(env) / RESIDENT_FILE
    if path.exists():
        return _read(path)
    if not create:
        return None
    found = Address(free_port(), secrets.token_hex(16))
    if _write(path, found, replace=False, python=sys.executable):
        return found
    return _read(path)


def owner(env: Mapping[str, str]) -> str:
    """The interpreter of the installation this home's gate runs from.

    ``resident.json`` names it since the address is written with it: the
    installation that created the address, or the one the owner named with
    ``ember-gate resident own``.  Empty when the file is missing, cannot be
    read, or was written before installations were named: then any
    installation may start the gate, as before.

    Why it is there: every ``ember-gate`` on the machine reads the same
    home.  Without a named installation, a development checkout whose
    ``ember-gate resident ensure`` found the gate down started it from its
    own working tree, and that server then answered every call, with
    whatever code the checkout held, for as long as it lived.
    """
    try:
        data = json.loads((ember_home(env) / RESIDENT_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    named = data.get("python") if isinstance(data, dict) else None
    return named if isinstance(named, str) else ""


def same_installation(one: str, other: str) -> bool:
    """True when two interpreters are of one installation.

    Compared by the directory they are in: ``python.exe`` and
    ``pythonw.exe`` of one environment are one installation, and so is an
    interpreter under another spelling of the same path.
    """
    if not one or not other:
        return False

    def folder(path: str) -> str:
        return os.path.normcase(os.path.abspath(os.path.dirname(path)))

    return folder(one) == folder(other)


def own(env: Mapping[str, str], python: str | None = None) -> str:
    """Name this installation as the one the home's gate runs from.

    The owner's decision, for a home whose address was written before
    installations were named, or after the gate was installed somewhere
    else.  Port and token stay.  Returns the interpreter named.

    Raises
    ------
    ValueError
        If there is no address to name an installation for.
    """
    where = address(env)
    if where is None:
        raise ValueError("there is no resident address to name an installation for")
    named = python or sys.executable
    before = owner(env)
    _write(ember_home(env) / RESIDENT_FILE, where, replace=True, python=named)
    if not same_installation(before, named):
        note(
            env,
            f"owned: the gate of this home runs from {named}"
            + (f" (before: {before})" if before else "")
            + ", by the owner's command",
        )
    return named


def move(env: Mapping[str, str]) -> Address:
    """Give the gate a new port and keep its token: the owner's decision.

    For the one case nothing else repairs: another program has taken the
    port for good.  The host's settings have to be printed again afterwards.

    Raises
    ------
    ValueError
        If there is no address to move.
    """
    old = address(env)
    if old is None:
        raise ValueError("there is no resident address to move")
    found = Address(free_port(), old.token)
    _write(ember_home(env) / RESIDENT_FILE, found, replace=True, python=owner(env))
    note(env, f"moved: port {old.port} to port {found.port}, by the owner's command")
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


def state(where: Address, timeout: float = 5.0) -> tuple[str, dict[str, Any] | None]:
    """Who, if anyone, answers at *where*.

    - ``running``: this gate, with what it says about itself.
    - ``down``: nothing accepts a connection on the port.
    - ``busy``: something accepted the connection and did not answer in
      time.  A gate on a loaded machine looks like this, so it is never
      taken for ``down``.
    - ``foreign``: something answered, but not as this gate: another
      program, or a gate that holds another token.
    """
    connection = HTTPConnection(HOST, where.port, timeout=timeout)
    try:
        try:
            connection.connect()
        except OSError:
            return "down", None
        try:
            headers = {TOKEN_HEADER: where.token}
            connection.request("GET", "/health", headers=headers)
            response = connection.getresponse()
            status, body = response.status, response.read()
        except (OSError, HTTPException):
            return "busy", None
    finally:
        connection.close()
    if status != 200:
        return "foreign", None
    try:
        data = json.loads(body)
    except ValueError:
        return "foreign", None
    if isinstance(data, dict) and data.get("ok"):
        return "running", data
    return "foreign", None


def health(where: Address, timeout: float = 5.0) -> dict[str, Any] | None:
    """What a resident gate at *where* says about itself, or ``None``."""
    return state(where, timeout)[1]


def stop(where: Address, timeout: float = 5.0) -> bool:
    """Ask the resident gate at *where* to exit; true when it answered."""
    try:
        status, _ = _request(where, "POST", "/stop", timeout=timeout)
    except (OSError, HTTPException):
        return False
    return status == 200


def console() -> str:
    """``none``, ``hidden`` or ``visible``: the console of this process.

    On Windows a server with a visible console is a window on the owner's
    screen; anywhere else the answer is ``none``.
    """
    if os.name != "nt":
        return "none"
    try:
        import ctypes

        api: Any = getattr(ctypes, "windll")  # noqa: B009 - absent off Windows
        window = api.kernel32.GetConsoleWindow()
        if not window:
            return "none"
        shown = api.user32.IsWindowVisible(window)
        return "visible" if shown else "hidden"
    except Exception:
        return "none"


def interpreter(python: str | None = None) -> str:
    """The interpreter a detached server runs under.

    On Windows ``pythonw.exe`` beside the given one, where there is one: it
    has no console, so none can appear.
    """
    exe = Path(python or sys.executable)
    if os.name == "nt":
        quiet = exe.with_name("pythonw.exe")
        if quiet.exists():
            return str(quiet)
    return str(exe)


def spawn(env: Mapping[str, str], python: str | None = None) -> None:
    """Start a resident gate for the Ember home of *env*, detached, unseen.

    On Windows the process gets no window (``CREATE_NO_WINDOW``, and not
    ``DETACHED_PROCESS``: without any console, the interpreter a launcher
    starts opens a visible one of its own).  It is asked to leave the job of
    the process that starts it, so it does not end with that session; where
    the job does not allow that, it is started inside it.  What the server
    writes to standard error is appended to ``resident.err``.

    The server runs under the interpreter the home names (:func:`owner`),
    whichever installation asks for it; under this process's interpreter
    only when the home names none.

    Raises
    ------
    OSError
        If the home names an interpreter that is not there any more.
    """
    named = python or owner(env)
    if named and not Path(named).exists():
        raise FileNotFoundError(
            f"the installation this home's gate runs from is gone: {named}"
        )
    command = [interpreter(named or None), *SERVER_ARGS]
    home = ember_home(env)
    home.mkdir(parents=True, exist_ok=True)
    # The process environment underneath, so the interpreter finds what it
    # needs (SystemRoot on Windows, PATH); the given variables on top.
    with (home / ERROR_FILE).open("ab") as errors:
        kwargs: dict[str, Any] = {
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.DEVNULL,
            "stderr": errors,
            "close_fds": True,
            "env": {**os.environ, **env},
        }
        if os.name != "nt":
            subprocess.Popen(command, start_new_session=True, **kwargs)  # noqa: S603
            return
        quiet = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
        try:
            flags = quiet | subprocess.CREATE_BREAKAWAY_FROM_JOB
            subprocess.Popen(command, creationflags=flags, **kwargs)  # noqa: S603
        except OSError:
            subprocess.Popen(command, creationflags=quiet, **kwargs)  # noqa: S603


def ensure(
    env: Mapping[str, str] | None = None,
    *,
    python: str | None = None,
    wait: float = 0.0,
) -> str:
    """See that a resident gate answers for the Ember home of *env*.

    Returns ``not configured`` when ``resident.json`` is absent (the
    command hook is in use), ``running`` when the gate answers, ``started``
    after spawning one, and ``not answering`` when something holds the port
    and does not answer as this gate: then nothing is started, because a
    second server could not bind the port either.  With *wait*, polls up
    to that many seconds and returns ``running`` once the gate answers.

    A gate that answers from another installation than the one the home
    names (:func:`owner`) is asked to stop, and the home's own is started
    in its place.  When the home's installation is gone, nothing is
    started and the answer is ``not answering``: :func:`check` says why.
    """
    given = os.environ if env is None else env
    where = address(given)
    if where is None:
        return "not configured"
    found, said = state(where)
    if found == "running" and not _stranger(given, said):
        return "running"
    if found == "running":
        note(
            given,
            f"replace: the gate on port {where.port} runs from "
            f"{(said or {}).get('python')}, this home's runs from {owner(given)}",
        )
        stop(where)
        gone = time.monotonic() + 5.0
        while found != "down" and time.monotonic() < gone:
            time.sleep(0.1)
            found = state(where, timeout=2.0)[0]
    result = "not answering"
    if found == "down":
        try:
            spawn(given, python)
        except OSError as exc:
            note(given, f"not started: {exc}")
            return result
        result = "started"
    deadline = time.monotonic() + wait
    while wait and time.monotonic() < deadline:
        time.sleep(0.1)
        if state(where, timeout=2.0)[0] == "running":
            return "running"
    return result


def _stranger(env: Mapping[str, str], said: Mapping[str, Any] | None) -> bool:
    """True when a gate that answered runs from another installation.

    Never true while the home names no installation.  A gate that does not
    say where it runs from (one started before gates said so) counts as a
    stranger once the home names one.
    """
    named = owner(env)
    if not named:
        return False
    return not same_installation(named, str((said or {}).get("python") or ""))


# ---------------------------------------------------------------------------
# Is the gate where the host calls it?
# ---------------------------------------------------------------------------
def settings_file(env: Mapping[str, str]) -> Path:
    """The user settings file of Claude Code."""
    base = env.get("CLAUDE_CONFIG_DIR")
    return (Path(base) if base else Path.home() / ".claude") / "settings.json"


def configured(settings: Path) -> list[Address]:
    """The loopback addresses the HTTP hooks of a settings file post to.

    Only hooks to ``http://127.0.0.1:<port>/hook`` count.  A file that is
    missing or cannot be read holds none.
    """
    try:
        data = json.loads(settings.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return []
    found: list[Address] = []
    hooks = data.get("hooks") if isinstance(data, dict) else None
    for groups in (hooks or {}).values() if isinstance(hooks, dict) else ():
        for group in groups if isinstance(groups, list) else ():
            entries = group.get("hooks") if isinstance(group, dict) else None
            for entry in entries if isinstance(entries, list) else ():
                if not isinstance(entry, dict) or entry.get("type") != "http":
                    continue
                url = str(entry.get("url") or "")
                prefix = f"http://{HOST}:"
                if not url.startswith(prefix) or not url.endswith("/hook"):
                    continue
                port = url[len(prefix) : -len("/hook")]
                headers = entry.get("headers")
                token = headers.get(TOKEN_HEADER) if isinstance(headers, dict) else ""
                if port.isdigit():
                    found.append(Address(int(port), str(token or "")))
    return found


def check(env: Mapping[str, str], settings: Path | None = None) -> list[str]:
    """What keeps the gate from checking calls, in plain words; none when fine.

    Looks at three things: the address file, whether the gate answers
    there, and whether the host's settings post to that address with that
    token.  Settings without an HTTP hook to the loopback interface are not
    this module's business (the command hook is in use, or the hook is
    registered elsewhere).
    """
    where = address(env)
    if where is None:
        return []
    problems: list[str] = []
    found, said = state(where)
    named = owner(env)
    if found == "down":
        problems.append(f"no gate is running on port {where.port}")
    elif found != "running":
        problems.append(
            f"port {where.port} is held by something that does not answer as this gate"
        )
    elif _stranger(env, said):
        problems.append(
            f"the gate on port {where.port} runs from "
            f"{(said or {}).get('python') or 'an installation it does not name'}, "
            f"not from this home's installation ({named}): its code is not the "
            "installed gate's"
        )
    if named and not Path(named).exists():
        problems.append(
            f"the installation this home's gate runs from is gone ({named}); "
            "from the installation that should run it: ember-gate resident own"
        )
    calls = configured(settings or settings_file(env))
    if calls and where not in calls:
        ports = sorted({call.port for call in calls})
        if where.port not in ports:
            listed = ", ".join(str(port) for port in ports)
            problems.append(
                f"the settings post to port {listed}, the gate's address is "
                f"port {where.port}"
            )
        else:
            problems.append("the settings carry another token than the gate's")
    return problems


def attend(
    env: Mapping[str, str], *, wait: float = 20.0, settings: Path | None = None
) -> str:
    """See to the resident gate at the start of a session.

    Starts the gate when none answers and waits up to *wait* seconds for it
    (a cold start took seven seconds on a busy machine), then checks that
    it is where the host calls it.  Returns what the session has to be
    told, or nothing: a gate that is not checking calls says so, in fixed
    words, instead of letting the session run unchecked in silence.
    """
    if address(env) is None:
        return ""
    ensure(env, wait=wait)
    problems = check(env, settings)
    if not problems:
        return ""
    note(env, "warning: " + "; ".join(problems))
    return (
        "EmberArmor gate warning: the gate is NOT checking this session's tool "
        f"calls ({'; '.join(problems)}). Tell the user now. To repair: "
        "ember-gate resident ensure, then ember-gate resident check."
    )


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
        self.started_at = time.strftime("%Y-%m-%dT%H:%M:%S")
        self.last_request = self.started
        self.served = 0
        #: Set when the server leaves for a fresh copy of itself.
        self.replace = False
        self.state_path = ember_home(env) / STATE_FILE

    def note(self, text: str) -> None:
        """Append a line to ``resident.log``."""
        note(self.env, text)

    def beat(self, ended: str = "") -> None:
        """Record that the server lives, or how it ended, in ``resident.state``.

        The next server reads it: one that ended without a word (killed
        with the session that started it, say) is then named in the log.
        """
        data = {
            "pid": os.getpid(),
            "started": self.started_at,
            "seen": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "served": self.served,
            "ended": ended,
        }
        with contextlib.suppress(OSError):
            self.state_path.write_text(json.dumps(data), encoding="utf-8")

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
        self.beat(ended=reason)
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
        """Record that the server lives; exit after ``idle_seconds`` idle."""
        while True:
            time.sleep(min(_WATCH_SECONDS, max(self.idle_seconds / 4, 0.01)))
            if time.monotonic() - self.last_request > self.idle_seconds:
                self.note("exit: idle")
                self.beat(ended="idle")
                self.shutdown()
                return
            self.beat()


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
            "console": console(),
            "python": sys.executable,
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


def _unspoken(env: Mapping[str, str]) -> None:
    """Name in the log a server that ended without saying so."""
    path = ember_home(env) / STATE_FILE
    try:
        last = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    if isinstance(last, dict) and not last.get("ended"):
        note(
            env,
            f"previous: pid {last.get('pid')} started {last.get('started')} "
            f"ended without a word, last seen {last.get('seen')}, "
            f"served {last.get('served')}",
        )


def serve(
    env: Mapping[str, str] | None = None,
    *,
    idle_minutes: float | None = None,
    respawn: bool = True,
    marker_of: Any = marker,
    block: bool = True,
    patience: float = PATIENCE_SECONDS,
) -> _Gate:
    """Run the resident gate for the Ember home of *env*.

    Creates ``resident.json`` when there is none, and never changes one
    that exists.  When the port in it cannot be bound, the server waits up
    to *patience* seconds for whoever holds it: when that is a resident
    gate answering with the same token, the process exits with status 0,
    since the work is done; when the port comes free, it is taken; and
    when it stays held by something that does not answer as this gate, the
    log says so and the process exits with status 1.  The address stays as
    it is in every case.  With *block* false the server is returned
    unstarted, for a thread of the caller's; the watchdog runs either way.
    """
    given = dict(os.environ if env is None else env)
    where = address(given, create=True)
    assert where is not None
    named = owner(given)
    if named and not same_installation(named, sys.executable):
        # Not this installation's home to serve: its code is not the code
        # the owner installed as the gate.
        note(
            given,
            f"not started: this home's gate runs from {named}; this process "
            f"runs from {sys.executable}. To make this installation the "
            "home's: ember-gate resident own",
        )
        raise SystemExit(1)
    idle = resident_idle(given) if idle_minutes is None else idle_minutes * 60
    deadline = time.monotonic() + patience
    while True:
        try:
            gate = _Gate(
                where, given, idle_seconds=idle, respawn=respawn, marker_of=marker_of
            )
            break
        except OSError as exc:
            found = state(where, timeout=3.0)[0]
            if found == "running":
                raise SystemExit(0) from None  # Another resident gate answers.
            if time.monotonic() >= deadline:
                note(
                    given,
                    f"not started: port {where.port} cannot be bound ({exc}) and "
                    f"what holds it does not answer as this gate ({found}). The "
                    "address is kept. If another program owns the port for "
                    "good: ember-gate resident move",
                )
                raise SystemExit(1) from None
            time.sleep(0.5)
    _unspoken(given)
    gate.note(
        f"start: pid {os.getpid()}, port {where.port}, console {console()}, "
        f"marker {gate.started_marker}"
    )
    gate.beat()
    threading.Thread(target=gate.watch, daemon=True).start()
    if block:
        try:
            gate.serve_forever()
        finally:
            gate.server_close()
        gate.replace_self()
    return gate


def run() -> None:
    """Entry point of a detached server: a crash is written to the log."""
    try:
        serve()
    except SystemExit:
        raise
    except BaseException as exc:
        note(os.environ, f"crash: {type(exc).__name__}: {exc}")
        raise


def main(argv: list[str]) -> int:
    """``ember-gate resident start|ensure|stop|status|check|move|own``."""
    action = argv[0] if argv else "status"
    env = os.environ
    if action == "start":
        serve(env)
        return 0
    if action == "ensure":
        print(ensure(env, wait=8.0))
        return 0
    where = address(env)
    if where is None:
        print("not configured: run ember-gate install claude-code --print --resident")
        return 1
    if action == "stop":
        print("stopped" if stop(where) else "not running")
        return 0
    if action == "move":
        stop(where)
        moved = move(env)
        print(
            f"moved to port {moved.port}. Print the settings again and put them "
            "in place: ember-gate install claude-code --print --resident"
        )
        return 0
    if action == "own":
        named = own(env)
        print(
            f"this home's gate now runs from {named}. Start it from there: "
            "ember-gate resident ensure"
        )
        return 0
    if action == "check":
        problems = check(env)
        for problem in problems:
            print(f"problem: {problem}")
        if not problems:
            print(f"ok: the gate answers on port {where.port}, where the host calls it")
        return 1 if problems else 0
    if action == "status":
        found, data = state(where)
        if data is None:
            print(f"not running (port {where.port}: {found})")
            return 1
        print(json.dumps({"port": where.port, **data}, indent=2))
        return 0
    print(f"ember-gate resident: unknown action {action!r}", file=sys.stderr)
    return 2
