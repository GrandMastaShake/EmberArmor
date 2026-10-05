"""Hash-chained JSONL audit log of gate evaluations.

One JSON object per line in ``<ember home>/audit/YYYY-MM.jsonl``.  Each entry
carries the hash of the previous entry (``prev``) and its own ``hash``; the
first entry links to a fixed genesis value and ``head`` holds the hash of
the last one.  Accidental damage and naive editing, including entries
removed from either end, then show up in :meth:`AuditLog.verify`.  That is
not proof against someone with write access who recomputes the chain;
nothing local can be.  Appends are serialised with a file lock that works on
Windows and POSIX.

An empty marker file named ``.last.<file>.<size>.<hash>`` repeats what the
last append left behind.  Its name is read from the directory listing, so
the next append links to the hash without opening a file the previous
append has just written (Windows scans such a file on its next open, which
costs more than the whole evaluation).  When the size no longer matches,
the log is read as before.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import sys
import time
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from ember_armor.ledger.engine import PastCall
from ember_armor.ledger.facts import FILE_TOOLS, Facts, shell_tool
from ember_armor.ledger.paths import PathFact
from ember_armor.ledger.redact import (
    MAX_ITEMS,
    MAX_TEXT,
    redact_argv,
    redact_path,
    redact_value,
    session_key,
    writable,
)
from ember_armor.ledger.shell import Dynamic, SimpleCommand

TYPE_CHECKING = False
if TYPE_CHECKING:
    from typing import Any

if sys.platform == "win32":
    import msvcrt
else:
    import fcntl

try:
    # CPython's own SHA-2: the same digest as hashlib's, without loading
    # OpenSSL on every hook call.  The module is ``_sha2`` from Python 3.12
    # and ``_sha256`` before that.
    from _sha2 import sha256 as _sha256  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - Python 3.11
    try:
        from _sha256 import sha256 as _sha256  # type: ignore[import-not-found]
    except ImportError:  # other interpreters
        from hashlib import sha256 as _sha256

GENESIS = "0" * 64
HEAD_NAME = "head"
_MARKER_PREFIX = ".last."
_MONTH_RE = re.compile(r"[0-9]{4}-[0-9]{2}\.jsonl")
_TAIL_BLOCK = 65_536
_HISTORY_FILES = 2
#: What decoding a damaged line can raise: not JSON, not UTF-8, a number of
#: more digits than Python converts, brackets nested deeper than it follows.
_UNREADABLE = (ValueError, RecursionError)
#: What reading an entry that is JSON, but not an entry of this log, can
#: raise (a missing field, a wrong type, a time no clock can hold).
_MISSHAPEN = (KeyError, TypeError, ValueError, AttributeError, OSError, OverflowError)


class AuditError(OSError):
    """The audit log could not be written."""


@dataclass(frozen=True)
class Verification:
    """Result of recomputing the hash chain."""

    entries: int
    problems: tuple[str, ...]

    @property
    def ok(self) -> bool:
        """True when every entry links to its predecessor and is unmodified."""
        return not self.problems


def summarise(facts: Facts) -> dict[str, Any]:
    """Redacted, size-capped summary of a call for the audit log.

    Shell commands are stored as parsed argument vectors, never as the raw
    string.  File tools keep only their path; file contents are not logged.
    A command, and a path it touches, carries the directory it runs in
    (``cwd``) when that is not the working directory of the call, so that a
    rule with a directory scope can judge the call again later.
    """
    summary: dict[str, Any] = {"windows": facts.windows}
    if not facts.located:
        # The host named no working directory: the entry's "cwd" is only
        # what the paths were resolved against.
        summary["located"] = False
    if facts.commands:
        summary["commands"] = [
            {
                "shell": command.shell,
                "argv": redact_argv(command.argv),
                **_elsewhere(command.cwd),
            }
            for command in facts.commands[:MAX_ITEMS]
        ]
    if facts.paths:
        summary["paths"] = [
            {
                "path": redact_path(path.path),
                "op": path.op,
                "recursive": path.recursive,
                **_elsewhere(path.cwd),
            }
            for path in facts.paths[:MAX_ITEMS]
        ]
    if facts.dynamic:
        summary["dynamic"] = [
            {"kind": reason.kind, "detail": redact_argv([reason.detail])[0]}
            for reason in facts.dynamic[:MAX_ITEMS]
        ]
    if facts.assigned:
        summary["assigned"] = [name[:MAX_TEXT] for name in facts.assigned[:MAX_ITEMS]]
    if facts.tool in FILE_TOOLS:
        key = FILE_TOOLS[facts.tool][0]
        summary["args"] = redact_value({key: facts.args.get(key)})
    elif not facts.shell and shell_tool(facts.tool) is None:
        summary["args"] = redact_value(facts.args)
    return summary


def _elsewhere(cwd: str) -> dict[str, str]:
    """The ``cwd`` of a command or path, when it is not that of the call."""
    return {"cwd": redact_path(cwd)} if cwd else {}


def restore(entry: Mapping[str, Any]) -> Facts:
    """Rebuild the facts of an earlier call from its audit entry."""
    call = entry.get("call") or {}
    return Facts(
        tool=str(entry.get("tool", "")),
        cwd=str(entry.get("cwd", "/")),
        session=str(entry.get("session", "")),
        windows=bool(call.get("windows", False)),
        commands=tuple(
            SimpleCommand(
                tuple(c.get("argv", ())),
                c.get("shell", "bash"),
                cwd=str(c.get("cwd", "")),
            )
            for c in call.get("commands", ())
        ),
        paths=tuple(
            PathFact(
                p["path"],
                p["op"],
                bool(p.get("recursive", False)),
                str(p.get("cwd", "")),
            )
            for p in call.get("paths", ())
        ),
        dynamic=tuple(
            Dynamic(d.get("kind", ""), d.get("detail", ""))
            for d in call.get("dynamic", ())
        ),
        assigned=tuple(str(name) for name in call.get("assigned", ())),
        args=call.get("args") or {},
        located=call.get("located") is not False,
    )


def _canonical(entry: Mapping[str, Any]) -> bytes:
    body = {key: value for key, value in entry.items() if key != "hash"}
    text = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.encode("utf-8")


def entry_hash(entry: Mapping[str, Any]) -> str:
    """SHA-256 over the entry without its ``hash`` field (``prev`` included)."""
    digest: str = _sha256(_canonical(entry)).hexdigest()
    return digest


def _line_hash(line: bytes) -> str | None:
    """Stored hash of a log line, or ``None`` if the line is damaged."""
    try:
        entry = json.loads(line)
    except _UNREADABLE:
        return None
    stored = entry.get("hash") if isinstance(entry, dict) else None
    return stored if isinstance(stored, str) else None


def _writable(value: Any) -> Any:
    """*value* with every string in it made writable (see ``redact.writable``)."""
    if isinstance(value, str):
        return writable(value)
    if isinstance(value, dict):
        return {_writable(key): _writable(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_writable(item) for item in value]
    return value


def _link_after(line: bytes) -> str:
    """Value the next entry's ``prev`` must have after *line*."""
    fallback: str = _sha256(line).hexdigest()
    return _line_hash(line) or fallback


def _last_line(path: Path) -> bytes | None:
    with path.open("rb") as handle:
        size = handle.seek(0, os.SEEK_END)
        data = b""
        while size > 0:
            step = min(_TAIL_BLOCK, size)
            size -= step
            handle.seek(size)
            data = handle.read(step) + data
            lines = data.rstrip(b"\r\n").split(b"\n")
            if len(lines) > 1 or size == 0:
                return lines[-1].rstrip(b"\r") or None
    return None


def _try_lock(handle: Any) -> bool:
    try:
        if sys.platform == "win32":
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return False
    return True


def _unlock(handle: Any) -> None:
    if sys.platform == "win32":
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


class AuditLog:
    """Append-only, hash-chained log in one directory.

    Parameters
    ----------
    directory:
        The audit directory (``<ember home>/audit``).  Created on first write.
    lock_timeout:
        Seconds to wait for the append lock before giving up.
    """

    def __init__(self, directory: Path, lock_timeout: float = 10.0) -> None:
        self.directory = directory
        self.lock_timeout = lock_timeout

    def _names(self) -> list[str]:
        """Entries of the audit directory (none when it does not exist)."""
        try:
            return os.listdir(self.directory)
        except FileNotFoundError:
            return []

    def files(self, names: list[str] | None = None) -> list[Path]:
        """Monthly log files, oldest first."""
        names = self._names() if names is None else names
        return sorted(self.directory / n for n in names if _MONTH_RE.fullmatch(n))

    def _marker(self, names: list[str]) -> tuple[str, int, str] | None:
        """File name, size and hash recorded by the last append's marker."""
        for name in names:
            if name.startswith(_MARKER_PREFIX):
                parts = name[len(_MARKER_PREFIX) :].rsplit(".", 2)
                if len(parts) == 3 and parts[1].isdigit() and len(parts[2]) == 64:
                    return parts[0], int(parts[1]), parts[2]
        return None

    def _mark(self, names: list[str], file: str, size: int, digest: str) -> None:
        """Leave the marker for the next append, replacing any older one."""
        marker = self.directory / f"{_MARKER_PREFIX}{file}.{size}.{digest}"
        old = [n for n in names if n.startswith(_MARKER_PREFIX)]
        if old:
            os.replace(self.directory / old[0], marker)
        else:
            marker.touch()
        for name in old[1:]:
            with contextlib.suppress(OSError):
                (self.directory / name).unlink()

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        self.directory.mkdir(parents=True, exist_ok=True)
        with (self.directory / ".lock").open("a+b") as handle:
            deadline = time.monotonic() + self.lock_timeout
            while not _try_lock(handle):
                if time.monotonic() >= deadline:
                    raise AuditError("timed out waiting for the audit log lock")
                time.sleep(0.005)
            try:
                yield
            finally:
                _unlock(handle)

    def _head(self) -> str | None:
        """Hash of the last entry as recorded at the last append, if any."""
        try:
            return (self.directory / HEAD_NAME).read_text(encoding="ascii").strip()
        except (FileNotFoundError, ValueError):
            return None

    def _link(self, files: list[Path]) -> tuple[str, bool]:
        """What the next entry links to, and whether a newline must come first.

        Normally the hash of the last line.  When ``head`` names another
        hash although that line is intact, entries were removed from the end
        (or an append was cut short): the new entry then links to ``head``,
        so the gap stays visible to :meth:`verify`.  A damaged last line is
        linked to as it is; it is its own evidence.
        """
        for path in reversed(files):
            line = _last_line(path)
            if line is None:
                continue
            with path.open("rb") as handle:
                handle.seek(-1, os.SEEK_END)
                unfinished = path == files[-1] and handle.read(1) != b"\n"
            head = self._head()
            intact = _line_hash(line) is not None
            link = head if intact and head else _link_after(line)
            return link, unfinished
        return self._head() or GENESIS, False

    def append(
        self, record: Mapping[str, Any], when: datetime | None = None
    ) -> dict[str, Any]:
        """Append one entry and return it with ``ts``, ``prev`` and ``hash``.

        The entry goes to the file of its month, or to the newest file if
        that is later: entries are never inserted before existing ones.

        Raises
        ------
        AuditError
            If the lock cannot be taken or the file cannot be written.
        """
        moment = (when or datetime.now(UTC)).astimezone(UTC)
        target = self.directory / f"{moment:%Y-%m}.jsonl"
        entry = {"ts": moment.isoformat(timespec="milliseconds"), **record}
        try:
            with self._locked():
                names = self._names()
                files = self.files(names)
                target = max([target, *files[-1:]])
                marker = self._marker(names)
                if (
                    marker is not None
                    and files[-1:] == [target]
                    and marker[:2] == (target.name, os.stat(target).st_size)
                ):
                    # The file is as the last append left it: link to its hash.
                    entry["prev"], unfinished = marker[2], False
                else:
                    entry["prev"], unfinished = self._link(files)
                try:
                    entry["hash"] = entry_hash(entry)
                except UnicodeEncodeError:
                    # Half a surrogate pair in a field of the call: the
                    # entry is kept, with the half written as its escape.
                    entry = _writable(entry)
                    entry["hash"] = entry_hash(entry)
                line = json.dumps(entry, sort_keys=True, ensure_ascii=False)
                with target.open("ab") as handle:
                    # After a line cut short by a crash, start a new one.
                    handle.write(b"\n" * unfinished + line.encode("utf-8") + b"\n")
                    written = handle.tell()
                head = self.directory / HEAD_NAME
                head.write_text(entry["hash"] + "\n", encoding="ascii")
                self._mark(names, target.name, written, entry["hash"])
        except AuditError:
            raise
        except OSError as exc:
            raise AuditError(f"cannot write audit log {target}: {exc}") from exc
        return entry

    def entries(self, last_files: int | None = None) -> Iterator[dict[str, Any]]:
        """Readable entries, oldest first (damaged lines are skipped)."""
        files = self.files()
        for path in files if last_files is None else files[-last_files:]:
            with path.open("rb") as handle:
                for line in handle:
                    entry = None
                    with contextlib.suppress(*_UNREADABLE):
                        entry = json.loads(line)
                    if isinstance(entry, dict):
                        yield entry

    def verify(self) -> Verification:
        """Recompute the chain over every file and report what does not fit."""
        problems: list[str] = []
        expected = GENESIS
        count = 0
        for path in self.files():
            with path.open("rb") as handle:
                for number, raw in enumerate(handle, start=1):
                    line = raw.rstrip(b"\r\n")
                    if not line:
                        continue
                    count += 1
                    where = f"{path.name}:{number}"
                    stored = _line_hash(line)
                    if stored is None:
                        problems.append(f"{where}: not a valid log entry")
                    else:
                        entry = json.loads(line)
                        if entry.get("prev") != expected:
                            problems.append(f"{where}: chain broken (prev mismatch)")
                        if entry_hash(entry) != stored:
                            problems.append(f"{where}: entry modified (hash mismatch)")
                    expected = _link_after(line)
        head = self._head()
        if head is not None and head != expected:
            problems.append(
                "head: the last entry is not the one recorded at the last append "
                "(entries were removed from the end, or an append was cut short)"
            )
        return Verification(count, tuple(problems))

    def session_entries(self, session: str) -> list[dict[str, Any]]:
        """Entries of *session* in the newest log files, oldest first.

        Only lines that mention the session are decoded: the cost of the
        rest of the log is one substring test per line.
        """
        found: list[dict[str, Any]] = []
        # The id as an entry holds it (capped, and writable).
        session = session_key(session)
        marker = json.dumps(session, ensure_ascii=False).encode("utf-8")
        needle = b'"session": ' + marker
        for path in self.files()[-_HISTORY_FILES:]:
            with path.open("rb") as handle:
                for line in handle:
                    if needle not in line:
                        continue
                    with contextlib.suppress(*_UNREADABLE):
                        entry = json.loads(line)
                        if isinstance(entry, dict) and entry.get("session") == session:
                            found.append(entry)
        return found

    def earlier(self, session: str) -> list[PastCall]:
        """Earlier calls of *session* that were proposed and not denied.

        A call counts as denied only when the gate blocked it (``deny`` in
        ``enforce`` mode).  v0 does not know whether a call succeeded.
        """
        return past_calls(self.session_entries(session))


def past_calls(entries: Iterable[Mapping[str, Any]]) -> list[PastCall]:
    """The calls among audit *entries* that were proposed and not denied."""
    calls: list[PastCall] = []
    for entry in entries:
        with contextlib.suppress(*_MISSHAPEN):
            if "call" not in entry:
                continue
            if (entry["mode"], entry["decision"]) == ("enforce", "deny"):
                continue
            when = datetime.fromisoformat(entry["ts"]).timestamp()
            calls.append(PastCall(when, restore(entry)))
    return calls
