"""Hash-chained JSONL audit log of gate evaluations.

One JSON object per line in ``<ember home>/audit/YYYY-MM.jsonl``.  Each entry
carries the hash of the previous entry (``prev``) and its own ``hash``, so
accidental damage and naive editing show up in :meth:`AuditLog.verify`.  That
is not proof against someone with write access who recomputes the chain;
nothing local can be.  Appends are serialised with a file lock that works on
Windows and POSIX.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import time
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ember_armor.ledger.engine import PastCall
from ember_armor.ledger.facts import FILE_TOOLS, SHELL_TOOLS, Facts
from ember_armor.ledger.redact import MAX_ITEMS, redact_argv, redact_value
from ember_armor.ledger.shell import Dynamic, SimpleCommand
from ember_armor.ledger.shellpaths import PathFact

if os.name == "nt":
    import msvcrt
else:
    import fcntl

GENESIS = "0" * 64
_TAIL_BLOCK = 65_536
_HISTORY_FILES = 2


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
    """
    summary: dict[str, Any] = {"windows": facts.windows}
    if facts.commands:
        summary["commands"] = [
            {"shell": command.shell, "argv": redact_argv(command.argv)}
            for command in facts.commands[:MAX_ITEMS]
        ]
    if facts.paths:
        summary["paths"] = [
            {"path": path.path, "op": path.op, "recursive": path.recursive}
            for path in facts.paths[:MAX_ITEMS]
        ]
    if facts.dynamic:
        summary["dynamic"] = [
            {"kind": reason.kind, "detail": redact_argv([reason.detail])[0]}
            for reason in facts.dynamic[:MAX_ITEMS]
        ]
    if facts.tool in FILE_TOOLS:
        key = FILE_TOOLS[facts.tool][0]
        summary["args"] = redact_value({key: facts.args.get(key)})
    elif facts.tool not in SHELL_TOOLS:
        summary["args"] = redact_value(facts.args)
    return summary


def restore(entry: Mapping[str, Any]) -> Facts:
    """Rebuild the facts of an earlier call from its audit entry."""
    call = entry.get("call") or {}
    return Facts(
        tool=str(entry.get("tool", "")),
        cwd=str(entry.get("cwd", "/")),
        session=str(entry.get("session", "")),
        windows=bool(call.get("windows", False)),
        commands=tuple(
            SimpleCommand(tuple(c.get("argv", ())), c.get("shell", "bash"))
            for c in call.get("commands", ())
        ),
        paths=tuple(
            PathFact(p["path"], p["op"], bool(p.get("recursive", False)))
            for p in call.get("paths", ())
        ),
        dynamic=tuple(
            Dynamic(d.get("kind", ""), d.get("detail", ""))
            for d in call.get("dynamic", ())
        ),
        args=call.get("args") or {},
    )


def _canonical(entry: Mapping[str, Any]) -> bytes:
    body = {key: value for key, value in entry.items() if key != "hash"}
    text = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.encode("utf-8")


def entry_hash(entry: Mapping[str, Any]) -> str:
    """SHA-256 over the entry without its ``hash`` field (``prev`` included)."""
    return hashlib.sha256(_canonical(entry)).hexdigest()


def _line_hash(line: bytes) -> str | None:
    """Stored hash of a log line, or ``None`` if the line is damaged."""
    try:
        entry = json.loads(line)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    stored = entry.get("hash") if isinstance(entry, dict) else None
    return stored if isinstance(stored, str) else None


def _link_after(line: bytes) -> str:
    """Value the next entry's ``prev`` must have after *line*."""
    return _line_hash(line) or hashlib.sha256(line).hexdigest()


def _last_line(path: Path) -> bytes | None:
    try:
        handle = path.open("rb")
    except FileNotFoundError:
        return None
    with handle:
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
        if os.name == "nt":
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return False
    return True


def _unlock(handle: Any) -> None:
    if os.name == "nt":
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

    def files(self) -> list[Path]:
        """Monthly log files, oldest first."""
        return sorted(self.directory.glob("[0-9][0-9][0-9][0-9]-[0-9][0-9].jsonl"))

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

    def _previous_hash(self, target: Path) -> str:
        candidates = [path for path in self.files() if path <= target]
        for path in reversed(candidates):
            line = _last_line(path)
            if line is not None:
                return _link_after(line)
        return GENESIS

    def append(self, record: Mapping[str, Any], when: datetime | None = None) -> dict:
        """Append one entry and return it with ``ts``, ``prev`` and ``hash``.

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
                entry["prev"] = self._previous_hash(target)
                entry["hash"] = entry_hash(entry)
                line = json.dumps(entry, sort_keys=True, ensure_ascii=False)
                with target.open("ab") as handle:
                    handle.write(line.encode("utf-8") + b"\n")
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
                    with contextlib.suppress(json.JSONDecodeError, UnicodeDecodeError):
                        entry = json.loads(line)
                        if isinstance(entry, dict):
                            yield entry

    def verify(self) -> Verification:
        """Recompute the chain over every file and report what does not fit."""
        problems: list[str] = []
        expected: str | None = None
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
                        if expected is not None and entry.get("prev") != expected:
                            problems.append(f"{where}: chain broken (prev mismatch)")
                        if entry_hash(entry) != stored:
                            problems.append(f"{where}: entry modified (hash mismatch)")
                    expected = _link_after(line)
        return Verification(count, tuple(problems))

    def earlier(self, session: str) -> list[PastCall]:
        """Earlier calls of *session* that were proposed and not denied.

        A call counts as denied only when the gate blocked it (``deny`` in
        ``enforce`` mode).  v0 does not know whether a call succeeded.
        """
        calls: list[PastCall] = []
        for entry in self.entries(last_files=_HISTORY_FILES):
            if entry.get("session") != session or "call" not in entry:
                continue
            if entry.get("mode") == "enforce" and entry.get("decision") == "deny":
                continue
            with contextlib.suppress(KeyError, TypeError, ValueError):
                when = datetime.fromisoformat(entry["ts"]).timestamp()
                calls.append(PastCall(when, restore(entry)))
        return calls
