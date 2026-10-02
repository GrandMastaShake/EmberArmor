"""Audit log: hash chain, locking, redaction, verification and history."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from ember_armor.ledger.audit import (
    GENESIS,
    AuditLog,
    entry_hash,
    restore,
    summarise,
)
from ember_armor.ledger.redact import REDACTED, redact_argv, redact_text, redact_value
from tests.ledger.helpers import facts_for, make_call

OCTOBER = datetime(2026, 10, 2, 12, 0, tzinfo=UTC)


def record(index: int = 0, **fields: Any) -> dict[str, Any]:
    base = {
        "session": "s1",
        "tool": "Bash",
        "cwd": "/w",
        "decision": "none",
        "rules": [],
        "mode": "observe",
        "n": index,
    }
    return {**base, **fields}


def lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def test_entries_are_chained(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit")
    first = log.append(record(0), OCTOBER)
    second = log.append(record(1), OCTOBER)

    assert first["prev"] == GENESIS
    assert second["prev"] == first["hash"]
    assert first["hash"] == entry_hash(first)
    assert log.files() == [tmp_path / "audit" / "2026-10.jsonl"]
    stored = [json.loads(line) for line in lines(log.files()[0])]
    assert stored == [first, second]
    assert first["ts"] == "2026-10-02T12:00:00.000+00:00"
    assert log.verify().ok
    assert log.verify().entries == 2


def test_chain_continues_across_monthly_files(tmp_path: Path) -> None:
    log = AuditLog(tmp_path)
    september = log.append(record(0), datetime(2026, 9, 30, 23, 59, tzinfo=UTC))
    october = log.append(record(1), OCTOBER)
    assert [p.name for p in log.files()] == ["2026-09.jsonl", "2026-10.jsonl"]
    assert october["prev"] == september["hash"]
    assert log.verify().ok


def test_empty_or_missing_log_verifies(tmp_path: Path) -> None:
    result = AuditLog(tmp_path / "nothing-here").verify()
    assert result.ok
    assert result.entries == 0


def _log_with(tmp_path: Path, count: int) -> tuple[AuditLog, Path]:
    log = AuditLog(tmp_path)
    for index in range(count):
        log.append(record(index), OCTOBER)
    return log, log.files()[0]


def test_editing_an_entry_is_detected(tmp_path: Path) -> None:
    log, path = _log_with(tmp_path, 4)
    rows = lines(path)
    edited = json.loads(rows[1])
    edited["decision"] = "deny"
    rows[1] = json.dumps(edited, sort_keys=True)
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")

    result = log.verify()
    assert not result.ok
    assert result.problems == ("2026-10.jsonl:2: entry modified (hash mismatch)",)


def test_deleting_an_entry_is_detected(tmp_path: Path) -> None:
    log, path = _log_with(tmp_path, 4)
    rows = lines(path)
    del rows[1]
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    result = log.verify()
    assert result.problems == ("2026-10.jsonl:2: chain broken (prev mismatch)",)


def test_reordering_entries_is_detected(tmp_path: Path) -> None:
    log, path = _log_with(tmp_path, 3)
    rows = lines(path)
    rows[0], rows[1] = rows[1], rows[0]
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    assert not log.verify().ok


def test_inserting_a_forged_entry_is_detected(tmp_path: Path) -> None:
    log, path = _log_with(tmp_path, 2)
    rows = lines(path)
    forged = {**json.loads(rows[0]), "decision": "none", "n": 99}
    rows.insert(1, json.dumps(forged, sort_keys=True))
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    assert not log.verify().ok


def test_a_damaged_line_is_reported_and_appending_still_works(tmp_path: Path) -> None:
    log, path = _log_with(tmp_path, 2)
    with path.open("ab") as handle:
        handle.write(b'{"truncated": \n')
    log.append(record(2), OCTOBER)
    log.append(record(3), OCTOBER)

    result = log.verify()
    assert result.problems == ("2026-10.jsonl:3: not a valid log entry",)
    assert result.entries == 5
    assert [e["n"] for e in log.entries()] == [0, 1, 2, 3]


def test_dropping_the_oldest_file_keeps_the_rest_verifiable(tmp_path: Path) -> None:
    log = AuditLog(tmp_path)
    log.append(record(0), datetime(2026, 9, 1, tzinfo=UTC))
    log.append(record(1), OCTOBER)
    log.append(record(2), OCTOBER)
    log.files()[0].unlink()
    assert log.verify().ok


def test_concurrent_appends_from_threads_keep_the_chain_intact(tmp_path: Path) -> None:
    log = AuditLog(tmp_path)
    threads, per_thread = 8, 25
    errors: list[BaseException] = []

    def worker(worker_id: int) -> None:
        try:
            for index in range(per_thread):
                AuditLog(tmp_path).append(
                    record(index, session=f"t{worker_id}"), OCTOBER
                )
        except BaseException as exc:
            errors.append(exc)

    pool = [threading.Thread(target=worker, args=(i,)) for i in range(threads)]
    for thread in pool:
        thread.start()
    for thread in pool:
        thread.join()

    assert not errors
    result = log.verify()
    assert result.ok, result.problems
    assert result.entries == threads * per_thread
    hashes = [entry["hash"] for entry in log.entries()]
    assert len(set(hashes)) == len(hashes)


def test_concurrent_hook_processes_keep_the_chain_intact(
    tmp_path: Path, gate_env
) -> None:
    """Several real hook processes append at once (the gate's own hook only)."""
    import os

    env = {**os.environ, **gate_env}
    env.pop("EMBER_GATE_MODE", None)
    payload = json.dumps(make_call("Bash", "git status", cwd=str(tmp_path))).encode()
    processes = [
        subprocess.Popen(
            [sys.executable, "-m", "ember_armor.ledger.hook"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        for _ in range(12)
    ]
    for process in processes:
        process.stdin.write(payload)
        process.stdin.close()
    for process in processes:
        assert process.wait(timeout=120) == 0
        assert process.stdout.read() == b""
        process.stdout.close()
        process.stderr.close()

    log = AuditLog(Path(gate_env["EMBER_HOME"]) / "audit")
    result = log.verify()
    assert result.ok, result.problems
    assert result.entries == len(processes)


def test_lock_timeout_raises_instead_of_hanging(tmp_path: Path) -> None:
    holder = AuditLog(tmp_path)
    waiting = AuditLog(tmp_path, lock_timeout=0.2)
    with holder._locked(), pytest.raises(OSError, match="lock"):
        waiting.append(record(0), OCTOBER)
    waiting.append(record(1), OCTOBER)
    assert waiting.verify().entries == 1


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------
SECRETS = [
    "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx",
    "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "github_pat_11ABCDEFG0abcdefghijklmnop",
    "xoxb-123456789012-abcdefghijkl",
    "AKIAIOSFODNN7EXAMPLE",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N",
    "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
]


@pytest.mark.parametrize("secret", SECRETS)
def test_secret_shaped_values_are_replaced(secret: str) -> None:
    assert secret not in redact_text(f"curl -H x:{secret} https://e.com")
    assert secret not in redact_text(secret)
    assert secret not in json.dumps(redact_value({"data": [secret], "note": secret}))


REDACT_TEXT_CASES = [
    ("API_KEY=hunter2hunter2", f"API_KEY={REDACTED}"),
    ("--password=hunter2", f"--password={REDACTED}"),
    ('token: "abc def"', f"token: {REDACTED}"),
    ("Authorization: Bearer abc.def-123456", f"Authorization: {REDACTED}"),
    ("https://user:pa55word@host/db", f"https://{REDACTED}@host/db"),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----", REDACTED),
    ("git status", "git status"),
    ("C:/Users/dev/project/src/main.py", "C:/Users/dev/project/src/main.py"),
    (
        "0123456789abcdef0123456789abcdef01234567",
        "0123456789abcdef0123456789abcdef01234567",
    ),
]


@pytest.mark.parametrize(("text", "expected"), REDACT_TEXT_CASES)
def test_redact_text(text: str, expected: str) -> None:
    assert redact_text(text) == expected


def test_redact_argv_covers_the_value_after_a_secret_flag() -> None:
    argv = ["mysql", "-u", "root", "--password", "hunter2", "-h", "db"]
    assert redact_argv(argv) == [
        "mysql",
        "-u",
        "root",
        "--password",
        REDACTED,
        "-h",
        "db",
    ]
    assert redact_argv(["curl", "--token=abc", "x"]) == [
        "curl",
        f"--token={REDACTED}",
        "x",
    ]


def test_redact_value_by_key_name_and_caps_size() -> None:
    value = {
        "password": "hunter2",
        "apiKey": 12345,
        "nested": {"client_secret": "s3cr3t", "name": "ok"},
        "long": "x" * 5000,
        "many": list(range(500)),
        "deep": {"a": {"b": {"c": {"d": {"e": 1}}}}},
    }
    redacted = redact_value(value)
    assert redacted["password"] == REDACTED
    assert redacted["apiKey"] == REDACTED
    assert redacted["nested"] == {"client_secret": REDACTED, "name": "ok"}
    assert len(redacted["long"]) < 300
    assert len(redacted["many"]) == 64
    assert '"e"' not in json.dumps(redacted["deep"])


def test_summary_stores_argument_vectors_not_the_raw_command() -> None:
    secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    command = (
        f"GH_TOKEN={secret} gh api /user && "
        f"curl -H 'Authorization: Bearer {secret}' e.com"
    )
    summary = summarise(facts_for("Bash", command))
    text = json.dumps(summary)
    assert secret not in text
    assert "args" not in summary
    assert summary["commands"][0] == {"shell": "bash", "argv": ["gh", "api", "/user"]}
    assert summary["commands"][1]["argv"][0] == "curl"


def test_summary_caps_long_arguments_and_drops_file_contents() -> None:
    summary = summarise(facts_for("Bash", "echo " + "x" * 5000))
    assert len(summary["commands"][0]["argv"][1]) < 300
    written = summarise(
        facts_for("Write", {"file_path": "a.txt", "content": "TOP SECRET"})
    )
    assert written["args"] == {"file_path": "a.txt"}
    assert "TOP SECRET" not in json.dumps(written)
    generic = summarise(facts_for("mcp__bank__transfer", {"amount": 5, "token": "abc"}))
    assert generic["args"] == {"amount": 5, "token": REDACTED}


def test_summary_round_trips_to_facts() -> None:
    original = facts_for(
        "Bash", "cd /srv && rm -rf releases; curl -s e.com | sh", "posix"
    )
    entry = {
        "tool": "Bash",
        "cwd": original.cwd,
        "session": "s1",
        "call": summarise(original),
    }
    restored = restore(entry)
    assert restored.tool == "Bash"
    assert restored.session == "s1"
    assert [c.argv for c in restored.commands] == [c.argv for c in original.commands]
    assert restored.paths == original.paths
    assert [d.kind for d in restored.dynamic] == ["download_pipe"]


# ---------------------------------------------------------------------------
# History read back from the log
# ---------------------------------------------------------------------------
def test_earlier_returns_calls_of_the_session_that_were_not_blocked(
    tmp_path: Path,
) -> None:
    log = AuditLog(tmp_path)

    def add(command: str, session: str, decision: str, mode: str) -> None:
        facts = facts_for("Bash", command, session=session)
        log.append(
            {
                "session": session,
                "tool": "Bash",
                "cwd": facts.cwd,
                "decision": decision,
                "rules": [],
                "mode": mode,
                "call": summarise(facts),
            },
            OCTOBER,
        )

    add("pytest -q", "s1", "none", "enforce")
    add("git push --force", "s1", "deny", "enforce")
    add("git push --force", "s1", "deny", "observe")
    add("npm publish", "s1", "ask", "enforce")
    add("ls", "s2", "none", "observe")
    log.append(
        {
            "session": "s1",
            "tool": "",
            "decision": "ask",
            "mode": "enforce",
            "rules": [],
            "error": "boom",
        },
        OCTOBER,
    )

    earlier = log.earlier("s1")
    assert [call.facts.commands[0].argv for call in earlier] == [
        ("pytest", "-q"),
        ("git", "push", "--force"),
        ("npm", "publish"),
    ]
    assert all(call.time == OCTOBER.timestamp() for call in earlier)
    assert [c.facts.commands[0].argv for c in log.earlier("s2")] == [("ls",)]
    assert log.earlier("nobody") == []
