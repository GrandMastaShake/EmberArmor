"""Audit log: damage at either end, cut-off lines, history cost, redaction.

Secrets in these tests are made-up strings.  Command strings are data;
nothing runs them.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from ember_armor.ledger.audit import HEAD_NAME, AuditLog, summarise
from ember_armor.ledger.redact import REDACTED, redact_argv, redact_path, redact_value
from tests.ledger.helpers import facts_for

SEPTEMBER = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
OCTOBER = datetime(2026, 10, 2, 12, 0, tzinfo=UTC)
SECRET = "Zq9hunter2"


def record(index: int = 0, **fields: Any) -> dict[str, Any]:
    base = {"session": "s1", "tool": "Bash", "cwd": "/w", "decision": "none",
            "rules": [], "mode": "observe", "n": index}  # fmt: skip
    return {**base, **fields}


def filled(tmp_path: Path, count: int) -> tuple[AuditLog, Path]:
    log = AuditLog(tmp_path)
    for index in range(count):
        log.append(record(index), OCTOBER)
    return log, log.files()[0]


def numbers(log: AuditLog) -> list[int]:
    return [entry["n"] for entry in log.entries()]


# ---------------------------------------------------------------------------
# Damage
# ---------------------------------------------------------------------------
def test_an_entry_after_a_line_cut_short_is_not_lost(tmp_path: Path) -> None:
    log, path = filled(tmp_path, 3)
    data = path.read_bytes()
    path.write_bytes(data[:-40])  # a crash in the middle of the third write
    log.append(record(3, decision="deny"), OCTOBER)
    log.append(record(4), OCTOBER)

    assert numbers(log) == [0, 1, 3, 4]
    result = log.verify()
    assert result.problems == ("2026-10.jsonl:3: not a valid log entry",)
    assert result.entries == 5


def test_entries_removed_from_the_end_are_reported(tmp_path: Path) -> None:
    log, path = filled(tmp_path, 5)
    rows = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(b"".join(rows[:2]))
    result = log.verify()
    assert result.entries == 2
    assert len(result.problems) == 1
    assert result.problems[0].startswith("head: the last entry is not the one recorded")
    # A later append does not paper over the gap: the chain breaks there.
    log.append(record(5), OCTOBER)
    assert log.verify().problems == ("2026-10.jsonl:3: chain broken (prev mismatch)",)


def test_entries_removed_from_the_start_are_reported(tmp_path: Path) -> None:
    log, path = filled(tmp_path, 5)
    rows = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(b"".join(rows[2:]))
    assert log.verify().problems == ("2026-10.jsonl:1: chain broken (prev mismatch)",)


def test_an_emptied_log_is_reported(tmp_path: Path) -> None:
    log, path = filled(tmp_path, 2)
    path.unlink()
    assert not log.verify().ok
    log.append(record(2), OCTOBER)
    assert log.verify().problems == ("2026-10.jsonl:1: chain broken (prev mismatch)",)


def test_an_entry_dated_before_the_newest_file_goes_to_the_newest_file(
    tmp_path: Path,
) -> None:
    log = AuditLog(tmp_path)
    log.append(record(0), OCTOBER)
    log.append(record(1), SEPTEMBER)
    log.append(record(2), OCTOBER)
    assert [path.name for path in log.files()] == ["2026-10.jsonl"]
    assert numbers(log) == [0, 1, 2]
    assert log.verify().ok


def test_a_log_written_before_the_head_record_existed_still_verifies(
    tmp_path: Path,
) -> None:
    log, _ = filled(tmp_path, 3)
    (tmp_path / HEAD_NAME).unlink()
    assert log.verify().ok
    log.append(record(3), OCTOBER)
    assert log.verify().ok
    assert (tmp_path / HEAD_NAME).exists()


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------
def test_history_decodes_only_the_lines_of_its_session(tmp_path: Path) -> None:
    log = AuditLog(tmp_path)
    call = {"windows": False, "commands": [{"shell": "bash", "argv": ["pytest"]}]}
    for index in range(300):
        session = "mine" if index % 100 == 0 else f"other-{index}"
        log.append(record(index, session=session, call=call), OCTOBER)
    # A session id that needs JSON escaping, and one that is a prefix of another.
    log.append(record(900, session='we"ird', call=call), OCTOBER)
    log.append(record(901, session="mine-too", call=call), OCTOBER)

    assert len(log.earlier("mine")) == 3
    assert len(log.earlier('we"ird')) == 1
    assert log.earlier("nobody") == []


def test_history_cost_is_bounded_for_a_large_log(tmp_path: Path) -> None:
    log = AuditLog(tmp_path)
    log.append(record(0, session="big", call={"windows": False}), OCTOBER)
    filler = json.dumps(record(1, session="x", call={"pad": "p" * 300}))
    with log.files()[0].open("ab") as handle:
        handle.write((filler + "\n").encode() * 50_000)
    started = time.perf_counter()
    assert len(log.earlier("big")) == 1
    assert time.perf_counter() - started < 2.0


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------
ARGV = [
    ["docker", "login", "-u", "alex", "-p", SECRET, "registry.example.com"],
    ["mysql", "-u", "root", f"-p{SECRET}", "-e", "select 1"],
    ["curl", "-u", f"alex:{SECRET}", "https://example.com/api"],
    ["curl", "-H", f"Cookie: session={SECRET}abcdef0123456789", "https://example.com"],
    ["vercel", "deploy", "--yes", "-t", f"{SECRET}0123456789abcdef0123456789abcd"],
    ["export", f"STRIPE_KEY={SECRET}_live"],
    ["sshpass", "-p", SECRET, "ssh", "alex@host", "ls"],
    ["git", "remote", "set-url", "origin", f"https://{SECRET}@github.com/a/b.git"],
    ["curl", f"https://example.com/file?sig={SECRET}&se=2026"],
    ["eval", f"deploy --key {SECRET}"],
    ["deploy", "--key", SECRET],
    ["gh", "auth", "login", "--with-token", SECRET],
]


@pytest.mark.parametrize("argv", ARGV)
def test_secrets_on_the_command_line_are_redacted(argv: list[str]) -> None:
    logged = json.dumps(redact_argv(argv))
    assert SECRET not in logged
    assert REDACTED in logged
    assert redact_argv(argv)[0] == argv[0]


def test_harmless_arguments_are_left_alone() -> None:
    for argv in (
        ["docker", "run", "-p", "8080:80", "nginx"],
        ["ls", "-p", "src"],
        ["git", "show", "HEAD~1"],
        ["grep", "-rn", "password", "src"],
    ):
        assert redact_argv(argv) == argv


def test_everything_below_a_secret_named_key_is_redacted() -> None:
    value = {
        "auth": SECRET,
        "pwd": SECRET,
        "key": SECRET,
        "credentials": {"user": "a", "pw": SECRET, "more": [SECRET, {"x": SECRET}]},
        "token_count": 5,
        "keyboard": "qwerty",
        "k" * 600: "long key",
    }
    logged = redact_value(value)
    assert SECRET not in json.dumps(logged)
    assert logged["credentials"]["user"] == REDACTED
    assert logged["keyboard"] == "qwerty"
    assert max(len(key) for key in logged) == 256


def test_paths_are_capped_and_keep_ordinary_names() -> None:
    scratch = "/tmp/b579bf47-9957-43ad-84da-1eed1905cad7/scratchpad/notes.txt"
    assert redact_path(scratch) == scratch
    token = "ghp_" + "a1B2" * 6
    assert redact_path(f"/w/out-{token}.txt") == f"/w/out-{REDACTED}.txt"
    assert len(redact_path("/w/" + "a" * 5000)) < 1100
    facts = facts_for("Bash", f"echo hi > out-{token}.txt")
    assert summarise(facts)["paths"] == [
        {"path": f"/work/app/out-{REDACTED}.txt", "op": "write", "recursive": False}
    ]


def test_redaction_of_repetitive_input_is_fast() -> None:
    # Each of these took seconds per string before the patterns were bounded.
    value = {f"k{i}": "a-" * 1024 for i in range(64)}
    argv = ["echo", *("a-" * 1024 for _ in range(96)), "key" * 2000, "pass" * 2000]
    started = time.perf_counter()
    redact_value(value)
    redact_argv(argv)
    assert time.perf_counter() - started < 2.0
