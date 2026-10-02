"""``ember-gate replay``: recorded tool calls in, aggregates out.

The transcripts are small and synthetic.  The command strings in them are
data for the parser; the replay never runs anything and never writes to the
audit log.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ember_armor.ledger import cli
from ember_armor.ledger.model import LedgerError
from ember_armor.ledger.replay import (
    ReplayReport,
    render,
    replay,
    tool_calls,
    transcript_files,
)
from tests.ledger.helpers import rule, write_ledger

TRANSCRIPTS = Path(__file__).parent / "transcripts"
SESSION_A = str(TRANSCRIPTS / "session-a.jsonl")
SECRET = "ghp_" + "a1B2c3D4e5" * 4


def tool_line(
    call_id: str,
    name: str,
    tool_input: dict[str, Any],
    *,
    session: str = "s1",
    at: str | None = "2026-09-30T10:00:00Z",
) -> str:
    """One assistant transcript line with a single ``tool_use`` block."""
    block = {"type": "tool_use", "id": call_id, "name": name, "input": tool_input}
    entry: dict[str, Any] = {
        "type": "assistant",
        "sessionId": session,
        "cwd": "/work/app",
        "message": {"role": "assistant", "content": [block]},
    }
    if at is not None:
        entry["timestamp"] = at
    return json.dumps(entry)


def bash(call_id: str, command: str, **fields: Any) -> str:
    return tool_line(call_id, "Bash", {"command": command}, **fields)


def write_transcript(path: Path, *lines: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


# ---------------------------------------------------------------------------
# Aggregates
# ---------------------------------------------------------------------------
def test_fixture_transcript_gives_the_expected_aggregates(gate_env) -> None:
    report = replay([SESSION_A], env=gate_env, windows=False)
    assert (report.files, report.lines, report.skipped_lines) == (1, 16, 2)
    assert report.calls == 8
    assert report.errors == 0
    assert dict(report.tools) == {
        "Bash": 5,
        "Read": 1,
        "Edit": 1,
        "mcp__db__query": 1,
    }
    assert dict(report.decisions) == {"none": 4, "ask": 3, "deny": 1}
    assert dict(report.rules) == {
        "builtin.secrets.read": 1,
        "builtin.git.force-push": 1,
        "builtin.delete.protected": 1,
        "builtin.delete.recursive": 1,
        "builtin.shell.download-pipe": 1,
    }
    assert report.effects["builtin.delete.protected"] == "deny"
    assert report.effects["builtin.git.force-push"] == "ask"
    assert dict(report.dynamic) == {"download_pipe": 1, "parse_error": 1}
    assert report.examples["builtin.git.force-push"] == [
        "Bash: git push --force origin main"
    ]
    assert report.examples["builtin.secrets.read"] == [
        'Read: {"file_path": "/work/app/.env"}'
    ]


def test_replay_writes_nothing(gate_env) -> None:
    replay([SESSION_A], env=gate_env, windows=False)
    assert not Path(gate_env["EMBER_HOME"]).exists()
    assert not Path(gate_env["EMBER_LEDGER"]).exists()


def test_directories_are_searched_for_transcripts(gate_env, tmp_path) -> None:
    write_transcript(tmp_path / "t" / "one.jsonl", bash("c1", "git status"))
    write_transcript(tmp_path / "t" / "deep" / "two.jsonl", bash("c2", "ls"))
    write_transcript(tmp_path / "t" / "notes.txt", bash("c3", "ls"))
    names = [path.name for path in transcript_files([str(tmp_path / "t")])]
    assert names == ["two.jsonl", "one.jsonl"]
    report = replay([str(tmp_path / "t"), SESSION_A], env=gate_env, windows=False)
    assert report.files == 3
    assert report.calls == 10


def test_a_missing_path_is_an_error(gate_env, tmp_path) -> None:
    with pytest.raises(FileNotFoundError, match="nope.jsonl"):
        replay([str(tmp_path / "nope.jsonl")], env=gate_env)


def test_a_repeated_tool_use_is_counted_once(gate_env, tmp_path) -> None:
    first = write_transcript(
        tmp_path / "first.jsonl",
        bash("c1", "git push --force"),
        bash("c1", "git push --force"),
    )
    resumed = write_transcript(
        tmp_path / "resumed.jsonl",
        bash("c1", "git push --force"),
        bash("c2", "git push --force"),
        bash("", "git push --force"),
        bash("", "git push --force"),
    )
    report = replay([first, resumed], env=gate_env, windows=False)
    assert report.calls == 4
    assert report.rules["builtin.git.force-push"] == 4


def test_other_line_shapes_are_skipped(tmp_path) -> None:
    path = tmp_path / "odd.jsonl"
    path.write_text(
        "\n".join(
            [
                "",
                "null",
                '"text"',
                "{}",
                '{"message": null}',
                '{"message": {"content": "plain text"}}',
                '{"message": {"content": [null, 3, {"type": "text"}]}}',
                '{"message": {"content": [{"type": "tool_use", "name": 7}]}}',
                '{"message": {"content": [{"type": "tool_use", "name": "Read"}]}}',
                "{broken",
                bash("ok", "ls", at=None),
            ]
        ),
        encoding="utf-8",
    )
    report = ReplayReport()
    found = list(tool_calls(path, report))
    assert [(call_id, call["tool_name"]) for call_id, call, _ in found] == [
        ("ok", "Bash")
    ]
    assert found[0][2] == 0.0
    assert (report.lines, report.skipped_lines) == (10, 3)


# ---------------------------------------------------------------------------
# Examples: redacted, truncated, capped
# ---------------------------------------------------------------------------
def test_examples_are_redacted_and_truncated(gate_env, tmp_path) -> None:
    tail = "TAIL-OF-A-VERY-LONG-ARGUMENT"
    command = (
        f"git push --force https://user:{SECRET}@example.com/repo.git "
        f"--password hunter2 {'x' * 300}{tail}"
    )
    transcript = write_transcript(tmp_path / "t.jsonl", bash("c1", command))
    report = replay([transcript], env=gate_env, windows=False)
    (line,) = report.examples["builtin.git.force-push"]
    assert line.startswith("Bash: git push --force https://[REDACTED]@")
    assert len(line) <= 160
    for output in (render(report), json.dumps(report.as_dict())):
        assert SECRET not in output
        assert "hunter2" not in output
        assert tail not in output
        assert "x" * 60 not in output


def test_examples_are_limited_per_rule_and_distinct(gate_env, tmp_path) -> None:
    lines = [bash(f"c{i}", f"git push --force origin b{i % 5}") for i in range(10)]
    transcript = write_transcript(tmp_path / "t.jsonl", *lines)
    report = replay([transcript], env=gate_env, windows=False, examples=2)
    assert report.rules["builtin.git.force-push"] == 10
    assert report.examples["builtin.git.force-push"] == [
        "Bash: git push --force origin b0",
        "Bash: git push --force origin b1",
    ]
    none = replay([transcript], env=gate_env, windows=False, examples=0)
    assert none.examples["builtin.git.force-push"] == []
    assert "e.g." not in render(none)


def test_example_of_an_unparsed_command_names_only_the_reason(gate_env, tmp_path):
    write_ledger(
        Path(gate_env["EMBER_LEDGER"]),
        rule("dyn", when={"type": "dynamic_shell"}, effect="ask"),
    )
    transcript = write_transcript(tmp_path / "t.jsonl", bash("c1", "echo 'open quote"))
    report = replay([transcript], env=gate_env, windows=False)
    assert report.examples["dyn"] == ["Bash: (dynamic shell: parse_error)"]


def test_non_ascii_arguments_are_escaped(gate_env, tmp_path) -> None:
    transcript = write_transcript(
        tmp_path / "t.jsonl", bash("c1", "git push --force origin café")
    )
    report = replay([transcript], env=gate_env, windows=False)
    assert report.examples["builtin.git.force-push"] == [
        "Bash: git push --force origin caf\\xe9"
    ]


# ---------------------------------------------------------------------------
# The active ledger, history rules
# ---------------------------------------------------------------------------
TESTS_FIRST = rule(
    "tests-first",
    text="Run the tests before pushing.",
    effect="ask",
    when={
        "type": "all",
        "of": [
            {"type": "command", "program": "git", "subcommand": ["push"]},
            {
                "type": "not_preceded_by",
                "predicate": {"type": "command", "program": "pytest"},
            },
        ],
    },
)


def test_history_rules_see_earlier_calls_of_the_same_session(gate_env, tmp_path):
    write_ledger(Path(gate_env["EMBER_LEDGER"]), TESTS_FIRST)
    transcript = write_transcript(
        tmp_path / "t.jsonl",
        bash("a1", "git push", session="careless"),
        bash("b1", "pytest -q", session="careful"),
        bash("b2", "git push", session="careful"),
        bash("a2", "git push origin main", session="careless"),
    )
    report = replay([transcript], env=gate_env, windows=False)
    assert report.rules["tests-first"] == 2
    assert report.examples["tests-first"] == [
        "Bash: git push",
        "Bash: git push origin main",
    ]


def test_time_windows_use_the_transcript_timestamps(gate_env, tmp_path) -> None:
    burst = rule(
        "burst",
        effect="ask",
        when={
            "type": "count_exceeds",
            "predicate": {"type": "command", "program": "npm"},
            "max": 1,
            "within_seconds": 60,
        },
    )
    write_ledger(Path(gate_env["EMBER_LEDGER"]), burst)
    transcript = write_transcript(
        tmp_path / "t.jsonl",
        bash("c1", "npm publish", at="2026-09-30T10:00:00Z"),
        bash("c2", "npm publish", at="2026-09-30T10:00:10Z"),
        bash("c3", "npm publish", at="2026-09-30T10:00:20Z"),
        bash("c4", "npm publish", at="2026-09-30T10:30:00Z"),
        bash("c5", "npm publish", at=None),
    )
    report = replay([transcript], env=gate_env, windows=False)
    # c3 has two earlier calls inside its minute; c4 has none; c5 reuses
    # c4's time and so sees c4 only.
    assert report.rules["burst"] == 1


def test_an_unconfirmed_rule_is_counted_as_a_warning(gate_env, tmp_path) -> None:
    write_ledger(Path(gate_env["EMBER_LEDGER"]), rule("mine", confirmed=False))
    transcript = write_transcript(tmp_path / "t.jsonl", bash("c1", "git push --force"))
    report = replay([transcript], env=gate_env, windows=False)
    assert report.effects["mine"] == "warn"
    assert dict(report.decisions) == {"ask": 1}


def test_a_broken_ledger_stops_the_replay(gate_env) -> None:
    Path(gate_env["EMBER_LEDGER"]).write_text("{broken", encoding="utf-8")
    with pytest.raises(LedgerError, match="not valid JSON"):
        replay([SESSION_A], env=gate_env)


def test_a_call_the_gate_cannot_read_is_counted_as_an_error(gate_env, tmp_path):
    transcript = write_transcript(
        tmp_path / "t.jsonl", tool_line("c1", "", {"command": "ls"}), bash("c2", "ls")
    )
    report = replay([transcript], env=gate_env, windows=False)
    assert (report.calls, report.errors) == (2, 1)
    assert dict(report.decisions) == {"none": 1}


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------
@pytest.fixture
def cli_env(gate_env: dict[str, str], monkeypatch, tmp_path):
    for name in ("EMBER_GATE_MODE", "EMBER_GATE_BUILTIN"):
        monkeypatch.delenv(name, raising=False)
    for name, value in gate_env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.chdir(tmp_path)
    return gate_env


def test_cli_prints_aggregates_only(cli_env, capsys) -> None:
    assert cli.main(["replay", SESSION_A]) == 0
    out = capsys.readouterr().out
    assert "files: 1   lines: 16 (2 skipped)   tool calls: 8   gate errors: 0" in out
    assert "        5  Bash" in out
    assert "        1  builtin.delete.protected [deny]" in out
    assert "e.g. Bash: git push --force origin main" in out
    assert "Show the working tree status" not in out
    assert not Path(cli_env["EMBER_HOME"]).exists()


def test_cli_json_and_example_limit(cli_env, capsys) -> None:
    assert cli.main(["replay", "--json", "--examples", "0", SESSION_A]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["calls"] == 8
    assert report["decisions"] == {"none": 4, "ask": 3, "deny": 1}
    assert report["rules"]["builtin.shell.download-pipe"] == {
        "effect": "ask",
        "count": 1,
        "examples": [],
    }


def test_cli_reports_a_missing_transcript(cli_env, capsys) -> None:
    assert cli.main(["replay", "no-such-dir"]) == 1
    assert "no such transcript" in capsys.readouterr().err
