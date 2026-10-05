"""Reminders as the command line shows them: check, log, hook and install.

The gate's own CLI is the only process started.  Command strings are data
for the gate; nothing executes them.  Everything lives under ``tmp_path``.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from ember_armor.ledger import cli, store
from ember_armor.ledger.audit import AuditLog
from ember_armor.ledger.gate import LOGGED_UNCONFIRMED, REMINDED
from ember_armor.ledger.remind import CLOSING
from tests.ledger.helpers import make_call, rule, run_gate, write_ledger

HOOK = "ember_armor.ledger.hook"
DEPLOY = {"type": "command", "program": "deploy-site"}
TEXT = "Never deploy the site on a Friday."
SOURCE = "the owner, in the kickoff notes"
STANDING = f'EmberArmor reminder, rule standing: "{TEXT}" (source: {SOURCE}).'
SESSION = ["--event", "session-start"]


@pytest.fixture
def world(tmp_path: Path) -> dict[str, Any]:
    """An Ember home with one confirmed rule, and a repository with a ledger."""
    home, repo = tmp_path / "home", tmp_path / "repo"
    standing = rule("standing", effect="warn", when=DEPLOY, text=TEXT, source=SOURCE)
    write_ledger(home / "ledger.json", standing)
    write_ledger(repo / ".ember" / "ledger.json")
    return {
        "env": {"EMBER_HOME": str(home), "HOME": "/home/dev"},
        "user": home / "ledger.json",
        "project": repo / ".ember" / "ledger.json",
        "repo": repo,
        "standing": standing,
    }


def deploy(world: dict[str, Any], mode: str) -> subprocess.CompletedProcess[bytes]:
    """One ``deploy-site`` call of session ``s-1`` through the real hook."""
    call = make_call("Bash", "deploy-site --now", cwd=str(world["repo"]), session="s-1")
    return run_gate([], world["env"], stdin=json.dumps(call), mode=mode, module=HOOK)


def start(world: dict[str, Any]) -> str:
    return json.dumps(
        {
            "session_id": "s-1",
            "cwd": str(world["repo"]),
            "hook_event_name": "SessionStart",
            "source": "compact",
        }
    )


def summary_of(stdout: bytes) -> str:
    output = json.loads(stdout)
    assert set(output) == {"hookSpecificOutput"}
    specific = output["hookSpecificOutput"]
    assert set(specific) == {"hookEventName", "additionalContext"}
    assert specific["hookEventName"] == "SessionStart"
    return specific["additionalContext"]


def entries(world: dict[str, Any]) -> list[dict[str, Any]]:
    return list(AuditLog(Path(world["env"]["EMBER_HOME"]) / "audit").entries())


# ---------------------------------------------------------------------------
# ember-gate check
# ---------------------------------------------------------------------------
def test_check_shows_what_each_mode_would_send(world) -> None:
    draft = rule("draft", effect="deny", when=DEPLOY, confirmed=False)
    write_ledger(world["user"], world["standing"], draft)
    args = ["check", "deploy-site --now", "--cwd", str(world["repo"])]
    done = run_gate(args, world["env"])
    assert done.returncode == 0, done.stderr
    out = done.stdout.decode().replace("\r\n", "\n")
    assert out.startswith("decision: warn (mode: observe)\n")
    assert (
        "  to the agent, by mode:\n"
        "    observe: nothing is printed\n"
        "    remind: a reminder quoting standing; logged only: draft (not confirmed)\n"
        "    enforce: a reminder quoting standing; logged only: draft (not confirmed)\n"
        "  reminder text:\n"
        f"    {STANDING}\n"
        f"    {CLOSING}\n"
    ) in out
    done = run_gate([*args, "--json"], world["env"], mode="remind")
    report = json.loads(done.stdout)
    assert report["mode"] == "remind"
    assert report["reminder"] == f"{STANDING}\n{CLOSING}"
    assert report["delivery"] == {"standing": REMINDED, "draft": LOGGED_UNCONFIRMED}
    assert {m: v["prints"] for m, v in report["by_mode"].items()} == {
        "observe": "nothing",
        "remind": "reminder",
        "enforce": "reminder",
    }
    assert report["by_mode"]["observe"]["reminder"] is None
    assert report["by_mode"]["enforce"]["reminder"] == report["reminder"]
    # A dry run writes nothing.
    assert entries(world) == []


def test_check_tells_a_decision_from_a_reminder(world) -> None:
    args = ["check", "git push --force", "--cwd", str(world["repo"])]
    out = run_gate(args, world["env"]).stdout.decode()
    assert "    observe: nothing is printed" in out
    assert "    remind: a reminder quoting builtin.git.force-push" in out
    assert "    enforce: the host is told to ask, quoting builtin.git.force-push" in out
    report = json.loads(run_gate([*args, "--json"], world["env"]).stdout)
    assert {m: v["prints"] for m, v in report["by_mode"].items()} == {
        "observe": "nothing",
        "remind": "reminder",
        "enforce": "decision",
    }
    # A call no rule fires on has no table.
    args = ["check", "git status", "--cwd", str(world["repo"])]
    done = run_gate(args, world["env"])
    assert done.stdout.decode().strip() == "decision: none (mode: observe)"
    assert "by_mode" not in json.loads(run_gate([*args, "--json"], world["env"]).stdout)


def test_check_with_a_session_says_when_a_rule_was_reminded_recently(world) -> None:
    deploy(world, "remind")
    args = ["check", "deploy-site", "--cwd", str(world["repo"]), "--session"]
    out = run_gate([*args, "s-1"], world["env"], mode="remind").stdout.decode()
    assert (
        "    remind: nothing is printed; logged only: standing "
        "(reminded inside the interval)"
    ) in out
    assert "reminder text:" not in out
    fresh = run_gate([*args, "s-other"], world["env"], mode="remind").stdout.decode()
    assert "    remind: a reminder quoting standing" in fresh


def test_check_does_not_take_words_from_an_unconfirmed_rule_into_a_reminder(
    world,
) -> None:
    theirs = rule("theirs", when=DEPLOY, text="UNVOUCHED words.")
    write_ledger(world["project"], theirs)
    args = ["check", "deploy-site", "--cwd", str(world["repo"]), "--json"]
    report = json.loads(run_gate(args, world["env"], mode="remind").stdout)
    assert report["delivery"] == {"standing": REMINDED, "theirs": LOGGED_UNCONFIRMED}
    assert "UNVOUCHED" not in report["reminder"]
    store.confirm_project_rule(world["env"], world["project"], "theirs")
    report = json.loads(run_gate(args, world["env"], mode="remind").stdout)
    assert report["delivery"] == {"theirs": REMINDED, "standing": REMINDED}
    assert '"UNVOUCHED words."' in report["reminder"]


# ---------------------------------------------------------------------------
# ember-gate log
# ---------------------------------------------------------------------------
def test_log_tail_and_stats_show_what_was_reminded(world) -> None:
    deploy(world, "remind")
    deploy(world, "remind")
    deploy(world, "observe")
    rows = run_gate(["log", "tail"], world["env"]).stdout.decode().splitlines()
    assert rows[0].endswith("Bash  standing  reminded: standing")
    assert rows[1].endswith("Bash  standing  reminded: -")
    assert rows[2].endswith("Bash  standing")
    stats = json.loads(run_gate(["log", "stats", "--json"], world["env"]).stdout)
    assert stats["rule"] == {"standing": 3}
    assert stats["reminded"] == {"standing": 1}
    assert stats["event"] == {}
    assert run_gate(["log", "verify"], world["env"]).returncode == 0


def test_log_tail_and_stats_show_a_session_start(world) -> None:
    run_gate(SESSION, world["env"], stdin=start(world), mode="remind", module=HOOK)
    deploy(world, "remind")
    rows = run_gate(["log", "tail"], world["env"]).stdout.decode().splitlines()
    assert rows[0].endswith("session-start  remind   compact  announced: standing")
    assert rows[1].endswith("Bash  standing  reminded: standing")
    stats = json.loads(run_gate(["log", "stats", "--json"], world["env"]).stdout)
    assert stats["entries"] == 2
    assert stats["event"] == {"session-start": 1}
    assert stats["decision"] == {"warn": 1}
    assert stats["mode"] == {"remind": 1}


# ---------------------------------------------------------------------------
# ember-gate hook --event, and the printed settings snippet
# ---------------------------------------------------------------------------
def test_the_summary_is_the_same_through_ember_gate_hook(world) -> None:
    done = run_gate(["hook", *SESSION], world["env"], stdin=start(world), mode="remind")
    assert (done.returncode, done.stderr) == (0, b"")
    assert summary_of(done.stdout) == f"{STANDING}\n{CLOSING}"
    # Without the option the same input is a tool call the gate cannot read.
    done = run_gate(["hook"], world["env"], stdin=start(world), mode="remind")
    assert done.stdout == b""
    assert b"gate failure" in done.stderr


def test_ember_gate_hook_reminds_like_the_module(world) -> None:
    call = make_call("Bash", "deploy-site", cwd=str(world["repo"]), session="")
    for args in (["hook"], ["hook", "--event", "pre-tool-use"]):
        done = run_gate(args, world["env"], stdin=json.dumps(call), mode="remind")
        assert (done.returncode, done.stderr) == (0, b"")
        specific = json.loads(done.stdout)["hookSpecificOutput"]
        assert specific == {
            "hookEventName": "PreToolUse",
            "additionalContext": f"{STANDING}\n{CLOSING}",
        }


@pytest.mark.parametrize(
    "arguments", [["--event", "bogus"], ["--bogus"], ["extra"], ["--event"]]
)
def test_ember_gate_hook_never_ends_in_a_usage_error(world, arguments) -> None:
    # Arguments nobody knows are a gate failure: exit status 2 would block
    # the call on the host.
    for mode in ("observe", "remind"):
        done = run_gate(["hook", *arguments], world["env"], stdin="{}", mode=mode)
        assert (done.returncode, done.stdout) == (0, b"")
        assert b"unknown hook arguments" in done.stderr
    done = run_gate(["hook", *arguments], world["env"], stdin="{}", mode="enforce")
    assert done.returncode == 0
    specific = json.loads(done.stdout)["hookSpecificOutput"]
    assert specific["permissionDecision"] == "ask"
    assert "unknown hook arguments" in specific["permissionDecisionReason"]


def test_ember_gate_hook_help_is_still_help(world) -> None:
    done = run_gate(["hook", "--help"], world["env"])
    assert done.returncode == 0
    assert b"session-start" in done.stdout


def test_install_prints_the_session_start_entry_next_to_the_other(capsys) -> None:
    assert cli.main(["install", "claude-code", "--print"]) == 0
    hooks = json.loads(capsys.readouterr().out)["hooks"]
    assert set(hooks) == {"PreToolUse", "SessionStart"}
    (pre,) = hooks["PreToolUse"]
    (entry,) = hooks["SessionStart"]
    assert "matcher" not in entry
    (command,) = entry["hooks"]
    assert command["type"] == "command"
    assert command["command"] == pre["hooks"][0]["command"]
    assert command["args"] == [
        "-I",
        "-m",
        "ember_armor.ledger.hook",
        "--event",
        "session-start",
    ]


def test_the_printed_session_start_hook_runs_as_printed(world, capsys) -> None:
    assert cli.main(["install", "claude-code", "--print"]) == 0
    hooks = json.loads(capsys.readouterr().out)["hooks"]
    (command,) = hooks["SessionStart"][0]["hooks"]
    env = {k: v for k, v in os.environ.items() if not k.startswith("EMBER_")}
    env.update(world["env"], EMBER_GATE_MODE="remind")
    done = subprocess.run(
        [command["command"], *command["args"]],
        input=start(world).encode(),
        capture_output=True,
        cwd=world["repo"],
        env=env,
        timeout=60,
        check=False,
    )
    assert (done.returncode, done.stderr) == (0, b"")
    assert summary_of(done.stdout) == f"{STANDING}\n{CLOSING}"
