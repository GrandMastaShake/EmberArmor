"""Shared helpers for the constraint-ledger tests.

Command strings in these tests (``rm -rf /`` and friends) are *data* handed to
the parser or to the gate.  Nothing here ever executes them.  The only
subprocesses started are the gate's own CLI and hook, always with
``EMBER_HOME`` pointing into a temporary directory.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from ember_armor.ledger.facts import Facts, extract

POSIX_ENV = {"HOME": "/home/dev", "TMPDIR": "/tmp"}
WINDOWS_ENV = {
    "USERPROFILE": r"C:\Users\dev",
    "TEMP": r"C:\Users\dev\AppData\Local\Temp",
}
POSIX_CWD = "/work/app"
WINDOWS_CWD = r"C:\work\app"


def make_call(
    tool: str, payload: Any, *, cwd: str = POSIX_CWD, session: str = "s1"
) -> dict[str, Any]:
    """A tool call in Claude Code PreToolUse shape."""
    tool_input = payload if isinstance(payload, dict) else {"command": payload}
    return {
        "session_id": session,
        "cwd": cwd,
        "tool_name": tool,
        "tool_input": tool_input,
    }


def facts_for(
    tool: str, payload: Any, platform: str = "posix", *, session: str = "s1"
) -> Facts:
    """Facts for a call under a fixed, platform-independent environment."""
    windows = platform == "windows"
    call = make_call(
        tool, payload, cwd=WINDOWS_CWD if windows else POSIX_CWD, session=session
    )
    return extract(call, windows=windows, env=WINDOWS_ENV if windows else POSIX_ENV)


def write_ledger(path: Path, *rules: dict[str, Any]) -> None:
    """Write a version-1 ledger with the given rules."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"version": 1, "rules": list(rules)}), encoding="utf-8")


def rule(rule_id: str = "r1", **overrides: Any) -> dict[str, Any]:
    """A valid, confirmed rule; keyword arguments replace fields."""
    base: dict[str, Any] = {
        "id": rule_id,
        "text": "Never force-push here.",
        "source": "test suite",
        "effect": "deny",
        "when": {
            "type": "command",
            "program": "git",
            "subcommand": ["push"],
            "flags_any": ["--force"],
        },
        "confirmed": True,
    }
    base.update(overrides)
    return base


def run_gate(
    args: list[str],
    env: dict[str, str],
    *,
    stdin: str | bytes = "",
    mode: str | None = None,
    module: str = "ember_armor.ledger.cli",
) -> subprocess.CompletedProcess[bytes]:
    """Run the gate's own CLI (or hook module) in a fresh interpreter."""
    full_env = {**os.environ, **env}
    full_env.pop("EMBER_GATE_MODE", None)
    full_env.pop("EMBER_GATE_BUILTIN", None)
    if mode is not None:
        full_env["EMBER_GATE_MODE"] = mode
    data = stdin.encode("utf-8") if isinstance(stdin, str) else stdin
    return subprocess.run(
        [sys.executable, "-m", module, *args],
        input=data,
        capture_output=True,
        env=full_env,
        timeout=60,
        check=False,
    )
