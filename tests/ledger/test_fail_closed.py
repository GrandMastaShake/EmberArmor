"""Ways the gate used to approve silently in enforce mode.

Unparsed shell input, unreadable configuration, a broken or hostile project
ledger, a shell call without a command string.  Every test keeps the gate
inside ``tmp_path``.  Command strings are data; nothing runs them.  The only
process started is the gate's own hook.
"""

from __future__ import annotations

import codecs
import json
from pathlib import Path
from typing import Any

import pytest

from ember_armor.ledger import config, store
from ember_armor.ledger.audit import AuditLog
from ember_armor.ledger.gate import check
from ember_armor.ledger.model import LedgerError
from tests.ledger.helpers import make_call, rule, run_gate, write_ledger

HOOK = "ember_armor.ledger.hook"
PROTECTED = "builtin.delete.protected"


def home_env(tmp_path: Path, **extra: str) -> dict[str, str]:
    """Environment with an Ember home under ``tmp_path`` and no override."""
    env = {
        "EMBER_HOME": str(tmp_path / "home"),
        "EMBER_LEDGER": "",
        "HOME": "/home/dev",
    }
    return {**env, **extra}


def write_config(env: dict[str, str], data: bytes) -> None:
    home = Path(env["EMBER_HOME"])
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.json").write_bytes(data)


def run(
    command: Any, env: dict[str, str], *, tool: str = "Bash", cwd: str = "/work/app"
):
    return check(make_call(tool, command, cwd=cwd), env=env, windows=False)


def hook(
    env: dict[str, str], stdin: str | bytes
) -> tuple[dict[str, Any] | None, bytes]:
    done = run_gate([], env, stdin=stdin, module=HOOK)
    assert done.returncode == 0
    assert b'"allow"' not in done.stdout
    output = json.loads(done.stdout)["hookSpecificOutput"] if done.stdout else None
    return output, done.stderr


def entries(env: dict[str, str]) -> list[dict[str, Any]]:
    return list(AuditLog(Path(env["EMBER_HOME"]) / "audit").entries())


# ---------------------------------------------------------------------------
# Shell input the parser cannot read
# ---------------------------------------------------------------------------
UNREADABLE = [
    ("Bash", "rm -rf 'oops"),
    ("Bash", "echo ok; cat <("),
    pytest.param("Bash", "true; " * 2001 + "rm -rf src", id="too many commands"),
    pytest.param("Bash", "echo " + "a" * 200_050 + "\nrm -rf src", id="too long"),
    ("PowerShell", 'Write-Output "unterminated'),
    ("PowerShell", "powershell -enc %%%"),
]


@pytest.mark.parametrize(("tool", "command"), UNREADABLE)
def test_unparsed_shell_input_asks_in_enforce_mode(gate_env, tool, command) -> None:
    result = run(command, {**gate_env, "EMBER_GATE_MODE": "enforce"}, tool=tool)
    assert result.decision.effect == "ask"
    assert result.blocking
    assert "builtin.shell.unreadable" in [fired.id for fired in result.decision.fired]


AFTER_VALID_SYNTAX = [
    ("Bash", "files=(a b c)\nrm -rf ~"),
    ("Bash", "declare -a d=(x y); rm -rf /"),
    ("Bash", "shopt -s extglob; ls !(keep); rm -rf ~"),
    (
        "PowerShell",
        "$o = [pscustomobject]@{ A = 1 }\nRemove-Item -Recurse -Force $HOME",
    ),
    ("PowerShell", "$o = [ordered]@{ A = 1 }; Remove-Item -Recurse -Force $HOME"),
]


@pytest.mark.parametrize(("tool", "command"), AFTER_VALID_SYNTAX)
def test_a_delete_after_valid_syntax_is_still_denied(gate_env, tool, command) -> None:
    result = run(command, {**gate_env, "EMBER_GATE_MODE": "enforce"}, tool=tool)
    assert result.decision.effect == "deny"
    assert result.decision.fired[0].id == PROTECTED


BAD_SHELL_INPUTS = [
    {"command": ["rm", "-rf", "/"]},
    {"command": None},
    {"command": 5},
    {},
    {"cmd": "rm -rf /"},
]


@pytest.mark.parametrize("tool_input", BAD_SHELL_INPUTS)
@pytest.mark.parametrize("tool", ["Bash", "PowerShell"])
def test_a_shell_call_the_gate_cannot_read_is_a_gate_failure(
    gate_env, tool: str, tool_input: dict[str, Any]
) -> None:
    result = run(tool_input, {**gate_env, "EMBER_GATE_MODE": "enforce"}, tool=tool)
    assert result.decision.effect == "ask"
    assert "no command string" in result.decision.error
    assert run(tool_input, gate_env, tool=tool).decision.effect == "none"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ENFORCE = '{"mode": "enforce"}'
UNREADABLE_CONFIGS = [
    ENFORCE.encode("utf-16"),
    codecs.BOM_UTF16_LE + ENFORCE.encode("utf-16-le"),
    b"\xff\xfe\x00garbage",
    b'{"mode": "enforce"',
    b'{"Mode": "enforce"}',
    b'{"mode": 1}',
    b'{"mode": false}',
    b'{"mode": "enforce", "builtin": "no"}',
    b'{"disposable": "**/out"}',
    pytest.param(b"[" * 100_000, id="nested too deep"),
]


@pytest.mark.parametrize("data", UNREADABLE_CONFIGS)
def test_a_configuration_nobody_can_read_is_treated_as_enforce(tmp_path, data) -> None:
    env = home_env(tmp_path)
    write_config(env, data)
    with pytest.raises(config.ConfigError):
        config.read_config(env)
    result = run("git status", env)
    assert (result.mode, result.decision.effect) == ("enforce", "ask")
    assert result.decision.error
    # The built-in rules still apply on top of the failure.
    assert run("rm -rf /", env).decision.effect == "deny"


def test_the_hook_asks_when_the_configuration_is_utf16(tmp_path) -> None:
    env = home_env(tmp_path)
    write_config(env, ENFORCE.encode("utf-16"))
    output, stderr = hook(env, json.dumps(make_call("Bash", "git status")))
    assert output is not None
    assert output["permissionDecision"] == "ask"
    assert b"gate failure" in stderr
    assert [e["decision"] for e in entries(env)] == ["ask"]


def test_a_byte_order_mark_is_accepted(tmp_path) -> None:
    env = home_env(tmp_path)
    write_config(env, codecs.BOM_UTF8 + ENFORCE.encode())
    assert config.gate_mode(env) == "enforce"
    user = Path(env["EMBER_HOME"]) / "ledger.json"
    document = {"version": 1, "rules": [rule("with-bom")]}
    user.write_bytes(codecs.BOM_UTF8 + json.dumps(document).encode())
    result = run("git status", env)
    assert (result.decision.effect, result.decision.error) == ("none", None)
    assert run("git push --force", env).decision.fired[0].id == "with-bom"


def test_disposable_directories_come_from_the_user_configuration_only(tmp_path) -> None:
    env = home_env(tmp_path, EMBER_GATE_MODE="enforce")
    assert run("rm -rf out bin", env).decision.effect == "ask"
    write_config(env, b'{"disposable": ["**/out", "**/bin"]}')
    assert config.disposable_patterns(env) == ("**/out", "**/bin")
    assert run("rm -rf out bin", env).decision.effect == "none"
    assert run("rm -rf out src", env).decision.effect == "ask"
    assert run("rm -rf /", env).decision.effect == "deny"


def test_deeply_nested_hook_input_is_a_gate_failure_not_silence(tmp_path) -> None:
    env = home_env(tmp_path)
    write_config(env, ENFORCE.encode())
    deep = "[" * 100_000 + "]" * 100_000
    stdin = '{"tool_name": "Bash", "tool_input": {"command": "rm -rf /", "x": '
    stdin += deep + "}}"
    output, stderr = hook(env, stdin)
    assert output is not None
    assert output["permissionDecision"] == "ask"
    assert b"malformed hook input" in stderr
    assert [e["decision"] for e in entries(env)] == ["ask"]


# ---------------------------------------------------------------------------
# Ledger files
# ---------------------------------------------------------------------------
def test_an_explicit_ledger_that_does_not_exist_is_an_error(tmp_path) -> None:
    env = home_env(tmp_path, EMBER_LEDGER=str(tmp_path / "typo-ledger.json"))
    write_ledger(tmp_path / "home" / "ledger.json", rule("no-push"))
    with pytest.raises(LedgerError, match="does not exist"):
        store.load_all("/work/app", env)
    result = run("git push --force", {**env, "EMBER_GATE_MODE": "enforce"})
    assert result.decision.effect == "ask"
    assert "does not exist" in result.decision.error
    # The default user ledger may be absent.
    assert store.load_all("/work/app", home_env(tmp_path / "other"))


BROKEN_PROJECT_LEDGERS = [
    b"{ not json",
    codecs.BOM_UTF16_LE + '{"version": 1, "rules": []}'.encode("utf-16-le"),
    b'{"version": 1, "rules": [{"id": "x"}]}',
    b'{"version": 1, "rules": [], "extra": true}',
    pytest.param(b"[" * 100_000, id="nested too deep"),
]


@pytest.mark.parametrize("data", BROKEN_PROJECT_LEDGERS)
@pytest.mark.parametrize("mode", ["observe", "enforce"])
def test_a_broken_project_ledger_only_adds_an_ask(tmp_path, data, mode) -> None:
    env = home_env(tmp_path, EMBER_GATE_MODE=mode)
    write_ledger(tmp_path / "home" / "ledger.json", rule("no-push"))
    project = tmp_path / "repo"
    (project / ".ember").mkdir(parents=True)
    (project / ".ember" / "ledger.json").write_bytes(data)

    denied = run("rm -rf /", env, cwd=str(project))
    assert denied.decision.effect == "deny"
    assert denied.decision.fired[0].id == PROTECTED
    assert denied.decision.error
    pushed = run("git push --force", env, cwd=str(project))
    assert pushed.decision.effect == "deny"
    assert "no-push" in [fired.id for fired in pushed.decision.fired]
    harmless = run("git status", env, cwd=str(project))
    assert harmless.decision.effect == ("ask" if mode == "enforce" else "none")
    # Observe mode still records what would have been denied.
    assert [e["decision"] for e in entries(env)][:2] == ["deny", "deny"]
