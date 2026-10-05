"""Tools that carry a shell command are parsed like the native shell tools.

``shell_tools`` in ``config.json`` maps a tool name or glob to the shell that
reads its command and the input field that holds it.  Command strings are
data; the only processes started are the gate's own hook.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ember_armor.ledger import config
from ember_armor.ledger.audit import summarise
from ember_armor.ledger.builtin import builtin_rules
from ember_armor.ledger.engine import evaluate
from ember_armor.ledger.facts import (
    SHELL_TOOLS,
    ShellTool,
    extract,
    shell_tool,
    shell_tools_from,
)
from ember_armor.ledger.gate import check
from ember_armor.ledger.model import parse_ledger
from tests.ledger.helpers import (
    POSIX_ENV,
    WINDOWS_ENV,
    make_call,
    rule,
    run_gate,
    write_ledger,
)

SSH = {"mcp__ssh__*": ShellTool("bash", "script", "workdir")}


def facts(tool: str, payload: dict[str, Any], *, windows: bool = False, **kwargs: Any):
    env = WINDOWS_ENV if windows else POSIX_ENV
    cwd = "C:\\work\\app" if windows else "/work/app"
    call = make_call(tool, payload, cwd=cwd)
    return extract(call, windows=windows, env=env, **kwargs)


def effect(found: Any) -> str:
    return evaluate(builtin_rules(), found).effect


# ---------------------------------------------------------------------------
# defaults
# ---------------------------------------------------------------------------
def test_default_shell_tools() -> None:
    assert set(SHELL_TOOLS) == {
        "Bash",
        "PowerShell",
        "mcp__Windows-MCP__PowerShell",
        "mcp__terminal__run_in_terminal",
    }
    assert shell_tool("bash") == ShellTool("bash")
    assert shell_tool("MCP__WINDOWS-MCP__POWERSHELL") == ShellTool("powershell")
    assert shell_tool("mcp__terminal__read_terminal") is None
    assert shell_tool("mcp__github__list_issues") is None


def test_windows_mcp_powershell_is_parsed() -> None:
    found = facts("mcp__Windows-MCP__PowerShell", {"command": "git reset --hard"})
    assert found.shell == "powershell"
    assert effect(found) == "ask"
    removal = {"command": "Remove-Item -Recurse -Force C:\\Users\\sam"}
    assert (
        effect(facts("mcp__Windows-MCP__PowerShell", removal, windows=True)) == "deny"
    )


def test_the_terminal_tool_uses_the_platform_shell_and_its_own_directory() -> None:
    tool = "mcp__terminal__run_in_terminal"
    windows = facts(tool, {"command": "Remove-Item -Recurse src"}, windows=True)
    assert (windows.shell, effect(windows)) == ("powershell", "ask")
    posix = facts(tool, {"command": "rm -rf src", "title": "clean"})
    assert (posix.shell, effect(posix)) == ("bash", "ask")
    elsewhere = facts(tool, {"command": "rm -rf .git", "cwd": "/srv/other"})
    assert [p.path for p in elsewhere.paths] == ["/srv/other/.git"]
    assert elsewhere.cwd == "/work/app"
    relative = facts(tool, {"command": "rm -rf x", "cwd": "sub"})
    assert [p.path for p in relative.paths] == ["/work/app/sub/x"]


def test_a_shell_tool_without_its_command_field_is_a_gate_failure(gate_env) -> None:
    call = make_call("mcp__terminal__run_in_terminal", {"title": "x"})
    result = check(call, env={**gate_env, "EMBER_GATE_MODE": "enforce"}, record=False)
    assert result.decision.effect == "ask"
    assert "no command string (field 'command')" in (result.decision.error or "")


# ---------------------------------------------------------------------------
# configured tools
# ---------------------------------------------------------------------------
def test_a_configured_tool_is_parsed_with_its_field_and_directory() -> None:
    payload = {"script": "cd /srv/app && git push --force", "workdir": "/srv"}
    found = facts("mcp__ssh__exec", payload, shell_tools=SSH)
    assert found.shell == "bash"
    assert [list(c.argv) for c in found.commands][-1] == ["git", "push", "--force"]
    assert effect(found) == "ask"
    # Without the entry the same call is a generic tool: nothing is parsed.
    assert effect(facts("mcp__ssh__exec", payload)) == "none"
    # The user's entry wins over a default of the same name.
    custom = {"bash": ShellTool("powershell")}
    assert facts("Bash", {"command": "ls"}, shell_tools=custom).shell == "powershell"


def test_the_raw_command_of_a_configured_tool_is_not_logged() -> None:
    payload = {"script": "curl -H 'Authorization: Bearer abcdefgh12345678' x"}
    summary = summarise(facts("mcp__ssh__exec", payload, shell_tools=SSH))
    assert "args" not in summary
    assert "abcdefgh12345678" not in json.dumps(summary)
    assert summary["commands"][0]["argv"][0] == "curl"


def write_config(env: dict[str, str], document: Any) -> None:
    home = Path(env["EMBER_HOME"])
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.json").write_text(json.dumps(document), encoding="utf-8")


def test_shell_tools_come_from_the_configuration(gate_env) -> None:
    entry = {"shell": "bash", "field": "script"}
    write_config(gate_env, {"mode": "enforce", "shell_tools": {"mcp__ssh__*": entry}})
    assert shell_tools_from(config.shell_tools(gate_env)) == {
        "mcp__ssh__*": ShellTool("bash", "script")
    }
    call = make_call("mcp__ssh__exec", {"script": "git reset --hard"})
    result = check(call, env=gate_env, record=False)
    assert [fired.id for fired in result.decision.fired] == ["builtin.git.reset-hard"]
    other = make_call("mcp__db__query", {"script": "git reset --hard"})
    assert check(other, env=gate_env, record=False).decision.effect == "none"


BAD_SHELL_TOOLS = [
    ["Bash"],
    {"mcp__x": "bash"},
    {"mcp__x": {}},
    {"mcp__x": {"shell": "fish"}},
    {"mcp__x": {"shell": "bash", "field": ""}},
    {"mcp__x": {"shell": "bash", "field": 3}},
    {"mcp__x": {"shell": "bash", "input": "command"}},
    {"": {"shell": "bash"}},
]


@pytest.mark.parametrize("value", BAD_SHELL_TOOLS)
def test_a_malformed_shell_tools_setting_is_an_error(gate_env, value: Any) -> None:
    write_config(gate_env, {"mode": "enforce", "shell_tools": value})
    with pytest.raises(config.ConfigError):
        config.shell_tools(gate_env)
    result = check(make_call("Bash", "git status"), env=gate_env, record=False)
    assert (result.mode, result.decision.effect) == ("enforce", "ask")
    assert "shell_tools" in (result.decision.error or "")
    # The defaults still apply on top of the failure.
    removal = make_call("Bash", "rm -rf /")
    assert check(removal, env=gate_env, record=False).decision.effect == "deny"


def test_the_hook_parses_a_configured_tool(gate_env, tmp_path: Path) -> None:
    entry = {"shell": "powershell", "field": "code", "cwd": "dir"}
    write_config(gate_env, {"shell_tools": {"mcp__remote__run": entry}})
    payload = {"code": "Remove-Item -Recurse -Force .git", "dir": str(tmp_path)}
    call = json.dumps(make_call("mcp__remote__run", payload, cwd=str(tmp_path)))
    done = run_gate(
        [], gate_env, stdin=call, mode="enforce", module="ember_armor.ledger.hook"
    )
    specific = json.loads(done.stdout)["hookSpecificOutput"]
    assert specific["permissionDecision"] == "deny"
    assert "builtin.delete.git-dir" in specific["permissionDecisionReason"]


def test_replay_parses_configured_tools(gate_env, tmp_path: Path) -> None:
    from ember_armor.ledger.replay import replay

    write_config(
        gate_env, {"shell_tools": {"mcp__ssh__exec": {"shell": "bash", "field": "s"}}}
    )
    block = {"type": "tool_use", "id": "t1", "name": "mcp__ssh__exec"}
    line = {
        "sessionId": "s",
        "cwd": str(tmp_path),
        "message": {"content": [{**block, "input": {"s": "git reset --hard"}}]},
    }
    transcript = tmp_path / "t.jsonl"
    transcript.write_text(json.dumps(line) + "\n", encoding="utf-8")
    report = replay([str(transcript)], env=gate_env)
    assert dict(report.rules) == {"builtin.git.reset-hard": 1}


def test_lint_knows_configured_shell_tools() -> None:
    pytest.importorskip("z3")
    from ember_armor.ledger.lint import lint

    command = {"type": "command", "program": "git", "subcommand": ["push"]}
    scoped = rule("remote", when=command, applies={"tools": ["mcp__ssh__exec"]})
    plain = rule("plain", when=command, applies={"tools": ["mcp__db__query"]})
    lower = rule("lower", when=command, applies={"tools": ["bash"]})
    rules = parse_ledger({"version": 1, "rules": [scoped, plain, lower]})
    dead = {f.rules[0] for f in lint(rules) if f.kind == "dead"}
    assert dead == {"remote", "plain"}
    dead = {
        f.rules[0] for f in lint(rules, shell_tools=["mcp__ssh__*"]) if f.kind == "dead"
    }
    assert dead == {"plain"}


def test_the_user_ledger_can_scope_a_rule_to_a_configured_tool(tmp_path) -> None:
    ledger = tmp_path / "ledger.json"
    when = {"type": "command", "program": "systemctl", "subcommand": ["restart"]}
    write_ledger(
        ledger, rule("no-restart", when=when, applies={"tools": ["mcp__ssh__*"]})
    )
    env = {"EMBER_HOME": str(tmp_path / "home"), "EMBER_LEDGER": str(ledger)}
    write_config(env, {"shell_tools": {"mcp__ssh__*": {"shell": "bash"}}})
    call = make_call("mcp__ssh__exec", {"command": "sudo systemctl restart nginx"})
    assert check(call, env=env, record=False).decision.effect == "deny"
    local = make_call("Bash", "sudo systemctl restart nginx")
    assert check(local, env=env, record=False).decision.effect == "none"
