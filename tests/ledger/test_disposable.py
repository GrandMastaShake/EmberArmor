"""The disposable-directory exemption is judged from the working directory.

A build, cache or temporary directory spares a recursive delete only when
that directory is not the working directory and not above it.  Command
strings are data; nothing runs.
"""

from __future__ import annotations

import pytest

from ember_armor.ledger.builtin import builtin_rules
from ember_armor.ledger.engine import evaluate
from ember_armor.ledger.facts import extract
from ember_armor.ledger.model import parse_ledger
from tests.ledger.helpers import POSIX_ENV, WINDOWS_ENV, facts_for, make_call


def decide(
    command: str,
    cwd: str,
    *,
    windows: bool = False,
    tool: str = "Bash",
    disposable: tuple[str, ...] = (),
) -> tuple[str, list[str]]:
    env = WINDOWS_ENV if windows else POSIX_ENV
    facts = extract(make_call(tool, command, cwd=cwd), windows=windows, env=env)
    decision = evaluate(builtin_rules(disposable), facts)
    return decision.effect, [
        fired.id.removeprefix("builtin.") for fired in decision.fired
    ]


POSIX = [
    # the project lies below a directory with a disposable name
    ("/home/dev/build/proj", "rm -rf .git", "deny"),
    ("/home/dev/build/proj", "rm -rf src", "ask"),
    ("/home/dev/build/proj", "rm -rf .", "ask"),
    ("/home/dev/build/proj", "rm -rf *", "ask"),
    ("/home/dev/build/proj", "rm -rf ..", "ask"),
    ("/home/dev/build/proj", "rm -rf /home/dev/build", "ask"),
    ("/home/dev/build/proj", "rm -rf /home/dev/build/proj", "ask"),
    ("/home/dev/build/proj/sub", "rm -rf ../.git", "deny"),
    ("/home/dev/build/proj", "git status; rm -rf ./lib/", "ask"),
    ("/srv/dist/app", "rm -rf src", "ask"),
    ("/srv/target/app", "find . -delete", "ask"),
    ("/srv/coverage/app", "rm -rf docs", "ask"),
    ("/home/dev/.cache/checkout", "rm -rf .git", "deny"),
    ("/home/dev/obj/app", "rm -rf pkg", "ask"),
    # inside such a project the disposable directories below it still count
    ("/home/dev/build/proj", "rm -rf node_modules", "none"),
    ("/home/dev/build/proj", "rm -rf build", "none"),
    ("/home/dev/build/proj", "rm -rf ./dist/assets", "none"),
    ("/home/dev/build/proj", "rm -rf ../dist", "none"),
    ("/home/dev/build/proj", "cd build && rm -rf *", "none"),
    ("/home/dev/build/proj", "rm -rf packages/*/node_modules", "none"),
    # the working directory is in a temporary directory
    ("/tmp/work/proj", "rm -rf src", "ask"),
    ("/tmp/work/proj", "rm -rf .git", "deny"),
    ("/tmp/work/proj", "rm -rf /tmp/work", "ask"),
    ("/tmp/work/proj", "rm -rf /tmp", "ask"),
    ("/tmp/work/proj", 'rm -rf "$TMPDIR/work/proj"', "ask"),
    ("/tmp/work/proj", "rm -rf dist", "none"),
    ("/tmp/work/proj", "rm -rf /tmp/work/proj/tmp", "none"),
    # seen from elsewhere, the same directories are disposable
    ("/work/app", "rm -rf /tmp/work", "none"),
    ("/work/app", 'rm -rf "$TMPDIR/x"', "none"),
    ("/work/app", "rm -rf ../dist", "none"),
    ("/work/app", "rm -rf /srv/build/out", "none"),
    ("/work/app", "rm -rf /tmp/clone/.git", "none"),
    ("/work/app/src", "rm -rf ../.git", "deny"),
    ("/work/app/src", "rm -rf ../node_modules", "none"),
]


@pytest.mark.parametrize(("cwd", "command", "effect"), POSIX)
def test_posix_working_directories(cwd: str, command: str, effect: str) -> None:
    assert decide(command, cwd)[0] == effect


TEMP = "C:\\Users\\dev\\AppData\\Local\\Temp"
WINDOWS = [
    (f"{TEMP}\\scratch", "Remove-Item -Recurse -Force .git", "deny"),
    (f"{TEMP}\\scratch", "Remove-Item -Recurse src", "ask"),
    (f"{TEMP}\\scratch", "Remove-Item -Recurse .", "ask"),
    (f"{TEMP}\\scratch", "Remove-Item -Recurse $env:TEMP", "ask"),
    (f"{TEMP}\\scratch", "Remove-Item -Recurse $env:TEMP\\scratch", "ask"),
    (f"{TEMP}\\scratch", "Remove-Item -Recurse node_modules", "none"),
    (f"{TEMP}\\scratch", "Remove-Item -Recurse .\\build\\out", "none"),
    ("C:\\Build\\proj", "Remove-Item -Recurse src", "ask"),
    ("C:\\Build\\proj", "Remove-Item -Recurse C:\\build\\proj\\.git", "deny"),
    ("C:\\Build\\proj", "Remove-Item -Recurse C:\\BUILD", "ask"),
    ("C:\\dev\\TEMP\\proj", 'cmd /c "rd /s /q src"', "ask"),
    ("C:\\work\\app", "Remove-Item -Recurse $env:TEMP\\x", "none"),
    ("C:\\work\\app", "Remove-Item -Recurse C:\\Build\\proj\\out", "none"),
]


@pytest.mark.parametrize(("cwd", "command", "effect"), WINDOWS)
def test_windows_working_directories(cwd: str, command: str, effect: str) -> None:
    assert decide(command, cwd, windows=True, tool="PowerShell")[0] == effect


def test_git_bash_in_a_temporary_directory() -> None:
    cwd = f"{TEMP}\\claude\\scratchpad"
    assert decide("rm -rf .git", cwd, windows=True)[0] == "deny"
    assert decide("rm -rf work", cwd, windows=True)[0] == "ask"
    assert (
        decide("rm -rf /c/Users/dev/AppData/Local/Temp", cwd, windows=True)[0] == "ask"
    )
    assert decide("rm -rf work/.venv", cwd, windows=True)[0] == "none"


def test_the_users_own_patterns_follow_the_same_rule() -> None:
    patterns = ("**/out", "/srv/scratch")
    assert decide("rm -rf out", "/work/app", disposable=patterns)[0] == "none"
    assert decide("rm -rf src", "/x/out/app", disposable=patterns)[0] == "ask"
    assert (
        decide("rm -rf /srv/scratch/a", "/work/app", disposable=patterns)[0] == "none"
    )
    assert decide("rm -rf a", "/srv/scratch/b", disposable=patterns)[0] == "ask"


def test_not_within_in_a_user_rule() -> None:
    rule = {
        "id": "r",
        "text": "t",
        "source": "s",
        "effect": "deny",
        "confirmed": True,
        "when": {"type": "path", "op": "write", "not_within": ["**/gen", "notes"]},
    }
    rules = parse_ledger({"version": 1, "rules": [rule]})

    def effect(path: str) -> str:
        call = {"file_path": path, "content": ""}
        return evaluate(rules, facts_for("Write", call)).effect

    assert effect("src/a.py") == "deny"
    assert effect("gen/a.py") == "none"
    assert effect("pkg/gen/a.py") == "none"
    assert effect("notes/todo.md") == "none"
    assert effect("/work/app") == "deny"
    assert effect("/work") == "deny"
    # /work/gen is beside the working directory /work/app, not above it.
    assert effect("/work/gen/a.py") == "none"


def test_not_within_never_looks_at_the_shared_part_of_the_path() -> None:
    rule = {
        "id": "r",
        "text": "t",
        "source": "s",
        "effect": "deny",
        "confirmed": True,
        "when": {"type": "path", "op": "write", "not_within": ["**/app", "**/work"]},
    }
    rules = parse_ledger({"version": 1, "rules": [rule]})
    for path in ("a.py", "/work/app/a.py", "/work/b.py", "/work", "/work/app"):
        call = {"file_path": path, "content": ""}
        assert evaluate(rules, facts_for("Write", call)).effect == "deny", path
    call = {"file_path": "/work/app/app/a.py", "content": ""}
    assert evaluate(rules, facts_for("Write", call)).effect == "none"
