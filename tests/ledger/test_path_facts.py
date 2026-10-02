"""Path facts for forms that used to resolve to the wrong place.

Variables, working-directory moves, deletes fed by a pipe, device paths and
wildcard operands.  Command strings are data; nothing runs.
"""

from __future__ import annotations

from typing import Any

import pytest

from ember_armor.ledger.facts import MAX_PATH_CHARS, extract
from ember_armor.ledger.paths import (
    NO_PATH,
    expand_variables,
    may_match,
    normalize,
    resolve_pattern,
)
from tests.ledger.helpers import WINDOWS_ENV, facts_for, make_call


def paths(
    tool: str, payload: Any, platform: str = "posix"
) -> list[tuple[str, str, bool]]:
    facts = facts_for(tool, payload, platform)
    return [(p.path, p.op, p.recursive) for p in facts.paths]


def deleted(command: str, tool: str = "Bash", platform: str = "posix") -> list[str]:
    return [path for path, op, _ in paths(tool, command, platform) if op == "delete"]


# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------
BASH_VARIABLES = [
    # a lower-case name is not the environment variable
    ('rm -rf "$tmpdir/x"', ["/work/app/$tmpdir/x"]),
    ('rm -rf "$TMPDIR/x"', ["/tmp/x"]),
    ('rm -rf "$home"', ["/work/app/$home"]),
    # an assignment the parser cannot resolve hides the environment value
    ('TMPDIR=$(pwd); rm -rf "$TMPDIR"', ["/work/app/$TMPDIR"]),
    ('HOME=dist; rm -rf "$HOME/x"', ["/work/app/$HOME/x"]),
    # a whole-word reference takes the value assigned before it ...
    ('x=src; rm -rf "$x"; x=dist', ["/work/app/src"]),
    # ... inside a longer word, two different values make the name unknown
    ('x=src; rm -rf "$x/a"; x=dist', ["/work/app/$x/a"]),
    # values made of literals and known variables resolve
    ('d="$TMPDIR/work"; rm -rf "$d"', ["/tmp/work"]),
    ('d="$PWD/src"; rm -rf "$d"', ["/work/app/src"]),
    ('a=/srv; b="$a/data"; rm -rf "$b/old"', ["/srv/data/old"]),
    ('w=$(mktemp -d); rm -rf "$w"', ["/tmp/mktemp"]),
    # loop variables and arrays over literal words
    ('for d in dist src; do rm -rf "$d"; done', ["/work/app/dist", "/work/app/src"]),
    ('dirs=(a b); rm -rf "${dirs[@]}"', ["/work/app/a", "/work/app/b"]),
    ('for d in $(ls); do rm -rf "$d"; done', ["/work/app/$d"]),
    ("rm -rf {a,b}", ["/work/app/a", "/work/app/b"]),
]


@pytest.mark.parametrize(("command", "expected"), BASH_VARIABLES)
def test_bash_variables(command: str, expected: list[str]) -> None:
    assert deleted(command) == expected


POWERSHELL_VARIABLES = [
    # a plain variable is never the environment
    ("Remove-Item -Recurse $temp", ["C:/work/app/$temp"]),
    ("Remove-Item -Recurse $env:TEMP\\x", ["C:/Users/dev/AppData/Local/Temp/x"]),
    ("Remove-Item -Recurse $HOME\\x", ["C:/Users/dev/x"]),
    ("$Tmp = $PWD; Remove-Item -Recurse $tmp", ["C:/work/app"]),
    ("$t = (Get-Location).Path; Remove-Item -Recurse $t", ["C:/work/app/$t"]),
    (
        '$w = Join-Path $env:TEMP "work"; Remove-Item -Recurse $w',
        ["C:/Users/dev/AppData/Local/Temp/work"],
    ),
    (
        '$w = "$env:TEMP\\work"; Remove-Item -Recurse $W',
        ["C:/Users/dev/AppData/Local/Temp/work"],
    ),
    (
        'Remove-Item -Recurse (Join-Path $env:TEMP "work")',
        ["C:/Users/dev/AppData/Local/Temp/work"],
    ),
    (
        "foreach ($d in 'dist','src') { Remove-Item -Recurse $d }",
        ["C:/work/app/dist", "C:/work/app/src"],
    ),
    (
        "$env:TEMP = 'C:\\x'; Remove-Item -Recurse $env:TEMP\\y",
        ["C:/work/app/$env:TEMP/y"],
    ),
]


@pytest.mark.parametrize(("command", "expected"), POWERSHELL_VARIABLES)
def test_powershell_variables(command: str, expected: list[str]) -> None:
    assert deleted(command, "PowerShell", "windows") == expected


# ---------------------------------------------------------------------------
# Working directory
# ---------------------------------------------------------------------------
MOVES = [
    ("cd && rm -rf .", ["/home/dev"]),
    ("cd; rm -rf ./*", ["/home/dev"]),
    ("cd build && make && cd - && rm -rf src", ["/work/app/src"]),
    ("cd build && cd $OLDPWD && rm -rf src", ["/work/app/src"]),
    ("pushd build && make && popd && rm -rf src", ["/work/app/src"]),
    ("pushd /a && pushd /b && popd && rm -rf x", ["/a/x"]),
    # a move inside a subshell or substitution ends with it
    ("(cd build && make) && rm -rf src", ["/work/app/src"]),
    ("if (cd build && make); then rm -rf src; fi", ["/work/app/src"]),
    ("v=$(cd build && cat VERSION); rm -rf src", ["/work/app/src"]),
    ("bash -c 'cd build'; rm -rf src", ["/work/app/src"]),
    ("(cd build && rm -rf out)", ["/work/app/build/out"]),
]


@pytest.mark.parametrize(("command", "expected"), MOVES)
def test_working_directory_is_followed(command: str, expected: list[str]) -> None:
    assert deleted(command) == expected


# ---------------------------------------------------------------------------
# Deletes and reads fed by a pipe
# ---------------------------------------------------------------------------
PIPED = [
    (
        "find . -name node_modules | xargs rm -rf",
        [("/work/app/node_modules", "delete", True)],
    ),
    ("find . -name '*.pyc' | xargs rm -f", [("/work/app/*.pyc", "delete", False)]),
    ("find src | xargs rm -f", [("/work/app/src", "delete", True)]),
    ("find . -name x | xargs -I{} rm -rf {}", [("/work/app/x", "delete", True)]),
    ("ls -d */dist | xargs rm -rf", [("/work/app/*/dist", "delete", True)]),
    ("git ls-files | xargs rm -rf", [("/work/app", "delete", True)]),
    ("find . -name '.env*' | xargs cat", [("/work/app/.env*", "read", False)]),
    (
        "find ~ -type f -exec rm -f {} +",
        [("/home/dev", "delete", True), ("/home/dev", "delete", False)],
    ),
    ("find . -name '*.tmp' -exec rm -f {} +", [("/work/app/*.tmp", "delete", False)]),
]


@pytest.mark.parametrize(("command", "expected"), PIPED)
def test_bash_targets_from_a_pipe(command: str, expected: list[Any]) -> None:
    assert paths("Bash", command) == expected


PS_PIPED = [
    (
        "Get-ChildItem -Path . -Recurse -Filter __pycache__ | Remove-Item -Recurse",
        [("C:/work/app/**/__pycache__", "delete", True)],
    ),
    (
        "Get-ChildItem .\\dist | Remove-Item -Recurse",
        [("C:/work/app/dist", "delete", True)],
    ),
    (
        "Get-ChildItem C:\\Users\\dev -Recurse | Remove-Item",
        [("C:/Users/dev", "delete", True)],
    ),
    ("gci dist | Remove-Item", [("C:/work/app/dist", "delete", False)]),
    (
        "Get-ChildItem .\\dist | % { Remove-Item -Recurse $_.FullName }",
        [("C:/work/app/dist", "delete", True)],
    ),
    ("Get-Process | Remove-Item -Recurse", [("C:/work/app", "delete", True)]),
    (
        "Get-ChildItem -Force -Filter .env* | Get-Content",
        [("C:/work/app/.env*", "read", False)],
    ),
]


@pytest.mark.parametrize(("command", "expected"), PS_PIPED)
def test_powershell_targets_from_a_pipe(command: str, expected: list[Any]) -> None:
    assert paths("PowerShell", command, "windows") == expected


WHAT_IF = [
    ("Remove-Item -Recurse x -WhatIf", []),
    ("Remove-Item -Recurse x -WhatIf:$true", []),
    ("Remove-Item -Recurse x -wi", []),
    ("Remove-Item -Recurse x -WhatIf:$false", ["C:/work/app/x"]),
    ("Remove-Item -Recurse x -WhatIf:0", ["C:/work/app/x"]),
]


@pytest.mark.parametrize(("command", "expected"), WHAT_IF)
def test_what_if_false_is_a_real_delete(command: str, expected: list[str]) -> None:
    assert deleted(command, "PowerShell", "windows") == expected


# ---------------------------------------------------------------------------
# Searches by file name, and tools
# ---------------------------------------------------------------------------
NAMED = [
    ("rg KEY --hidden -g .env", [("/work/app/**/.env", "read", False)]),
    ("rg KEY -g '!*.min.js' src", [("/work/app/src", "read", False)]),
    (
        "grep -r KEY --include=.env conf",
        [("/work/app/conf", "read", False), ("/work/app/conf/**/.env", "read", False)],
    ),
    ("awk -F= '{print $2}' .env", [("/work/app/.env", "read", False)]),
    ("cut -d= -f2 .env", [("/work/app/.env", "read", False)]),
    (
        "diff .env .env.example",
        [("/work/app/.env", "read", False), ("/work/app/.env.example", "read", False)],
    ),
]


@pytest.mark.parametrize(("command", "expected"), NAMED)
def test_readers_and_name_filters(command: str, expected: list[Any]) -> None:
    assert paths("Bash", command) == expected


def test_grep_tool_glob_is_a_read_below_the_path() -> None:
    assert paths("Grep", {"pattern": "K", "glob": ".env"}) == [
        ("/work/app/**/.env", "read", False)
    ]
    assert paths("Grep", {"pattern": "K", "path": "src", "glob": "*.py"}) == [
        ("/work/app/src/**/*.py", "read", False)
    ]
    assert paths("Grep", {"pattern": "K", "path": "src"}) == [
        ("/work/app/src", "read", False)
    ]


@pytest.mark.parametrize(
    "tool", ["PowerShell", "mcp__Windows-MCP__PowerShell", "powershell"]
)
def test_every_powershell_tool_is_parsed(tool: str) -> None:
    facts = facts_for(tool, "Remove-Item -Recurse $HOME", "windows")
    assert [c.argv for c in facts.commands] == [("Remove-Item", "-Recurse", "$HOME")]
    assert [p.path for p in facts.paths] == ["C:/Users/dev"]


def test_an_overlong_path_marks_the_call_instead_of_being_matched() -> None:
    long = "key" * MAX_PATH_CHARS
    facts = facts_for("Bash", f"cat {long}; rm -rf src")
    assert [(d.kind, d.detail) for d in facts.dynamic] == [
        ("parse_error", "path too long")
    ]
    assert [p.path for p in facts.paths] == ["/work/app/src"]
    with pytest.raises(ValueError, match="path longer than"):
        extract(make_call("Read", {"file_path": long}), windows=False, env={})


# ---------------------------------------------------------------------------
# paths.py
# ---------------------------------------------------------------------------
DEVICE_PATHS = [
    (r"\\?\C:\Users\dev", "C:/Users/dev"),
    (r"\\.\C:\Users\dev", "C:/Users/dev"),
    ("//localhost/C$/Users/dev", "C:/Users/dev"),
    ("//127.0.0.1/c$/Users", "C:/Users"),
    ("/mnt/c/Users/dev", "C:/Users/dev"),
    ("/cygdrive/d/data", "D:/data"),
    (r"\\?\UNC\server\share\x", "//server/share/x"),
    ("//server/C$/Users", "//server/C$/Users"),
    ("/mnt/data/x", "/mnt/data/x"),
]


@pytest.mark.parametrize(("raw", "expected"), DEVICE_PATHS)
def test_windows_device_and_mount_paths(raw: str, expected: str) -> None:
    assert normalize(raw, r"C:\work", windows=True) == expected


def test_mount_paths_are_left_alone_on_posix() -> None:
    assert normalize("/mnt/c/Users", "/", windows=False) == "/mnt/c/Users"


def test_expand_variables_with_a_shell_lookup() -> None:
    env = {"TEMP": "/t", "HOME": "/h"}
    known = {"work": "$TEMP/w", "loop": "$loop"}

    def lookup(name: str) -> str | None:
        return known.get(name, env.get(name))

    assert expand_variables("$work/x", env, lookup) == "/t/w/x"
    assert expand_variables("${work}/x", env, lookup) == "/t/w/x"
    assert expand_variables("$other/x", env, lookup) == "$other/x"
    # the environment forms never go through the shell lookup
    assert expand_variables("$env:temp/x %Home%", env, lambda name: None) == "/t/x /h"
    assert expand_variables("$temp", env, lambda name: None) == "$temp"
    # a value that refers to itself stops after a few rounds
    assert expand_variables("$loop", env, lookup) == "$loop"


def test_a_pattern_whose_variable_is_not_set_matches_nothing() -> None:
    assert resolve_pattern("$TMPDIR", "/w", windows=False, variables={}) == NO_PATH
    assert (
        resolve_pattern("$TMPDIR", "/w", windows=False, variables={"TMPDIR": "/t"})
        == "/t"
    )
    # ... so an operand with the same unset variable is not "under" it
    facts = facts_for("Bash", 'rm -rf "$TEMP/x"')
    assert [p.path for p in facts.paths] == ["/work/app/$TEMP/x"]


MAY_MATCH = [
    ("/w/.env*", "**/.env", True),
    ("/w/.env.*", "**/.env.local", True),
    ("/w/.en?", "**/.env", True),
    ("/w/.env[.a-z]*", "**/.env.production", True),
    ("/home/dev/.aws/cred*", "**/.aws/credentials", True),
    ("/w/**/.env*", "**/.env", True),
    ("/w/.envrc*", "**/.env", False),
    ("/w/other/cred*", "**/.aws/credentials", False),
    # only an extension, or only wildcards: too unspecific
    ("/w/*.json", "**/credentials.json", False),
    ("/w/*", "**/id_rsa", False),
    ("/w/?d_rsa", "**/id_rsa", False),
    # a literal path still matches as before
    ("/w/.env", "**/.env", True),
    ("/w/.env.example", "**/.env", False),
]


@pytest.mark.parametrize(("path", "pattern", "expected"), MAY_MATCH)
def test_may_match(path: str, pattern: str, expected: bool) -> None:
    assert may_match(path, pattern, windows=False) is expected


def test_may_match_folds_case_on_windows() -> None:
    assert may_match("C:/w/.ENV*", "**/.env", windows=True)
    assert not may_match("/w/.ENV*", "**/.env", windows=False)


def test_windows_environment_is_not_read_through_lower_case_bash_names() -> None:
    call = make_call("Bash", 'tmp=$(pwd); rm -rf "$tmp"', cwd=r"C:\work\app")
    env = {**WINDOWS_ENV, "TMP": r"C:\Users\dev\AppData\Local\Temp"}
    facts = extract(call, windows=True, env=env)
    assert [p.path for p in facts.paths] == ["C:/work/app/$tmp"]
