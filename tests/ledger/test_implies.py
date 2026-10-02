"""Implications lint may take as certain, and the ones it must not."""

from __future__ import annotations

from typing import Any

import pytest

from ember_armor.ledger.implies import (
    command_implies,
    directory_inside,
    path_implies,
    resolved,
)
from ember_armor.ledger.model import CommandPred, PathPred, parse_predicate


def command(**fields: Any) -> CommandPred:
    pred = parse_predicate({"type": "command", **fields}, "test")
    assert isinstance(pred, CommandPred)
    return pred


def path(**fields: Any) -> PathPred:
    pred = parse_predicate({"type": "path", **fields}, "test")
    assert isinstance(pred, PathPred)
    return pred


INSIDE_CASES = [
    # inner pattern, outer pattern, flavour, expected
    ("src/gen", "src", "posix", True),
    ("src", "src", "posix", True),
    ("src", "src/gen", "posix", False),
    ("srcs", "src", "posix", False),
    ("/work/app/src", "/work", "posix", True),
    ("/work/app/src", "src", "posix", False),
    ("src", "/work/app", "posix", False),
    ("/a/node_modules/x", "**/node_modules", "posix", True),
    ("**/node_modules/.cache", "**/node_modules", "posix", True),
    ("**/node_modules", "**/node_modules/.cache", "posix", False),
    ("**/a/b", "**/b", "posix", True),
    # a wildcard in the inner pattern is never read as a literal
    ("/a/*", "/a/?", "posix", False),
    ("/a/*", "/a/b", "posix", False),
    ("/a/*", "/a/*", "posix", True),
    ("**/x", "/a", "posix", False),
    # home and variables only compare with each other
    ("~/x", "~", "posix", True),
    ("~", "/work/app", "posix", False),
    ("$TEMP/x", "$TEMP", "posix", True),
    ("%TEMP%\\x", "%TEMP%", "windows", True),
    ("~/x", "$HOME", "posix", False),
    # ".." is never compared
    ("src/../gen", "src", "posix", False),
    ("~/../x", "~", "posix", False),
    ("src/gen", "src/..", "posix", False),
    # flavours
    (r"C:\Work\App\SRC\gen", "c:/work/app/src", "windows", True),
    (r"C:\Work\App\SRC\gen", "c:/work/app/src", "posix", False),
    ("/c/work/app/src", "C:/work", "windows", True),
    ("/Work/app", "/work", "posix", False),
]


@pytest.mark.parametrize(("inner", "outer", "flavour", "expected"), INSIDE_CASES)
def test_directory_inside(inner: str, outer: str, flavour: str, expected: bool) -> None:
    windows = flavour == "windows"
    a = resolved(inner, None, windows=windows)
    b = resolved(outer, None, windows=windows)
    assert directory_inside(a, b, windows=windows) is expected


def test_patterns_of_different_bases_compare_only_when_absolute() -> None:
    def inside(inner: str, base_a: str | None, outer: str, base_b: str | None) -> bool:
        a = resolved(inner, base_a, windows=False)
        b = resolved(outer, base_b, windows=False)
        return directory_inside(a, b, windows=False)

    assert inside("src/gen", "/work/app", "src", "/work/app")
    assert not inside("src/gen", "/work/app", "src", None)
    assert not inside("src/gen", None, "src", "/work/app")
    assert inside("src/gen", "/work/app", "/work/app/src", None)
    assert inside("~/x", "/work/app", "~", "/work/app")
    assert not inside("~/x", "/work/app", "~", None)
    assert not inside("~/x", "/work/app", "/work/app", "/work/app")


def test_a_bare_glob_matches_in_any_directory() -> None:
    assert resolved("*.pem", None, windows=False, bare=True) == "**/*.pem"
    assert resolved("*.pem", "/work", windows=False) == "/work/*.pem"


COMMAND_CASES = [
    # a, b, expected: does a imply b?
    (command(program="git", subcommand=["push"]), command(program="git"), True),
    (command(program="git"), command(program="git", subcommand=["push"]), False),
    (
        command(program="git", subcommand=["push", "origin"]),
        command(program="git", subcommand=["push"]),
        True,
    ),
    (
        command(program="git", subcommand=["push"]),
        command(program="git", subcommand=["pull"]),
        False,
    ),
    (command(program="git"), command(program=["git", "gh"]), True),
    (command(program=["git", "gh"]), command(program="git"), False),
    (command(subcommand=["push"]), command(program="git"), False),
    (command(program="git"), command(), True),
    # shells and letter case
    (command(program="git", shell="bash"), command(program="git"), True),
    (command(program="git"), command(program="git", shell="bash"), False),
    (command(program="GIT"), command(program="git"), False),
    (
        command(program="Remove-Item", shell="powershell"),
        command(program="remove-item"),
        True,
    ),
    # flags
    (
        command(program="git", flags_any=["--force"]),
        command(program="git", flags_any=["-f", "--force"]),
        True,
    ),
    (
        command(program="git", flags_any=["-f", "--force"]),
        command(program="git", flags_any=["--force"]),
        False,
    ),
    (
        command(program="git", flags_all=["--delete", "--force"]),
        command(program="git", flags_any=["--force", "-D"]),
        True,
    ),
    (
        command(program="git", flags_all=["--delete", "--force"]),
        command(program="git", flags_all=["--force"]),
        True,
    ),
    (
        command(program="git", flags_any=["--force"]),
        command(program="git", flags_all=["--force"]),
        True,
    ),
    (
        command(program="git", flags_any=["--force", "-f"]),
        command(program="git", flags_all=["--force"]),
        False,
    ),
    (command(program="git"), command(program="git", flags_any=["--force"]), False),
    # argument globs
    (
        command(program="rm", args_any_glob=["*.log"]),
        command(program="rm", args_any_glob=["*.log", "*.tmp"]),
        True,
    ),
    (command(program="rm"), command(program="rm", args_any_glob=["*.log"]), False),
]


@pytest.mark.parametrize(("a", "b", "expected"), COMMAND_CASES)
def test_command_implies(a: CommandPred, b: CommandPred, expected: bool) -> None:
    assert command_implies(a, b) is expected


PATH_CASES = [
    (path(op="write", under=["src/gen"]), path(op="write", under=["src"]), True),
    (path(op="write", under=["src/gen"]), path(under=["src"]), True),
    (path(under=["src/gen"]), path(op="write", under=["src"]), False),
    (path(op="read", under=["src/gen"]), path(op="write", under=["src"]), False),
    (path(op="write", under=["src", "docs"]), path(op="write", under=["src"]), False),
    (path(op="write", under=["src/a", "src/b"]), path(under=["src"]), True),
    (path(op="write"), path(op="write", under=["src"]), False),
    # recursive
    (path(op="delete", recursive=True), path(op="delete"), True),
    (path(op="delete"), path(op="delete", recursive=True), False),
    (path(op="delete", recursive=False), path(op="delete", recursive=True), False),
    # exceptions: b's must all be covered by a's
    (path(under=["src"], not_under=["src/gen"]), path(under=["src"]), True),
    (path(under=["src"]), path(under=["src"], not_under=["src/gen"]), False),
    (
        path(under=["src"], not_under=["src/gen"]),
        path(under=["src"], not_under=["src/gen/deep"]),
        True,
    ),
    (
        path(under=["src"], not_under=["src/gen/deep"]),
        path(under=["src"], not_under=["src/gen"]),
        False,
    ),
    # not_within spares less than not_under does for the same directory
    (path(not_within=["**/gen"]), path(not_within=["**/gen"]), True),
    (path(not_within=["**/gen", "**/x"]), path(not_within=["**/gen"]), True),
    (path(not_within=["**/gen"]), path(not_within=["**/gen", "**/x"]), False),
    (path(not_under=["src/gen"]), path(not_within=["src/gen"]), True),
    (path(not_under=["src/gen"]), path(not_within=["src/gen/deep"]), True),
    (path(not_within=["src/gen"]), path(not_under=["src/gen"]), False),
    (path(not_within=["src/gen"]), path(), True),
    (path(), path(not_within=["src/gen"]), False),
    # globs: only equal patterns, or a literal glob inside a directory
    (path(glob=["**/.env"]), path(glob=["**/.env", "**/*.pem"]), True),
    (path(glob=["**/.env", "**/*.pem"]), path(glob=["**/.env"]), False),
    (path(glob=["*.env"]), path(glob=["**/*.env"]), True),
    (path(glob=["src/gen/a.py"]), path(under=["src"]), True),
    (path(glob=["src/*.py"]), path(under=["src"]), False),
    (path(under=["src"]), path(glob=["src/**"]), False),
]


@pytest.mark.parametrize(("a", "b", "expected"), PATH_CASES)
def test_path_implies(a: PathPred, b: PathPred, expected: bool) -> None:
    assert path_implies(a, None, b, None, windows=False) is expected


def test_path_implies_respects_the_rule_base() -> None:
    inner = path(op="write", under=["src/gen"])
    outer = path(op="write", under=["src"])
    assert path_implies(inner, "/work/app", outer, "/work/app", windows=False)
    assert not path_implies(inner, "/work/app", outer, "/work/lib", windows=False)
    assert not path_implies(inner, "/work/app", outer, None, windows=False)
