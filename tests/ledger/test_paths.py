"""Path normalisation and pattern matching, for both path flavours."""

from __future__ import annotations

import pytest

from ember_armor.ledger.paths import (
    expand_variables,
    is_under,
    matches_glob,
    normalize,
    resolve_pattern,
)

WIN_HOME = "C:/Users/dev"
NIX_HOME = "/home/dev"

WINDOWS_CASES = [
    # raw, cwd, expected
    (r"C:\Users\x", r"C:\work", "C:/Users/x"),
    ("c:/users/x", r"C:\work", "C:/users/x"),
    ("/c/Users/x", r"C:\work", "C:/Users/x"),
    ("/c", r"C:\work", "C:/"),
    ("/c/", r"C:\work", "C:/"),
    ("/d/data/file.txt", r"C:\work", "D:/data/file.txt"),
    ("src/app.py", r"C:\work\app", "C:/work/app/src/app.py"),
    (r".\src\..\lib", r"C:\work\app", "C:/work/app/lib"),
    ("..", r"C:\work\app", "C:/work"),
    (r"..\..\..\..", r"C:\work\app", "C:/"),
    (".", "/c/work/app", "C:/work/app"),
    ("~", r"C:\work", "C:/Users/dev"),
    ("~/notes.txt", r"C:\work", "C:/Users/dev/notes.txt"),
    (r"~\notes.txt", r"C:\work", "C:/Users/dev/notes.txt"),
    ("/tmp/x", r"C:\work", "/tmp/x"),
    ("/dev/null", r"C:\work", "/dev/null"),
    (r"\\server\share\dir\f", r"C:\work", "//server/share/dir/f"),
    (r"C:\work\app\\", r"C:\work", "C:/work/app"),
    ("C:", r"D:\x", "C:/"),
    (r"$env:TEMP\build", r"C:\work", "C:/Users/dev/AppData/Local/Temp/build"),
    (r"%TEMP%\build", r"C:\work", "C:/Users/dev/AppData/Local/Temp/build"),
    ("$HOME/.ssh/id_rsa", r"C:\work", "C:/Users/dev/.ssh/id_rsa"),
    ("${HOME}/x", r"C:\work", "C:/Users/dev/x"),
    ("$UNKNOWN/x", r"C:\work", "C:/work/$UNKNOWN/x"),
    # ``..`` does not cancel a segment that was not resolved.
    (r"$env:NOPE\..", r"C:\work", "C:/work/$env:NOPE/.."),
    (r"%NOPE%\..\x", r"C:\work", "C:/work/%NOPE%/../x"),
    (r"$PSScriptRoot\..\..", r"C:\work", "C:/work/$PSScriptRoot/../.."),
    (r"$env:TEMP\..", r"C:\work", "C:/Users/dev/AppData/Local"),
]


@pytest.mark.parametrize(("raw", "cwd", "expected"), WINDOWS_CASES)
def test_normalize_windows(raw: str, cwd: str, expected: str) -> None:
    variables = {"HOME": WIN_HOME, "TEMP": r"C:\Users\dev\AppData\Local\Temp"}
    assert (
        normalize(raw, cwd, windows=True, home=WIN_HOME, variables=variables)
        == expected
    )


POSIX_CASES = [
    ("/etc/hosts", "/work", "/etc/hosts"),
    ("src/app.py", "/work/app", "/work/app/src/app.py"),
    ("./a/../b", "/work", "/work/b"),
    ("../..", "/work/app", "/"),
    ("../../../..", "/work/app", "/"),
    ("/", "/work", "/"),
    ("//usr//lib/", "/work", "/usr/lib"),
    ("~", "/work", "/home/dev"),
    ("~/x", "/work", "/home/dev/x"),
    ("~other/x", "/work", "/work/~other/x"),
    ("$HOME/x", "/work", "/home/dev/x"),
    ("$TMPDIR/build", "/work", "/tmp/build"),
    ("/c/Users/x", "/work", "/c/Users/x"),
    (r"a\b", "/work", r"/work/a\b"),
    ("C:/x", "/work", "/work/C:/x"),
    # ``..`` does not cancel a segment that was not resolved.
    ("$UNSET/..", "/work", "/work/$UNSET/.."),
    ("$UNSET/../x", "/work", "/work/$UNSET/../x"),
    ("a/$UNSET/../../b", "/work", "/work/a/$UNSET/../../b"),
    ("/a/${UNSET}/../b", "/work", "/a/${UNSET}/../b"),
    ("$(pwd)/..", "/work", "/work/$(pwd)/.."),
    ("`pwd`/../x", "/work", "/work/`pwd`/../x"),
    ("%NAME%/..", "/work", "/work/%NAME%/.."),
    ("$UNSET/x/..", "/work", "/work/$UNSET"),
    ("$HOME/..", "/work", "/home"),
    ("$HOME/../$UNSET/..", "/work", "/home/$UNSET/.."),
]


@pytest.mark.parametrize(("raw", "cwd", "expected"), POSIX_CASES)
def test_normalize_posix(raw: str, cwd: str, expected: str) -> None:
    variables = {"HOME": NIX_HOME, "TMPDIR": "/tmp"}
    assert (
        normalize(raw, cwd, windows=False, home=NIX_HOME, variables=variables)
        == expected
    )


def test_msys_and_native_forms_are_the_same_path() -> None:
    forms = [r"C:\Users\x", "c:/Users/x", "/c/Users/x", r"c:\Users\.\x\y\.."]
    assert {normalize(f, "/c/work", windows=True) for f in forms} == {"C:/Users/x"}


def test_expand_variables_leaves_unknown_and_defaults_alone() -> None:
    known = {"HOME": "/h"}
    assert expand_variables("$HOME/a", known) == "/h/a"
    assert expand_variables("$env:HOME/a", known) == "/h/a"
    assert expand_variables("${HOME:-/x}/a", known) == "${HOME:-/x}/a"
    assert expand_variables("$OTHER/a", known) == "$OTHER/a"
    assert expand_variables("100%", known) == "100%"


GLOB_CASES = [
    # path, pattern, windows, expected
    ("/work/app/.env", "**/.env", False, True),
    ("/.env", "**/.env", False, True),
    ("/work/app/.env.example", "**/.env", False, False),
    ("/work/app/.env.prod.local", "**/.env.*.local", False, True),
    ("/work/a/b/key.pem", "**/*.pem", False, True),
    ("/work/a/b/key.pem", "/work/*.pem", False, False),
    ("/work/a/b/key.pem", "/work/**/*.pem", False, True),
    ("/work/a/key.pem", "/work/?/key.pem", False, True),
    ("/work/ab/key.pem", "/work/?/key.pem", False, False),
    ("/work/app/File.TXT", "**/*.txt", False, False),
    ("C:/work/app/File.TXT", "**/*.txt", True, True),
    ("C:/", "?:/", True, True),
    ("C:/Users", "?:/", True, False),
    ("C:/Users/dev", "?:/Users/*", True, True),
    ("C:/Users/dev/x", "?:/Users/*", True, False),
    ("c:/users/DEV", "?:/Users/*", True, True),
    ("/", "/", False, True),
    ("/home/dev", "/home/*", False, True),
    ("/work/a1", "/work/a[0-9]", False, True),
    ("/work/ab", "/work/a[!0-9]", False, True),
    ("/work/a(1)+", "/work/a(1)+", False, True),
]


@pytest.mark.parametrize(("path", "pattern", "windows", "expected"), GLOB_CASES)
def test_matches_glob(path: str, pattern: str, windows: bool, expected: bool) -> None:
    assert matches_glob(path, pattern, windows=windows) is expected


UNDER_CASES = [
    ("/work/app/node_modules", "**/node_modules", False, True),
    ("/work/app/node_modules/x/y", "**/node_modules", False, True),
    ("/work/app/node_modules_old", "**/node_modules", False, False),
    ("/work/app/src", "/work/app", False, True),
    ("/work/app", "/work/app", False, True),
    ("/work/application", "/work/app", False, False),
    ("/anything", "/", False, True),
    ("/", "/", False, True),
    ("C:/x", "C:/", True, True),
    ("D:/x", "C:/", True, False),
    ("C:/Work/App/Src", "c:/work/app", True, True),
    ("/Work/App", "/work/app", False, False),
    ("/tmp/x", "**/tmp", False, True),
    ("C:/Users/dev/AppData/Local/Temp/x", "**/temp", True, True),
]


@pytest.mark.parametrize(("path", "directory", "windows", "expected"), UNDER_CASES)
def test_is_under(path: str, directory: str, windows: bool, expected: bool) -> None:
    assert is_under(path, directory, windows=windows) is expected


PATTERN_CASES = [
    # pattern, base, windows, bare_anywhere, expected
    ("secrets", "/proj", False, False, "/proj/secrets"),
    ("secrets/", "/proj", False, False, "/proj/secrets"),
    ("*.pem", "/proj", False, True, "**/*.pem"),
    ("*.pem", "/proj", False, False, "/proj/*.pem"),
    ("keys/*.pem", "/proj", False, True, "/proj/keys/*.pem"),
    ("**/node_modules/", "/proj", False, False, "**/node_modules"),
    ("~", "/proj", False, True, "/home/dev"),
    ("~/.ssh", "/proj", False, False, "/home/dev/.ssh"),
    ("?:/", "C:/proj", True, False, "?:/"),
    (r"?:\Users\*", "C:/proj", True, False, "?:/Users/*"),
    (r"C:\Data", "C:/proj", True, False, "C:/Data"),
    ("/c/data", "C:/proj", True, False, "C:/data"),
    ("$TMPDIR", "/proj", False, True, "/tmp"),
]


@pytest.mark.parametrize(
    ("pattern", "base", "windows", "bare", "expected"), PATTERN_CASES
)
def test_resolve_pattern(
    pattern: str, base: str, windows: bool, bare: bool, expected: str
) -> None:
    resolved = resolve_pattern(
        pattern,
        base,
        windows=windows,
        home="/home/dev",
        variables={"TMPDIR": "/tmp"},
        bare_anywhere=bare,
    )
    assert resolved == expected
