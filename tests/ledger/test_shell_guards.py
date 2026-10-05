"""Which commands of a string may not run, as the parsers report it.

The parsers flatten a command string into simple commands.  For the
directory a command runs in that is not enough: a ``cd`` behind ``&&``, in a
branch, in a loop or in the body of a function does not move the commands
after it for certain.  The parsers therefore record the ranges of commands
that may not run (``maybe``), may run any number of times (``loop``) or run
when a function is called (``defined``).

The command strings below are data for the parsers.  Nothing runs them.
"""

from __future__ import annotations

import pytest

from ember_armor.ledger.shell import ParseResult, parse_shell
from ember_armor.ledger.shell.core import Guards, SimpleCommand


def guards(parsed: ParseResult) -> list[tuple[int, int, str]]:
    """The guarded ranges as ``(first command, end, kind)``, in text order."""
    found = [(*parsed.scopes[number], kind) for number, kind in parsed.guards.items()]
    return sorted(found)


def programs(parsed: ParseResult) -> list[str]:
    return [command.argv[0] if command.argv else "" for command in parsed.commands]


# ---------------------------------------------------------------------------
# Bash
# ---------------------------------------------------------------------------
BASH = [
    # (command, the guarded ranges)
    ("a; b; c", []),
    ("a && b", [(1, 2, "maybe")]),
    ("a || b", [(1, 2, "maybe")]),
    ("a && b && c; d", [(1, 3, "maybe"), (2, 3, "maybe")]),
    ("a || b || c; d", [(1, 3, "maybe"), (2, 3, "maybe")]),
    # What follows ``||`` is skipped up to the next ``&&``, and the other way
    # round.
    ("a || b && c; d", [(1, 2, "maybe"), (2, 3, "maybe")]),
    ("a && b || c; d", [(1, 2, "maybe"), (2, 3, "maybe")]),
    # A ``cd`` is taken to succeed: moves alone leave nothing in doubt.
    ("cd a && cd b; c", []),
    ("cd a && b && c", [(2, 3, "maybe")]),
    ("cd a && cd b && c && d", [(3, 4, "maybe")]),
    ("pushd a && make && popd; c", [(2, 3, "maybe")]),
    ("cd a || cd b; c", [(1, 2, "maybe")]),
    ("a | b && c", [(2, 3, "maybe")]),
    ("[[ -d a ]] && b", [(0, 1, "maybe")]),
    ("(( n > 1 )) && b", [(0, 1, "maybe")]),
    ("(a) && b", [(1, 2, "maybe")]),
    ("{ a; b; } && c", [(2, 3, "maybe")]),
    ("a && { b; c; }; d", [(1, 3, "maybe")]),
    ("a && b; c && d", [(1, 2, "maybe"), (3, 4, "maybe")]),
    # A new line behind the operator carries the list on.
    ("a &&\nb\nc", [(1, 2, "maybe")]),
    ("a ||\n\n  b; c", [(1, 2, "maybe")]),
    # Compound commands.
    ("if a; then b; fi; c", [(1, 2, "maybe")]),
    ("if a; then b; else c; fi", [(1, 2, "maybe"), (2, 3, "maybe")]),
    (
        "if a; then b; elif c; then d; else e; fi; f",
        [(1, 2, "maybe"), (2, 4, "maybe"), (4, 5, "maybe")],
    ),
    ("if a && b; then c; fi", [(1, 2, "maybe"), (2, 3, "maybe")]),
    ("if (a) then b; fi", [(1, 2, "maybe")]),
    ("case $x in a) b;; c|d) e; f;; esac; g", [(0, 1, "maybe"), (1, 3, "maybe")]),
    ("case $x in a) b;& (c) d;; esac", [(0, 1, "maybe"), (1, 2, "maybe")]),
    ("for i in 1 2; do a; b; done; c", [(0, 2, "loop")]),
    ("for ((i = 0; i < 3; i++)); do a; done", [(0, 1, "loop")]),
    ("while a; do b; done; c", [(0, 2, "loop")]),
    ("until a; do b; done", [(0, 2, "loop")]),
    ("select x in a b; do c; done", [(0, 1, "loop")]),
    ("while read l; do a; done < list | sort", [(0, 2, "loop")]),
    (
        "for d in a b; do if c; then d; fi; done",
        [(0, 2, "loop"), (1, 2, "maybe")],
    ),
    ("f() { a; b; }; c", [(0, 2, "defined")]),
    ("function f { a; }; c", [(0, 1, "defined")]),
    ("function f() { a; }; c", [(0, 1, "defined")]),
    ("f()\n{\n  a\n}\nc", [(0, 1, "defined")]),
    ("f() { if a; then b; fi; }", [(0, 2, "defined"), (1, 2, "maybe")]),
    # A group, a subshell as a body, and a word that only looks reserved.
    ("{ a; b; }; c", []),
    ("time { a; b; }", []),
    ("f() (a; b); c", []),
    ("echo if then fi; echo '{'", []),
    ("echo for i in 1 2", []),
]


@pytest.mark.parametrize(("command", "expected"), BASH)
def test_bash_ranges(command: str, expected: list[tuple[int, int, str]]) -> None:
    parsed = parse_shell(command, "bash")
    assert not parsed.dynamic
    assert guards(parsed) == expected


def test_a_function_body_carries_the_name() -> None:
    parsed = parse_shell("f() { a; }; function g-h { b; }; i() (c)", "bash")
    named = {parsed.scopes[number]: name for number, name in parsed.named.items()}
    assert named == {(0, 1): "f", (1, 2): "g-h"}


def test_the_guards_do_not_change_what_is_parsed() -> None:
    command = "if a; then b && c; fi; for x in 1; do d; done; f() { e; }; g || h"
    parsed = parse_shell(command, "bash")
    assert programs(parsed) == ["a", "b", "c", "d", "e", "g", "h"]
    assert parsed.commands[1] == SimpleCommand(("b",), "bash")


def test_a_parse_error_keeps_the_ranges_read_so_far() -> None:
    parsed = parse_shell("if a; then cd x; b; (", "bash")
    assert [reason.kind for reason in parsed.dynamic] == ["parse_error"]
    assert guards(parsed) == [(1, 3, "maybe")]


def test_a_keyword_that_closes_nothing_is_ignored() -> None:
    parsed = parse_shell("fi; done; }; esac; a && b", "bash")
    assert guards(parsed) == [(1, 2, "maybe")]


def test_of_two_scopes_with_one_range_the_later_is_the_outer() -> None:
    # The loop lies in the subshell here, and the subshell in the branch
    # there: the order in ``scopes`` says which is which.
    inner = parse_shell("(for d in a; do x; done)", "bash")
    assert inner.scopes == [(0, 1), (0, 1)]
    assert inner.guards == {0: "loop"}
    outer = parse_shell("if a; then (b; c); fi", "bash")
    assert outer.scopes == [(1, 3), (1, 3)]
    assert outer.guards == {1: "maybe"}


def test_the_ranges_of_a_nested_script_move_with_it() -> None:
    parsed = parse_shell("bash -c 'a && cd x; f() { b; }'; c", "bash")
    assert programs(parsed) == ["bash", "a", "cd", "b", "c"]
    assert guards(parsed) == [(2, 3, "maybe"), (3, 4, "defined")]
    assert set(parsed.named.values()) == {"f"}
    # The script itself comes after its own scopes: it is the outer one.
    assert parsed.scopes[-1] == (1, 4)
    assert len(parsed.scopes) - 1 not in parsed.guards


def test_a_script_that_is_only_a_loop_lies_inside_its_shell() -> None:
    parsed = parse_shell("bash -c 'for i in 1 2; do a; done'", "bash")
    assert parsed.scopes == [(1, 2), (1, 2)]
    assert parsed.guards == {0: "loop"}


def test_guards_closes_what_is_left_open() -> None:
    parsed = ParseResult()
    tracker = Guards(parsed)
    parsed.commands.append(SimpleCommand(("a",), "bash"))
    tracker.link("&&")
    tracker.enter("if")
    tracker.branch("if")
    parsed.commands.append(SimpleCommand(("b",), "bash"))
    tracker.enter("loop", "loop")
    parsed.commands.append(SimpleCommand(("c",), "bash"))
    tracker.finish()
    assert guards(parsed) == [(1, 3, "maybe"), (1, 3, "maybe"), (2, 3, "loop")]
    # The innermost one was closed first.
    assert [parsed.guards[number] for number in range(3)] == ["loop", "maybe", "maybe"]


# ---------------------------------------------------------------------------
# PowerShell
# ---------------------------------------------------------------------------
POWERSHELL = [
    ("a; b", []),
    ("a && b; c || d", [(1, 2, "maybe"), (3, 4, "maybe")]),
    ("a &&\n  b\nc", [(1, 2, "maybe")]),
    ("if ($x) { a }; b", [(0, 1, "maybe")]),
    (
        "if ($x) { a } elseif ($y) { b } else { c }",
        [(0, 1, "maybe"), (1, 2, "maybe"), (2, 3, "maybe")],
    ),
    ("if ($x) { a }\nelse { b }", [(0, 1, "maybe"), (1, 2, "maybe")]),
    ("switch ($x) { 1 { a } }", [(0, 1, "loop"), (0, 1, "maybe")]),
    ("foreach ($d in $all) { a; b }", [(0, 2, "loop")]),
    ("while ($x) { a }", [(0, 1, "loop")]),
    ("do { a } until ($x)", [(0, 1, "loop")]),
    ("for ($i = 0; $i -lt 3; $i++) { a }", [(0, 1, "loop")]),
    # ``try`` and ``finally`` run once; ``catch`` may not.
    ("try { a } catch { b } finally { c }", [(1, 2, "maybe")]),
    ("trap { a }", [(0, 1, "maybe")]),
    # A block that is called where it stands runs once.
    ("& { a; b }", []),
    (". { a }", []),
    # Handed to a command, stored, or part of an expression: any number of
    # times, here or elsewhere.
    ("$sb = { a }", [(0, 1, "loop")]),
    ("{ a }", [(0, 1, "loop")]),
    ("Start-Job { a }", [(0, 1, "loop")]),
    ("Invoke-Command -ScriptBlock { a } -ComputerName h", [(0, 1, "loop")]),
    ("Get-ChildItem | ForEach-Object { a }", [(1, 2, "loop")]),
    ("pwsh -Command { a }", [(0, 1, "loop")]),
    ("$items.ForEach{ a }", [(0, 1, "loop")]),
    ("$items.ForEach({ a })", [(0, 1, "loop")]),
    ("@{ go = { a } }", [(0, 1, "loop")]),
    ("& $tool { a }", [(0, 1, "loop")]),
    ("function Go { a; b }", [(0, 2, "defined")]),
    ("filter Go { a }", [(0, 1, "defined")]),
    ("function Go { if ($x) { a } }", [(0, 1, "defined"), (0, 1, "maybe")]),
]


@pytest.mark.parametrize(("command", "expected"), POWERSHELL)
def test_powershell_ranges(command: str, expected: list[tuple[int, int, str]]) -> None:
    parsed = parse_shell(command, "powershell")
    assert not [reason for reason in parsed.dynamic if reason.kind == "parse_error"]
    assert guards(parsed) == expected


NAMES = [
    ("function Go { a }", "go"),
    ("function Go-There($x) { a }", "go-there"),
    ("function global:Go { a }", "go"),
    ("function script:Go ($x) { a }", "go"),
    ("filter Skip-Empty { a }", "skip-empty"),
]


@pytest.mark.parametrize(("command", "name"), NAMES)
def test_a_powershell_function_carries_its_name_in_lower_case(
    command: str, name: str
) -> None:
    assert list(parse_shell(command, "powershell").named.values()) == [name]


CD_FUNCTIONS = [
    ("cd..", ("Set-Location", "..")),
    ("cd\\", ("Set-Location", "\\")),
    ("cd~", ("Set-Location", "~")),
    ("CD..", ("Set-Location", "..")),
    ("cd ..", ("Set-Location", "..")),
    # Only the three functions PowerShell defines.
    ("cd...", ("cd...",)),
    ("'cd..'", None),
]


@pytest.mark.parametrize(("command", "argv"), CD_FUNCTIONS)
def test_the_cd_functions_of_powershell(
    command: str, argv: tuple[str, ...] | None
) -> None:
    parsed = parse_shell(command, "powershell")
    assert [c.argv for c in parsed.commands] == ([argv] if argv else [])


START_PROCESS = [
    (r"Start-Process git -ArgumentList status -WorkingDirectory:C:\srv", (r"C:\srv",)),
    (r"Start-Process git -ArgumentList status -WorkingDirectory C:\srv", (r"C:\srv",)),
    (r"Start-Process git -ArgumentList status -wo:C:\srv", (r"C:\srv",)),
    (
        r"Start-Process -FilePath:git -ArgumentList:status "
        r"-WorkingDirectory:'C:\my dir'",
        (r"C:\my dir",),
    ),
    ("Start-Process git -ArgumentList status -WorkingDirectory:$where", ("?",)),
    ("Start-Process git -ArgumentList status", ()),
]


@pytest.mark.parametrize(("command", "chdir"), START_PROCESS)
def test_start_process_reads_a_parameter_with_its_value_attached(
    command: str, chdir: tuple[str, ...]
) -> None:
    parsed = parse_shell(command, "powershell")
    assert parsed.commands[-1].argv == ("git", "status")
    assert parsed.commands[-1].chdir == chdir


# ---------------------------------------------------------------------------
# cmd.exe
# ---------------------------------------------------------------------------
CMD = [
    ("a & b", []),
    ("a && b || c & d", [(1, 2, "maybe"), (2, 3, "maybe")]),
    ("cd a && cd b & c", []),
    # The rest of the line belongs to the ``if``.
    ("if exist x cd x & dir", [(0, 2, "maybe")]),
    ("if exist x (cd x) & dir", [(0, 1, "maybe")]),
    ("if exist x (cd x) else (cd y) & dir", [(0, 1, "maybe"), (1, 2, "maybe")]),
    ("if exist x (cd x) else cd y & dir", [(0, 1, "maybe"), (1, 3, "maybe")]),
    ("(if exist x cd x) & dir", [(0, 1, "maybe")]),
    ("if not defined X if exist y cd y", [(0, 1, "maybe")]),
    ("for %i in (a b) do cd %i & dir", [(0, 2, "loop")]),
    ("for %i in (a b) do (cd %i & dir) & echo", [(0, 2, "loop")]),
    ("for /f %i in ('dir /b') do echo %i", [(1, 2, "loop")]),
]


@pytest.mark.parametrize(("command", "expected"), CMD)
def test_cmd_ranges(command: str, expected: list[tuple[int, int, str]]) -> None:
    assert guards(parse_shell(command, "cmd")) == expected


LINES = [
    (
        "echo hi\nrmdir /s /q C:/Users",
        [("echo", "hi"), ("rmdir", "/s", "/q", "C:/Users")],
    ),
    ("echo hi\r\ngit reset --hard\r\n", [("echo", "hi"), ("git", "reset", "--hard")]),
    ("cd C:/tmp\ngit reset --hard", [("cd", "C:/tmp"), ("git", "reset", "--hard")]),
    ("(\necho a\necho b\n)", [("echo", "a"), ("echo", "b")]),
    # A caret at the end of a line carries the command on.
    ("git reset ^\n  --hard", [("git", "reset", "--hard")]),
    ("git reset ^\r\n--hard & echo x", [("git", "reset", "--hard"), ("echo", "x")]),
    # A quote does not reach past the end of its line.
    ('echo "a\ngit reset --hard', [("echo", "a"), ("git", "reset", "--hard")]),
    ("echo a ^& echo b", [("echo", "a", "&", "echo", "b")]),
    ("echo a > out.txt\necho b", [("echo", "a"), ("echo", "b")]),
]


@pytest.mark.parametrize(("script", "expected"), LINES)
def test_a_new_line_starts_a_new_command_in_cmd(
    script: str, expected: list[tuple[str, ...]]
) -> None:
    parsed = parse_shell(script, "cmd")
    assert [command.argv for command in parsed.commands] == expected


GLUED = [
    ("cd..", ("cd", "..")),
    ("cd\\", ("cd", "\\")),
    ("cd/d C:\\srv", ("cd", "/d", "C:\\srv")),
    ("cd..\\..\\x", ("cd", "..\\..\\x")),
    ("cd\\srv\\repo", ("cd", "\\srv\\repo")),
    ("cd.", ("cd", ".")),
    ("CHDIR..", ("CHDIR", "..")),
    ("@cd..", ("cd", "..")),
    ("if exist x cd..", ("cd", "..")),
    ("cd ..", ("cd", "..")),
    ("cdx", ("cdx",)),
    ("cd-rom", ("cd-rom",)),
]


@pytest.mark.parametrize(("command", "argv"), GLUED)
def test_cmd_reads_cd_without_a_blank(command: str, argv: tuple[str, ...]) -> None:
    assert parse_shell(command, "cmd").commands[-1].argv == argv
