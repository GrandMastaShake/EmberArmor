"""Statements the parsers used to drop, skip or leave wrapped.

PowerShell casts, typed and multiple assignments, hashtable values, method
arguments and wrappers; Bash substitutions inside ``[[ ]]``, ``${x:-...}``,
arithmetic and unquoted here-documents; ``coproc``, ``trap`` and ``time``.
Command strings are data; nothing runs.
"""

from __future__ import annotations

import pytest

from ember_armor.ledger.shell import ParseResult, parse_shell

GIT = ["git", "reset", "--hard"]


def bash(command: str) -> ParseResult:
    return parse_shell(command, "bash")


def powershell(command: str) -> ParseResult:
    return parse_shell(command, "powershell")


def argvs(result: ParseResult) -> list[list[str]]:
    return [list(command.argv) for command in result.commands]


def kinds(result: ParseResult) -> list[str]:
    return [reason.kind for reason in result.dynamic]


# ---------------------------------------------------------------------------
# PowerShell: nothing in brackets is skipped
# ---------------------------------------------------------------------------
PS_EXTRACTED = [
    "[void](git reset --hard)",
    "[void] (git reset --hard)",
    "[string]$r = git reset --hard",
    "[string]$r=git reset --hard",
    "$a, $b = git reset --hard",
    "$a = $b = git reset --hard",
    "$a=$b=git reset --hard",
    "$x = @{ a = (git reset --hard) }",
    "$x = @{ a = git reset --hard }",
    "$x = @{a=git reset --hard}",
    "$p.Add((git reset --hard))",
    "[void]$p.Add((git reset --hard))",
    "$x[(git reset --hard)]",
    "@(1,2).ForEach({ git reset --hard })",
    "$x = [int](git reset --hard)",
    "[System.IO.File]::WriteAllText('a', (git reset --hard))",
    "!(git reset --hard)",
    "return git reset --hard",
    "return $x = git reset --hard",
    "& { param($force) git reset --hard }",
    "function f { [CmdletBinding()]param($a) git reset --hard }",
    '$x = @"\nstate: $(git reset --hard)\n"@',
    "sudo git reset --hard",
    "gsudo -n git reset --hard",
    "wsl git reset --hard",
    "wsl -d Ubuntu -- git reset --hard",
    "Start-Process git -ArgumentList 'reset','--hard'",
    "Start-Process git 'reset --hard' -Wait",
    "Start-Process -FilePath git -ArgumentList 'reset --hard' -NoNewWindow",
    "Start-Process pwsh -ArgumentList '-NoProfile','-Command','git reset --hard'",
    "Start-Process cmd -ArgumentList '/c git reset --hard'",
    "$g = 'git'; & $g reset --hard",
    "$h = '--hard'; git reset $h",
    "cmd /c \"for /f %i in ('git reset --hard') do echo %i\"",
]


@pytest.mark.parametrize("command", PS_EXTRACTED)
def test_powershell_finds_the_command(command: str) -> None:
    result = powershell(command)
    assert GIT in argvs(result)
    assert "parse_error" not in kinds(result)


PS_EXACT = [
    ("[void]$list.Add('x')", []),
    ("$h = @{ format = 'C:'; Path = 'x' }", []),
    ("$o = [pscustomobject]@{ Name = 'a' }\nGet-Date", [["Get-Date"]]),
    ("$a, $b = 1, 2", []),
    ("$x = 5; $x += 1; $y = $x * 2", []),
    (
        "Remove-Item x \u2013Recurse \u2014Force",
        [["Remove-Item", "x", "-Recurse", "-Force"]],
    ),
    (
        "Microsoft.PowerShell.Management\\Remove-Item x -Recurse",
        [["Remove-Item", "x", "-Recurse"]],
    ),
    ("npx -y vercel@latest rm my-app", [["vercel", "rm", "my-app"]]),
    ("sudo Remove-Item x -Recurse", [["Remove-Item", "x", "-Recurse"]]),
    ("wsl --shutdown", [["wsl", "--shutdown"]]),
    ('"text" > out.txt', [[]]),
    ('Remove-Item "$($env:USERPROFILE)\\x"', [["Remove-Item", "$env:USERPROFILE\\x"]]),
    # A cmdlet never takes a parameter name from a variable.
    (
        "$w = '-WhatIf'; Remove-Item src -Recurse $w",
        [["Remove-Item", "src", "-Recurse", "$w"]],
    ),
    ("$m = 'fix'; git commit -m $m", [["git", "commit", "-m", "fix"]]),
]


@pytest.mark.parametrize(("command", "expected"), PS_EXACT)
def test_powershell_statements(command: str, expected: list[list[str]]) -> None:
    result = powershell(command)
    assert argvs(result) == expected
    assert result.dynamic == []


def test_a_redirection_of_an_expression_is_kept() -> None:
    (command,) = powershell('"mode" > C:\\x\\config.json').commands
    assert [r.target for r in command.redirects] == ["C:\\x\\config.json"]


def test_powershell_marks_what_it_cannot_follow() -> None:
    assert kinds(powershell("sudo $cmd --force")) == ["variable_command"]
    assert kinds(powershell("Start-Process $exe")) == ["variable_command"]
    marked = powershell("Start-Process powershell -ArgumentList $a")
    assert kinds(marked) == ["nested_dynamic"]
    assert kinds(powershell("sudo " * 40 + "git status")) == ["parse_error"]
    assert kinds(powershell("[void](git status")) == ["parse_error"]


def test_typed_and_multiple_assignments_are_not_known_values() -> None:
    result = powershell("[string]$r = 'x'; $a, $b = 1, 2; $h.k = 'v'; $ok = 'y'")
    assert result.unknown == {"r", "a", "b", "h"}
    assert result.variables == {"ok": "y"}


# ---------------------------------------------------------------------------
# Bash: substitutions run wherever the shell expands
# ---------------------------------------------------------------------------
BASH_EXTRACTED = [
    "[[ -n $(git reset --hard) ]]",
    '[[ "$(git reset --hard)" == x ]] && ls',
    "echo ${x:-$(git reset --hard)}",
    'echo "${x:=$(git reset --hard)}"',
    "echo ${x:+`git reset --hard`}",
    "echo $(( $(git reset --hard) + 1 ))",
    "(( n = $(git reset --hard) ))",
    "$((cd sub; git reset --hard))",
    "((cd sub; git reset --hard) && (ls))",
    "cat <<EOF\n$(git reset --hard)\nEOF",
    "cat <<EOF\n`git reset --hard`\nEOF",
    "cat <<-EOF\n\t$(git reset --hard)\n\tEOF",
    "bash <<EOF | tee log\ngit reset --hard\nEOF",
    "coproc git reset --hard",
    "coproc W { git reset --hard; }",
    "trap 'git reset --hard' EXIT",
    'trap "git reset --hard" INT TERM',
    "trap -- 'git reset --hard' EXIT",
    "time { git reset --hard; }",
    "time -p git reset --hard",
    'eval "X=1; git reset --hard"',
    'sh -c "cd $(pwd) && git reset --hard"',
    "find . -exec sudo git reset --hard \\;",
    "find . -exec sh -c 'git reset --hard' \\;",
    "wsl git reset --hard",
    "wsl -e git reset --hard",
    "uv run git reset --hard",
]


@pytest.mark.parametrize("command", BASH_EXTRACTED)
def test_bash_finds_the_command(command: str) -> None:
    result = bash(command)
    assert GIT in argvs(result)
    assert "parse_error" not in kinds(result)


BASH_EXACT = [
    ("echo $(( a + b )) $((i+1)) $(( n * (m + 1) ))", 1),
    ("(( i++ )); echo $i", 1),
    ("for ((i=0;i<3;i++)); do echo $i; done", 1),
    ("cat <<'EOF'\n$(git reset --hard) `rm -rf x`\nEOF", 1),
    ('cat <<"EOF"\n$(git reset --hard)\nEOF', 1),
    ("cat <<EOF\ncost: \\$(5)\nEOF", 1),
    ("trap - EXIT", 1),
    ("trap '' INT", 1),
    ("trap -l", 1),
    ("wsl --shutdown", 1),
    ("[[ -d x && ! -f y ]] && echo ok", 1),
]


@pytest.mark.parametrize(("command", "count"), BASH_EXACT)
def test_bash_adds_no_command_where_none_runs(command: str, count: int) -> None:
    result = bash(command)
    assert len(result.commands) == count
    assert result.dynamic == []


def test_a_script_with_substitutions_is_read_as_written_and_marked() -> None:
    result = bash('bash -c "cd $(pwd) && git push --force"')
    assert ["git", "push", "--force"] in argvs(result)
    assert "nested_dynamic" in kinds(result)
    # Nothing of a script that is one expansion is known.
    assert kinds(bash('bash -c "$SCRIPT"')) == ["nested_dynamic"]
    assert kinds(bash('eval "$CMD"')) == ["eval"]


def test_a_program_named_through_known_variables_is_resolved() -> None:
    result = bash("T=git; D=/usr/bin; $D/$T reset --hard")
    assert argvs(result) == [["/usr/bin/git", "reset", "--hard"]]
    assert result.dynamic == []
    assert kinds(bash("T=$(which git); $T reset --hard")) == ["variable_command"]


def test_stacked_wrappers_beyond_the_cap_are_a_parse_error() -> None:
    result = bash("sudo " * 40 + "git reset --hard")
    assert kinds(result) == ["parse_error"]
    assert len(result.commands) == 1
    assert kinds(bash("sudo " * 32 + "git reset --hard")) == []
    assert argvs(bash("sudo " * 32 + "git reset --hard")) == [GIT]


def test_assigned_names_are_recorded() -> None:
    result = bash(
        "A=1; B=2 make; export C=3; env D=4 E=5 ls; unset F; declare -x G=7; "
        "H+=x; sudo env I=1 ls"
    )
    assert result.assigned == ["A", "B", "C", "D", "E", "F", "G", "H", "I"]
    result = powershell(
        "$env:A = 'x'; $b = 'y'; [Environment]::SetEnvironmentVariable('C', 'z'); "
        "$env:D += ';w'"
    )
    assert result.assigned == ["A", "C", "D"]
    nested = bash("bash -c 'X=1 make'")
    assert nested.assigned == ["X"]
