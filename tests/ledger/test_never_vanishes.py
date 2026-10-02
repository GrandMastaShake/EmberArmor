"""A statement the parsers cannot turn into commands must never vanish.

A known destructive command is wrapped in every construct the Bash and
PowerShell parsers know, one construct inside another, and the built-in pack
must never answer ``none``: either the command is found, or the call is
marked ``parse_error`` and asked about.

The command strings are only parsed.  They are never executed.
"""

from __future__ import annotations

import itertools

import pytest

from ember_armor.ledger.builtin import builtin_rules
from ember_armor.ledger.engine import evaluate
from ember_armor.ledger.shell import parse_shell
from tests.ledger.helpers import facts_for

BASH_COMMANDS = ["git reset --hard", "rm -rf src"]
#: ``{}`` is where the wrapped command goes.
BASH_CONSTRUCTS = [
    "{}",
    "{};",
    "true && {}",
    "false || {}",
    "ls; {}",
    "ls | {}",
    "{} | cat",
    "{} || true",
    "{} && echo ok",
    "{} &",
    "{} > /dev/null 2>&1",
    "{} 2>&1 | tee log.txt",
    "\n{}\n",
    "# note\n{}",
    "echo hi # note\n{}",
    "{} # note",
    "X=1; {}",
    "({})",
    "(cd . && {})",
    "{{ {}; }}",
    "$({})",
    "echo $({})",
    'echo "$({})"',
    "echo `{}`",
    'echo "`{}`"',
    "x=$({})",
    "x=`{}`",
    'x="$({})"',
    "export x=$({})",
    "local x=$({})",
    "arr=($({}))",
    "if {}; then :; fi",
    "if true; then {}; fi",
    "if false; then :; else {}; fi",
    "if false; then :; elif {}; then :; fi",
    "if false; then :; elif true; then {}; fi",
    "if [[ -d x ]]; then {}; fi",
    "if [ -d x ]; then {}; fi",
    "while {}; do break; done",
    "while true; do {}; break; done",
    "until {}; do :; done",
    "for i in 1 2; do {}; done",
    "for i in $({}); do :; done",
    "for ((i=0;i<1;i++)); do {}; done",
    "select x in a; do {}; break; done",
    "case x in x) {} ;; esac",
    "case x in a|b) : ;; *) {} ;; esac",
    "case $({}) in *) : ;; esac",
    "f() {{ {}; }}; f",
    "function f {{ {}; }}; f",
    "! {}",
    "time {}",
    "bash -c '{}'",
    "bash -lc '{}'",
    'sh -c "{}"',
    "zsh -c '{}'",
    "eval '{}'",
    'eval "{}"',
    "bash <<'EOF'\n{}\nEOF",
    "bash <<EOF\n{}\nEOF",
    "bash <<EOF | tee log\n{}\nEOF",
    "sh -s <<'EOF'\n{}\nEOF",
    "bash <<< '{}'",
    "cat <<EOF\n$({})\nEOF",
    "cat <<EOF\n`{}`\nEOF",
    "cat <<-EOF\n\t$({})\n\tEOF",
    "cat <<EOF > out.txt\ntext $({}) text\nEOF\necho done",
    "[[ -n $({}) ]]",
    '[[ -n "$({})" ]] && ls',
    "[[ $({}) == x ]]",
    "[[ -f a ]] && {}",
    '[ -n "$({})" ]',
    'test -n "$({})"',
    "echo ${{x:-$({})}}",
    "echo ${{x:=$({})}}",
    "echo ${{x:+$({})}}",
    'echo "${{x:-$({})}}"',
    "echo ${{x:-`{}`}}",
    "echo $(( $({}) + 1 ))",
    'echo "$(( `{}` ))"',
    "(( x = $({}) ))",
    "(( 1 )) && {}",
    "(({}) && (ls))",
    "$(({}))",
    "coproc P {{ {}; }}",
    "trap '{}' EXIT",
    'trap "{}" INT TERM',
    "trap -- '{}' EXIT",
    "cat <({})",
    "diff <({}) <(ls)",
    "echo x > >({})",
    "cd . && {}",
    'echo "$(echo "$({})")"',
    "X=$(mktemp -d); {}",
]
#: Constructs that run one simple command: only another of them fits inside.
BASH_PREFIXES = [
    "A=1 B=2 {}",
    "sudo {}",
    "sudo -u root {}",
    "sudo -E env A=1 {}",
    "env A=1 {}",
    "nohup {} &",
    "exec {}",
    "command {}",
    "timeout 5 {}",
    "nice -n 5 {}",
    "stdbuf -oL {}",
    "ls | xargs {}",
    "wsl {}",
    "wsl -e {}",
    "wsl -d Ubuntu -- {}",
    "find . -name x -exec {} \\;",
    "coproc {}",
]
#: Constructs that only take a native program (``rm`` is not one in cmd.exe).
BASH_NATIVE_CONSTRUCTS = ['cmd //c "{}"', 'cmd /c "{}"']
PS_COMMANDS = ["git reset --hard", "Remove-Item -Recurse -Force src"]
PS_CONSTRUCTS = [
    "{}",
    "{};",
    "ls; {}",
    "cd x && {}",
    "{} || Write-Host no",
    "{} | Out-Null",
    "{} > $null",
    "{} 2>&1",
    "{} | Out-File log.txt",
    "# note\n{}",
    "<# note #> {}",
    "{} # note",
    "$ErrorActionPreference = 'Stop'; {}",
    "& {{ {} }}",
    ". {{ {} }}",
    "({})",
    "$({})",
    "@({})",
    "$x = {}",
    "$x={}",
    "$x = ({})",
    "$x = $({})",
    "$x = @({})",
    "$null = {}",
    "$x += {}",
    "$x[0] = {}",
    "$x.y = {}",
    "$a, $b = {}",
    "$env:X = {}",
    "[void]({})",
    "[void] ({})",
    "[string]$r = {}",
    "[string]$r=({})",
    "[string[]]$r = {}",
    "$x = [int]({})",
    "$x = @{{ a = ({}) }}",
    "$x = @{{ a = {} }}",
    "$x = @{{ a = 1; b = {{ {} }} }}",
    "$x = @{{\n  a = 1\n  b = ({})\n}}",
    "$x = [pscustomobject]@{{ a = ({}) }}",
    "$x = [ordered]@{{ a = $({}) }}",
    "Invoke-RestMethod -Uri x -Headers @{{ a = ({}) }}",
    "$p.Add(({}))",
    "[void]$p.Add(({}))",
    "$p.Add('a', ({}))",
    "$x[({})]",
    "[System.IO.File]::WriteAllText('a', ({}))",
    "[Math]::Max(1, ({}))",
    "@(1,2).ForEach({{ {} }})",
    "$l.ForEach({{ {} }})",
    "$l.Where({{ {} }})",
    "1..3 | ForEach-Object {{ {} }}",
    "1..3 | % {{ {} }}",
    "1..3 | foreach {{ {} }}",
    "Get-ChildItem | Where-Object {{ {} }}",
    "if ($true) {{ {} }}",
    "if ($false) {{ }} else {{ {} }}",
    "if ($false) {{ }} elseif ($true) {{ {} }}",
    "if ({}) {{ }}",
    "if (-not ({})) {{ }}",
    "while ($true) {{ {}; break }}",
    "while ({}) {{ break }}",
    "do {{ {} }} while ($false)",
    "do {{ {} }} until ($true)",
    "for ($i = 0; $i -lt 1; $i++) {{ {} }}",
    "foreach ($i in 1..2) {{ {} }}",
    "foreach ($i in {}) {{ }}",
    "switch (1) {{ 1 {{ {} }} }}",
    "switch ({}) {{ default {{ }} }}",
    "switch (1) {{ default {{ {} }} }}",
    "try {{ {} }} catch {{ }}",
    "try {{ throw 'x' }} catch {{ {} }}",
    "try {{ }} finally {{ {} }}",
    "trap {{ {} }}",
    "function f {{ {} }}; f",
    "function f {{ param($a) {} }}; f",
    "filter f {{ {} }}",
    "$sb = {{ {} }}; & $sb",
    "Invoke-Command -ScriptBlock {{ {} }}",
    "icm {{ {} }}",
    "Start-Job -ScriptBlock {{ {} }}",
    "Measure-Command {{ {} }}",
    "Write-Host ({})",
    'Write-Host "$({})"',
    '"$({})"',
    '$x = "a $({}) b"',
    '$x = @"\n$({})\n"@',
    "return {}",
    "return ({})",
    "-not ({})",
    "!({})",
    "1 + ({})",
    "'a' -eq ({})",
    "$x = if ($true) {{ {} }} else {{ 1 }}",
    "Invoke-Expression '{}'",
    'iex "{}"',
    'powershell -Command "{}"',
    "powershell -NoProfile -Command {{ {} }}",
    "pwsh -c '{}'",
    "powershell –Command '{}'",
    "Start-Process powershell -ArgumentList '-Command', '{}'",
    "Start-Process -FilePath pwsh -ArgumentList '-NoProfile -Command {}' -Wait",
]
PS_PREFIXES = ["sudo {}", "gsudo {}"]
#: Constructs that only take a native program (not a cmdlet).
PS_NATIVE_CONSTRUCTS = [
    'cmd /c "{}"',
    "npx {}",
    "Start-Process cmd -ArgumentList '/c {}'",
]


def _nests(outer: str, inner: str) -> bool:
    """True when *inner* can stand inside *outer* without breaking its quotes."""
    hole = outer.index("{}")
    quote = next((c for c in reversed(outer[:hole]) if c in "'\"`"), "")
    quoted = bool(quote) and outer[:hole].count(quote) % 2 == 1
    if "\n" in inner and (quoted or "\n" not in outer):
        return False
    if inner.rstrip().endswith(("&", ";", "note")) or inner.startswith(
        ("#", "<#", "\n")
    ):
        return False
    return not quoted or not any(char in inner for char in "'\"`")


def _decision(tool: str, command: str, platform: str) -> str:
    return evaluate(builtin_rules(), facts_for(tool, command, platform)).effect


def _cases(
    constructs: list[str], prefixes: list[str], native: list[str], commands: list[str]
) -> list[str]:
    """Every construct around each command, then one construct inside another."""
    simple = ["{}", *(p for p in prefixes if not p.startswith(("A=", "coproc")))]
    cases = [c.format(command) for c in constructs + prefixes for command in commands]
    cases += [c.format(commands[0]) for c in native]
    pairs = [*itertools.product(constructs, constructs + prefixes)]
    pairs += itertools.product(prefixes, simple)
    cases += [
        outer.format(inner.format(commands[0]))
        for outer, inner in pairs
        if _nests(outer, inner)
    ]
    return cases


def _bash_cases() -> list[str]:
    return _cases(BASH_CONSTRUCTS, BASH_PREFIXES, BASH_NATIVE_CONSTRUCTS, BASH_COMMANDS)


def _powershell_cases() -> list[str]:
    return _cases(PS_CONSTRUCTS, PS_PREFIXES, PS_NATIVE_CONSTRUCTS, PS_COMMANDS)


def test_the_generated_sets_are_large() -> None:
    assert len(_bash_cases()) > 5000
    assert len(_powershell_cases()) > 5000


@pytest.mark.parametrize("platform", ["posix", "windows"])
def test_a_wrapped_destructive_command_never_passes_in_bash(platform: str) -> None:
    missed = [
        case for case in _bash_cases() if _decision("Bash", case, platform) == "none"
    ]
    assert missed == []


def test_a_wrapped_destructive_command_never_passes_in_powershell() -> None:
    missed = [
        case
        for case in _powershell_cases()
        if _decision("PowerShell", case, "windows") == "none"
    ]
    assert missed == []


@pytest.mark.parametrize(
    ("shell", "cases"),
    [("bash", _bash_cases()), ("powershell", _powershell_cases())],
)
def test_every_generated_statement_yields_commands_or_a_mark(
    shell: str, cases: list[str]
) -> None:
    for case in cases:
        result = parse_shell(case, shell)
        assert result.commands or result.dynamic, case


CAPS = [
    ("bash", "sudo " * 40 + "git reset --hard"),
    ("bash", "env " * 33 + "rm -rf src"),
    ("powershell", "sudo " * 40 + "git reset --hard"),
    ("bash", "echo " + "{a,b}" * 12 + "; git reset --hard"),
    ("bash", "x; " * 2100 + "git reset --hard"),
    ("powershell", "x; " * 2100 + "git reset --hard"),
    ("bash", "eval " * 12 + "git reset --hard"),
    ("bash", "git reset --hard " + "a" * 200_000),
]


@pytest.mark.parametrize(
    ("shell", "command"), CAPS, ids=[f"{s}-{c[:24]}" for s, c in CAPS]
)
def test_hitting_a_cap_is_a_parse_error(shell: str, command: str) -> None:
    kinds = [reason.kind for reason in parse_shell(command, shell).dynamic]
    assert "parse_error" in kinds
    tool = "Bash" if shell == "bash" else "PowerShell"
    assert _decision(tool, command, "windows") == "ask"
