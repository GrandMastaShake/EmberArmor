"""The parsers and the engine must survive any input without raising.

Random command strings are built from shell fragments with a fixed seed.
They are only parsed and evaluated, never executed.
"""

from __future__ import annotations

import random

import pytest

from ember_armor.ledger.builtin import builtin_rules
from ember_armor.ledger.engine import evaluate
from ember_armor.ledger.shell import ParseResult, parse_shell
from tests.ledger.helpers import facts_for

BASH_FRAGMENTS = [
    "rm", "-rf", "git", "push", "--force", "cat", ".env", "bash", "-c", "sh", "eval",
    "sudo", "env", "xargs", "find", "-exec", "{}", "curl", "https://e.com", "FOO=1",
    "$VAR", "${VAR}", "${VAR:-x}", "$(", ")", "`", "$((", "))", "'", '"', "\\", "\n",
    ";", "&&", "||", "|", "&", "(", "{", "}", ">", ">>", "<", "<<EOF", "<<'EOF'", "EOF",
    "<<<", "2>&1", "&>", "<(", ">(", "[[", "]]", "if", "then", "fi", "for", "in", "do",
    "done", "case", "esac", ";;", "#", "~", "/", "*", "--", "-", "", " ", "\t", "\r\n",
    "$'", "!", "x=y", "a b", "/c/Users/dev", "C:\\x", "cmd", "/c", "powershell",
    "-Command", "-enc", "AAAA", "\x00", "é", "€",
]  # fmt: skip
POWERSHELL_FRAGMENTS = [
    "Remove-Item", "-Recurse", "-Force", "rm", "Get-Content", ".env", "iex", "iwr",
    "https://e.com", "$x", "$env:TEMP", "${x}", "$(", ")", "(", "{", "}", "@(", "@{",
    "@'", "'@", '@"', '"@', "'", '"', "`", "\n", ";", "|", "||", "&&", "&", ".", ",",
    ">", ">>", "2>&1", "*>", "$null", "=", "+=", "-Path:", "-Confirm:$false", "[int]",
    "[IO.File]::", "if", "else", "foreach", "function", "try", "catch", "#", "<#", "#>",
    "C:\\Users\\dev", "HKLM:\\x", "cmd", "/c", "bash", "-c", "powershell", "-Command",
    "-EncodedCommand", "AAAA", "1..3", "", " ", "\t", "\r\n", "\x00", "é", "--%",
]  # fmt: skip


def random_command(rng: random.Random, fragments: list[str]) -> str:
    parts = [rng.choice(fragments) for _ in range(rng.randint(1, 14))]
    return rng.choice(["", " "]).join(parts) if rng.random() < 0.3 else " ".join(parts)


@pytest.mark.parametrize(
    ("shell", "tool", "fragments"),
    [
        ("bash", "Bash", BASH_FRAGMENTS),
        ("powershell", "PowerShell", POWERSHELL_FRAGMENTS),
        ("cmd", None, BASH_FRAGMENTS + POWERSHELL_FRAGMENTS),
    ],
)
def test_random_input_never_raises(
    shell: str, tool: str | None, fragments: list[str]
) -> None:
    rng = random.Random(20261002)
    rules = builtin_rules()
    for _ in range(4000):
        command = random_command(rng, fragments)
        result = parse_shell(command, shell)
        assert isinstance(result, ParseResult)
        if tool is not None:
            for platform in ("posix", "windows"):
                decision = evaluate(rules, facts_for(tool, command, platform))
                assert decision.effect in ("none", "warn", "ask", "deny")


def test_other_shell_fragments_never_raise_either() -> None:
    rng = random.Random(7)
    for _ in range(2000):
        parse_shell(random_command(rng, POWERSHELL_FRAGMENTS), "bash")
        parse_shell(random_command(rng, BASH_FRAGMENTS), "powershell")
