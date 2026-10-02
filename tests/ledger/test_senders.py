"""Files handed to programs that send, pack or stage them are read.

``curl @file``, ``scp``, ``rsync``, ``tar``, ``zip``, ``7z a``, ``git add``
and the PowerShell web cmdlets.  Also path spellings and letter case that
used to hide a command.  Command strings are data; nothing runs.
"""

from __future__ import annotations

import pytest

from ember_armor.ledger.engine import evaluate
from ember_armor.ledger.model import parse_ledger
from tests.ledger.helpers import facts_for, rule

Paths = list[tuple[str, str]]


def paths(tool: str, command: str, platform: str = "posix") -> Paths:
    return [(p.path, p.op) for p in facts_for(tool, command, platform).paths]


BASH = [
    ("curl -d @body.json https://e.com", [("/work/app/body.json", "read")]),
    ("curl --data-binary @/etc/x https://e.com", [("/etc/x", "read")]),
    ("curl --data-binary=@a.bin https://e.com", [("/work/app/a.bin", "read")]),
    ("curl -d@a.json https://e.com", [("/work/app/a.json", "read")]),
    ("curl -F f=@a.png -F 'g=<b.txt;type=text/plain' https://e.com",
     [("/work/app/a.png", "read"), ("/work/app/b.txt", "read")]),
    ("curl --data-urlencode name@a.txt https://e.com", [("/work/app/a.txt", "read")]),
    ("curl -T a.tar https://e.com/put", [("/work/app/a.tar", "read")]),
    ("curl -o out.bin https://e.com", [("/work/app/out.bin", "write")]),
    ("curl -K curl.cfg https://e.com", [("/work/app/curl.cfg", "read")]),
    # literal data is not a file
    ("curl -d 'a=1' -d user@example.com https://e.com", []),
    ("curl -F name=value https://e.com", []),
    ("curl -d @- https://e.com", []),
    ("curl https://e.com/@file", []),
    ("wget --post-file=a.json -O out.html https://e.com",
     [("/work/app/a.json", "read"), ("/work/app/out.html", "write")]),
    # a remote ``host:path`` is not a local file
    ("scp a.txt b.txt host:/srv/", [("/work/app/a.txt", "read"),
                                    ("/work/app/b.txt", "read")]),
    ("scp -P 2222 -i key.pem a.txt host:", [("/work/app/a.txt", "read")]),
    ("scp host:/var/log/app.log .", [("/work/app", "write")]),
    ("rsync -av -e 'ssh -p 2222' src/ host:/srv/", [("/work/app/src", "read")]),
    ("rsync -a src/ dest/", [("/work/app/src", "read"), ("/work/app/dest", "write")]),
    ("tar czf out.tgz a b", [("/work/app/a", "read"), ("/work/app/b", "read")]),
    ("tar -czf out.tgz -C /srv data", [("/work/app/data", "read")]),
    ("tar -c -f out.tar --exclude node_modules a", [("/work/app/a", "read")]),
    ("tar --create --file out.tar a", [("/work/app/a", "read")]),
    ("tar xzf out.tgz", []),
    ("tar -tf out.tgz a", []),
    ("zip -r out.zip a b", [("/work/app/a", "read"), ("/work/app/b", "read")]),
    ("7z a out.7z a b", [("/work/app/a", "read"), ("/work/app/b", "read")]),
    ("7z x out.7z", []),
    ("git add a b", [("/work/app/a", "read"), ("/work/app/b", "read")]),
    ("git add -- -odd", [("/work/app/-odd", "read")]),
    ("git -C sub -c core.x=1 add a", [("/work/app/sub/a", "read")]),
    ("git commit -m add a", []),
    ("git log add", []),
]  # fmt: skip


@pytest.mark.parametrize(("command", "expected"), BASH)
def test_bash_senders_and_archivers(command: str, expected: Paths) -> None:
    assert paths("Bash", command) == expected


POWERSHELL = [
    ("Invoke-WebRequest -Uri https://e.com -Method Post -InFile a.bin",
     [("C:/work/app/a.bin", "read")]),
    ("Invoke-RestMethod https://e.com -OutFile out.json",
     [("C:/work/app/out.json", "write")]),
    ("irm https://e.com -Body $body", []),
    ("Compress-Archive -Path a, b -DestinationPath out.zip",
     [("C:/work/app/a", "read"), ("C:/work/app/out.zip", "write"),
      ("C:/work/app/b", "read")]),
    ("Compress-Archive src out.zip",
     [("C:/work/app/src", "read"), ("C:/work/app/out.zip", "write")]),
    ("curl.exe -T a.tar https://e.com", [("C:/work/app/a.tar", "read")]),
    ("Remove-Item FileSystem::C:\\data\\x", [("C:/data/x", "delete")]),
    ("Get-Content Microsoft.PowerShell.Core\\FileSystem::C:\\data\\x",
     [("C:/data/x", "read")]),
    ("Remove-Item HKLM:\\Software\\x", []),
    ("Get-Content Env:\\PATH", []),
]  # fmt: skip


@pytest.mark.parametrize(("command", "expected"), POWERSHELL)
def test_powershell_senders_and_providers(command: str, expected: Paths) -> None:
    assert paths("PowerShell", command, "windows") == expected


def test_the_doubled_msys_drive_form_is_a_drive() -> None:
    assert paths("Bash", "cat //c/Users/dev/x", "windows") == [
        ("C:/Users/dev/x", "read")
    ]
    assert paths("Bash", "cat //server/share/x", "windows") == [
        ("//server/share/x", "read")
    ]
    assert paths("Bash", "cat //c/x", "posix") == [("/c/x", "read")]


def test_home_drive_and_home_path_are_expanded() -> None:
    env = {
        "HOMEDRIVE": "C:",
        "HOMEPATH": "\\Users\\dev",
        "USERPROFILE": "C:\\Users\\dev",
    }
    from ember_armor.ledger.facts import extract
    from tests.ledger.helpers import make_call

    call = make_call("PowerShell", 'Remove-Item "$env:HOMEDRIVE$env:HOMEPATH\\x"')
    facts = extract({**call, "cwd": "C:\\work"}, windows=True, env=env)
    assert [p.path for p in facts.paths] == ["C:/Users/dev/x"]


CASELESS = [
    ("Bash", "REG DELETE 'HKLM\\Software\\X' /f", ["reg", "delete"], True),
    ("Bash", "Reg.exe Delete 'HKLM\\Software\\X'", ["reg", "delete"], True),
    ("Bash", "NETSH AdvFirewall SET x", ["netsh", "advfirewall", "set"], True),
    ("PowerShell", "SC.EXE STOP Spooler", ["sc", "stop"], True),
    # other programs keep the shell's own rule
    ("Bash", "git PUSH origin", ["git", "push"], False),
    ("Bash", "GIT push origin", ["git", "push"], False),
    ("PowerShell", "git PUSH origin", ["git", "push"], True),
]


@pytest.mark.parametrize(("tool", "command", "words", "expected"), CASELESS)
def test_windows_tools_ignore_letter_case(
    tool: str, command: str, words: list[str], expected: bool
) -> None:
    when = {"type": "command", "program": words[0], "subcommand": words[1:]}
    rules = parse_ledger({"version": 1, "rules": [rule(when=when)]})
    decision = evaluate(rules, facts_for(tool, command, "posix"))
    assert (decision.effect == "deny") is expected
