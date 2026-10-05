"""The directory each parsed command runs in.

``cd``, ``pushd``, ``popd`` and their PowerShell forms move it, a subshell or
a nested shell ends with its moves, and a program's own option names it for
one command (``git -C``, ``make -C``, ``npm --prefix``, ``pnpm -C``, ``yarn
--cwd``, ``cargo -C``, and the directory options of wrappers).  A directory
the command string does not name is unknown, never silently the old one.

The command strings below are data for the parsers.  Nothing runs them.
"""

from __future__ import annotations

import pytest

from ember_armor.ledger.audit import restore, summarise
from ember_armor.ledger.facts import ShellTool, extract
from ember_armor.ledger.paths import UNKNOWN_DIR
from ember_armor.ledger.shell import parse_shell
from ember_armor.ledger.shell.core import SimpleCommand, find_exec, find_runs
from tests.ledger.helpers import POSIX_ENV, WINDOWS_ENV, facts_for, make_call

HERE = ""  # the working directory of the call
POSIX = "/work/app"
WINDOWS = "C:/work/app"


def directories(tool: str, command: str, platform: str = "posix") -> list[str]:
    """Program and directory of each command, as ``program@directory``."""
    facts = facts_for(tool, command, platform)
    return [f"{(c.argv or ('',))[0]}@{c.cwd}" for c in facts.commands]


def last(tool: str, command: str, platform: str = "posix") -> str:
    """The directory the last command of the string runs in."""
    return facts_for(tool, command, platform).commands[-1].cwd


# ---------------------------------------------------------------------------
# cd, pushd, popd in Bash
# ---------------------------------------------------------------------------
BASH_MOVES = [
    ("git commit", HERE),
    ("cd /srv/repo && git commit", "/srv/repo"),
    ("cd sub && git commit", "/work/app/sub"),
    ("cd .. && git commit", "/work"),
    ("cd ~/proj && git commit", "/home/dev/proj"),
    ("cd && git commit", "/home/dev"),
    ("cd -P /srv/repo && git commit", "/srv/repo"),
    ("cd -- /srv/repo && git commit", "/srv/repo"),
    ("cd /srv/repo; cd sub; git commit", "/srv/repo/sub"),
    ("cd /srv/repo && cd sub && cd - && git commit", "/srv/repo"),
    ("cd /srv && cd $OLDPWD && git commit", HERE),
    ("pushd /srv/repo; git commit", "/srv/repo"),
    ("pushd /srv/repo; popd; git commit", HERE),
    ("pushd /srv/a; pushd /srv/b; popd; git commit", "/srv/a"),
    ("pushd /srv/a; cd /tmp; pushd; git commit", HERE),
    ("(cd /srv/repo && make); git commit", HERE),
    ("(cd /srv/repo && git commit)", "/srv/repo"),
    ("x=$(cd /srv/repo && pwd); git commit", HERE),
    ("bash -c 'cd /srv/repo && make'; git commit", HERE),
    ("bash -c 'cd /srv/repo && git commit'", "/srv/repo"),
    ("sh -c 'cd /srv && cd repo && git commit'", "/srv/repo"),
    ("cd /srv/repo && bash -c 'git commit'", "/srv/repo"),
    ("cd /srv/repo && bash -c 'cd sub && git commit'", "/srv/repo/sub"),
    ("{ cd /srv/repo; }; git commit", "/srv/repo"),
    ("if cd /srv/repo; then git commit; fi", "/srv/repo"),
    ("cd /srv/repo || exit 1; git commit", "/srv/repo"),
    ("DIR=/srv/repo; cd $DIR && git commit", "/srv/repo"),
    ('DIR=/srv/repo; cd "$DIR/sub" && git commit', "/srv/repo/sub"),
    ("for d in /srv/one; do cd $d && git commit; done", "/srv/one"),
    # ``eval`` runs in the shell itself: its ``cd`` stays in force.
    ('eval "cd /srv/repo"; git commit', "/srv/repo"),
    ("cd /srv/repo && sudo git commit", "/srv/repo"),
    ("cd /srv/repo && find . -name '*.py' -exec git add {} \\;", "/srv/repo"),
]


@pytest.mark.parametrize(("command", "expected"), BASH_MOVES)
def test_bash_moves_are_followed(command: str, expected: str) -> None:
    assert last("Bash", command) == expected


BASH_UNKNOWN = [
    "cd $WHERE && git commit",
    'cd "$(git rev-parse --show-toplevel)" && git commit',
    "cd `pwd`/x && git commit",
    "cd proj* && git commit",
    "cd ~other && git commit",
    "cd a b && git commit",
    "cd - && git commit",
    "popd; git commit",
    "pushd +1; git commit",
    "pushd -n /srv/repo; git commit",
    "popd -n; git commit",
    "for d in one two; do cd $d && git commit; done",
    "cd $WHERE; cd sub; git commit",
    "HOME_DIR=$(pwd); cd $HOME_DIR && git commit",
    "read target; cd $target && git commit",
    'eval "cd $WHERE"; git commit',
]


@pytest.mark.parametrize("command", BASH_UNKNOWN)
def test_a_move_the_gate_cannot_read_leaves_the_directory_unknown(command: str) -> None:
    assert last("Bash", command) == UNKNOWN_DIR


def test_an_absolute_move_makes_the_directory_known_again() -> None:
    found = directories("Bash", "cd $WHERE; git status; cd /srv/repo; git commit")
    assert found == ["cd@", "git@?", "cd@?", "git@/srv/repo"]


def test_cd_minus_returns_from_an_unknown_directory() -> None:
    assert last("Bash", "cd /srv/repo; cd $WHERE; cd -; git commit") == "/srv/repo"


def test_a_bare_cd_without_a_home_is_unknown() -> None:
    call = make_call("Bash", "cd && git commit")
    facts = extract(call, windows=False, env={})
    assert facts.commands[-1].cwd == UNKNOWN_DIR


def test_the_cd_command_itself_runs_where_the_shell_was() -> None:
    assert directories("Bash", "cd /srv/repo && git commit") == [
        "cd@",
        "git@/srv/repo",
    ]


def test_a_subshell_ends_with_its_moves_also_when_unknown() -> None:
    found = directories("Bash", "(cd $WHERE && make); git commit")
    assert found == ["cd@", "make@?", "git@"]


# ---------------------------------------------------------------------------
# The program's own directory option
# ---------------------------------------------------------------------------
OPTION_CASES = [
    ("git -C /srv/repo commit", "/srv/repo"),
    ("git -C sub commit", "/work/app/sub"),
    ("git -C /srv -C repo commit", "/srv/repo"),
    ("git -C /srv -C repo -C .. status", "/srv"),
    ("git -c user.name=x -C /srv/repo commit", "/srv/repo"),
    ("git --no-pager -C /srv/repo log", "/srv/repo"),
    ("sudo git -C /srv/repo commit", "/srv/repo"),
    ("cd /srv && git -C repo commit", "/srv/repo"),
    # After the subcommand ``-C`` is another option of git.
    ("git commit -C HEAD", HERE),
    ("git -C /srv/repo commit -C HEAD~1", "/srv/repo"),
    ("git diff -C --stat", HERE),
    ("git commit -m 'use -C /tmp here'", HERE),
    ("make -C build all", "/work/app/build"),
    ("make -Cbuild", "/work/app/build"),
    ("make --directory=build all", "/work/app/build"),
    ("make --directory build all", "/work/app/build"),
    ("make all -C build", "/work/app/build"),
    ("make -C build -C sub", "/work/app/build/sub"),
    ("gmake -j4 -C build", "/work/app/build"),
    ("make all", HERE),
    ("npm --prefix web run build", "/work/app/web"),
    ("npm --prefix=web run build", "/work/app/web"),
    ("npm run build --prefix web", "/work/app/web"),
    ("npm -C web test", "/work/app/web"),
    ("npm test -- --prefix other", HERE),
    ("pnpm -C web build", "/work/app/web"),
    ("pnpm --dir web build", "/work/app/web"),
    ("pnpm --dir=web build", "/work/app/web"),
    ("pnpm --filter api -C web build", "/work/app/web"),
    ("yarn --cwd web build", "/work/app/web"),
    ("yarn --cwd=/srv/web build", "/srv/web"),
    ("cargo -C crate build", "/work/app/crate"),
    ("cargo +nightly -C crate build", "/work/app/crate"),
    ("cargo build --release", HERE),
]


@pytest.mark.parametrize(("command", "expected"), OPTION_CASES)
def test_directory_options_move_one_command(command: str, expected: str) -> None:
    assert last("Bash", command) == expected


def test_a_directory_option_moves_only_its_own_command() -> None:
    found = directories("Bash", "git -C /srv/repo fetch && git status")
    assert found == ["git@/srv/repo", "git@"]


OPTION_UNKNOWN = [
    "git -C $REPO commit",
    'git -C "$(pwd)/x" commit',
    "git -C",
    "git --git-dir=/srv/repo/.git commit",
    "git --git-dir /srv/repo/.git --work-tree /srv/repo commit",
    "git --work-tree=/srv/repo commit",
    "make -C $BUILD",
    "npm --prefix $WEB run build",
    # After the subcommand these may belong to the script that is run.
    "pnpm build -C web",
    "pnpm run build --dir web",
    "yarn build --cwd web",
    "cargo build -C crate",
    "xargs -I{} git -C {} commit",
    "cd $WHERE && git -C sub commit",
]


@pytest.mark.parametrize("command", OPTION_UNKNOWN)
def test_a_directory_option_the_gate_cannot_follow_is_unknown(command: str) -> None:
    assert last("Bash", command) == UNKNOWN_DIR


def test_an_absolute_option_is_known_from_an_unknown_directory() -> None:
    assert last("Bash", "cd $WHERE && git -C /srv/repo commit") == "/srv/repo"


# ---------------------------------------------------------------------------
# Wrappers and nested shells that start a command somewhere else
# ---------------------------------------------------------------------------
WRAPPER_CASES = [
    ("env -C /srv/repo git commit", "/srv/repo", ("/srv/repo",)),
    ("env --chdir=/srv/repo git commit", "/srv/repo", ("/srv/repo",)),
    ("env --chdir /srv/repo FOO=1 git commit", "/srv/repo", ("/srv/repo",)),
    ("sudo -D /srv/repo git commit", "/srv/repo", ("/srv/repo",)),
    ("sudo --chdir=/srv/repo -u dev git commit", "/srv/repo", ("/srv/repo",)),
    ("pnpm -C web exec git commit", "/work/app/web", ("web",)),
    ("pnpm --dir web exec git commit", "/work/app/web", ("web",)),
    ("yarn --cwd web exec git commit", "/work/app/web", ("web",)),
    ("uv run --directory /srv/tool pytest", "/srv/tool", ("/srv/tool",)),
    ("wsl --cd /srv/repo git commit", "/srv/repo", ("/srv/repo",)),
    ("sudo -D /srv env -C repo git commit", "/srv/repo", ("/srv", "repo")),
    ("env -C /srv git -C repo commit", "/srv/repo", ("/srv",)),
    # Where ``npm exec`` starts the command under ``--prefix`` is not known.
    ("npm --prefix web exec git commit", UNKNOWN_DIR, (UNKNOWN_DIR,)),
    ("npm -C web exec -- git commit", UNKNOWN_DIR, (UNKNOWN_DIR,)),
    ("env -C $DIR git commit", UNKNOWN_DIR, ("$DIR",)),
    ("env git commit", HERE, ()),
    ("pnpm exec git commit", HERE, ()),
]


@pytest.mark.parametrize(("command", "expected", "chdir"), WRAPPER_CASES)
def test_wrappers_that_change_the_directory(
    command: str, expected: str, chdir: tuple[str, ...]
) -> None:
    facts = facts_for("Bash", command)
    assert facts.commands[-1].argv[0] in ("git", "pytest")
    assert facts.commands[-1].chdir == chdir
    assert facts.commands[-1].cwd == expected


NESTED_CASES = [
    ("env -C /srv/repo bash -c 'git commit'", "/srv/repo"),
    ("env -C /srv/repo bash -c 'cd sub && git commit'", "/srv/repo/sub"),
    ("sudo -D /srv/repo sh -c 'git commit'", "/srv/repo"),
    ("env -C /srv/repo bash <<'EOF'\ngit commit\nEOF", "/srv/repo"),
    ("env -C /srv/repo bash <<'EOF' | tee log\ngit commit\nEOF", "/srv/repo"),
    ("env -C /srv/repo bash <<< 'git commit'", "/srv/repo"),
    ("pwsh -WorkingDirectory /srv/repo -Command 'git commit'", "/srv/repo"),
    ("pwsh -wd /srv/repo -c 'git commit'", "/srv/repo"),
    ("find /srv -name .git -execdir git commit \\;", UNKNOWN_DIR),
    ("find /srv -name x -execdir sh -c 'git commit' \\;", UNKNOWN_DIR),
    ("find . -name x -exec sh -c 'cd /srv/repo && git commit' \\;", "/srv/repo"),
]


@pytest.mark.parametrize(("command", "expected"), NESTED_CASES)
def test_nested_shells_start_where_their_starter_puts_them(
    command: str, expected: str
) -> None:
    facts = facts_for("Bash", command)
    commits = [c for c in facts.commands if c.argv[:2] == ("git", "commit")]
    assert [c.cwd for c in commits] == [expected]


def test_a_nested_shell_keeps_its_moves_to_itself() -> None:
    found = directories("Bash", "env -C /srv/repo bash -c 'cd sub'; git commit")
    assert found[-1] == "git@"


def test_find_runs_tells_execdir_from_exec() -> None:
    args = ["/srv", "-name", "x", "-exec", "rm", "{}", ";", "-execdir", "ls", ";"]
    assert find_runs(args) == [(("rm", "/srv/x"), False), (("ls",), True)]
    assert find_exec(args) == [("rm", "/srv/x"), ("ls",)]


# ---------------------------------------------------------------------------
# PowerShell and cmd.exe
# ---------------------------------------------------------------------------
POWERSHELL_MOVES = [
    (r"Set-Location C:\srv\repo; git commit", "C:/srv/repo"),
    (r"cd C:\srv\repo; git commit", "C:/srv/repo"),
    (r"sl C:\srv\repo; git commit", "C:/srv/repo"),
    (r"chdir sub; git commit", "C:/work/app/sub"),
    (r"Set-Location -Path C:\srv\repo; git commit", "C:/srv/repo"),
    (r"Set-Location -LiteralPath C:\srv\repo; git commit", "C:/srv/repo"),
    (r"Set-Location -Path:C:\srv\repo; git commit", "C:/srv/repo"),
    (r"Set-Location C:\srv\repo -ErrorAction Stop; git commit", "C:/srv/repo"),
    (r"cd C:\srv\repo -ea Stop -PassThru; git commit", "C:/srv/repo"),
    (r"cd 'C:\srv\my repo'; git commit", "C:/srv/my repo"),
    (r"cd $env:USERPROFILE\proj; git commit", "C:/Users/dev/proj"),
    (r"cd ~\proj; git commit", "C:/Users/dev/proj"),
    (r"$d = 'C:\srv\repo'; cd $d; git commit", "C:/srv/repo"),
    (r"cd C:\srv\repo; cd -; git commit", HERE),
    (r"Push-Location C:\srv\repo; git commit", "C:/srv/repo"),
    (r"pushd C:\srv\repo; git commit; popd; git status", HERE),
    (r"Push-Location C:\srv\repo; Pop-Location; git commit", HERE),
    # Without a path Push-Location stays and remembers where it is.
    (r"Push-Location; cd C:\srv\repo; Pop-Location; git commit", HERE),
    (r"if ($true) { cd C:\srv\repo }; git commit", "C:/srv/repo"),
    (r"& { cd C:\srv\repo }; git commit", "C:/srv/repo"),
    (r"powershell -Command 'cd C:\srv\repo; make'; git commit", HERE),
    (r"powershell -Command 'cd C:\srv\repo; git commit'", "C:/srv/repo"),
    (r"Invoke-Expression 'cd C:\srv\repo'; git commit", "C:/srv/repo"),
    (r"git -C C:\srv\repo commit", "C:/srv/repo"),
    (r"git -C ..\other commit", "C:/work/other"),
    (r"cd C:\srv; git -C repo commit", "C:/srv/repo"),
    (r"npm --prefix web run build", "C:/work/app/web"),
    (r"pwsh -WorkingDirectory C:\srv\repo -Command 'git commit'", "C:/srv/repo"),
    (
        r"Start-Process git -ArgumentList commit -WorkingDirectory C:\srv\repo",
        "C:/srv/repo",
    ),
    (r'cmd /c "cd /d C:\srv\repo && git commit"', "C:/srv/repo"),
    (r'cmd /c "cd /d C:\srv\repo & cd sub & git commit"', "C:/srv/repo/sub"),
    (r'cmd /c "pushd C:\srv\repo && git commit"', "C:/srv/repo"),
    (r'cmd /c "cd C:\srv\repo && make"; git commit', HERE),
    (r'cmd /c "cd && git commit"', HERE),
    (r"wsl --cd /srv/repo git commit", "/srv/repo"),
]


@pytest.mark.parametrize(("command", "expected"), POWERSHELL_MOVES)
def test_powershell_and_cmd_moves_are_followed(command: str, expected: str) -> None:
    assert last("PowerShell", command, "windows") == expected


POWERSHELL_UNKNOWN = [
    "cd $dir; git commit",
    "cd (Get-Location); git commit",
    "cd (Split-Path $PSScriptRoot); git commit",
    "Set-Location; git commit",
    "Set-Location -StackName work; git commit",
    "Pop-Location; git commit",
    "cd +; git commit",
    r"cd C:\srv\re*; git commit",
    r"cd C:\a C:\b; git commit",
    r"cd -Bogus C:\srv\repo; git commit",
    "Get-ChildItem | ForEach-Object { cd $_; git commit }",
    "Start-Process git -ArgumentList commit -WorkingDirectory $dir",
    'cmd /c "cd /d %TARGET% && git commit"',
    'cmd /c "cd /x C:\\srv && git commit"',
    "git -C $repo commit",
]


@pytest.mark.parametrize("command", POWERSHELL_UNKNOWN)
def test_powershell_moves_the_gate_cannot_read_are_unknown(command: str) -> None:
    facts = facts_for("PowerShell", command, "windows")
    commits = [c for c in facts.commands if c.argv[0] == "git" and "commit" in c.argv]
    assert [c.cwd for c in commits] == [UNKNOWN_DIR]


def test_msys_paths_are_drive_paths_on_windows() -> None:
    found = directories(
        "Bash", "cd /c/srv/repo && git commit; git -C /d/x status", "windows"
    )
    assert found == ["cd@", "git@C:/srv/repo", "git@D:/x"]


def test_a_known_environment_variable_resolves_in_cmd() -> None:
    command = 'cmd /c "cd /d %USERPROFILE%\\proj && git commit"'
    assert last("PowerShell", command, "windows") == "C:/Users/dev/proj"


# ---------------------------------------------------------------------------
# Paths, the terminal tool, the audit summary
# ---------------------------------------------------------------------------
def test_a_path_carries_the_directory_and_command_it_belongs_to() -> None:
    facts = facts_for("Bash", "cat a.txt; cd /srv/repo && rm -rf build")
    found = [(p.path, p.op, p.cwd, p.source) for p in facts.paths]
    assert found == [
        ("/work/app/a.txt", "read", "", 0),
        ("/srv/repo/build", "delete", "/srv/repo", 2),
    ]


def test_the_same_path_from_two_directories_is_two_facts() -> None:
    facts = facts_for("Bash", "cat /etc/hosts; cd /srv && cat /etc/hosts")
    assert [(p.path, p.cwd) for p in facts.paths] == [
        ("/etc/hosts", ""),
        ("/etc/hosts", "/srv"),
    ]
    assert facts.paths[0] == facts.paths[1]  # the directory is no part of identity


def test_a_redirection_belongs_to_the_directory_of_the_shell() -> None:
    facts = facts_for("Bash", "git -C /srv/repo log > out.txt")
    assert facts.commands[0].cwd == "/srv/repo"
    assert [(p.path, p.op, p.cwd) for p in facts.paths] == [
        ("/work/app/out.txt", "write", "")
    ]


def test_operands_are_relative_to_where_a_wrapper_starts_the_command() -> None:
    facts = facts_for("Bash", "env -C /srv/app rm -rf data")
    assert [(p.path, p.op, p.recursive, p.cwd) for p in facts.paths] == [
        ("/srv/app/data", "delete", True, "/srv/app")
    ]


def test_paths_resolve_as_before_when_a_move_is_unclear() -> None:
    # The path tracker stays where it was; only the directory is unknown.
    facts = facts_for("Bash", "cd $WHERE && rm -rf build")
    assert [(p.path, p.cwd) for p in facts.paths] == [("/work/app/build", UNKNOWN_DIR)]


def test_git_add_reads_below_the_directory_it_names() -> None:
    facts = facts_for("Bash", "git -C api add .env")
    assert [(p.path, p.cwd) for p in facts.paths] == [
        ("/work/app/api/.env", "/work/app/api")
    ]


def test_a_tool_with_its_own_start_directory_names_it_on_every_command() -> None:
    carrier = {"run": ShellTool("bash", cwd="cwd")}
    call = make_call("run", {"command": "git status; cd sub; make", "cwd": "/srv/x"})
    facts = extract(call, windows=False, env=POSIX_ENV, shell_tools=carrier)
    assert facts.cwd == "/work/app"
    assert [c.cwd for c in facts.commands] == ["/srv/x", "/srv/x", "/srv/x/sub"]


def test_parsers_leave_the_directory_to_the_facts() -> None:
    parsed = parse_shell("cd /srv && git status", "bash")
    assert [c.cwd for c in parsed.commands] == ["", ""]
    assert parsed.commands[1] == SimpleCommand(("git", "status"), "bash")


def test_scopes_record_where_they_start_and_which_outlive_themselves() -> None:
    parsed = parse_shell("env -C /srv sh -c 'make'; eval 'cd /tmp'", "bash")
    assert parsed.entered == {0: ("bash", ("/srv",))}
    assert [parsed.scopes[number] for number in parsed.kept] == [(3, 4)]


@pytest.mark.parametrize("platform", ["posix", "windows"])
def test_the_audit_summary_keeps_a_directory_that_differs(platform: str) -> None:
    other = "C:/srv/repo" if platform == "windows" else "/srv/repo"
    facts = facts_for(
        "Bash", f"git status; cd {other} && rm -rf build; cd $X; ls", platform
    )
    summary = summarise(facts)
    assert [c.get("cwd") for c in summary["commands"]] == [
        None,
        None,
        other,
        other,
        UNKNOWN_DIR,
    ]
    assert summary["paths"] == [
        {"path": f"{other}/build", "op": "delete", "recursive": True, "cwd": other}
    ]
    entry = {"tool": "Bash", "cwd": facts.cwd, "session": "s1", "call": summary}
    restored = restore(entry)
    assert [c.cwd for c in restored.commands] == [c.cwd for c in facts.commands]
    assert [p.cwd for p in restored.paths] == [other]


def test_an_entry_without_directories_restores_to_the_directory_of_the_call() -> None:
    entry = {
        "tool": "Bash",
        "cwd": "/work/app",
        "call": {
            "commands": [{"shell": "bash", "argv": ["git", "status"]}],
            "paths": [{"path": "/work/app/a", "op": "read"}],
        },
    }
    restored = restore(entry)
    assert [c.cwd for c in restored.commands] == [""]
    assert [p.cwd for p in restored.paths] == [""]


def test_windows_environment_is_used_for_the_home_directory() -> None:
    call = make_call("PowerShell", "cd ~; git commit", cwd=r"C:\work\app")
    facts = extract(call, windows=True, env=WINDOWS_ENV)
    assert facts.commands[-1].cwd == "C:/Users/dev"


DRIVELESS = [
    # In PowerShell and cmd.exe a rooted path without a drive letter lies on
    # the drive the shell is on.
    ("PowerShell", r"cd \srv\repo; git commit", "C:/srv/repo"),
    ("PowerShell", "cd /srv/repo; git commit", "C:/srv/repo"),
    ("PowerShell", r"git -C \srv\repo commit", "C:/srv/repo"),
    ("PowerShell", r'cmd /c "cd /d \srv\repo && git commit"', "C:/srv/repo"),
    ("PowerShell", r"cd D:\x; cd \srv\repo; git commit", "D:/srv/repo"),
    ("PowerShell", r"cd $somewhere; cd \srv\repo; git commit", UNKNOWN_DIR),
    # In Bash on Windows such a path is one of the POSIX layer's own.
    ("Bash", "cd /srv/repo && git commit", "/srv/repo"),
    ("Bash", "git -C /srv/repo commit", "/srv/repo"),
]


@pytest.mark.parametrize(("tool", "command", "expected"), DRIVELESS)
def test_a_path_without_a_drive_letter_on_windows(
    tool: str, command: str, expected: str
) -> None:
    assert last(tool, command, "windows") == expected
