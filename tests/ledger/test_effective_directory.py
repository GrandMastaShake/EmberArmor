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
    # What lies above a directory that is not known is not known either.
    'cd "$REPO_SRC/.." && git commit',
    'cd "$(dirname "$0")/.." && git commit',
    'cd "$(git rev-parse --show-toplevel)/.." && git commit',
    "cd /a/$UNKNOWN/../b && git commit",
    "cd $WHERE/../.. && git commit",
    # A variable may bring a wildcard in.
    'for d in */; do cd "$d" && git commit; done',
    "for d in /srv/*/; do pushd $d; git commit; popd; done",
    "D='*/'; cd $D && git commit",
    "D=~other; cd $D && git commit",
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
    # Options without a value in one word with ``-C``, and the start of the
    # long option, as make reads them.
    ("make -sC build", "/work/app/build"),
    ("make -kC build all", "/work/app/build"),
    ("make -sCbuild", "/work/app/build"),
    ("make --dir=build", "/work/app/build"),
    ("make --dir build", "/work/app/build"),
    ("make --directo build", "/work/app/build"),
    ("make -fC all", HERE),  # ``C`` is the makefile
    ("make --debug all", HERE),
    ("git --attr-source HEAD -C /srv/repo commit", "/srv/repo"),
    ("git --super-prefix x/ -C /srv/repo status", "/srv/repo"),
    ("git --config-env a=B -C /srv/repo status", "/srv/repo"),
]


@pytest.mark.parametrize(("command", "expected"), OPTION_CASES)
def test_directory_options_move_one_command(command: str, expected: str) -> None:
    assert last("Bash", command) == expected


def test_a_directory_option_moves_only_its_own_command() -> None:
    found = directories("Bash", "git -C /srv/repo fetch && git status")
    assert found == ["git@/srv/repo", "git@"]


OPTION_UNKNOWN = [
    "git -C $REPO commit",
    'git -C "$REPO/.." commit',
    'git -C "$REPO/../sibling" commit',
    'for d in */; do git -C "$d" commit; done',
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
    # ``{}`` is a different directory for each file found.
    ("find /srv -type d -exec env -C {} git commit \\;", UNKNOWN_DIR),
    ("find /srv -name x -exec sh -c 'cd {} && git commit' \\;", UNKNOWN_DIR),
    ("cd /srv/repo && find . -name x -exec git commit {} \\;", "/srv/repo"),
]
FIND_PLACED = [
    ("find /srv -maxdepth 1 -type d -exec git -C {} commit \\;", UNKNOWN_DIR),
    ("find . -name .git -exec git -C {}/.. commit \\;", UNKNOWN_DIR),
    ("find /srv -type d -exec make -C {} all \\;", UNKNOWN_DIR),
    ("find . -name '*.c' -exec git -C /srv/repo add {} \\;", UNKNOWN_DIR),
    # Without a directory option the command runs where ``find`` does.
    ("cd /srv/repo && find . -name '*.c' -exec git add {} +", "/srv/repo"),
    ("find . -name Makefile -exec make -f {} all \\;", HERE),
]


@pytest.mark.parametrize(("command", "expected"), FIND_PLACED)
def test_a_directory_option_filled_in_by_find_is_unknown(
    command: str, expected: str
) -> None:
    assert last("Bash", command) == expected


def test_find_marks_the_commands_it_fills_a_file_name_into() -> None:
    parsed = parse_shell("find . -exec git -C {} status \\; -exec ls \\;", "bash")
    assert [c.argv[0] for c in parsed.commands] == ["find", "git", "ls"]
    assert parsed.commands[1].argv == ("git", "-C", ".", "status")
    assert parsed.placed == {1}


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
    (r"if ($true) { cd C:\srv\repo; git commit }", "C:/srv/repo"),
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
    # ``cd..``, ``cd\`` and ``cd~`` are functions of PowerShell, and cmd.exe
    # needs no blank between ``cd`` and a dot or a slash.
    ("cd..; git commit", "C:/work"),
    ("cd..; cd app; git commit", HERE),
    ("cd\\; git commit", "C:/"),
    ("cd~; git commit", "C:/Users/dev"),
    ('cmd /c "cd.. && git commit"', "C:/work"),
    ('cmd /c "cd\\ && git commit"', "C:/"),
    (r'cmd /c "cd..\.. && git commit"', "C:/"),
    (r'cmd /c "cd/d C:\srv\repo && git commit"', "C:/srv/repo"),
    (r'cmd /c "cd\srv\repo && git commit"', "C:/srv/repo"),
    ('cmd /c "chdir.. && git commit"', "C:/work"),
    (
        r"Start-Process git -ArgumentList commit -WorkingDirectory:C:\srv\repo",
        "C:/srv/repo",
    ),
    (r"Set-Location FileSystem::C:\srv\repo; git commit", "C:/srv/repo"),
    # A block that is called where it stands, and ``try``, run once.
    (r"try { cd C:\srv\repo } catch { }; git commit", "C:/srv/repo"),
    (r". { cd C:\srv\repo }; git commit", "C:/srv/repo"),
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
    r"Set-Location $PSScriptRoot\..; git commit",
    'cmd /c "cd /d %REPO%\\.. && git commit"',
    "Start-Process git -ArgumentList commit -WorkingDirectory:$dir",
    # Another provider: programs then run where the shell last was on disk.
    r"Set-Location HKLM:\Software; git commit",
    "cd Env:; git commit",
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
    # What ``C:`` without a slash means there is not followed.
    ("Bash", "cd C: && git commit", UNKNOWN_DIR),
    ("Bash", "cd C:sub && git commit", UNKNOWN_DIR),
]


@pytest.mark.parametrize(("tool", "command", "expected"), DRIVELESS)
def test_a_path_without_a_drive_letter_on_windows(
    tool: str, command: str, expected: str
) -> None:
    assert last(tool, command, "windows") == expected


# ---------------------------------------------------------------------------
# Limits the specification names
# ---------------------------------------------------------------------------
LIMITS = [
    # A ``cd`` is taken to succeed, and is followed where the shell would
    # not move: in the background.
    ("cd /no/such/dir; git commit", "/no/such/dir"),
    ("cd /srv/repo & git commit", "/srv/repo"),
    # Directory options of other programs are not read.
    ("go -C /srv/x build ./...", HERE),
    ("terraform -chdir=/srv/x plan", HERE),
    ("tar -C /srv/x -czf out.tgz .", HERE),
    ("hg -R /srv/x status", HERE),
    ("docker run --workdir /srv/x image make", HERE),
    ("GIT_DIR=/srv/x/.git git commit", HERE),
    ("GIT_WORK_TREE=/srv/x git commit", HERE),
    # The body of a function is judged where it is defined, not where it
    # is called.
    ("f() { git commit; }; cd /srv/repo; f", HERE),
    # A script the shell sources and an alias are not read.
    ("source ./env.sh; git commit", HERE),
    ("alias gs='cd /tmp'; gs; git commit", HERE),
    # Moves that may not have run are read coarsely, towards "unknown".
    ("if a; then cd /srv/x; else cd /srv/x; fi; git commit", UNKNOWN_DIR),
    ("pushd x && make && popd; git commit", UNKNOWN_DIR),
]


@pytest.mark.parametrize(("command", "expected"), LIMITS)
def test_known_limits_of_the_directory_a_command_runs_in(
    command: str, expected: str
) -> None:
    facts = facts_for("Bash", command)
    programs = [c for c in facts.commands if c.argv[0] not in ("cd", "cat", "f")]
    assert programs[-1].cwd == expected


PIPED = [
    # A stage of a Bash pipeline runs in a process of its own (or, with
    # ``lastpipe``, does not): where the shell is afterwards is not known.
    ("cd /srv/repo | cat; git commit", UNKNOWN_DIR),
    ("echo x | cd /srv/repo; git commit", UNKNOWN_DIR),
    ("cd /srv/repo | cat; cd /srv/other; git commit", "/srv/other"),
    ("cd /srv/repo && ls | cat; git commit", "/srv/repo"),
    ("cd /srv/repo; cd sub | cat; cd -; git commit", UNKNOWN_DIR),
]


@pytest.mark.parametrize(("command", "expected"), PIPED)
def test_a_cd_inside_a_bash_pipeline_leaves_the_directory_unknown(
    command: str, expected: str
) -> None:
    assert last("Bash", command) == expected


# ---------------------------------------------------------------------------
# Moves that may not have run
# ---------------------------------------------------------------------------
BASH_DOUBT = [
    # The right side of ``||`` and what ``&&`` hangs behind a command that
    # can fail.
    "cd /srv/repo || cd /tmp; git commit",
    "cd a || { cd b; }; git commit",
    "false && cd /tmp; git commit",
    "[ -d /tmp/ci ] && cd /tmp/ci; git commit",
    "[[ -d /tmp/ci ]] && cd /tmp/ci; git commit",
    "(( RETRIES > 1 )) && cd /tmp/ci; git commit",
    "mkdir -p out && cd out; git commit",
    "true && { echo ready; cd /tmp; }; git commit",
    "git fetch && git pull || cd /tmp; git commit",
    # ``popd`` hangs behind ``make``: when that fails the shell stays in x.
    "pushd x && make && popd; git commit",
    # A branch, and a loop that does not end where it began.
    'if [ -n "$CI" ]; then cd /tmp/ci; fi; git commit',
    "if a; then cd /tmp/a; else cd /tmp/b; fi; git commit",
    "if a; then b; elif c; then cd /tmp; fi; git commit",
    "case $1 in a) cd /tmp;; esac; git commit",
    "case $1 in a) echo;; *) cd /tmp;; esac; git commit",
    "while false; do cd /tmp; done; git commit",
    "until cd /srv/repo; do sleep 1; done; git commit",
    "for d in /srv/one; do cd $d; done; git commit",
    "for i in 1 2; do cd sub; done; git commit",
    "select d in a b; do cd $d; break; done; git commit",
    # A function that moves, once it is called.
    "f() { cd /tmp; }; f; git commit",
    "function f { cd /tmp; }; f; git commit",
    "function f() { cd /tmp; }; cd /srv/repo; f; git commit",
    "f() { g; }; g() { cd /tmp; }; f; git commit",
    "f() { if a; then cd /tmp; fi; }; f; git commit",
    "f() { pushd /tmp; make; popd; }; f; git commit",
]


@pytest.mark.parametrize("command", BASH_DOUBT)
def test_a_move_that_may_not_have_run_leaves_the_directory_unknown(
    command: str,
) -> None:
    assert last("Bash", command) == UNKNOWN_DIR


BASH_SURE = [
    # Inside the list, the branch or the loop the move is followed.
    ("mkdir -p out && cd out && git commit", "/work/app/out"),
    ("[ -d /srv/repo ] && cd /srv/repo && git commit", "/srv/repo"),
    ("if [ -d /srv/repo ]; then cd /srv/repo; git commit; fi", "/srv/repo"),
    ("if a; then b; elif cd /srv/repo; then git commit; fi", "/srv/repo"),
    ("case $1 in a) cd /srv/repo; git commit;; esac", "/srv/repo"),
    ("cd /srv/repo || { echo gone; exit 1; }; git commit", "/srv/repo"),
    # A ``cd`` is taken to succeed, so moves alone make no doubt.
    ("cd /srv && cd repo; git commit", "/srv/repo"),
    ("cd /srv/repo && git status; git commit", "/srv/repo"),
    ("cd /srv/repo && git status || echo failed; git commit", "/srv/repo"),
    # What ends where it began leaves no doubt.
    ("if [ -d x ]; then (cd x && make); fi; git commit", HERE),
    ("if [ -d x ]; then pushd x; make; popd; fi; git commit", HERE),
    ("for d in a b; do pushd $d; make; popd; done; git commit", HERE),
    ("for i in 1 2 3; do cd sub; make; cd ..; done; git commit", HERE),
    ("for d in a b; do (cd $d && make); done; git commit", HERE),
    ("for d in a b; do if [ -d $d ]; then pushd $d; popd; fi; done; git commit", HERE),
    ('while read f; do git add "$f"; done < list; git commit', HERE),
    ("[ -f x ] && echo yes || echo no; git commit", HERE),
    # A function is defined, not run; one that does not move changes nothing.
    ("f() { cd /tmp; }; git commit", HERE),
    ("function f { cd /tmp; }; git commit", HERE),
    ("f()\n{\n  cd /tmp\n}\ngit commit", HERE),
    ("cleanup() { cd /tmp; rm -f x.lock; }; trap cleanup EXIT; git commit", HERE),
    ("f() { echo hi; }; f; git commit", HERE),
    ("f() (cd /tmp; make); f; git commit", HERE),
    ("f() { cd /tmp; }; f; cd /srv/repo; git commit", "/srv/repo"),
]


@pytest.mark.parametrize(("command", "expected"), BASH_SURE)
def test_a_move_is_followed_where_it_is_certain(command: str, expected: str) -> None:
    assert last("Bash", command) == expected


def test_a_loop_that_moves_is_unknown_from_its_first_command() -> None:
    # On the second pass ``git commit`` runs where the first one ended.
    found = directories("Bash", "for i in 1 2; do git commit; cd /tmp; done")
    assert found == ["git@?", "cd@?"]


def test_the_second_branch_does_not_start_where_the_first_ended() -> None:
    command = "if a; then cd one; git status; else cd two; git commit; fi"
    assert directories("Bash", command) == [
        "a@",
        "cd@",
        "git@/work/app/one",
        "cd@?",
        "git@?",
    ]


def test_an_absolute_move_ends_the_doubt() -> None:
    command = "[ -d x ] && cd x; git status; cd /srv/repo; git commit"
    assert directories("Bash", command)[2:] == ["git@?", "cd@?", "git@/srv/repo"]


def test_a_function_body_is_judged_where_it_is_defined() -> None:
    found = directories("Bash", "f() { cd /tmp; make; }; cd /srv/repo; f")
    assert found == ["cd@", "make@/tmp", "cd@", "f@/srv/repo"]


def test_many_nested_loops_give_up_on_the_directory() -> None:
    # Each loop is tried once before it is walked: past a fixed number of
    # steps the directory inside is simply unknown.
    depth = 40
    body = "pushd x; " * 30 + "make; " + "popd; " * 30
    command = "for a in 1 2; do " * depth + body + "done; " * depth + "git commit"
    facts = facts_for("Bash", command)
    assert facts.commands[-1].cwd == UNKNOWN_DIR
    assert not facts.dynamic


POWERSHELL_DOUBT = [
    r"if ($true) { cd C:\srv\repo }; git commit",
    r"if ($x) { cd C:\tmp } else { cd C:\srv\repo }; git commit",
    r"switch ($x) { 1 { cd C:\tmp } }; git commit",
    r"try { build } catch { cd C:\tmp }; git commit",
    r"foreach ($d in 'a') { cd $d }; git commit",
    r"while ($x) { cd sub }; git commit",
    r"do { cd sub } while ($false); git commit",
    r"cd C:\srv\repo || cd C:\tmp; git commit",
    r"Test-Path x && cd x; git commit",
    # A block that is stored, or handed to a command, runs when and where
    # that says.
    r"$sb = { Set-Location C:\tmp }; git commit",
    r"Start-Job { Set-Location C:\tmp }; git commit",
    r"Invoke-Command -ComputerName h -ScriptBlock { cd C:\tmp }; git commit",
    r"pwsh -Command { cd C:\tmp }; git commit",
    r"$items.ForEach{ cd C:\tmp }; git commit",
    r"@{ go = { cd C:\tmp } }; git commit",
    r"function Go { Set-Location C:\tmp }; Go; git commit",
    r"function global:Go($a) { Set-Location C:\tmp }; go 1; git commit",
    r"filter Go { Set-Location C:\tmp }; 1 | Go; git commit",
    'cmd /c "(if exist x cd x) & git commit"',
    'cmd /c "if exist x (cd x) else (cd y) & git commit"',
    'cmd /c "cd a || cd b & git commit"',
    'cmd /c "for %i in (a b) do cd %i & git commit"',
    'cmd /c "dir x && cd x & git commit"',
]


@pytest.mark.parametrize("command", POWERSHELL_DOUBT)
def test_powershell_moves_that_may_not_have_run_are_unknown(command: str) -> None:
    assert last("PowerShell", command, "windows") == UNKNOWN_DIR


POWERSHELL_SURE = [
    (r"if ($x) { Push-Location C:\tmp; make; Pop-Location }; git commit", HERE),
    (
        r"1..3 | ForEach-Object { Push-Location sub; make; Pop-Location }; git commit",
        HERE,
    ),
    (r"function Go { Set-Location C:\tmp }; git commit", HERE),
    (r"function Show { Get-Location }; Show; git commit", HERE),
    (r"git status && git commit", HERE),
    # In cmd.exe the rest of the line belongs to the ``if``.
    ('cmd /c "if exist x cd x & git commit"', "C:/work/app/x"),
    ('cmd /c "if exist x (cd x & git commit)"', "C:/work/app/x"),
]


@pytest.mark.parametrize(("command", "expected"), POWERSHELL_SURE)
def test_powershell_moves_are_followed_where_they_are_certain(
    command: str, expected: str
) -> None:
    assert last("PowerShell", command, "windows") == expected


# ---------------------------------------------------------------------------
# A call that does not say where it is made
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("cwd", [None, "", "relative/dir", 7])
def test_a_call_without_a_working_directory_runs_nowhere_known(cwd: object) -> None:
    call = {"tool_name": "Bash", "tool_input": {"command": "git commit"}}
    if cwd is not None:
        call["cwd"] = cwd
    facts = extract(call, windows=False, env=POSIX_ENV)
    assert not facts.located
    assert [c.cwd for c in facts.commands] == [UNKNOWN_DIR]


def test_an_absolute_move_places_a_call_without_a_working_directory() -> None:
    call = {
        "tool_name": "Bash",
        "tool_input": {"command": "git status; cd /srv/repo && git commit"},
    }
    facts = extract(call, windows=False, env=POSIX_ENV)
    assert [c.cwd for c in facts.commands] == [UNKNOWN_DIR, UNKNOWN_DIR, "/srv/repo"]


TOOL_STARTS = [
    # (working directory of the call, the tool's own field, where it starts)
    ("/work/app", "/srv/x", "/srv/x"),
    ("/work/app", "sub", "/work/app/sub"),
    ("/work/app", "~/proj", "/home/dev/proj"),
    ("/work/app", "$HOME/proj", "/home/dev/proj"),
    (None, "/srv/x", "/srv/x"),
    (None, "sub", UNKNOWN_DIR),
    ("/work/app", "$NOPE", UNKNOWN_DIR),
    ("/work/app", "$NOPE/..", UNKNOWN_DIR),
    ("/work/app", "/srv/*/x", UNKNOWN_DIR),
    ("/work/app", "~other", UNKNOWN_DIR),
]


@pytest.mark.parametrize(("cwd", "field", "expected"), TOOL_STARTS)
def test_where_a_tool_with_its_own_start_directory_starts(
    cwd: str | None, field: str, expected: str
) -> None:
    carrier = {"run": ShellTool("bash", cwd="cwd")}
    call = make_call("run", {"command": "git commit", "cwd": field})
    if cwd is None:
        del call["cwd"]
    facts = extract(call, windows=False, env=POSIX_ENV, shell_tools=carrier)
    assert [c.cwd for c in facts.commands] == [expected]


def test_the_terminal_tool_with_a_variable_for_its_directory() -> None:
    payload = {"command": "git commit -m x", "cwd": "$env:NOPE"}
    facts = facts_for("mcp__terminal__run_in_terminal", payload, "windows")
    assert [c.cwd for c in facts.commands] == [UNKNOWN_DIR]


def test_the_audit_summary_says_when_the_call_named_no_directory() -> None:
    call = {"tool_name": "Read", "tool_input": {"file_path": "/srv/x/a"}}
    facts = extract(call, windows=False, env=POSIX_ENV)
    summary = summarise(facts)
    assert summary["located"] is False
    restored = restore({"tool": "Read", "cwd": facts.cwd, "call": summary})
    assert not restored.located
    assert "located" not in summarise(facts_for("Read", {"file_path": "/srv/x/a"}))
    assert restore({"tool": "Read", "cwd": "/work/app", "call": {}}).located


DRIVES = [
    # ``D:`` on its own goes to wherever the shell last was on that drive.
    ("D:; git commit", UNKNOWN_DIR),
    (r"D:; cd \srv\repo; git commit", UNKNOWN_DIR),
    (r"D:; cd D:\srv\repo; git commit", "D:/srv/repo"),
    (r'cmd /c "D: && cd \srv\repo && git commit"', UNKNOWN_DIR),
    (r'cmd /c "D: && cd /d D:\srv\repo && git commit"', "D:/srv/repo"),
    # ``D:`` and ``D:dir`` as a directory are that as well; on the drive the
    # shell is on they are relative paths.
    ("Set-Location C:; git commit", HERE),
    ("cd C:sub; git commit", "C:/work/app/sub"),
    ("cd D:; git commit", UNKNOWN_DIR),
    ("cd D:x; git commit", UNKNOWN_DIR),
    ("git -C D:x commit", UNKNOWN_DIR),
    # Without ``/d`` cmd.exe does not leave the drive it is on.
    (r'cmd /c "cd D:\x && git commit"', HERE),
    (r'cmd /c "cd /d D:\x && git commit"', "D:/x"),
    (r'cmd /c "cd C:\srv\repo && git commit"', "C:/srv/repo"),
    (r'cmd /c "pushd D:\x && git commit"', "D:/x"),
    (r'cmd /c "D: && cd C:\srv && git commit"', UNKNOWN_DIR),
]


@pytest.mark.parametrize(("command", "expected"), DRIVES)
def test_switching_drives_leaves_the_directory_unknown(
    command: str, expected: str
) -> None:
    assert last("PowerShell", command, "windows") == expected


def test_a_cd_inside_a_cmd_pipeline_is_followed() -> None:
    # A limit: cmd.exe runs the stage in a process of its own and stays put.
    command = r'cmd /c "cd /d C:\srv\repo | more & git commit"'
    assert last("PowerShell", command, "windows") == "C:/srv/repo"


def test_a_directory_with_a_wildcard_character_is_unknown() -> None:
    assert last("Bash", 'cd "app/[id]" && git commit') == UNKNOWN_DIR


def test_a_slash_word_in_cmd_is_a_switch() -> None:
    command = 'cmd /c "cd /d /srv/x && git commit"'
    assert last("PowerShell", command, "windows") == UNKNOWN_DIR


def test_a_stored_block_that_is_run_later_is_not_followed() -> None:
    # A limit: the block leaves the directory unknown where it is stored,
    # the absolute ``cd`` makes it known again, and the call is not read.
    command = r"$b = { cd C:\tmp }; git status; cd C:\srv\repo; & $b; git commit"
    found = directories("PowerShell", command, "windows")
    assert found == [
        "Set-Location@?",
        "git@?",
        "Set-Location@?",
        "git@C:/srv/repo",
    ]


def test_try_and_finally_run_once_in_powershell() -> None:
    command = "Push-Location x; try { make } finally { Pop-Location }; git commit"
    assert last("PowerShell", command, "windows") == HERE


def test_the_current_directory_of_dotnet_is_not_followed() -> None:
    command = r"[Environment]::CurrentDirectory = 'C:\srv\x'; git commit"
    assert last("PowerShell", command, "windows") == HERE
