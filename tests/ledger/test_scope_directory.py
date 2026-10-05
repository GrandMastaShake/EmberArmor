"""``applies.cwd_under`` and ``cwd_not_under`` are judged for each command.

A rule scoped to a directory fires on a command that runs there however the
command got there (the working directory of the call, ``cd``, ``git -C``,
``pushd``, ``Set-Location``, a nested ``cmd /c``), and not on one that left
it first.  The rule sees only the commands in scope and the paths they
touch.  A directory the gate cannot read counts as in scope.

The command strings below are data for the parsers.  Nothing runs them.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from ember_armor.ledger.audit import AuditLog, restore, summarise
from ember_armor.ledger.engine import MemoryHistory, evaluate
from ember_armor.ledger.facts import Facts, extract
from ember_armor.ledger.gate import check
from ember_armor.ledger.model import LedgerError, Rule, parse_rule
from tests.ledger.helpers import POSIX_ENV, WINDOWS_ENV, make_call, rule, write_ledger

COMMIT = {"type": "command", "program": "git", "subcommand": ["commit"]}
#: Per path flavour: the directory the rule is scoped to and another one, as
#: the gate names them and as a Windows shell types them.
DIRS = {
    "posix": ("/srv/repo", "/srv/other", "/srv/repo", "/srv/other"),
    "windows": ("C:/srv/repo", "C:/srv/other", r"C:\srv\repo", r"C:\srv\other"),
}


def scoped(when: dict[str, Any] | None = None, **applies: Any) -> Rule:
    return parse_rule(rule("scoped", when=when or COMMIT, applies=applies))


def facts(tool: str, command: Any, cwd: str, platform: str = "posix") -> Facts:
    windows = platform == "windows"
    call = make_call(tool, command, cwd=cwd)
    return extract(call, windows=windows, env=WINDOWS_ENV if windows else POSIX_ENV)


def fires(item: Rule, tool: str, command: Any, cwd: str, platform: str = "posix"):
    return evaluate([item], facts(tool, command, cwd, platform)).effect != "none"


# ---------------------------------------------------------------------------
# The invariant: every way into the directory, and every way out of it
# ---------------------------------------------------------------------------
def forms(platform: str, inside: bool) -> list[tuple[str, str, str]]:
    """``(tool, working directory, command)``: six ways to run ``git commit``.

    With *inside* the call starts in the other directory and the commit runs
    in the scoped one.  Without, it is the other way round: the mirror cases
    that leave the scoped directory before the command.
    """
    here, there, typed_here, typed_there = DIRS[platform]
    start, end = (there, here) if inside else (here, there)
    typed = typed_here if inside else typed_there
    # In cmd.exe a word that starts with a slash is a switch, so the POSIX
    # flavour names the directory relative to where the call starts.
    for_cmd = typed if platform == "windows" else f"../{end.rsplit('/', 1)[-1]}"
    return [
        ("Bash", end, "git commit"),
        ("Bash", start, f"cd {end} && git commit"),
        ("Bash", start, f"git -C {end} commit"),
        ("Bash", start, f"pushd {end}; git commit"),
        ("PowerShell", start, f"Set-Location {typed}; git commit"),
        ("PowerShell", start, f'cmd /c "cd /d {for_cmd} && git commit"'),
    ]


def commit_directory(found: Facts) -> str:
    """Where the one ``git commit`` of the call runs."""
    (commit,) = [c for c in found.commands if c.argv[0] == "git"]
    return commit.cwd or found.cwd


@pytest.mark.parametrize("platform", ["posix", "windows"])
@pytest.mark.parametrize("effect", ["deny", "ask", "warn"])
def test_a_directory_scoped_rule_fires_alike_for_every_way_in(
    platform: str, effect: str
) -> None:
    here = DIRS[platform][0]
    item = parse_rule(
        rule("scoped", when=COMMIT, effect=effect, applies={"cwd_under": [here]})
    )
    calls = [
        facts(tool, command, cwd, platform)
        for tool, cwd, command in forms(platform, inside=True)
    ]
    assert len(calls) == 6
    # Each form is read, not guessed: the directory is known every time.
    assert [commit_directory(found) for found in calls] == [here] * 6
    decisions = [evaluate([item], found) for found in calls]
    assert all(decision == decisions[0] for decision in decisions)
    assert decisions[0].effect == effect
    assert [fired.id for fired in decisions[0].fired] == ["scoped"]


@pytest.mark.parametrize("platform", ["posix", "windows"])
def test_a_directory_scoped_rule_does_not_fire_after_leaving(platform: str) -> None:
    here, there = DIRS[platform][:2]
    item = scoped(cwd_under=[here])
    for tool, cwd, command in forms(platform, inside=False):
        found = facts(tool, command, cwd, platform)
        assert commit_directory(found) == there, (tool, cwd, command)
        assert evaluate([item], found).effect == "none", (tool, cwd, command)


@pytest.mark.parametrize("platform", ["posix", "windows"])
def test_a_rule_scoped_to_the_other_directory_sees_the_mirror_cases(
    platform: str,
) -> None:
    # The same twelve calls, judged by a rule scoped to the other directory.
    item = scoped(cwd_under=[DIRS[platform][1]])
    for tool, cwd, command in forms(platform, inside=False):
        assert fires(item, tool, command, cwd, platform), (tool, cwd, command)
    for tool, cwd, command in forms(platform, inside=True):
        assert not fires(item, tool, command, cwd, platform), (tool, cwd, command)


@pytest.mark.parametrize("platform", ["posix", "windows"])
def test_every_way_in_reaches_a_subdirectory_too(platform: str) -> None:
    here = DIRS[platform][0]
    item = scoped(cwd_under=[here])
    typed = DIRS[platform][2]
    separator = "\\" if platform == "windows" else "/"
    for command in (
        f"Set-Location {typed}{separator}src{separator}lib; git commit",
        f"Set-Location {typed}; Set-Location src; git commit",
        f"git -C {typed} -C src commit",
    ):
        assert fires(item, "PowerShell", command, DIRS[platform][1], platform)


# ---------------------------------------------------------------------------
# What the rule sees
# ---------------------------------------------------------------------------
SEEN = [
    # working directory, command, fires
    ("/srv/repo", "git commit", True),
    ("/srv/repo/sub", "git commit", True),
    ("/srv/repository", "git commit", False),
    ("/work", "git status && cd /srv/repo && git commit", True),
    ("/work", "cd /srv/repo && git status; cd /work && git commit", False),
    ("/work", "(cd /srv/repo && git status); git commit", False),
    ("/work", "(cd /srv/repo && git commit); git status", True),
    ("/work", "git -C /srv/repo status && git commit", False),
    ("/work", "bash -c 'cd /srv/repo && git commit'", True),
    ("/work", "bash -c 'cd /srv/repo && make'; git commit", False),
    ("/srv/repo", "bash -c 'cd /tmp && git commit'", False),
    ("/work", "sudo git -C /srv/repo commit", True),
    ("/work", "env -C /srv/repo git commit", True),
    ("/srv/repo", "env -C /tmp git commit", False),
    ("/work", "pnpm -C /srv/repo exec git commit", True),
    ("/srv/repo", "git --git-dir=/tmp/x/.git commit", True),  # unknown
    ("/work", "git -C /srv/repo/../other commit", False),
    ("/work", "git -C /srv/repo/sub/.. commit", True),
    ("/work", "cd /srv && git -C repo commit", True),
    ("/work", 'eval "cd /srv/repo"; git commit', True),
]


@pytest.mark.parametrize(("cwd", "command", "expected"), SEEN)
def test_only_commands_that_run_in_scope_are_seen(
    cwd: str, command: str, expected: bool
) -> None:
    assert fires(scoped(cwd_under=["/srv/repo"]), "Bash", command, cwd) is expected


UNKNOWN = [
    "cd $WHERE && git commit",
    'cd "$(git rev-parse --show-toplevel)" && git commit',
    "git -C $REPO commit",
    "popd; git commit",
    "cd - && git commit",
    "for d in a b; do cd $d && git commit; done",
    "find . -name .git -execdir git commit \\;",
    "npm --prefix web exec git commit",
]


@pytest.mark.parametrize("command", UNKNOWN)
def test_an_unknown_directory_counts_as_in_scope(command: str) -> None:
    # From a directory outside the scope: the rule must not be escaped (or,
    # here, missed) through a move the gate cannot read.
    assert fires(scoped(cwd_under=["/srv/repo"]), "Bash", command, "/work")


def test_an_unknown_directory_is_in_scope_only_until_a_known_one() -> None:
    item = scoped(cwd_under=["/srv/repo"])
    assert not fires(item, "Bash", "cd $WHERE; cd /tmp; git commit", "/work")


NOT_CERTAIN = [
    # (tool, working directory, command): in each of them the commit may run
    # in the scoped directory, C:/srv/repo, and the gate cannot tell.
    ("Bash", "C:/srv/other", 'cd "$REPO_SRC/.." && git commit -m x'),
    ("Bash", "C:/srv/other", 'git -C "$REPO_SRC/.." commit -m x'),
    ("Bash", "C:/srv/other", 'cd "$(dirname "$0")/.." && git commit'),
    ("Bash", "C:/srv/other", "cd /a/$UNKNOWN/../b && git commit"),
    ("PowerShell", r"C:\srv\other", r"Set-Location $PSScriptRoot\..; git commit"),
    ("PowerShell", r"C:\srv\other", 'cmd /c "cd /d %REPO%\\.. && git commit"'),
    ("Bash", "C:/srv", 'for d in */; do (cd "$d" && git commit -m x); done'),
    ("Bash", "C:/srv", 'for d in */; do git -C "$d" commit -m x; done'),
    ("Bash", "C:/srv", "for d in packages/*; do pushd $d; git commit; popd; done"),
    ("Bash", "C:/srv/other", "cd C:/srv/repo || cd C:/tmp; git commit -m x"),
    ("Bash", "C:/srv/repo", 'if [ -n "$CI" ]; then cd C:/tmp/ci; fi; git commit'),
    ("Bash", "C:/srv/repo", "false && cd /tmp; git commit"),
    ("Bash", "C:/srv/repo", "[ -d /tmp/ci ] && cd /tmp/ci; git commit"),
    ("Bash", "C:/srv/repo", "while false; do cd /tmp; done; git commit"),
    ("Bash", "C:/srv/repo", "case $1 in a) cd /tmp;; esac; git commit"),
    ("PowerShell", r"C:\srv\repo", r"if ($false) { cd C:\tmp }; git commit"),
    ("PowerShell", r"C:\srv\repo", r"$sb = { Set-Location C:\tmp }; git commit"),
    ("PowerShell", r"C:\srv\repo", r"Start-Job { Set-Location C:\tmp }; git commit"),
    ("Bash", "C:/srv/other", "find C:/srv -type d -exec git -C {} commit -m x \\;"),
    ("PowerShell", r"C:\srv\repo", "cd D:; git commit"),
]


@pytest.mark.parametrize(("tool", "cwd", "command"), NOT_CERTAIN)
def test_a_move_the_gate_cannot_be_sure_of_does_not_lead_out_of_a_rule(
    tool: str, cwd: str, command: str
) -> None:
    assert fires(scoped(cwd_under=["C:/srv/repo"]), tool, command, cwd, "windows")


STILL_THERE = [
    # (tool, working directory, command): the commit runs in C:/srv/repo.
    ("Bash", "C:/srv/repo", "cleanup() { cd C:/tmp; rm -f x.lock; }; git commit"),
    ("Bash", "C:/srv/repo", "f() { cd /tmp; }; trap f EXIT; git commit"),
    ("PowerShell", r"C:\srv\repo", r"function Go { Set-Location C:\tmp }; git commit"),
    ("PowerShell", r"C:\srv\other", "cd..; cd repo; git commit -m x"),
    ("PowerShell", r"C:\srv\other", 'cmd /c "cd.. && cd repo && git commit -m x"'),
    ("PowerShell", r"C:\srv\repo", 'cmd /c "cd D:\\x && git commit -m x"'),
    ("PowerShell", r"C:\srv\repo", "Set-Location C:; git commit"),
    ("PowerShell", r"C:\srv", "cd C:repo; git commit"),
    (
        "PowerShell",
        r"C:\srv\other",
        r"Set-Location FileSystem::C:\srv\repo; git commit",
    ),
    (
        "PowerShell",
        r"C:\srv\other",
        r"Start-Process git -ArgumentList 'commit','-m','x' "
        r"-WorkingDirectory:C:\srv\repo",
    ),
    ("Bash", "C:/srv/other", "make -sC C:/srv/repo all"),
    ("Bash", "C:/srv/other", "make --dir=C:/srv/repo"),
    ("Bash", "C:/srv/other", "git --attr-source HEAD -C C:/srv/repo commit -m x"),
]


@pytest.mark.parametrize(("tool", "cwd", "command"), STILL_THERE)
def test_more_ways_to_run_in_the_scoped_directory(
    tool: str, cwd: str, command: str
) -> None:
    when = {"type": "command", "program": ["git", "make"]}
    item = scoped(when, cwd_under=["C:/srv/repo"])
    found = facts(tool, command, cwd, "windows")
    assert evaluate([item], found).effect == "deny"
    last = [c for c in found.commands if c.argv[0] in ("git", "make")][-1]
    assert (last.cwd or found.cwd) == "C:/srv/repo"


@pytest.mark.parametrize("cwd", [None, "", "some/where"])
def test_a_call_that_names_no_directory_is_in_scope(cwd: str | None) -> None:
    item = scoped(cwd_under=["/srv/repo"])
    call = {"tool_name": "Bash", "tool_input": {"command": "git commit -m x"}}
    if cwd is not None:
        call["cwd"] = cwd
    found = extract(call, windows=False, env=POSIX_ENV)
    assert evaluate([item], found).effect == "deny"
    # It is not in a directory the rule leaves out, either.
    spared = scoped(cwd_not_under=["/"])
    assert evaluate([spared], found).effect == "deny"
    # A known directory places it again.
    moved = {**call, "tool_input": {"command": "cd /tmp && git commit"}}
    found = extract(moved, windows=False, env=POSIX_ENV)
    assert evaluate([item], found).effect == "none"


def test_another_tool_without_a_directory_is_in_scope() -> None:
    writes = scoped({"type": "path", "op": "write"}, cwd_under=["/srv/repo"])
    call = {"tool_name": "Write", "tool_input": {"file_path": "/etc/hosts"}}
    found = extract(call, windows=False, env=POSIX_ENV)
    assert evaluate([writes], found).effect == "deny"
    placed = extract({**call, "cwd": "/work"}, windows=False, env=POSIX_ENV)
    assert evaluate([writes], placed).effect == "none"


def test_the_tool_cwd_field_with_a_variable_is_in_scope() -> None:
    payload = {"command": "git commit -m x", "cwd": "$env:NOPE"}
    tool = "mcp__terminal__run_in_terminal"
    item = scoped(cwd_under=["C:/srv/repo"])
    assert fires(item, tool, payload, "C:/srv/other", "windows")
    payload = {"command": "git commit -m x", "cwd": r"C:\srv\elsewhere"}
    assert not fires(item, tool, payload, "C:/srv/other", "windows")


def test_a_scoped_rule_sees_only_the_paths_of_commands_in_scope() -> None:
    delete = {"type": "path", "op": "delete", "recursive": True}
    item = scoped(delete, cwd_under=["/srv/repo"])
    assert fires(item, "Bash", "cd /srv/repo && rm -rf build", "/work")
    assert fires(item, "Bash", "rm -rf build", "/srv/repo")
    # The delete runs elsewhere, although a command in scope is present.
    assert not fires(item, "Bash", "git -C /srv/repo status; rm -rf build", "/work")
    # It is the directory the command runs in that counts, not the path.
    assert not fires(item, "Bash", "rm -rf /srv/repo/build", "/work")
    assert fires(item, "Bash", "cd /srv/repo && rm -rf /tmp/build", "/work")


def test_a_redirection_is_seen_in_the_directory_of_the_shell() -> None:
    write = {"type": "path", "op": "write", "glob": ["**/notes.txt"]}
    item = scoped(write, cwd_under=["/srv/repo"])
    assert fires(item, "Bash", "git -C /tmp log > notes.txt", "/srv/repo")
    assert not fires(item, "Bash", "git -C /srv/repo log > notes.txt", "/work")


def test_an_obligation_looks_at_the_commands_in_scope() -> None:
    raw = rule("signed", applies={"cwd_under": ["/srv/repo"]})
    del raw["when"]
    raw["require"] = {"type": "command", "program": "git", "flags_any": ["-S"]}
    item = parse_rule(raw)
    assert fires(item, "Bash", "git -C /srv/repo commit", "/work")
    assert not fires(item, "Bash", "git -C /srv/repo commit -S", "/work")
    # The signed commit runs elsewhere: in scope there is only an unsigned one.
    command = "git commit -S; git -C /srv/repo commit"
    assert fires(item, "Bash", command, "/work")
    assert not fires(item, "Bash", "git commit", "/work")  # nothing in scope


def test_call_level_predicates_hold_when_a_command_is_in_scope() -> None:
    item = scoped(
        {"type": "dynamic_shell", "reason": ["eval"]}, cwd_under=["/srv/repo"]
    )
    assert fires(item, "Bash", 'cd /srv/repo && eval "$X"', "/work")
    assert not fires(item, "Bash", 'eval "$X"', "/work")


def test_a_call_without_commands_is_judged_on_its_working_directory() -> None:
    item = scoped({"type": "dynamic_shell"}, cwd_under=["/srv/repo"])
    assert fires(item, "Bash", "echo 'unterminated", "/srv/repo")
    assert not fires(item, "Bash", "echo 'unterminated", "/work")


def test_the_scope_of_another_tool_is_the_working_directory_of_the_call() -> None:
    item = scoped({"type": "path", "op": "write"}, cwd_under=["/srv/repo"])
    assert fires(item, "Write", {"file_path": "/tmp/x.txt"}, "/srv/repo")
    assert not fires(item, "Write", {"file_path": "/srv/repo/x.txt"}, "/work")
    amount = {"type": "arg", "name": "amount", "op": ">", "value": 5}
    item = scoped(amount, cwd_under=["/srv/repo"])
    assert fires(item, "mcp__bank__pay", {"amount": 9}, "/srv/repo/sub")
    assert not fires(item, "mcp__bank__pay", {"amount": 9}, "/work")


def test_tools_and_directories_both_have_to_hold() -> None:
    item = scoped(cwd_under=["/srv/repo"], tools=["PowerShell"])
    assert not fires(item, "Bash", "git commit", "/srv/repo")
    item = scoped(cwd_under=["/srv/repo"], tools=["Bash"])
    assert fires(item, "Bash", "git -C /srv/repo commit", "/work")


# ---------------------------------------------------------------------------
# cwd_not_under
# ---------------------------------------------------------------------------
NOT_UNDER = [
    ("/srv/repo", "git commit", True),
    ("/srv/repo/vendor", "git commit", False),
    ("/srv/repo/vendor/lib", "git commit", False),
    ("/srv/repo", "cd vendor && git commit", False),
    ("/srv/repo", "git -C vendor/lib commit", False),
    ("/srv/repo/vendor", "cd .. && git commit", True),
    ("/srv/repo/vendor", "git -C /srv/repo commit", True),
    ("/srv/repo", "git -C vendor status; git commit", True),
    ("/work", "git commit", False),
    # An exception is not gained through a move the gate cannot read.
    ("/srv/repo/vendor", "cd $WHERE && git commit", True),
    ("/srv/repo/vendor", "git -C $X commit", True),
]


@pytest.mark.parametrize(("cwd", "command", "expected"), NOT_UNDER)
def test_cwd_not_under_leaves_directories_out(
    cwd: str, command: str, expected: bool
) -> None:
    item = scoped(cwd_under=["/srv/repo"], cwd_not_under=["/srv/repo/vendor"])
    assert fires(item, "Bash", command, cwd) is expected


def test_cwd_not_under_works_without_cwd_under() -> None:
    item = scoped(cwd_not_under=["/srv/scratch", "/tmp"])
    assert fires(item, "Bash", "git commit", "/work")
    assert not fires(item, "Bash", "git commit", "/tmp/x")
    assert not fires(item, "Bash", "cd /srv/scratch && git commit", "/work")
    assert fires(item, "Bash", "cd /srv/scratch && cd /work && git commit", "/tmp")
    assert not fires(item, "Write", {"file_path": "/work/a"}, "/tmp")


def test_cwd_not_under_on_windows_ignores_letter_case() -> None:
    item = scoped(cwd_under=[r"C:\srv\repo"], cwd_not_under=[r"c:\SRV\repo\Vendor"])
    typed = r"Set-Location C:\srv\repo\vendor; git commit"
    assert not fires(item, "PowerShell", typed, "C:/work", "windows")
    assert fires(item, "PowerShell", "git commit", r"C:\srv\repo\src", "windows")
    assert not fires(
        item, "Bash", "git -C /c/srv/repo/vendor commit", "C:/x", "windows"
    )


def test_relative_scope_directories_resolve_on_the_rule_base() -> None:
    raw = rule("scoped", when=COMMIT, applies={"cwd_under": ["packages/api"]})
    item = parse_rule(raw, origin="project", base="/srv/repo")
    assert fires(item, "Bash", "cd /srv/repo/packages/api && git commit", "/work")
    assert not fires(item, "Bash", "cd /srv/repo/packages/web && git commit", "/work")


def test_the_new_scope_fields_are_parsed_and_checked() -> None:
    item = scoped(cwd_not_under="/tmp", repo_root=["/srv/repo", "~/work/*"])
    assert item.applies.cwd_not_under == ("/tmp",)
    assert item.applies.repo_root == ("/srv/repo", "~/work/*")
    assert item.applies.directories
    assert not scoped(tools=["Bash"]).applies.directories
    with pytest.raises(LedgerError, match="unknown field"):
        scoped(cwd_not_below=["/tmp"])
    with pytest.raises(LedgerError, match="non-empty string or list"):
        scoped(repo_root=[3])


# ---------------------------------------------------------------------------
# History: a scoped rule sees of earlier calls what it would see now
# ---------------------------------------------------------------------------
TESTS_FIRST = {
    "type": "all",
    "of": [
        {"type": "command", "program": "git", "subcommand": ["push"]},
        {
            "type": "not_preceded_by",
            "predicate": {"type": "command", "program": "pytest"},
        },
    ],
}


def history_of(*calls: tuple[str, str]) -> MemoryHistory:
    history = MemoryHistory()
    for number, (cwd, command) in enumerate(calls):
        history.add(facts("Bash", command, cwd), 1000.0 + number)
    return history


HISTORY = [
    # earlier calls (working directory, command), then whether the push is asked about
    ([("/srv/repo", "pytest")], False),
    ([("/work", "cd /srv/repo && pytest")], False),
    ([("/work", "cd /srv/repo/tests && pytest -q")], False),
    ([("/work", "env -C /srv/repo pytest")], False),
    ([("/work", "pytest")], True),
    ([("/srv/repo", "cd /tmp/other && pytest")], True),
    ([("/srv/repo", "git status"), ("/work", "pytest")], True),
    ([], True),
]


@pytest.mark.parametrize(("earlier", "expected"), HISTORY)
def test_history_counts_only_earlier_commands_in_scope(
    earlier: list[tuple[str, str]], expected: bool
) -> None:
    item = scoped(TESTS_FIRST, cwd_under=["/srv/repo"])
    now = facts("Bash", "git -C /srv/repo push", "/work")
    decision = evaluate([item], now, history_of(*earlier), now=2000.0)
    assert (decision.effect != "none") is expected


def test_history_of_a_rule_without_a_directory_scope_is_unchanged() -> None:
    item = parse_rule(rule("unscoped", when=TESTS_FIRST))
    now = facts("Bash", "git push", "/srv/repo")
    assert evaluate([item], now, history_of(("/work", "pytest"))).effect == "none"
    assert evaluate([item], now, history_of(("/work", "ls"))).effect == "deny"


def test_count_exceeds_counts_the_commands_in_scope() -> None:
    push = {"type": "command", "program": "git", "subcommand": ["push"]}
    item = scoped(
        {"type": "count_exceeds", "predicate": push, "max": 1},
        cwd_under=["/srv/repo"],
    )
    now = facts("Bash", "git push", "/srv/repo")
    elsewhere = history_of(("/work", "git push"), ("/work", "git push"))
    assert evaluate([item], now, elsewhere).effect == "none"
    here = history_of(("/work", "git -C /srv/repo push"), ("/srv/repo", "git push"))
    assert evaluate([item], now, here).effect == "deny"


def test_history_from_the_audit_log_keeps_the_directory(gate_env) -> None:
    item = rule("tests-first", when=TESTS_FIRST, applies={"cwd_under": ["/srv/repo"]})
    write_ledger(Path(gate_env["EMBER_LEDGER"]), item)

    def run(command: str, cwd: str, session: str) -> str:
        call = make_call("Bash", command, cwd=cwd, session=session)
        return check(call, env=gate_env, windows=False).decision.effect

    # Tests in another directory do not vouch for the push in this one.
    assert run("cd /tmp/other && pytest", "/srv/repo", "a") == "none"
    assert run("git push", "/srv/repo", "a") == "deny"
    # Tests reached through ``cd`` do.
    assert run("cd /srv/repo && pytest", "/work", "b") == "none"
    assert run("git -C /srv/repo push", "/work", "b") == "none"
    log = AuditLog(Path(gate_env["EMBER_HOME"]) / "audit")
    entries = list(log.entries())
    assert entries[0]["call"]["commands"] == [
        {"shell": "bash", "argv": ["cd", "/tmp/other"]},
        {"shell": "bash", "argv": ["pytest"], "cwd": "/tmp/other"},
    ]
    assert entries[3]["call"]["commands"] == [
        {
            "shell": "bash",
            "argv": ["git", "-C", "/srv/repo", "push"],
            "cwd": "/srv/repo",
        }
    ]
    assert log.verify().ok


def test_a_restored_call_is_judged_like_the_original() -> None:
    item = scoped(cwd_under=["/srv/repo"])
    for cwd, command in (
        ("/work", "cd /srv/repo && git commit"),
        ("/srv/repo", "cd /tmp && git commit"),
        ("/work", "cd $X && git commit"),
        ("/work", "git commit"),
    ):
        original = facts("Bash", command, cwd)
        entry = {"tool": "Bash", "cwd": original.cwd, "call": summarise(original)}
        restored = restore(entry)
        assert evaluate([item], restored) == evaluate([item], original)
