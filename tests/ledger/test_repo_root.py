"""``applies.repo_root``: the nearest enclosing git repository of a command.

The scope holds when the nearest repository at or above the directory a
command runs in is exactly one of the directories listed.  That is how a rule
says "at the top-level repository, but not in a repository nested inside
it".  The lookup reads the filesystem, so the engine takes it as a parameter:
most tests here hand it a table, and a few at the end create repositories in
a temporary directory.

The command strings below are data for the parsers.  The only programs these
tests start are ``git init`` in a temporary directory and the gate's own hook.
"""

from __future__ import annotations

import errno
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from ember_armor.ledger import repo
from ember_armor.ledger.builtin import builtin_rules
from ember_armor.ledger.engine import MemoryHistory, evaluate
from ember_armor.ledger.facts import Facts, extract
from ember_armor.ledger.gate import check
from ember_armor.ledger.model import Rule, parse_rule
from ember_armor.ledger.paths import UNKNOWN_DIR
from tests.ledger.helpers import (
    POSIX_ENV,
    WINDOWS_ENV,
    make_call,
    rule,
    run_gate,
    write_ledger,
)

COMMIT = {"type": "command", "program": "git", "subcommand": ["commit"]}
#: Directories that hold a ``.git`` entry in the tests with a table.
REPOSITORIES = {
    "/srv/repo",
    "/srv/repo/vendor/lib",
    "/home/dev/work/site",
    "C:/srv/repo",
    "C:/srv/repo/vendor/lib",
}


def table(directory: str) -> str | None:
    """Stand-in for the filesystem: the repositories of :data:`REPOSITORIES`."""
    return repo.find_root(directory, lambda candidate: candidate in REPOSITORIES)


def rooted(when: dict[str, Any] | None = None, **applies: Any) -> Rule:
    applies.setdefault("repo_root", ["/srv/repo"])
    return parse_rule(rule("rooted", when=when or COMMIT, applies=applies))


def facts(tool: str, payload: Any, cwd: str, platform: str = "posix") -> Facts:
    windows = platform == "windows"
    call = make_call(tool, payload, cwd=cwd)
    return extract(call, windows=windows, env=WINDOWS_ENV if windows else POSIX_ENV)


def fires(item: Rule, tool: str, payload: Any, cwd: str, platform: str = "posix"):
    found = facts(tool, payload, cwd, platform)
    return evaluate([item], found, repo_root=table).effect != "none"


# ---------------------------------------------------------------------------
# The lookup
# ---------------------------------------------------------------------------
PARENTS = [
    ("/srv/repo/src", "/srv/repo"),
    ("/srv", "/"),
    ("/", None),
    ("C:/srv/repo", "C:/srv"),
    ("C:/srv", "C:/"),
    ("C:/", None),
    ("//host/share/", None),
]


@pytest.mark.parametrize(("directory", "expected"), PARENTS)
def test_parent_walks_up_to_the_root(directory: str, expected: str | None) -> None:
    assert repo.parent(directory) == expected


ROOTS = [
    ("/srv/repo", "/srv/repo"),
    ("/srv/repo/src/deep", "/srv/repo"),
    ("/srv/repo/vendor", "/srv/repo"),
    ("/srv/repo/vendor/lib", "/srv/repo/vendor/lib"),
    ("/srv/repo/vendor/lib/src", "/srv/repo/vendor/lib"),
    ("/srv/repository", None),
    ("/srv", None),
    ("/", None),
    ("C:/srv/repo/src", "C:/srv/repo"),
    ("C:/other", None),
    # Not looked up at all.
    ("//host/share/repo", UNKNOWN_DIR),
    ("/srv/$NAME/x", UNKNOWN_DIR),
    (UNKNOWN_DIR, UNKNOWN_DIR),
]


@pytest.mark.parametrize(("directory", "expected"), ROOTS)
def test_find_root_takes_the_nearest_repository(
    directory: str, expected: str | None
) -> None:
    assert table(directory) == expected


def test_a_network_path_is_never_probed() -> None:
    def probe(directory: str) -> bool:
        raise AssertionError(f"probed {directory}")

    assert repo.find_root("//host/share/repo/src", probe) == UNKNOWN_DIR


def test_the_windows_lookup_asks_only_about_paths_on_a_drive(monkeypatch) -> None:
    asked: list[str] = []

    def find_root(directory: str) -> str | None:
        asked.append(directory)
        return None

    monkeypatch.setattr(repo, "find_root", find_root)
    find = repo.finder(True)
    assert find("C:/srv/repo") is None
    assert find("/srv/repo") == UNKNOWN_DIR  # a directory inside WSL
    assert find("//host/share/x") == UNKNOWN_DIR
    assert asked == ["C:/srv/repo"]
    assert repo.finder(False) is find_root


def real(path: Path) -> str:
    """A temporary path in the normalised form the gate uses."""
    return str(path).replace("\\", "/")


def test_has_git_finds_a_directory_and_a_file(tmp_path: Path) -> None:
    (tmp_path / "top" / ".git").mkdir(parents=True)
    (tmp_path / "top" / "sub" / "module").mkdir(parents=True)
    # A worktree and a submodule have a file named .git, not a directory.
    (tmp_path / "top" / "sub" / "module" / ".git").write_text("gitdir: ../x\n")
    (tmp_path / "plain").mkdir()
    assert repo.has_git(real(tmp_path / "top"))
    assert repo.has_git(real(tmp_path / "top" / "sub" / "module"))
    assert not repo.has_git(real(tmp_path / "top" / "sub"))
    assert not repo.has_git(real(tmp_path / "plain"))
    assert not repo.has_git(real(tmp_path / "missing" / "deeper"))
    assert not repo.has_git(real(tmp_path / "top" / "sub" / "module" / ".git"))


def test_find_root_on_the_filesystem(tmp_path: Path) -> None:
    top, module = tmp_path / "top", tmp_path / "top" / "sub" / "module"
    (top / ".git").mkdir(parents=True)
    module.mkdir(parents=True)
    (module / ".git").write_text("gitdir: ../x\n")
    assert repo.find_root(real(top / "src" / "not" / "there")) == real(top)
    assert repo.find_root(real(top / "sub")) == real(top)
    assert repo.find_root(real(module / "src")) == real(module)
    assert repo.find_root(real(top / ".git" / "hooks")) == real(top)
    # A name that cannot exist is simply not there.
    assert repo.find_root(real(top) + "/src/**/*.py") == real(top)
    assert repo.find_root(real(top) + "/a\x00b") == real(top)


@pytest.mark.parametrize("code", [errno.ENOENT, errno.ENOTDIR, errno.EINVAL])
def test_a_name_that_cannot_be_there_is_absent(monkeypatch, code: int) -> None:
    def lstat(path: str) -> None:
        raise OSError(code, "no such thing")

    monkeypatch.setattr(os, "lstat", lstat)
    assert repo.has_git("/srv/repo") is False
    assert repo.find_root("/srv/repo/src") is None


def test_a_lookup_that_is_refused_raises(monkeypatch) -> None:
    def lstat(path: str) -> None:
        raise PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(os, "lstat", lstat)
    with pytest.raises(PermissionError):
        repo.find_root("/srv/repo/src")


def test_the_lookup_only_stats(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / "top" / ".git").mkdir(parents=True)
    asked: list[str] = []
    original = os.lstat

    def lstat(path: str) -> os.stat_result:
        asked.append(path)
        return original(path)

    monkeypatch.setattr(os, "lstat", lstat)
    monkeypatch.setattr(subprocess, "Popen", None)  # no git process
    monkeypatch.setattr("builtins.open", None)  # and no file is opened
    start = real(tmp_path / "top" / "a" / "b")
    assert repo.find_root(start) == real(tmp_path / "top")
    assert asked == [
        f"{start}/.git",
        f"{real(tmp_path / 'top' / 'a')}/.git",
        f"{real(tmp_path / 'top')}/.git",
    ]


# ---------------------------------------------------------------------------
# The scope, with a table for a filesystem
# ---------------------------------------------------------------------------
SCOPE = [
    # working directory, command, fires
    ("/srv/repo", "git commit", True),
    ("/srv/repo/src/deep", "git commit", True),
    ("/srv/repo/vendor", "git commit", True),
    ("/srv/repo/vendor/lib", "git commit", False),
    ("/srv/repo/vendor/lib/src", "git commit", False),
    ("/srv", "git commit", False),
    ("/srv/repository", "git commit", False),
    ("/work", "cd /srv/repo && git commit", True),
    ("/work", "git -C /srv/repo commit", True),
    ("/work", "git -C /srv/repo/vendor/lib commit", False),
    ("/srv/repo", "cd vendor/lib && git commit", False),
    ("/srv/repo", "git -C vendor/lib commit", False),
    ("/srv/repo", "git -C vendor/lib status && git commit", True),
    ("/srv/repo/vendor/lib", "cd ../.. && git commit", True),
    ("/srv/repo/vendor/lib", "git -C /srv/repo commit", True),
    ("/srv/repo", "(cd vendor/lib && git commit); git status", False),
    ("/srv/repo", "pushd vendor/lib; git status; popd; git commit", True),
    ("/srv/repo", "cd new/dir/not/made/yet && git commit", True),
    # A directory the gate cannot read counts as in scope.
    ("/work", "cd $WHERE && git commit", True),
    ("/srv/repo/vendor/lib", "git -C $X commit", True),
]


@pytest.mark.parametrize(("cwd", "command", "expected"), SCOPE)
def test_repo_root_tells_the_top_level_from_a_nested_repository(
    cwd: str, command: str, expected: bool
) -> None:
    assert fires(rooted(), "Bash", command, cwd) is expected


def test_cwd_under_cannot_say_what_repo_root_says() -> None:
    under = parse_rule(rule("under", when=COMMIT, applies={"cwd_under": ["/srv/repo"]}))
    nested = facts("Bash", "git commit", "/srv/repo/vendor/lib")
    assert evaluate([under], nested, repo_root=table).effect == "deny"
    assert evaluate([rooted()], nested, repo_root=table).effect == "none"


WINDOWS_SCOPE = [
    (r"C:\srv\repo", "PowerShell", "git commit", True),
    (r"C:\srv\repo\src", "PowerShell", "git commit", True),
    (r"C:\srv\repo\vendor\lib", "PowerShell", "git commit", False),
    (r"C:\work", "PowerShell", r"Set-Location C:\srv\repo; git commit", True),
    (r"C:\work", "PowerShell", r"git -C C:\srv\repo\vendor\lib commit", False),
    (r"C:\work", "PowerShell", r'cmd /c "cd /d C:\srv\repo && git commit"', True),
    (r"C:\work", "Bash", "cd /c/srv/repo && git commit", True),
    (r"C:\work", "Bash", "git -C /c/srv/repo/vendor/lib commit", False),
    (r"c:\SRV\Repo", "PowerShell", "git commit", True),
]


@pytest.mark.parametrize(("cwd", "tool", "command", "expected"), WINDOWS_SCOPE)
def test_repo_root_on_windows(
    cwd: str, tool: str, command: str, expected: bool
) -> None:
    def lookup(directory: str) -> str | None:
        # The table is spelt one way; the filesystem ignores letter case.
        return repo.find_root(
            directory, lambda d: d.lower() in {r.lower() for r in REPOSITORIES}
        )

    item = rooted(repo_root=[r"C:\srv\repo"])
    found = facts(tool, command, cwd, "windows")
    assert (evaluate([item], found, repo_root=lookup).effect != "none") is expected


def test_repo_root_takes_several_directories_and_patterns() -> None:
    item = rooted(repo_root=["/srv/none", "/srv/repo/vendor/lib"])
    assert fires(item, "Bash", "git commit", "/srv/repo/vendor/lib/src")
    assert not fires(item, "Bash", "git commit", "/srv/repo")
    # Every repository directly below a directory, and the home directory.
    item = rooted(repo_root=["/srv/*"])
    assert fires(item, "Bash", "git commit", "/srv/repo/src")
    assert not fires(item, "Bash", "git commit", "/srv/repo/vendor/lib")
    item = rooted(repo_root=["~/work/site"])
    assert fires(item, "Bash", "cd ~/work/site/docs && git commit", "/work")


def test_a_relative_repo_root_resolves_on_the_rule_base() -> None:
    raw = rule("rooted", when=COMMIT, applies={"repo_root": ["."]})
    item = parse_rule(raw, origin="project", base="/srv/repo")
    found = facts("Bash", "git commit", "/srv/repo/src")
    assert evaluate([item], found, repo_root=table).effect == "deny"
    found = facts("Bash", "git commit", "/srv/repo/vendor/lib")
    assert evaluate([item], found, repo_root=table).effect == "none"


def test_repo_root_combines_with_the_other_scopes() -> None:
    item = rooted(cwd_under=["/srv/repo/src"])
    assert fires(item, "Bash", "git commit", "/srv/repo/src/x")
    assert not fires(item, "Bash", "git commit", "/srv/repo/docs")
    item = rooted(cwd_not_under=["/srv/repo/docs"])
    assert fires(item, "Bash", "git commit", "/srv/repo/src")
    assert not fires(item, "Bash", "git commit", "/srv/repo/docs/api")
    item = rooted(tools=["PowerShell"])
    assert not fires(item, "Bash", "git commit", "/srv/repo")


def test_a_rule_with_repo_root_sees_only_the_paths_of_commands_in_scope() -> None:
    delete = {"type": "path", "op": "delete", "recursive": True}
    item = rooted(delete)
    assert fires(item, "Bash", "rm -rf build", "/srv/repo")
    assert not fires(item, "Bash", "cd vendor/lib && rm -rf build", "/srv/repo")
    assert not fires(item, "Bash", "git status; cd /tmp && rm -rf build", "/srv/repo")


FILE_TOOLS = [
    # tool, input, working directory, fires
    ("Write", {"file_path": "/srv/repo/src/a.py"}, "/work", True),
    ("Write", {"file_path": "/srv/repo/new/dir/a.py"}, "/work", True),
    ("Write", {"file_path": "/srv/repo/vendor/lib/a.py"}, "/srv/repo", False),
    ("Write", {"file_path": "vendor/lib/a.py"}, "/srv/repo", False),
    ("Write", {"file_path": "src/a.py"}, "/srv/repo", True),
    ("Write", {"file_path": "/tmp/a.py"}, "/srv/repo", False),
    ("Edit", {"file_path": "/srv/repo/.git/config"}, "/work", True),
    # A path with a variable nobody set is somewhere the gate does not know.
    ("Write", {"file_path": "$NOWHERE/a.py"}, "/work", True),
]


@pytest.mark.parametrize(("tool", "payload", "cwd", "expected"), FILE_TOOLS)
def test_for_a_file_tool_repo_root_looks_at_the_file(
    tool: str, payload: dict[str, Any], cwd: str, expected: bool
) -> None:
    item = rooted({"type": "path", "op": "write"})
    assert fires(item, tool, payload, cwd) is expected


def test_a_directory_given_to_a_file_tool_is_asked_about_itself() -> None:
    item = rooted({"type": "path", "op": "read"})
    assert fires(item, "Grep", {"pattern": "x", "path": "/srv/repo"}, "/work")
    assert not fires(
        item, "Grep", {"pattern": "x", "path": "/srv/repo/vendor/lib"}, "/work"
    )
    assert fires(
        item, "Grep", {"pattern": "x", "path": "/srv/repo", "glob": "*.py"}, "/work"
    )


def test_a_tool_without_paths_is_judged_on_its_working_directory() -> None:
    item = rooted({"type": "arg", "name": "amount", "op": ">", "value": 5})
    assert fires(item, "mcp__bank__pay", {"amount": 9}, "/srv/repo/src")
    assert not fires(item, "mcp__bank__pay", {"amount": 9}, "/srv/repo/vendor/lib")
    assert not fires(item, "mcp__bank__pay", {"amount": 9}, "/work")


def test_history_is_seen_through_the_same_scope() -> None:
    when = {
        "type": "all",
        "of": [
            {"type": "command", "program": "git", "subcommand": ["push"]},
            {
                "type": "not_preceded_by",
                "predicate": {"type": "command", "program": "pytest"},
            },
        ],
    }
    item = rooted(when)
    now = facts("Bash", "git push", "/srv/repo")
    nested = MemoryHistory()
    nested.add(facts("Bash", "cd vendor/lib && pytest", "/srv/repo"), 1.0)
    assert evaluate([item], now, nested, repo_root=table).effect == "deny"
    top = MemoryHistory()
    top.add(facts("Bash", "cd /srv/repo/tests && pytest", "/work"), 1.0)
    assert evaluate([item], now, top, repo_root=table).effect == "none"


# ---------------------------------------------------------------------------
# Cost and failure
# ---------------------------------------------------------------------------
def test_each_directory_is_looked_up_once_per_call() -> None:
    asked: list[str] = []

    def lookup(directory: str) -> str | None:
        asked.append(directory)
        return table(directory)

    command = "git commit; git commit; cd vendor/lib; git commit; git commit"
    rules = [
        rooted(),
        parse_rule(rule("again", when=COMMIT, applies={"repo_root": ["/x"]})),
    ]
    evaluate(rules, facts("Bash", command, "/srv/repo"), repo_root=lookup)
    assert sorted(asked) == ["/srv/repo", "/srv/repo/vendor/lib"]


def test_nothing_is_looked_up_unless_a_rule_names_a_repository() -> None:
    def lookup(directory: str) -> str | None:
        raise AssertionError(f"looked up {directory}")

    rules = [
        *builtin_rules(),
        parse_rule(rule("under", when=COMMIT, applies={"cwd_under": ["/srv"]})),
        parse_rule(rule("not", when=COMMIT, applies={"cwd_not_under": ["/tmp"]})),
        # Its tool does not match, so its directories are never judged.
        rooted(tools=["PowerShell"]),
    ]
    for command in ("git status", "cd /srv/repo && git commit", "rm -rf /"):
        evaluate(rules, facts("Bash", command, "/srv/repo"), repo_root=lookup)
    evaluate(rules, facts("Write", {"file_path": "a"}, "/srv/repo"), repo_root=lookup)


LAZY_PROBE = """
import json, sys
from ember_armor.ledger.engine import evaluate
from ember_armor.ledger.builtin import builtin_rules
from ember_armor.ledger.facts import extract
from ember_armor.ledger.model import parse_rule
call = {"tool_name": "Bash", "cwd": "/w", "tool_input": {"command": "git commit"}}
facts = extract(call, windows=False, env={})
evaluate(builtin_rules(), facts)
before = "ember_armor.ledger.repo" in sys.modules
rule = {"id": "r", "text": "t", "source": "s", "effect": "warn", "confirmed": True,
        "applies": {"repo_root": ["/w"]}, "when": {"type": "command", "program": "git"}}
evaluate([parse_rule(rule)], facts)
print(json.dumps([before, "ember_armor.ledger.repo" in sys.modules]))
"""


def test_the_lookup_module_is_loaded_only_when_a_rule_needs_it() -> None:
    env = {k: v for k, v in os.environ.items() if not k.startswith("EMBER_")}
    done = subprocess.run(
        [sys.executable, "-c", LAZY_PROBE],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout) == [False, True]


def refused(directory: str) -> str | None:
    if directory.startswith("/locked"):
        raise PermissionError(errno.EACCES, "Permission denied")
    return table(directory)


def test_a_failed_lookup_counts_as_in_scope_and_is_reported() -> None:
    decision = evaluate(
        [rooted()], facts("Bash", "git commit", "/locked/x"), repo_root=refused
    )
    assert decision.effect == "deny"
    assert decision.error is not None
    assert "repository lookup failed for /locked/x" in decision.error
    assert "Permission denied" in decision.error
    # The error is reported once, however many rules needed the answer.
    again = parse_rule(rule("again", when=COMMIT, applies={"repo_root": ["/x"]}))
    twice = evaluate(
        [rooted(), again], facts("Bash", "git commit", "/locked/x"), repo_root=refused
    )
    assert twice.error == decision.error
    assert [f.id for f in twice.fired] == ["rooted", "again"]
    # A lookup that worked reports nothing.
    fine = evaluate([rooted()], facts("Bash", "git commit", "/srv"), repo_root=refused)
    assert (fine.effect, fine.error) == ("none", None)


GATE_FAILURE = [
    # mode, command, decision, blocking
    ("enforce", "git commit", "deny", True),
    ("enforce", "git status", "ask", True),  # no rule fired: the failure asks
    ("observe", "git commit", "deny", False),
    ("observe", "git status", "none", False),
]


@pytest.mark.parametrize(("mode", "command", "effect", "blocking"), GATE_FAILURE)
def test_the_gate_treats_a_failed_lookup_as_a_gate_failure(
    gate_env, mode: str, command: str, effect: str, blocking: bool
) -> None:
    item = rule("rooted", when=COMMIT, applies={"repo_root": ["/srv/repo"]})
    write_ledger(Path(gate_env["EMBER_LEDGER"]), item)
    result = check(
        make_call("Bash", command, cwd="/locked/x"),
        env={**gate_env, "EMBER_GATE_MODE": mode},
        windows=False,
        repo_root=refused,
    )
    assert (result.decision.effect, result.blocking) == (effect, blocking)
    assert "repository lookup failed" in (result.decision.error or "")
    log = Path(gate_env["EMBER_HOME"]) / "audit"
    (entry,) = [json.loads(line) for f in log.glob("*.jsonl") for line in f.open()]
    assert "repository lookup failed" in entry["error"]
    assert entry["decision"] == effect


# ---------------------------------------------------------------------------
# End to end, with repositories in a temporary directory
# ---------------------------------------------------------------------------
@pytest.fixture
def repositories(tmp_path: Path) -> dict[str, Path]:
    """A repository with one nested in it, a hand-made one and a plain directory."""
    git = shutil.which("git")
    if git is None:
        pytest.skip("git is not installed")
    top = tmp_path / "work" / "top"
    nested = top / "packages" / "inner"
    made = tmp_path / "work" / "made"
    for directory in (top / "src", nested / "src", made, tmp_path / "work" / "plain"):
        directory.mkdir(parents=True)
    for directory in (top, nested):
        subprocess.run([git, "init", "-q", str(directory)], check=True, timeout=60)
    (made / ".git").mkdir()
    return {"top": top, "nested": nested, "made": made, "plain": made.parent / "plain"}


def test_real_repositories_through_the_gate(gate_env, repositories) -> None:
    top, nested = repositories["top"], repositories["nested"]
    item = rule("rooted", when=COMMIT, applies={"repo_root": [str(top)]})
    write_ledger(Path(gate_env["EMBER_LEDGER"]), item)

    def decide(command: str, cwd: Path) -> str:
        call = make_call("Bash", command, cwd=str(cwd))
        result = check(call, env=gate_env, record=False)
        assert result.decision.error is None
        return result.decision.effect

    assert decide("git commit", top) == "deny"
    assert decide("git commit", top / "src") == "deny"
    assert decide("git commit", nested) == "none"
    assert decide("git commit", nested / "src") == "none"
    assert decide("git commit", repositories["plain"]) == "none"
    assert decide("git commit", repositories["made"]) == "none"
    assert decide(f'git -C "{real(top)}" commit', repositories["plain"]) == "deny"
    assert decide(f'git -C "{real(nested)}" commit', top) == "none"
    assert decide(f'cd "{real(nested)}" && git commit', top) == "none"
    assert decide(f'cd "{real(top)}/src" && git commit', nested) == "deny"
    assert decide("cd packages/inner && git commit", top) == "none"
    assert decide("cd packages/not-made-yet && git commit", top) == "deny"


def test_a_hand_made_git_directory_is_a_repository(gate_env, repositories) -> None:
    made = repositories["made"]
    item = rule("rooted", when=COMMIT, applies={"repo_root": [str(made)]})
    write_ledger(Path(gate_env["EMBER_LEDGER"]), item)
    call = make_call("Bash", "git commit", cwd=str(made / "deep" / "er"))
    assert check(call, env=gate_env, record=False).decision.effect == "deny"
    call = make_call("Write", {"file_path": str(made / "a.txt")}, cwd=str(made.parent))
    write = rule(
        "rooted",
        when={"type": "path", "op": "write"},
        applies={"repo_root": [str(made)]},
    )
    write_ledger(Path(gate_env["EMBER_LEDGER"]), write)
    assert check(call, env=gate_env, record=False).decision.effect == "deny"


def test_the_hook_reads_the_real_filesystem(gate_env, repositories) -> None:
    top, nested = repositories["top"], repositories["nested"]
    item = rule("rooted", when=COMMIT, applies={"repo_root": [str(top)]})
    write_ledger(Path(gate_env["EMBER_LEDGER"]), item)

    def hook(cwd: Path) -> str:
        payload = json.dumps(make_call("Bash", "git commit", cwd=str(cwd)))
        done = run_gate(
            [],
            gate_env,
            stdin=payload,
            mode="enforce",
            module="ember_armor.ledger.hook",
        )
        assert done.returncode == 0, done.stderr
        return done.stdout.decode("utf-8")

    asked = json.loads(hook(top / "src"))
    assert asked["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert hook(nested) == ""
