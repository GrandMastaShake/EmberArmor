"""``ember-gate lint`` and stale directory scopes.

A rule's ``cwd_under``, ``cwd_not_under`` and ``repo_root`` encode facts
about this machine: that a directory exists, that a directory is the root
of a repository.  These tests make and unmake such directories under
``tmp_path`` and ask lint whether it notices.  No solver is needed; the two
tests that want one say so.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from ember_armor.ledger import cli
from ember_armor.ledger.lint import Finding, stale_scopes
from ember_armor.ledger.model import Rule, parse_rule
from ember_armor.ledger.paths import normalize
from tests.ledger.helpers import rule, write_ledger

WINDOWS = os.name == "nt"


def make(rule_id: str, base: str | None = None, **applies: Any) -> Rule:
    """A confirmed deny rule with the given directory scope."""
    return parse_rule(rule(rule_id, applies=applies), base=base)


def normal(path: Path) -> str:
    """The directory *path* names, the way lint prints it."""
    return normalize(str(path), "/", windows=WINDOWS)


def shown(path: Path) -> str:
    """How lint shows a scope written as ``str(path)``: the pattern as
    written, with the directory it names when the two differ."""
    pattern, directory = str(path), normal(path)
    return pattern if pattern == directory else f"{pattern} ({directory})"


def kinds(findings: list[Finding]) -> list[tuple[str, tuple[str, ...]]]:
    return [(finding.kind, finding.rules) for finding in findings]


# ---------------------------------------------------------------------------
# What is stale
# ---------------------------------------------------------------------------
def test_a_cwd_under_directory_that_exists_is_not_stale(tmp_path: Path) -> None:
    (tmp_path / "work").mkdir()
    assert stale_scopes([make("r", cwd_under=[str(tmp_path / "work")])]) == []


def test_a_cwd_under_directory_that_is_gone_is_stale(tmp_path: Path) -> None:
    findings = stale_scopes([make("r", cwd_under=[str(tmp_path / "gone")])])
    assert kinds(findings) == [("stale", ("r",))]
    [finding] = findings
    gone = shown(tmp_path / "gone")
    assert finding.message == f"r (deny): cwd_under {gone} does not exist"
    assert finding.scope is not None
    assert finding.scope.cwd_under == (str(tmp_path / "gone"),)


def test_a_cwd_not_under_directory_that_is_gone_is_stale(tmp_path: Path) -> None:
    (tmp_path / "work").mkdir()
    findings = stale_scopes(
        [
            make(
                "r",
                cwd_under=[str(tmp_path / "work")],
                cwd_not_under=[str(tmp_path / "work" / "vendor")],
            )
        ]
    )
    vendor = shown(tmp_path / "work" / "vendor")
    assert [f.message for f in findings] == [
        f"r (deny): cwd_not_under {vendor} does not exist"
    ]


def test_a_repo_root_that_is_a_repository_is_not_stale(tmp_path: Path) -> None:
    (tmp_path / "repo" / ".git").mkdir(parents=True)
    assert stale_scopes([make("r", repo_root=[str(tmp_path / "repo")])]) == []


def test_a_repo_root_whose_git_is_a_file_is_a_repository(tmp_path: Path) -> None:
    (tmp_path / "worktree").mkdir()
    (tmp_path / "worktree" / ".git").write_text("gitdir: elsewhere", encoding="utf-8")
    assert stale_scopes([make("r", repo_root=[str(tmp_path / "worktree")])]) == []


def test_a_repo_root_that_is_gone_is_stale(tmp_path: Path) -> None:
    [finding] = stale_scopes([make("r", repo_root=[str(tmp_path / "gone")])])
    gone = shown(tmp_path / "gone")
    assert finding.message == f"r (deny): repo_root {gone} does not exist"


def test_a_repo_root_that_holds_no_git_is_stale(tmp_path: Path) -> None:
    (tmp_path / "plain").mkdir()

    def find(directory: str) -> str | None:
        return None

    [finding] = stale_scopes(
        [make("r", repo_root=[str(tmp_path / "plain")])], find_root=find
    )
    plain = shown(tmp_path / "plain")
    assert finding.message == (
        f"r (deny): repo_root {plain} is not a repository and lies in none"
    )


def test_a_repo_root_inside_another_repository_names_it(tmp_path: Path) -> None:
    (tmp_path / "outer" / ".git").mkdir(parents=True)
    (tmp_path / "outer" / "inner").mkdir()
    [finding] = stale_scopes(
        [make("r", repo_root=[str(tmp_path / "outer" / "inner")])]
    )
    inner, outer = shown(tmp_path / "outer" / "inner"), normal(tmp_path / "outer")
    assert finding.message == (
        f"r (deny): repo_root {inner} is not a repository; "
        f"the nearest one around it is {outer}"
    )


def test_an_unconfirmed_rule_is_named_as_such(tmp_path: Path) -> None:
    draft = parse_rule(
        rule("draft", confirmed=False, applies={"cwd_under": [str(tmp_path / "x")]})
    )
    [finding] = stale_scopes([draft])
    assert finding.message.startswith("draft (deny, unconfirmed): cwd_under ")


def test_every_stale_directory_of_a_rule_is_reported(tmp_path: Path) -> None:
    findings = stale_scopes(
        [
            make(
                "r",
                cwd_under=[str(tmp_path / "a"), str(tmp_path / "b")],
                repo_root=[str(tmp_path / "c")],
            )
        ]
    )
    assert kinds(findings) == [("stale", ("r",))] * 3


# ---------------------------------------------------------------------------
# How patterns are placed
# ---------------------------------------------------------------------------
def test_the_home_directory_expands(tmp_path: Path) -> None:
    env = {"HOME": str(tmp_path), "USERPROFILE": str(tmp_path)}
    (tmp_path / "there").mkdir()
    assert stale_scopes([make("r", cwd_under=["~/there"])], env=env) == []
    [finding] = stale_scopes([make("r", cwd_under=["~/nowhere"])], env=env)
    nowhere = normal(tmp_path / "nowhere")
    assert finding.message == (
        f"r (deny): cwd_under ~/nowhere ({nowhere}) does not exist"
    )


def test_a_relative_pattern_resolves_against_the_rules_base(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    base = normal(tmp_path)
    assert stale_scopes([make("r", base=base, cwd_under=["src"])]) == []
    [finding] = stale_scopes([make("r", base=base, cwd_under=["lib"])])
    lib = normal(tmp_path / "lib")
    assert finding.message == f"r (deny): cwd_under lib ({lib}) does not exist"


def test_patterns_lint_cannot_place_are_passed_over(tmp_path: Path) -> None:
    rules = [
        # Relative without a base: resolved against each call's directory.
        make("relative", cwd_under=["src"]),
        make("dots", base=normal(tmp_path), cwd_under=["../elsewhere"]),
        make("glob", repo_root=[str(tmp_path / "*" / "repo")]),
        make("variable", cwd_under=["$TMPDIR/dir"]),
        make("network", cwd_under=["//host/share/dir"]),
    ]
    assert stale_scopes(rules, env={}) == []


def test_with_the_windows_flavour_only_drives_are_asked_about() -> None:
    asked: list[str] = []

    def exists(directory: str) -> bool:
        asked.append(directory)
        return False

    rules = [make("posix", cwd_under=["/srv/app"]), make("drive", cwd_under=["D:/x"])]
    findings = stale_scopes(rules, windows=True, env={}, exists=exists)
    assert asked == ["D:/x"]
    assert kinds(findings) == [("stale", ("drive",))]


def test_with_the_posix_flavour_paths_are_asked_about_as_written() -> None:
    asked: list[str] = []

    def exists(directory: str) -> bool:
        asked.append(directory)
        return True

    def find(directory: str) -> str | None:
        return directory

    rules = [make("r", cwd_under=["/srv/app"], repo_root=["/srv/app"])]
    assert (
        stale_scopes(rules, windows=False, env={}, exists=exists, find_root=find)
        == []
    )
    assert asked == ["/srv/app", "/srv/app"]


def test_a_lookup_the_filesystem_refuses_is_passed_over(tmp_path: Path) -> None:
    (tmp_path / "d").mkdir()

    def find(directory: str) -> str | None:
        raise PermissionError(13, "denied")

    rules = [make("r", repo_root=[str(tmp_path / "d")])]
    assert stale_scopes(rules, find_root=find) == []


def test_an_expired_rule_is_ignored(tmp_path: Path) -> None:
    old = parse_rule(
        rule("old", expires="2020-01-01", applies={"cwd_under": [str(tmp_path / "x")]})
    )
    assert stale_scopes([old], today=date(2026, 1, 1)) == []
    assert kinds(stale_scopes([old], today=date(2019, 1, 1))) == [("stale", ("old",))]


# ---------------------------------------------------------------------------
# The command
# ---------------------------------------------------------------------------
@pytest.fixture
def cli_env(
    gate_env: dict[str, str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> dict[str, str]:
    for name in ("EMBER_GATE_MODE", "EMBER_GATE_BUILTIN"):
        monkeypatch.delenv(name, raising=False)
    for name, value in gate_env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.chdir(tmp_path)
    return gate_env


def test_cli_prints_stale_scopes_and_exits_one(
    cli_env: dict[str, str], capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    pytest.importorskip("z3")
    write_ledger(
        tmp_path / "ledger.json",
        rule("gone", applies={"cwd_under": [str(tmp_path / "gone")]}),
    )
    assert cli.main(["lint"]) == 1
    out = capsys.readouterr().out
    gone = shown(tmp_path / "gone")
    assert f"stale: gone (deny): cwd_under {gone} does not exist" in out
    assert "1 finding" in out


def test_cli_json_carries_stale_findings(
    cli_env: dict[str, str], capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    pytest.importorskip("z3")
    write_ledger(
        tmp_path / "ledger.json",
        rule("gone", applies={"repo_root": [str(tmp_path / "gone")]}),
    )
    assert cli.main(["lint", "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["solver"] is True
    [finding] = report["findings"]
    assert finding["kind"] == "stale"
    assert finding["rules"] == ["gone"]
    assert finding["scope"] == {
        "tools": [],
        "cwd_under": [],
        "repo_root": [str(tmp_path / "gone")],
    }


def test_cli_prints_stale_scopes_even_without_the_solver(
    cli_env: dict[str, str],
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setitem(sys.modules, "z3", None)
    write_ledger(
        tmp_path / "ledger.json",
        rule("gone", applies={"cwd_under": [str(tmp_path / "gone")]}),
    )
    assert cli.main(["lint"]) == 3
    captured = capsys.readouterr()
    assert "stale: gone (deny): cwd_under " in captured.out
    assert "stale scopes only: 1 finding" in captured.out
    assert "no findings" not in captured.out
    assert "not installed" in captured.err


def test_cli_json_says_when_the_solver_was_missing(
    cli_env: dict[str, str],
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setitem(sys.modules, "z3", None)
    write_ledger(tmp_path / "ledger.json")
    assert cli.main(["lint", "--json"]) == 3
    report = json.loads(capsys.readouterr().out)
    assert report["solver"] is False
    assert report["findings"] == []
