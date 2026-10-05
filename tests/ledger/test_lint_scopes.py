"""Lint and the directory scopes that are judged for each command.

A rule with a directory scope sees only the commands in scope, so what lint
knows about its condition is its own.  ``repo_root`` is an atom lint knows
nothing about.  The findings must still hold on every call, including calls
whose commands run in several directories: the last tests check seeded
random ledgers against the engine, as ``test_lint_soundness`` does.

Every test here calls the real Z3 solver.  The command strings are data for
the parser; nothing runs them.
"""

from __future__ import annotations

import itertools
import random
from dataclasses import asdict
from typing import Any

import pytest

from ember_armor.ledger import repo
from ember_armor.ledger.engine import evaluate
from ember_armor.ledger.facts import Facts, extract
from ember_armor.ledger.lint import Finding, finding_data, lint
from ember_armor.ledger.model import Applies, Rule, parse_rule
from tests.ledger.helpers import POSIX_ENV, WINDOWS_ENV, make_call, rule
from tests.ledger.test_lint_soundness import ALWAYS, VALUES, predicate

pytest.importorskip("z3")

PUBLISH = {"type": "command", "program": "npm", "subcommand": ["publish"]}
NO_PUBLISH = {"type": "not", "of": PUBLISH}
CAP = {"type": "arg", "name": "amount", "op": ">", "value": 5}


def make(rule_id: str, when: dict[str, Any] | None = None, **fields: Any) -> Rule:
    if "require" in fields:
        raw = rule(rule_id, **fields)
        del raw["when"]
    else:
        raw = rule(rule_id, when=when, **fields)
    return parse_rule(raw)


def kinds(findings: list[Finding]) -> list[tuple[str, tuple[str, ...]]]:
    return [(finding.kind, finding.rules) for finding in findings]


# ---------------------------------------------------------------------------
# What lint concludes
# ---------------------------------------------------------------------------
def test_a_rule_with_a_repository_scope_is_shadowed_by_the_same_rule_everywhere() -> (
    None
):
    rules = [
        make("everywhere", PUBLISH),
        make("top", PUBLISH, applies={"repo_root": ["/srv/repo"]}),
    ]
    assert kinds(lint(rules, windows=False)) == [("shadowed", ("top", "everywhere"))]


def test_a_repository_scope_is_known_to_nothing_else() -> None:
    rules = [
        make("under", PUBLISH, applies={"cwd_under": ["/srv/repo"]}),
        make("top", PUBLISH, applies={"repo_root": ["/srv/repo"]}),
        make("other", PUBLISH, applies={"repo_root": ["/srv/other"]}),
    ]
    assert lint(rules, windows=False) == []


def test_the_same_repository_scope_twice_is_shadowed() -> None:
    scope = {"repo_root": ["/srv/repo"]}
    rules = [make("one", PUBLISH, applies=scope), make("two", PUBLISH, applies=scope)]
    assert kinds(lint(rules, windows=False)) == [("shadowed", ("two", "one"))]
    wider = {"repo_root": ["/srv/repo", "/srv/other"]}
    rules = [make("wide", PUBLISH, applies=wider), make("one", PUBLISH, applies=scope)]
    assert kinds(lint(rules, windows=False)) == [("shadowed", ("one", "wide"))]


def test_a_combined_scope_is_inside_its_parts() -> None:
    combined = {"cwd_under": ["/srv/repo/src"], "repo_root": ["/srv/repo"]}
    rules = [
        make("under", PUBLISH, applies={"cwd_under": ["/srv/repo"]}),
        make("both", PUBLISH, applies=combined),
    ]
    assert kinds(lint(rules, windows=False)) == [("shadowed", ("both", "under"))]
    rules = [
        make("top", PUBLISH, applies={"repo_root": ["/srv/repo"]}),
        make("both", PUBLISH, applies=combined),
    ]
    assert kinds(lint(rules, windows=False)) == [("shadowed", ("both", "top"))]


def test_an_exception_makes_a_scope_narrower_not_wider() -> None:
    whole = {"cwd_under": ["/srv/repo"]}
    most = {"cwd_under": ["/srv/repo"], "cwd_not_under": ["/srv/repo/vendor"]}
    rules = [make("whole", PUBLISH, applies=whole), make("most", PUBLISH, applies=most)]
    assert kinds(lint(rules, windows=False)) == [("shadowed", ("most", "whole"))]
    less = {"cwd_under": ["/srv/repo/src"], "cwd_not_under": ["/srv/repo"]}
    rules = [make("most", PUBLISH, applies=most), make("less", PUBLISH, applies=less)]
    assert kinds(lint(rules, windows=False)) == [("shadowed", ("less", "most"))]


def test_a_scope_that_only_an_unreadable_directory_meets_is_not_called_dead() -> None:
    # Under a directory and outside a directory around it: no known directory
    # is both, but a command in a directory the gate cannot read is in scope.
    odd = {"cwd_under": ["/srv/repo/src"], "cwd_not_under": ["/srv/repo"]}
    item = make("odd", PUBLISH, applies=odd)
    assert lint([item], windows=False) == []
    call = make_call("Bash", "cd $WHERE && npm publish", cwd="/tmp")
    facts = extract(call, windows=False, env=POSIX_ENV)
    assert evaluate([item], facts).effect == "deny"


def test_a_negated_condition_does_not_carry_from_a_narrow_scope_to_a_wide_one() -> None:
    rules = [
        make("wide", NO_PUBLISH, applies={"cwd_under": ["/work"]}),
        make("narrow", NO_PUBLISH, applies={"cwd_under": ["/work/app"]}),
    ]
    # The narrow rule can fire alone: it does not see the publish next door.
    assert lint(rules, windows=False) == []
    command = "cd /work/app && ls; cd /work/other && npm publish"
    facts = extract(
        make_call("Bash", command, cwd="/tmp"), windows=False, env=POSIX_ENV
    )
    assert [f.id for f in evaluate(rules, facts).fired] == ["narrow"]


def test_a_positive_condition_still_carries_from_a_narrow_scope_to_a_wide_one() -> None:
    rules = [
        make("wide", PUBLISH, applies={"cwd_under": ["/work"]}),
        make("narrow", PUBLISH, applies={"cwd_under": ["/work/app"]}),
        make("anywhere", PUBLISH, effect="ask"),
    ]
    assert kinds(lint(rules, windows=False)) == [("shadowed", ("narrow", "wide"))]


def test_a_contradiction_is_found_for_a_repository() -> None:
    scope = {"tools": ["transfer"], "repo_root": ["/srv/repo"]}
    rules = [
        make("cap", CAP, applies=scope),
        make("floor", require=CAP, applies=scope),
    ]
    (finding,) = lint(rules, windows=False)
    assert finding.kind == "contradiction"
    assert finding.rules == ("cap", "floor")
    assert finding.scope == Applies(tools=("transfer",), repo_root=("/srv/repo",))
    assert finding.message == (
        "deny rules cap, floor together deny every call "
        "for tool transfer and repository root /srv/repo"
    )
    assert finding_data(finding)["scope"] == {
        "tools": ("transfer",),
        "cwd_under": (),
        "repo_root": ("/srv/repo",),
    }


def test_findings_keep_their_shape_when_the_new_scopes_are_not_used() -> None:
    scope = {"tools": ["transfer"]}
    rules = [make("cap", CAP, applies=scope), make("floor", require=CAP, applies=scope)]
    (finding,) = lint(rules)
    assert finding_data(finding) == {
        "kind": "contradiction",
        "rules": ("cap", "floor"),
        "message": "deny rules cap, floor together deny every call for tool transfer",
        "scope": {"tools": ("transfer",), "cwd_under": ()},
    }
    dead = Finding("dead", ("r",), "r never fires")
    assert finding_data(dead) == {**asdict(dead), "scope": None}


# ---------------------------------------------------------------------------
# Findings hold on calls whose commands run in several directories
# ---------------------------------------------------------------------------
TOOLS = ["Bash", "Read", "Write", "transfer"]
ROOTS = {False: "/work", True: "C:/work"}
CWDS = {
    False: ["/work", "/work/app", "/work/app/sub", "/other", "/"],
    True: ["C:\\work", "C:\\work\\app", "C:\\work\\app\\sub", "D:\\other", "C:\\"],
}
FILES = ["src/a.py", "src/gen/x.py", ".env", "/etc/hosts"]


def repositories(windows: bool) -> set[str]:
    root = ROOTS[windows]
    return {f"{root}/app", f"{root}/app/sub"}


def finder(windows: bool):
    found = {name.lower() for name in repositories(windows)}

    def lookup(directory: str) -> str | None:
        return repo.find_root(directory, lambda d: d.lower() in found)

    return lookup


def scopes(windows: bool) -> list[dict[str, Any]]:
    root = ROOTS[windows]
    return [
        {},
        {"tools": ["Bash"]},
        {"tools": ["transfer"]},
        {"cwd_under": [root]},
        {"cwd_under": [f"{root}/app"]},
        {"cwd_under": [f"{root}/app/sub"]},
        {"cwd_under": [f"{root}/app", "/other"]},
        {"cwd_not_under": [f"{root}/app"]},
        {"cwd_under": [root], "cwd_not_under": [f"{root}/app/sub"]},
        {"cwd_under": [f"{root}/app"], "cwd_not_under": [f"{root}/app/sub"]},
        {"cwd_under": [f"{root}/app/sub"], "cwd_not_under": [f"{root}/app"]},
        {"repo_root": [f"{root}/app"]},
        {"repo_root": [f"{root}/app/sub"]},
        {"repo_root": [f"{root}/app", f"{root}/app/sub"]},
        {"cwd_under": [f"{root}/app"], "repo_root": [f"{root}/app"]},
        {"tools": ["Bash"], "repo_root": [f"{root}/app"]},
    ]


def commands(windows: bool) -> list[str]:
    root = ROOTS[windows]
    return [
        "git status",
        "git push",
        "git push --force origin main",
        "git push origin -f",
        "cat .env",
        "rm -rf src/gen",
        "eval $X",
        f"cd {root}/app && git push --force origin main",
        f"git -C {root}/app/sub push",
        f"git -C {root}/app push origin main; git status",
        f"cd {root}/app && git status; cd /other && git push",
        f"git push; git -C {root}/app status",
        f"(cd {root}/app/sub && git push --force); git status",
        f"cd {root}/app/sub && rm -rf src/gen; cat .env",
        f"cd {root}/app && cat src/a.py > src/gen/x.txt",
        f"pushd {root}/app; git push origin main; popd; cat .env",
        "cd $SOMEWHERE && git push --force origin main",
        f"cd {root}/app && cd $SOMEWHERE && git push",
        f"git -C {root}/app status && git -C /other push --force",
        f"env -C {root}/app/sub git push origin",
    ]


def random_ledger(rng: random.Random, windows: bool) -> list[Rule]:
    rules = []
    for index in range(rng.randint(2, 4)):
        raw = rule(
            f"r{index}",
            effect=rng.choice(["deny", "deny", "ask", "warn"]),
            applies=rng.choice(scopes(windows)),
        )
        key = "when" if rng.random() < 0.75 else "require"
        del raw["when"]
        raw[key] = predicate(rng, windows)
        rules.append(parse_rule(raw))
    if rng.random() < 0.3:
        # Two deny rules that split one scope between them: a contradiction
        # there, whatever the condition and whichever scope it is.
        scope, condition = rng.choice(scopes(windows)), predicate(rng, windows)
        rules.append(make("split-when", condition, applies=scope))
        rules.append(make("split-require", require=condition, applies=scope))
    return rules


def call_pool(windows: bool) -> list[Facts]:
    rng = random.Random(11)
    env = WINDOWS_ENV if windows else POSIX_ENV
    calls = []
    for tool, cwd in itertools.product(TOOLS, CWDS[windows]):
        for _ in range(20 if tool == "Bash" else 6):
            payload: dict[str, Any] = {
                name: rng.choice(VALUES)
                for name in ("amount", "fee", "env")
                if rng.random() < 0.7
            }
            if tool == "Bash":
                payload["command"] = rng.choice(commands(windows))
            elif tool in ("Read", "Write"):
                payload["file_path"] = rng.choice(FILES)
            call = make_call(tool, payload, cwd=cwd)
            calls.append(extract(call, windows=windows, env=env))
    return calls


POOLS = {windows: call_pool(windows) for windows in (False, True)}


def fires(checked: Rule, facts: Facts) -> bool:
    lookup = finder(facts.windows)
    return evaluate([checked], facts, repo_root=lookup).effect != "none"


def in_scope(applies: dict[str, Any], facts: Facts) -> bool:
    return fires(parse_rule(rule("scope", when=ALWAYS, applies=applies)), facts)


def counterexample(
    finding: Finding, rules: dict[str, Rule], pool: list[Facts]
) -> Facts | None:
    """A concrete call that contradicts *finding*, if the pool has one."""
    subject = rules[finding.rules[0]]
    others = [rules[rule_id] for rule_id in finding.rules[1:]]
    for facts in pool:
        if finding.kind == "dead":
            wrong = fires(subject, facts)
        elif finding.kind == "blanket":
            scope = subject.raw.get("applies", {})
            wrong = in_scope(scope, facts) and not fires(subject, facts)
        elif finding.kind == "shadowed":
            wrong = fires(subject, facts) and not all(fires(o, facts) for o in others)
        else:
            assert finding.scope is not None
            scope = {k: list(v) for k, v in asdict(finding.scope).items() if v}
            denied = any(fires(r, facts) for r in (subject, *others))
            wrong = in_scope(scope, facts) and not denied
        if wrong:
            return facts
    return None


def test_the_pool_has_calls_that_run_in_several_directories() -> None:
    for windows in (False, True):
        several = [
            facts
            for facts in POOLS[windows]
            if len({command.cwd for command in facts.commands}) > 1
        ]
        unknown = [f for f in POOLS[windows] if any(c.cwd == "?" for c in f.commands)]
        assert len(several) >= 30
        assert len(unknown) >= 5


@pytest.mark.parametrize("windows", [False, True], ids=["posix", "windows"])
def test_no_finding_is_contradicted_on_calls_with_several_directories(
    windows: bool,
) -> None:
    rng = random.Random(20261005)
    seen: dict[str, int] = {}
    for _ in range(300):
        ledger = random_ledger(rng, windows)
        by_id = {r.id: r for r in ledger}
        for finding in lint(ledger, windows=windows):
            seen[finding.kind] = seen.get(finding.kind, 0) + 1
            facts = counterexample(finding, by_id, POOLS[windows])
            assert facts is None, (finding, [r.raw for r in ledger], facts)
    # The check above means nothing unless findings of every kind turned up.
    assert all(seen.get(kind, 0) >= 5 for kind in
               ("dead", "blanket", "shadowed", "contradiction")), seen  # fmt: skip
