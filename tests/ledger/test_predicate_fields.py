"""Predicate fields that tie a condition to one command or one path.

``flags_none``, ``args_none_glob`` and ``args_regex`` on ``command``,
``not_glob`` on ``path``, arguments counted from the subcommand, exact
arithmetic and the history rules.  Command strings are data; nothing runs.
"""

from __future__ import annotations

from typing import Any

import pytest

from ember_armor.ledger.builtin import DESTRUCTIVE_SQL
from ember_armor.ledger.engine import MemoryHistory, PastCall, evaluate
from ember_armor.ledger.model import Decision, FiredRule, LedgerError, Rule, parse_rule
from tests.ledger.helpers import facts_for, rule


def make_rule(when: dict[str, Any], **fields: Any) -> Rule:
    return parse_rule(rule(fields.pop("rule_id", "r1"), when=when, **fields))


def fires(
    when: dict[str, Any], tool: str, payload: Any, platform: str = "posix"
) -> bool:
    decision = evaluate([make_rule(when)], facts_for(tool, payload, platform))
    return decision.effect != "none"


def command(**fields: Any) -> dict[str, Any]:
    return {"type": "command", **fields}


# ---------------------------------------------------------------------------
# command: exceptions and arguments belong to one command
# ---------------------------------------------------------------------------
DELETE = command(
    program="kubectl",
    subcommand=["delete"],
    flags_none=["--help", "-h"],
    args_none_glob=["--dry-run", "--dry-run=client"],
)
SAME_COMMAND = [
    ("kubectl delete pod a", True),
    ("kubectl delete pod a --dry-run=client", False),
    ("kubectl delete pod a --dry-run", False),
    ("kubectl delete pod a --dry-run=none", True),
    ("kubectl delete --help", False),
    ("kubectl delete -h", False),
    # an exception on one command does not excuse the next
    ("kubectl delete pod a --dry-run=client && kubectl delete pod b", True),
    ("kubectl delete --help; kubectl -n prod delete ns x", True),
    ("kubectl get pods --dry-run=client", False),
]


@pytest.mark.parametrize(("text", "expected"), SAME_COMMAND)
def test_exceptions_are_per_command(text: str, expected: bool) -> None:
    assert fires(DELETE, "Bash", text) is expected


DOT = command(program="git", subcommand=["checkout"], args_any_glob=["."])
AFTER_SUBCOMMAND = [
    ("git checkout .", True),
    ("git checkout -- .", True),
    ("git -C . checkout main", False),
    ("git --work-tree . checkout main", False),
    ("git -C . checkout .", True),
]


@pytest.mark.parametrize(("text", "expected"), AFTER_SUBCOMMAND)
def test_argument_globs_look_after_the_subcommand(text: str, expected: bool) -> None:
    assert fires(DOT, "Bash", text) is expected


def test_argument_globs_without_a_subcommand_see_every_argument() -> None:
    pred = command(program="certutil", args_any_glob=["root"])
    assert fires(pred, "Bash", "certutil -addstore root ca.cer")


SQL = command(program=["psql", "sqlite3"], args_regex=DESTRUCTIVE_SQL)
SQL_CASES = [
    ("psql -c 'DROP TABLE users'", True),
    ('psql -c "delete from users"', True),
    ('psql -c "delete from users where id = 1"', False),
    ('psql -c "TRUNCATE orders"', True),
    ('echo "DROP TABLE x" | sqlite3 db', True),
    ("psql <<EOF\nDROP TABLE x;\nEOF", True),
    ("psql <<'EOF'\n-- don't run twice\nDROP TABLE x;\nEOF", True),
    ("psql -c \"DO $$ BEGIN EXECUTE 'DROP TABLE x'; END $$\"", True),
    # the words are somewhere else in the command string
    ('sqlite3 dev.db .tables && git commit -m "drop table legacy"', False),
    ("sqlite3 dev.db .schema | grep -i 'drop table'", False),
    ('grep -n "DROP TABLE" migrations/*.sql && sqlite3 dev.db .schema', False),
    # ... or inside an SQL string literal
    ("sqlite3 db \"SELECT * FROM l WHERE m LIKE '%delete from cart%'\"", False),
    ("psql -c \"COMMENT ON TABLE t IS 'do not drop table without backup'\"", False),
    ("sqlite3 db \"SELECT 'DROP TABLE ' || name FROM sqlite_master\"", False),
    ("psql -c \"SELECT 'it''s'; DROP TABLE x\"", True),
]


@pytest.mark.parametrize(("text", "expected"), SQL_CASES)
def test_args_regex_reads_what_the_command_receives(text: str, expected: bool) -> None:
    assert fires(SQL, "Bash", text) is expected


# ---------------------------------------------------------------------------
# path: not_glob excludes the same path only
# ---------------------------------------------------------------------------
KEYS = {
    "type": "path",
    "op": "read",
    "glob": ["**/*key*.pem"],
    "not_glob": ["**/*public*.pem"],
}
NOT_GLOB = [
    ("cat private_key.pem", True),
    ("cat public_key.pem", False),
    ("cat private_key.pem public_key.pem", True),
    ("cat public_key.pem private_key.pem", True),
    ("cat PUBLIC_key.pem", True),
]


@pytest.mark.parametrize(("text", "expected"), NOT_GLOB)
def test_not_glob_is_per_path(text: str, expected: bool) -> None:
    assert fires(KEYS, "Bash", text) is expected


def test_a_wildcard_operand_matches_a_glob_but_never_an_exclusion() -> None:
    secret = {"type": "path", "op": "read", "glob": ["**/.env"]}
    assert fires(secret, "Bash", "cat .env*")
    assert not fires(secret, "Bash", "cat *")
    spared = {"type": "path", "op": "delete", "not_under": ["**/dist"]}
    assert fires(spared, "Bash", "rm -rf dis?")
    assert not fires(spared, "Bash", "rm -rf packages/*/dist")


# ---------------------------------------------------------------------------
# model
# ---------------------------------------------------------------------------
def test_new_fields_round_trip() -> None:
    parsed = make_rule(SQL).predicate
    assert parsed.args_regex == DESTRUCTIVE_SQL
    assert parsed.regex is not None
    assert make_rule(DELETE).predicate.flags_none == ("--help", "-h")
    assert make_rule(KEYS).predicate.not_glob == ("**/*public*.pem",)


BAD = [
    (command(program="psql", args_regex="("), "invalid regular expression"),
    (command(program="x", flags_none=[""]), "non-empty string or list"),
    ({"type": "path", "not_globs": ["x"]}, "unknown field(s) not_globs"),
    (
        {"type": "arg", "name": "amount", "op": ">", "value": "5000000"},
        "expected a number",
    ),
    ({"type": "arg", "name": "amount", "op": "<=", "value": None}, "expected a number"),
    ({"type": "expr", "lhs": {"a": 1e999}, "op": ">", "rhs": 0}, "finite number"),
]


@pytest.mark.parametrize(("when", "message"), BAD)
def test_typos_in_the_new_fields_are_errors(when: dict[str, Any], message: str) -> None:
    with pytest.raises(
        LedgerError, match=message.replace("(", r"\(").replace(")", r"\)")
    ):
        make_rule(when)


def test_the_reason_labels_a_project_rule_and_caps_its_text() -> None:
    fired = FiredRule("p1", "x" * 5000, "y" * 5000, "deny", "project")
    reason = Decision("deny", (fired,)).reason()
    assert "rule p1 from this repository's ledger (deny)" in reason
    assert len(reason) < 1000
    user = Decision("ask", (FiredRule("u1", "text", "me", "ask"),)).reason()
    assert user == 'EmberArmor ledger rule u1 (ask): "text" [source: me]'


# ---------------------------------------------------------------------------
# arithmetic is exact
# ---------------------------------------------------------------------------
def test_sums_are_exact() -> None:
    tenths = {"type": "expr", "lhs": {"x": 0.1, "y": 0.2}, "op": "<=", "rhs": 0.3}
    # As floats 0.1 + 0.2 > 0.3; the rule holds the floats, so it is exact
    # about them: the binary values of 0.1 and 0.2 add up to more than 0.3's.
    assert not fires(tenths, "pay", {"x": 1, "y": 1})
    units = {"type": "expr", "lhs": {"x": 1, "y": 2}, "op": "<=", "rhs": 3}
    assert fires(units, "pay", {"x": 1, "y": 1})
    big = {"type": "arg", "name": "n", "op": ">", "value": 9007199254740992}
    assert fires(big, "pay", {"n": 9007199254740993})
    assert not fires(big, "pay", {"n": 9007199254740992})


def test_a_cap_still_fires_on_an_infinite_amount() -> None:
    cap = {"type": "arg", "name": "amount", "op": ">", "value": 5_000_000}
    assert fires(cap, "pay", {"amount": float("inf")})
    assert fires(cap, "pay", {"amount": "1e999"})
    assert not fires(cap, "pay", {"amount": float("nan")})


# ---------------------------------------------------------------------------
# history
# ---------------------------------------------------------------------------
PUSH = command(program="git", subcommand=["push"])
TESTS = command(program="pytest")
TESTED = {"type": "all", "of": [{"type": "not_preceded_by", "predicate": TESTS}, PUSH]}


class CountingHistory(MemoryHistory):
    """History that counts how often it is read."""

    reads = 0

    def earlier(self, session: str) -> list[PastCall]:
        self.reads += 1
        return list(super().earlier(session))


def test_history_is_read_once_per_call_and_only_when_needed() -> None:
    history = CountingHistory()
    history.add(facts_for("Bash", "pytest"), 1.0)
    rules = [make_rule(TESTED, rule_id=f"r{i}") for i in range(10)]
    # The cheap part decides: an unrelated call never touches the log.
    assert evaluate(rules, facts_for("Bash", "git status"), history).effect == "none"
    assert (
        evaluate(rules, facts_for("Read", {"file_path": "a"}), history).effect == "none"
    )
    assert history.reads == 0
    assert evaluate(rules, facts_for("Bash", "git push"), history).effect == "none"
    assert history.reads == 1


def test_calls_without_a_session_share_no_history() -> None:
    history = MemoryHistory()
    history.add(facts_for("Bash", "pytest", session=""), 1.0)
    push = facts_for("Bash", "git push", session="")
    assert evaluate([make_rule(TESTED)], push, history).effect == "deny"
    count = {"type": "count_exceeds", "predicate": TESTS, "max": 0}
    assert evaluate([make_rule(count)], push, history).effect == "none"
