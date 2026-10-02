"""Loading, merging and editing ledgers.  Everything lives under ``tmp_path``."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from ember_armor.ledger import config, store
from ember_armor.ledger.builtin import builtin_rules
from ember_armor.ledger.model import LedgerError
from tests.ledger.helpers import rule, write_ledger

TODAY = date(2026, 10, 2)


@pytest.fixture
def home_env(tmp_path: Path) -> dict[str, str]:
    """Environment with an Ember home in ``tmp_path`` and no override."""
    return {"EMBER_HOME": str(tmp_path / "home")}


def ids(rules: list, origin: str | None = None) -> list[str]:
    return [r.id for r in rules if origin is None or r.origin == origin]


def test_ember_home_honours_the_environment(tmp_path: Path) -> None:
    assert config.ember_home({"EMBER_HOME": str(tmp_path)}) == tmp_path
    assert config.ember_home({}) == Path.home() / ".ember"
    assert (
        store.user_ledger_path({"EMBER_HOME": str(tmp_path)})
        == tmp_path / "ledger.json"
    )


def test_builtin_pack_is_active_without_any_ledger_file(
    tmp_path: Path, home_env
) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    (project / ".ember").mkdir()
    write_ledger(project / ".ember" / "ledger.json")
    rules = store.load_rules(str(project), home_env, TODAY)
    assert ids(rules) == [r.id for r in builtin_rules()]


def test_user_and_project_ledgers_are_merged(tmp_path: Path, home_env) -> None:
    write_ledger(tmp_path / "home" / "ledger.json", rule("user-rule"))
    project = tmp_path / "proj"
    write_ledger(project / ".ember" / "ledger.json", rule("project-rule"))
    nested = project / "src" / "deep"
    nested.mkdir(parents=True)

    rules = store.load_rules(str(nested), home_env, TODAY)

    assert ids(rules, "user") == ["user-rule"]
    assert ids(rules, "project") == ["project-rule"]
    assert ids(rules, "builtin") == [r.id for r in builtin_rules()]
    project_rule = next(r for r in rules if r.id == "project-rule")
    assert Path(project_rule.base) == project


def test_nearest_project_ledger_wins(tmp_path: Path, home_env) -> None:
    outer = tmp_path / "outer"
    inner = outer / "inner"
    write_ledger(outer / ".ember" / "ledger.json", rule("outer-rule"))
    write_ledger(inner / ".ember" / "ledger.json", rule("inner-rule"))
    assert store.find_project_ledger(str(inner)) == inner / ".ember" / "ledger.json"
    assert ids(store.load_rules(str(inner), home_env, TODAY), "project") == [
        "inner-rule"
    ]
    assert ids(store.load_rules(str(outer), home_env, TODAY), "project") == [
        "outer-rule"
    ]


def test_project_search_accepts_msys_and_missing_directories(tmp_path: Path) -> None:
    write_ledger(tmp_path / ".ember" / "ledger.json", rule("found"))
    missing = tmp_path / "does" / "not" / "exist"
    assert (
        store.find_project_ledger(str(missing)) == tmp_path / ".ember" / "ledger.json"
    )
    assert store.find_project_ledger("") is None


def test_ember_ledger_overrides_user_and_project(tmp_path: Path, home_env) -> None:
    write_ledger(tmp_path / "home" / "ledger.json", rule("user-rule"))
    project = tmp_path / "proj"
    write_ledger(project / ".ember" / "ledger.json", rule("project-rule"))
    override = tmp_path / "only.json"
    write_ledger(override, rule("override-rule"))

    rules = store.load_rules(
        str(project), {**home_env, "EMBER_LEDGER": str(override)}, TODAY
    )

    assert ids(rules, "override") == ["override-rule"]
    assert not ids(rules, "user")
    assert not ids(rules, "project")
    assert ids(rules, "builtin")


def test_same_file_is_not_loaded_as_both_user_and_project(tmp_path: Path) -> None:
    home = tmp_path / ".ember"
    write_ledger(home / "ledger.json", rule("once"))
    rules = store.load_all(str(tmp_path / "work"), {"EMBER_HOME": str(home)})
    assert [r.id for r in rules if r.id == "once"] == ["once"]


EXPIRY_CASES = [
    ("2026-10-01", False),
    ("2026-10-02", True),
    ("2026-10-03", True),
    ("2030-01-01T00:00:00", True),
    (None, True),
]


@pytest.mark.parametrize(("expires", "active"), EXPIRY_CASES)
def test_expired_rules_are_ignored(
    tmp_path: Path, expires: str | None, active: bool
) -> None:
    extra = {"expires": expires} if expires else {}
    write_ledger(tmp_path / "l.json", rule("timed", **extra))
    env = {
        "EMBER_HOME": str(tmp_path / "home"),
        "EMBER_LEDGER": str(tmp_path / "l.json"),
    }
    assert ("timed" in ids(store.load_rules("", env, TODAY))) is active
    assert "timed" in ids(store.load_all("", env))


CAP_CASES = [
    ("deny", True, "deny"),
    ("deny", False, "warn"),
    ("ask", True, "ask"),
    ("ask", False, "warn"),
    ("warn", True, "warn"),
    ("warn", False, "warn"),
]


@pytest.mark.parametrize(("declared", "confirmed", "effective"), CAP_CASES)
def test_unconfirmed_rules_are_capped_at_warn(
    tmp_path: Path, declared: str, confirmed: bool, effective: str
) -> None:
    write_ledger(tmp_path / "l.json", rule("r", effect=declared, confirmed=confirmed))
    env = {
        "EMBER_HOME": str(tmp_path / "home"),
        "EMBER_LEDGER": str(tmp_path / "l.json"),
    }
    active = next(r for r in store.load_rules("", env, TODAY) if r.id == "r")
    declared_rule = next(r for r in store.load_all("", env) if r.id == "r")
    assert active.effect == effective
    assert declared_rule.effect == declared


def test_builtin_pack_can_be_disabled_by_the_user_only(
    tmp_path: Path, home_env
) -> None:
    assert store.load_rules("", {**home_env, "EMBER_GATE_BUILTIN": "0"}, TODAY) == []
    assert store.load_rules("", {**home_env, "EMBER_GATE_BUILTIN": "1"}, TODAY)
    home = tmp_path / "home"
    home.mkdir()
    (home / "config.json").write_text(json.dumps({"builtin": False}), encoding="utf-8")
    assert store.load_rules("", home_env, TODAY) == []
    assert store.load_rules("", {**home_env, "EMBER_GATE_BUILTIN": "true"}, TODAY)


MODE_CASES = [
    ({}, None, "observe"),
    ({"EMBER_GATE_MODE": "enforce"}, None, "enforce"),
    ({"EMBER_GATE_MODE": "observe"}, {"mode": "enforce"}, "observe"),
    ({}, {"mode": "enforce"}, "enforce"),
    ({"EMBER_GATE_MODE": ""}, {"mode": "enforce"}, "enforce"),
    ({}, {}, "observe"),
]


@pytest.mark.parametrize(("extra", "file_config", "expected"), MODE_CASES)
def test_gate_mode_precedence(
    tmp_path: Path, extra, file_config, expected: str
) -> None:
    if file_config is not None:
        (tmp_path / "config.json").write_text(json.dumps(file_config), encoding="utf-8")
    assert config.gate_mode({"EMBER_HOME": str(tmp_path), **extra}) == expected


@pytest.mark.parametrize(
    ("extra", "content"),
    [
        ({"EMBER_GATE_MODE": "block"}, None),
        ({}, '{"mode": "strict"}'),
        ({}, "{broken"),
        ({}, "[]"),
    ],
)
def test_invalid_configuration_raises(tmp_path: Path, extra, content) -> None:
    if content is not None:
        (tmp_path / "config.json").write_text(content, encoding="utf-8")
    with pytest.raises(config.ConfigError):
        config.gate_mode({"EMBER_HOME": str(tmp_path), **extra})


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("{not json", "not valid JSON"),
        ("[]", "expected a JSON object"),
        ('{"version": 1}', "missing field(s) rules"),
        ('{"version": 1, "rules": [{"id": "x"}]}', "missing field(s)"),
    ],
)
def test_unreadable_ledger_raises_with_the_file_name(
    tmp_path: Path, content: str, message: str
) -> None:
    path = tmp_path / "bad.json"
    path.write_text(content, encoding="utf-8")
    env = {"EMBER_HOME": str(tmp_path / "home"), "EMBER_LEDGER": str(path)}
    with pytest.raises(LedgerError) as caught:
        store.load_rules("", env, TODAY)
    assert message in str(caught.value)
    assert "bad.json" in str(caught.value)


def test_project_ledger_cannot_claim_builtin_ids(tmp_path: Path, home_env) -> None:
    project = tmp_path / "proj"
    write_ledger(project / ".ember" / "ledger.json", rule("builtin.delete.recursive"))
    with pytest.raises(LedgerError, match="reserved"):
        store.load_rules(str(project), home_env, TODAY)


def test_add_confirm_remove_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "ledger.json"
    added = store.add_rule(path, rule("mine", confirmed=True))
    assert added.confirmed is False
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["version"] == 1
    assert stored["rules"][0]["confirmed"] is False

    store.confirm_rule(path, "mine")
    assert store.load_file(path, origin="user")[0].confirmed is True

    store.add_rule(path, rule("second"))
    assert [r.id for r in store.load_file(path, origin="user")] == ["mine", "second"]

    store.remove_rule(path, "mine")
    assert [r.id for r in store.load_file(path, origin="user")] == ["second"]
    assert not path.with_name("ledger.json.tmp").exists()


def test_editing_rejects_bad_input_and_leaves_the_file_alone(tmp_path: Path) -> None:
    path = tmp_path / "ledger.json"
    store.add_rule(path, rule("mine"))
    before = path.read_text(encoding="utf-8")
    with pytest.raises(LedgerError, match="duplicate id"):
        store.add_rule(path, rule("mine"))
    with pytest.raises(LedgerError, match="effect"):
        store.add_rule(path, rule("other", effect="allow"))
    with pytest.raises(LedgerError, match="no rule with id 'ghost'"):
        store.confirm_rule(path, "ghost")
    with pytest.raises(LedgerError, match="no rule with id 'ghost'"):
        store.remove_rule(path, "ghost")
    assert path.read_text(encoding="utf-8") == before
