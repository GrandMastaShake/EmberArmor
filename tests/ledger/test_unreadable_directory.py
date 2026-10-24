"""A directory above the call that cannot be looked at silences no other source.

Looking for a project ledger walks up from the call's directory.  Where a
level cannot be looked at (``Access is denied``), ``Path.is_file`` raises
rather than answering, and the error used to leave ``load_sources``: no
source was loaded, the built-in pack included, so in ``remind`` mode the hook
printed nothing for any call and in ``enforce`` mode it asked about every
call.  Now that level is a project ledger that cannot be loaded, said in the
fixed words, and the other sources are judged as before; the user's own
ledger in the home directory, never a project ledger, is passed over and the
search goes on above it.  The refusal is simulated; everything lives under
``tmp_path``.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from ember_armor.ledger import store
from ember_armor.ledger.gate import check
from ember_armor.ledger.hook import hook_output
from tests.ledger.helpers import make_call, rule, write_ledger

MODES = ("observe", "remind", "enforce")
FORCE_PUSH = "builtin.git.force-push"
DEPLOY = {"type": "command", "program": "deploy-site"}


def refusing(*refused: Path) -> Callable[..., bool]:
    """``Path.is_file`` that raises for *refused*, as Windows does when the
    directory may not be read, and answers as before for every other path."""
    real = Path.is_file
    names = {os.path.normcase(str(path)) for path in refused}

    def is_file(self: Path, *args: Any, **kwargs: Any) -> bool:
        if os.path.normcase(str(self)) in names:
            raise PermissionError(13, "Access is denied", str(self))
        return real(self, *args, **kwargs)

    return is_file


@pytest.fixture
def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """A user ledger with one rule, and a call two levels below a locked one."""
    home, work = tmp_path / "home", tmp_path / "locked" / "work"
    write_ledger(home / "ledger.json", rule("standing", when=DEPLOY))
    work.mkdir(parents=True)
    locked = tmp_path / "locked" / ".ember" / store.LEDGER_NAME
    monkeypatch.setattr(Path, "is_file", refusing(locked))
    return {"env": {"EMBER_HOME": str(home)}, "work": work, "locked": locked}


def test_the_search_raises_when_nothing_passes_the_level_over(world) -> None:
    with pytest.raises(PermissionError):
        store.find_project_ledger(str(world["work"]))


def test_a_level_that_cannot_be_looked_at_takes_no_other_source_with_it(
    world,
) -> None:
    rules, problems = store.load_sources(str(world["work"]), world["env"])
    ids = [found.id for found in rules]
    assert FORCE_PUSH in ids and "standing" in ids
    (problem,) = problems
    assert "cannot be looked for" in problem and "PermissionError" in problem
    assert store.sayable(problems) == [store.PROJECT_LEDGER_FAILED]


@pytest.mark.parametrize("mode", MODES)
def test_every_mode_still_judges_the_built_in_pack(world, mode) -> None:
    env = {**world["env"], "EMBER_GATE_MODE": mode}
    call = make_call(
        "Bash", "git push --force origin master", cwd=str(world["work"]), session=mode
    )
    result = check(call, env=env)
    assert FORCE_PUSH in [fired.id for fired in result.decision.fired]
    assert "cannot be looked for" in (result.decision.error or "")
    assert result.decision.said == store.PROJECT_LEDGER_FAILED
    printed = hook_output(result)
    # What the hook prints names neither the directory nor the reason.
    assert str(world["locked"].parent.parent) not in printed
    assert "PermissionError" not in printed
    if mode == "remind":
        specific = json.loads(printed)["hookSpecificOutput"]
        assert FORCE_PUSH in specific["additionalContext"]
    if mode == "enforce":
        specific = json.loads(printed)["hookSpecificOutput"]
        assert specific["permissionDecision"] == "ask"


def test_the_users_own_ledger_in_the_home_directory_is_passed_over(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    userhome = tmp_path / "userhome"
    work = userhome / "projects" / "work"
    work.mkdir(parents=True)
    write_ledger(tmp_path / ".ember" / store.LEDGER_NAME, rule("above"))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: userhome))
    locked = userhome / ".ember" / store.LEDGER_NAME
    monkeypatch.setattr(Path, "is_file", refusing(locked))
    env = {"EMBER_HOME": str(tmp_path / "ember-home")}
    rules, problems = store.load_sources(str(work), env)
    assert problems == []
    ids = [found.id for found in rules]
    assert FORCE_PUSH in ids
    # The search went on above the home directory and found the ledger there.
    assert "above" in ids
