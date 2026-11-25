"""The security graph (tools/security_graph/build_security_graph.py).

The committed graph under docs/security-graph must match the rules and the
corpus: when a rule or a corpus entry changes, rebuild it with
``python tools/security_graph/build_security_graph.py``.

Corpus commands are only parsed and evaluated, never executed.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from ember_armor.ledger.model import parse_rule
from tests.ledger.helpers import rule, write_ledger

SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "tools"
    / "security_graph"
    / "build_security_graph.py"
)


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("build_security_graph", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


graph = _load()


def _reach(**overrides: Any) -> set[str]:
    return graph.watch_of(parse_rule(rule(**overrides))).tools


def test_committed_graph_is_current() -> None:
    names = graph.stale()
    assert not names, (
        f"docs/security-graph is stale ({', '.join(names)}): "
        "run python tools/security_graph/build_security_graph.py"
    )


def test_outputs_are_ascii() -> None:
    for text in graph.outputs().values():
        text.encode("ascii")


def test_command_rule_reaches_shell_tools_only() -> None:
    reach = _reach()
    assert {"Bash", "PowerShell"} <= reach
    assert not reach & {"Read", "Write", "WebFetch"}


def test_path_read_rule_reaches_read_tools() -> None:
    reach = _reach(when={"type": "path", "op": "read", "glob": ["**/.env"]})
    assert {"Bash", "Read", "Grep"} <= reach
    assert "Write" not in reach


def test_path_write_rule_reaches_write_tools() -> None:
    reach = _reach(when={"type": "path", "op": "write", "glob": ["**/x"]})
    assert {"Write", "Edit", "MultiEdit", "NotebookEdit"} <= reach
    assert "Read" not in reach


def test_arg_rule_reaches_tools_without_facts() -> None:
    reach = _reach(when={"type": "arg", "name": "url", "op": "matches", "value": "x"})
    assert "WebFetch" in reach


def test_applies_tools_narrows_reach() -> None:
    reach = _reach(
        when={"type": "path", "op": "any", "glob": ["**/x"]},
        applies={"tools": ["Write"]},
    )
    assert reach == {"Write"}


def test_builtin_pack_gaps() -> None:
    built = json.loads(graph.outputs()[graph.JSON_NAME])
    summary, gaps = built["summary"], built["gaps"]
    assert summary["rules"] == len(graph.builtin_rules())
    assert summary["corpus_problems"] == []
    # test_corpus.py already demands a must-flag entry for every built-in rule.
    assert gaps["no_proof"] == []
    assert "WebFetch" in gaps["unwatched_tools"]
    assert "Bash" not in gaps["unwatched_tools"]


def test_user_ledger_rules_join_the_graph(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.json"
    write_ledger(
        ledger,
        rule("no-fetch", when={"type": "arg", "name": "url", "op": "matches",
                               "value": "pastebin"}, confirmed=False),
    )  # fmt: skip
    out = tmp_path / "out"
    assert graph.main(["--ledger", str(ledger), "--out", str(out)]) == 0
    built = json.loads((out / graph.JSON_NAME).read_text(encoding="utf-8"))
    assert "no-fetch" in built["gaps"]["no_proof"]
    assert "no-fetch" in built["gaps"]["unconfirmed"]
    assert "WebFetch" not in built["gaps"]["unwatched_tools"]
    assert graph.main(["--check", "--ledger", str(ledger), "--out", str(out)]) == 0


def test_ledger_without_out_is_refused(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as excinfo:
        graph.main(["--ledger", str(tmp_path / "ledger.json")])
    assert excinfo.value.code == 2
