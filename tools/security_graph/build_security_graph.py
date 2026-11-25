"""Build the EmberArmor security graph.

The graph maps every ledger rule to what it watches (programs, path
operations, shell signals), to the tools it can fire on, and to the proof
that it does: the corpus cases under ``tests/ledger/corpus`` that the gate
really flags, and the test files that name the rule.  It then lists the gaps:
tools no rule looks at, rules with no PowerShell case, rules that reach a
file tool without a file-tool case, program rules with no near-miss case,
and rules no test file names.

Nothing here runs a command.  Corpus commands are only parsed and evaluated
by the gate's own engine, exactly as ``tests/ledger/test_corpus.py`` does.

Usage, from the repository root::

    python tools/security_graph/build_security_graph.py          # write the graph
    python tools/security_graph/build_security_graph.py --check  # exit 1 if stale

To graph your own rules beside the built-in pack, name the ledger and a
directory outside the repository (your rules never go into the repo)::

    python tools/security_graph/build_security_graph.py \
        --ledger ~/.ember/ledger.json --out ~/ember-graph

Standard library plus the ``ember_armor`` package.  Output is plain ASCII and
deterministic (no dates, no hashes), so a stale graph shows as a diff.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from ember_armor.ledger.builtin import builtin_rules  # noqa: E402
from ember_armor.ledger.engine import evaluate  # noqa: E402
from ember_armor.ledger.facts import FILE_TOOLS, SHELL_TOOLS, extract  # noqa: E402
from ember_armor.ledger.model import (  # noqa: E402
    AllPred,
    AnyPred,
    ArgPred,
    AssignsPred,
    CommandPred,
    CountExceedsPred,
    DynamicShellPred,
    ExprPred,
    NotPrecededByPred,
    NotPred,
    PathPred,
    Rule,
    TextRegexPred,
    UnknownDirectoryPred,
    exceptable,
    parse_ledger,
    parse_rule,
)

OUT_DIR = REPO / "docs" / "security-graph"
CORPUS_DIR = REPO / "tests" / "ledger" / "corpus"
TESTS_DIR = REPO / "tests"
REPORT_NAME = "SECURITY_GRAPH.md"
JSON_NAME = "security_graph.json"
REBUILD = "python tools/security_graph/build_security_graph.py"

#: The same fixed environment the corpus tests use (tests/ledger/helpers.py).
POSIX = {"cwd": "/work/app", "env": {"HOME": "/home/dev", "TMPDIR": "/tmp"}}  # noqa: S108
WINDOWS = {
    "cwd": r"C:\work\app",
    "env": {
        "USERPROFILE": r"C:\Users\dev",
        "TEMP": r"C:\Users\dev\AppData\Local\Temp",
    },
}

SHELL_TOOL_NAMES = tuple(sorted(SHELL_TOOLS))
READ_TOOLS = tuple(sorted(t for t, (_, op) in FILE_TOOLS.items() if op == "read"))
WRITE_TOOLS = tuple(sorted(t for t, (_, op) in FILE_TOOLS.items() if op == "write"))
FILE_TOOL_NAMES = tuple(sorted(FILE_TOOLS))
#: Claude Code tools the gate parses no facts for.  A rule can still look at
#: their input with an ``arg`` or ``text_regex`` predicate.
OTHER_TOOLS = ("Agent", "Glob", "WebFetch", "WebSearch", "mcp__* (other MCP tools)")
ALL_TOOLS = (*SHELL_TOOL_NAMES, *FILE_TOOL_NAMES, *OTHER_TOOLS)
#: Fields that only a shell tool carries.
SHELL_FIELDS = {"command"}


# ---------------------------------------------------------------------------
# What a rule watches, and which tools it can reach
# ---------------------------------------------------------------------------
@dataclass
class Watch:
    """What one rule's predicate looks at, and the tools that can carry it."""

    programs: set[str] = field(default_factory=set)
    #: (program, first subcommand word or "") pairs, for near-miss matching.
    commands: set[tuple[str, str]] = field(default_factory=set)
    path_ops: set[str] = field(default_factory=set)
    signals: set[str] = field(default_factory=set)
    tools: set[str] = field(default_factory=set)
    history: bool = False


def _shell_names(shell: str) -> set[str]:
    return set(SHELL_TOOL_NAMES) if shell else set()


def _path_tools(op: str) -> set[str]:
    tools = set(SHELL_TOOL_NAMES)
    if op in ("read", "any"):
        tools.update(READ_TOOLS)
    if op in ("write", "any"):
        tools.update(WRITE_TOOLS)
    return tools


def _field_tools(name: str) -> set[str]:
    root = name.split(".")[0]
    if root in SHELL_FIELDS:
        return set(SHELL_TOOL_NAMES)
    tools = {t for t, (key, _) in FILE_TOOLS.items() if key == root}
    # Any tool with that input field: the other tools may carry it too.
    tools.update(OTHER_TOOLS)
    return tools


def walk(pred: Any, watch: Watch) -> None:
    """Collect what *pred* looks at into *watch* (union over the tree).

    ``not`` contributes what its inner predicate looks at: the reach is an
    upper bound on where the rule can fire, not a proof that it does.
    """
    if isinstance(pred, CommandPred):
        watch.programs.update(p.lower() for p in pred.program)
        sub = pred.subcommand[0].lower() if pred.subcommand else ""
        watch.commands.update((p.lower(), sub) for p in pred.program)
        if not pred.program:
            watch.signals.add("any-command")
        watch.tools.update(_shell_names(pred.shell))
    elif isinstance(pred, PathPred):
        watch.path_ops.add(pred.op)
        watch.tools.update(_path_tools(pred.op))
    elif isinstance(pred, DynamicShellPred):
        reasons = ",".join(pred.reason) if pred.reason else "any"
        watch.signals.add(f"dynamic:{reasons}")
        watch.tools.update(SHELL_TOOL_NAMES)
    elif isinstance(pred, UnknownDirectoryPred):
        watch.signals.add("unknown-directory")
        watch.tools.update(SHELL_TOOL_NAMES)
    elif isinstance(pred, AssignsPred):
        watch.signals.add("assigns:" + ",".join(pred.name))
        watch.tools.update(SHELL_TOOL_NAMES)
    elif isinstance(pred, TextRegexPred):
        watch.signals.add(f"text:{pred.field}")
        watch.tools.update(_field_tools(pred.field))
    elif isinstance(pred, ArgPred):
        watch.signals.add(f"arg:{pred.name}")
        watch.tools.update(_field_tools(pred.name))
    elif isinstance(pred, ExprPred):
        for name, _ in pred.lhs:
            watch.signals.add(f"arg:{name}")
            watch.tools.update(_field_tools(name))
    elif isinstance(pred, (AllPred, AnyPred)):
        for inner in pred.of:
            walk(inner, watch)
    elif isinstance(pred, NotPred):
        walk(pred.of, watch)
    elif isinstance(pred, (NotPrecededByPred, CountExceedsPred)):
        watch.history = True
        walk(pred.predicate, watch)


def watch_of(rule: Rule) -> Watch:
    """What *rule* watches, with its reach narrowed by ``applies.tools``."""
    watch = Watch()
    walk(rule.predicate, watch)
    if rule.applies.tools:
        allowed = {
            tool
            for tool in ALL_TOOLS
            for pattern in rule.applies.tools
            if fnmatchcase(tool.lower(), pattern.lower())
            or (tool.startswith("mcp__*") and pattern.lower().startswith("mcp__"))
        }
        watch.tools &= allowed
    return watch


def area_of(rule: Rule) -> str:
    parts = rule.id.split(".")
    if rule.origin == "builtin" and len(parts) >= 3:
        return parts[1]
    return f"{rule.origin}:{parts[0]}" if len(parts) > 1 else rule.origin


# ---------------------------------------------------------------------------
# Proof: corpus cases the gate flags, near misses, tests naming each rule
# ---------------------------------------------------------------------------
def _facts(tool: str, payload: Any, platform: str) -> Any:
    spec = WINDOWS if platform == "windows" else POSIX
    tool_input = payload if isinstance(payload, dict) else {"command": payload}
    call = {
        "session_id": "graph",
        "cwd": spec["cwd"],
        "tool_name": tool,
        "tool_input": tool_input,
    }
    return extract(call, windows=platform == "windows", env=spec["env"])


def _platforms(entry: Mapping[str, Any]) -> list[str]:
    return [entry["platform"]] if "platform" in entry else ["posix", "windows"]


def _program(argv0: str) -> str:
    name = argv0.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name[:-4] if name.endswith(".exe") else name


@dataclass
class Proof:
    flag_cases: Counter[str] = field(default_factory=Counter)  # by tool
    shells: Counter[str] = field(default_factory=Counter)  # bash/powershell/cmd
    platforms: Counter[str] = field(default_factory=Counter)
    near_miss: int = 0
    test_files: list[str] = field(default_factory=list)


def prove(
    rules: Sequence[Rule],
    must_flag: Sequence[Mapping[str, Any]],
    must_not_flag: Sequence[Mapping[str, Any]],
    watches: Mapping[str, Watch],
) -> tuple[dict[str, Proof], Counter[tuple[str, str]], list[str]]:
    """Evaluate the corpus against *rules*.

    Returns the proof per rule key, how often two rules fire on the same
    case (overlaps), and corpus problems (an entry whose expected rule did
    not fire), which the corpus tests should already have caught.
    """
    proof = {rule.key: Proof() for rule in rules}
    overlaps: Counter[tuple[str, str]] = Counter()
    problems: list[str] = []
    for entry in must_flag:
        payload = entry.get("command", entry.get("input"))
        extra = [parse_rule(item) for item in entry.get("rules", [])]
        fired_any: set[str] = set()
        entry_shells: dict[str, set[str]] = defaultdict(set)
        for platform in _platforms(entry):
            facts = _facts(entry["tool"], payload, platform)
            decision = evaluate([*rules, *extra], facts)
            keys = {f.key for f in decision.fired} & proof.keys()
            if entry["rule"] not in {f.id for f in decision.fired}:
                problems.append(
                    f"{entry['rule']} did not fire on {entry['tool']}/{platform}"
                )
            shells = {cmd.shell for cmd in facts.commands if cmd.shell}
            for key in keys:
                proof[key].platforms[platform] += 1
                entry_shells[key] |= shells
            fired_any |= keys
        for key in fired_any:
            proof[key].flag_cases[entry["tool"]] += 1
            for shell in entry_shells[key]:
                proof[key].shells[shell] += 1
        for a in sorted(fired_any):
            for b in sorted(fired_any):
                if a < b:
                    overlaps[(a, b)] += 1
    for entry in must_not_flag:
        payload = entry.get("command", entry.get("input"))
        seen: list[tuple[str, tuple[str, ...]]] = []
        for platform in _platforms(entry):
            facts = _facts(entry["tool"], payload, platform)
            for cmd in facts.commands:
                if cmd.argv:
                    args = tuple(a.lower() for a in cmd.argv[1:5])
                    seen.append((_program(cmd.argv[0]), args))
        for rule in rules:
            if any(
                prog == wanted and (not sub or sub in args)
                for prog, args in seen
                for wanted, sub in watches[rule.key].commands
            ):
                proof[rule.key].near_miss += 1
    return proof, overlaps, problems


def tests_naming(rules: Sequence[Rule], tests_dir: Path) -> dict[str, list[str]]:
    """Test files (not the corpus) whose text names each rule id."""
    found: dict[str, list[str]] = {rule.key: [] for rule in rules}
    if not tests_dir.is_dir():
        return found
    for path in sorted(tests_dir.rglob("*.py")):
        text = path.read_text(encoding="utf-8", errors="replace")
        rel = path.relative_to(tests_dir.parent).as_posix()
        for rule in rules:
            if f'"{rule.id}"' in text or f"'{rule.id}'" in text:
                found[rule.key].append(rel)
    return found


# ---------------------------------------------------------------------------
# The graph
# ---------------------------------------------------------------------------
def build(
    rules: Sequence[Rule],
    must_flag: Sequence[Mapping[str, Any]],
    must_not_flag: Sequence[Mapping[str, Any]],
    tests_dir: Path,
) -> dict[str, Any]:
    watches = {rule.key: watch_of(rule) for rule in rules}
    proof, overlaps, problems = prove(rules, must_flag, must_not_flag, watches)
    for key, files in tests_naming(rules, tests_dir).items():
        proof[key].test_files = files

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    rule_rows: list[dict[str, Any]] = []
    areas: dict[str, list[str]] = defaultdict(list)
    watched: set[str] = set()

    for rule in rules:
        w, p = watches[rule.key], proof[rule.key]
        area = area_of(rule)
        areas[area].append(rule.key)
        row = {
            "id": rule.key,
            "area": area,
            "origin": rule.origin,
            "effect": rule.effect,
            "confirmed": rule.confirmed,
            "exceptable": exceptable(rule.id),
            "text": rule.text,
            "programs": sorted(w.programs),
            "path_ops": sorted(w.path_ops),
            "signals": sorted(w.signals),
            "history": w.history,
            "reaches": sorted(w.tools),
            "flag_cases": dict(sorted(p.flag_cases.items())),
            "flag_shells": dict(sorted(p.shells.items())),
            "flag_platforms": dict(sorted(p.platforms.items())),
            "near_miss_cases": p.near_miss,
            "test_files": p.test_files,
        }
        rule_rows.append(row)
        nodes.append({"id": f"rule:{rule.key}", "kind": "rule", **row})
        edges.append(
            {"from": f"area:{area}", "to": f"rule:{rule.key}", "kind": "contains"}
        )
        for prog in sorted(w.programs):
            edges.append(
                {"from": f"rule:{rule.key}", "to": f"program:{prog}", "kind": "watches"}
            )
            watched.add(f"program:{prog}")
        for op in sorted(w.path_ops):
            edges.append(
                {"from": f"rule:{rule.key}", "to": f"path:{op}", "kind": "watches"}
            )
            watched.add(f"path:{op}")
        for sig in sorted(w.signals):
            edges.append(
                {"from": f"rule:{rule.key}", "to": f"signal:{sig}", "kind": "watches"}
            )
            watched.add(f"signal:{sig}")
        for tool in sorted(w.tools):
            edges.append(
                {"from": f"rule:{rule.key}", "to": f"tool:{tool}", "kind": "reaches"}
            )
        for tool, count in sorted(p.flag_cases.items()):
            edges.append(
                {
                    "from": f"rule:{rule.key}",
                    "to": f"tool:{tool}",
                    "kind": "proven_on",
                    "cases": count,
                }
            )
    for (a, b), count in sorted(overlaps.items()):
        edges.append(
            {"from": f"rule:{a}", "to": f"rule:{b}", "kind": "overlaps", "cases": count}
        )

    for area in sorted(areas):
        nodes.append({"id": f"area:{area}", "kind": "area", "rules": len(areas[area])})
    for item in sorted(watched):
        kind, _, name = item.partition(":")
        nodes.append({"id": item, "kind": kind, "name": name})
    reached = {t for w in watches.values() for t in w.tools}
    for tool in ALL_TOOLS:
        nodes.append({"id": f"tool:{tool}", "kind": "tool", "watched": tool in reached})

    gaps = find_gaps(rule_rows, reached)
    nodes.sort(key=lambda n: n["id"])
    return {
        "summary": {
            "rules": len(rules),
            "effects": dict(sorted(Counter(r.effect for r in rules).items())),
            "areas": {a: len(k) for a, k in sorted(areas.items())},
            "must_flag_entries": len(must_flag),
            "must_not_flag_entries": len(must_not_flag),
            "corpus_problems": problems,
            "tools_watched": sorted(reached & set(ALL_TOOLS)),
            "tools_unwatched": [t for t in ALL_TOOLS if t not in reached],
        },
        "gaps": gaps,
        "nodes": nodes,
        "edges": edges,
    }


def find_gaps(rows: Sequence[Mapping[str, Any]], reached: set[str]) -> dict[str, Any]:
    file_tools = set(FILE_TOOL_NAMES)
    shells = set(SHELL_TOOL_NAMES)
    gaps: dict[str, Any] = {
        "unwatched_tools": [t for t in ALL_TOOLS if t not in reached],
        "no_proof": [],
        "file_reach_without_file_case": [],
        "no_powershell_case": [],
        "no_near_miss_case": [],
        "unconfirmed": [],
    }
    for r in rows:
        cases = r["flag_cases"]
        if not cases:
            gaps["no_proof"].append(r["id"])
        reach_files = sorted(set(r["reaches"]) & file_tools)
        if reach_files and cases and not set(cases) & file_tools:
            gaps["file_reach_without_file_case"].append(
                {"rule": r["id"], "tools": reach_files}
            )
        if (
            set(r["reaches"]) & shells
            and cases
            and not r["flag_shells"].get("powershell")
        ):
            gaps["no_powershell_case"].append(
                {"rule": r["id"], "programs": r["programs"]}
            )
        if r["programs"] and r["near_miss_cases"] == 0:
            gaps["no_near_miss_case"].append(
                {"rule": r["id"], "programs": r["programs"]}
            )
        if not r["confirmed"]:
            gaps["unconfirmed"].append(r["id"])
    return gaps


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
def tool_groups(unwatched: Sequence[str]) -> dict[str, tuple[str, list[str]]]:
    """Tools grouped for the map: id -> (label, members)."""
    return {
        "G_shell": ("shell tools", list(SHELL_TOOL_NAMES)),
        "G_write": ("file write tools", list(WRITE_TOOLS)),
        "G_read": ("file read tools", list(READ_TOOLS)),
        "G_none": ("not watched", list(unwatched)),
    }


def _mermaid_id(text: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in text)


def _short(items: Iterable[str], limit: int = 6) -> str:
    items = list(items)
    if not items:
        return "-"
    head = ", ".join(items[:limit])
    return head + (f" +{len(items) - limit}" if len(items) > limit else "")


def _counts(counts: Mapping[str, int]) -> str:
    return ", ".join(f"{k} {v}" for k, v in counts.items()) or "-"


def render_markdown(graph: Mapping[str, Any]) -> str:
    s, gaps = graph["summary"], graph["gaps"]
    rules = [n for n in graph["nodes"] if n["kind"] == "rule"]
    out: list[str] = []
    add = out.append
    add("# EmberArmor security graph")
    add("")
    add(f"Generated by `{REBUILD}`. Do not edit by hand: a test fails")
    add("when this file or security_graph.json no longer matches the rules and corpus.")
    add("")
    add("## At a glance")
    add("")
    add(f"- Rules: {s['rules']} ({_counts(s['effects'])})")
    add(f"- Areas: {_counts(s['areas'])}")
    add(
        f"- Corpus: {s['must_flag_entries']} must-flag, "
        f"{s['must_not_flag_entries']} must-not-flag entries"
    )
    add(f"- Tools the rules can reach: {_short(s['tools_watched'], 20)}")
    add(f"- Tools no rule looks at: {_short(s['tools_unwatched'], 20)}")
    if s["corpus_problems"]:
        add(
            "- Corpus problems (expected rule did not fire): "
            f"{len(s['corpus_problems'])}"
        )
    add("")
    add("## Map: areas to the kinds of tool their rules reach")
    add("")
    add("Edge labels count rules. The dashed box is what no rule looks at.")
    add("")
    add("```mermaid")
    add("flowchart LR")
    groups = tool_groups(s["tools_unwatched"])
    reach: Counter[tuple[str, str]] = Counter()
    for r in rules:
        for gid, (_, members) in groups.items():
            if set(r["reaches"]) & set(members):
                reach[(r["area"], gid)] += 1
    for area, count in s["areas"].items():
        add(f'  A_{_mermaid_id(area)}["{area} ({count})"]')
    for gid, (label, members) in groups.items():
        add(f'  {gid}["{label}: {_short(members, 8)}"]')
    for (area, gid), count in sorted(reach.items()):
        add(f"  A_{_mermaid_id(area)} -- {count} --> {gid}")
    add("  style G_none stroke-dasharray: 5 5")
    add("```")
    add("")
    add("## Gaps worth a look")
    add("")
    add("Each list is generated. Empty lists mean no gap of that kind.")
    add("")
    add("### Tools no rule looks at")
    add("")
    add("The gate parses facts only for shell and file tools. A rule can still watch")
    add("these with an `arg` or `text_regex` predicate; none does today.")
    add("")
    for t in gaps["unwatched_tools"]:
        add(f"- {t}")
    if not gaps["unwatched_tools"]:
        add("- none")
    add("")
    add("### Rules with no corpus case that fires them")
    add("")
    for rid in gaps["no_proof"] or ["none"]:
        add(f"- {rid}")
    add("")
    add("### Rules that reach a file tool but have no file-tool case")
    add("")
    add("The rule can fire on these tools (it watches a path operation they do),")
    add("but every must-flag case for it is a shell command.")
    add("")
    for g in gaps["file_reach_without_file_case"] or [{"rule": "none", "tools": []}]:
        add(f"- {g['rule']}" + (f": {', '.join(g['tools'])}" if g["tools"] else ""))
    add("")
    add("### Rules with no PowerShell case")
    add("")
    add("No must-flag case runs the rule through PowerShell. Some of these watch")
    add("Unix-only programs, where that is expected.")
    add("")
    for g in gaps["no_powershell_case"] or [{"rule": "none", "programs": []}]:
        add(f"- {g['rule']}" + (f" ({_short(g['programs'])})" if g["programs"] else ""))
    add("")
    add("### Program rules with no near-miss case")
    add("")
    add("No must-not-flag entry runs a program the rule watches with the same")
    add("subcommand, so nothing tests that a harmless use of it passes.")
    add("")
    for g in gaps["no_near_miss_case"] or [{"rule": "none", "programs": []}]:
        add(f"- {g['rule']}" + (f" ({_short(g['programs'])})" if g["programs"] else ""))
    add("")
    if gaps["unconfirmed"]:
        add("")
        add("### Unconfirmed rules")
        add("")
        add("Their words never reach the agent until confirmed.")
        add("")
        for rid in gaps["unconfirmed"]:
            add(f"- {rid}")
    if s["corpus_problems"]:
        add("")
        add("### Corpus problems")
        add("")
        for item in s["corpus_problems"]:
            add(f"- {item}")
    add("")
    add("## Rules")
    add("")
    add("Watches: programs, path operations and shell signals the rule looks at.")
    add("Cases: must-flag entries the gate really flags with this rule, by tool.")
    add("Shells: of those cases, how many parse to a command in each shell.")
    add("Near: must-not-flag entries that run a watched program and subcommand.")
    add("Tests: test files that name the rule id (besides the corpus).")
    add("Fixed: no exception can drop the rule.")
    add("")
    by_area: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for r in rules:
        by_area[r["area"]].append(r)
    for area in sorted(by_area):
        add(f"### {area}")
        add("")
        add("| Rule | Effect | Watches | Cases | Shells | Near | Tests | Fixed |")
        add("|---|---|---|---|---|---|---|---|")
        for r in sorted(by_area[area], key=lambda x: x["id"]):
            watches = [
                *r["programs"],
                *(f"path:{o}" for o in r["path_ops"]),
                *r["signals"],
            ]
            add(
                f"| {r['id']} | {r['effect']} | {_short(watches, 5)} "
                f"| {_counts(r['flag_cases'])} | {_counts(r['flag_shells'])} "
                f"| {r['near_miss_cases'] if r['programs'] else '-'} "
                f"| {len(r['test_files'])} | {'yes' if not r['exceptable'] else ''} |"
            )
        add("")
    overlaps = [e for e in graph["edges"] if e["kind"] == "overlaps"]
    add("## Overlaps")
    add("")
    add("Rule pairs that fire together on the same must-flag case.")
    add("")
    for e in sorted(overlaps, key=lambda e: (-e["cases"], e["from"], e["to"])):
        add(f"- {e['from'][5:]} + {e['to'][5:]}: {e['cases']}")
    if not overlaps:
        add("- none")
    add("")
    text = "\n".join(out)
    return text.encode("ascii", "replace").decode("ascii")


def render_json(graph: Mapping[str, Any]) -> str:
    return json.dumps(graph, indent=1, sort_keys=True, ensure_ascii=True) + "\n"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def load_rules(ledgers: Sequence[Path]) -> list[Rule]:
    rules: list[Rule] = list(builtin_rules())
    for path in ledgers:
        doc = json.loads(path.read_text(encoding="utf-8"))
        rules.extend(parse_ledger(doc, origin="user", name=str(path)))
    return rules


def outputs(ledgers: Sequence[Path] = ()) -> dict[str, str]:
    must_flag = json.loads((CORPUS_DIR / "must_flag.json").read_text(encoding="utf-8"))
    must_not = json.loads(
        (CORPUS_DIR / "must_not_flag.json").read_text(encoding="utf-8")
    )
    graph = build(load_rules(ledgers), must_flag, must_not, TESTS_DIR)
    return {REPORT_NAME: render_markdown(graph), JSON_NAME: render_json(graph)}


def _read(path: Path) -> str | None:
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def stale(out_dir: Path = OUT_DIR, ledgers: Sequence[Path] = ()) -> list[str]:
    """Names of output files that differ from a fresh build."""
    return [
        name for name, text in outputs(ledgers).items() if _read(out_dir / name) != text
    ]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--check", action="store_true", help="exit 1 if the graph is stale"
    )
    parser.add_argument(
        "--ledger",
        action="append",
        type=Path,
        default=[],
        help="also graph the rules of this ledger file (needs --out)",
    )
    parser.add_argument(
        "--out", type=Path, help=f"output directory (default {OUT_DIR})"
    )
    args = parser.parse_args(argv)
    ledgers = [p.expanduser() for p in args.ledger]
    out_dir = args.out.expanduser() if args.out else OUT_DIR
    if ledgers and args.out is None:
        parser.error(
            "--ledger needs --out, so your own rules stay out of the repository"
        )
    if args.check:
        names = stale(out_dir, ledgers)
        if names:
            print(f"security graph is stale ({', '.join(names)}); run: {REBUILD}")
            return 1
        print("security graph is current")
        return 0
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, text in outputs(ledgers).items():
        with open(out_dir / name, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    print(f"wrote {out_dir / REPORT_NAME} and {out_dir / JSON_NAME}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
