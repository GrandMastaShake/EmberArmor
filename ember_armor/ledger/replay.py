"""Replay recorded tool calls from Claude Code transcripts through the ledger.

A transcript is a JSON-lines file.  An assistant line carries
``message.content`` blocks, and a block of type ``tool_use`` has the tool's
``name`` and ``input``.  Every other line shape is skipped.

Each recorded call is evaluated against the rules active today, as the gate
would in ``observe`` mode, and only aggregates are kept: calls per tool,
decisions, rules that fired, and a few redacted, truncated example calls per
rule.  Nothing is written to the audit log and no command is ever run.
"""

from __future__ import annotations

import contextlib
import json
import os
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any

from ember_armor.ledger.audit import restore, summarise
from ember_armor.ledger.config import ConfigError, rule_exceptions
from ember_armor.ledger.engine import MemoryHistory, RepoFinder, evaluate
from ember_armor.ledger.facts import extract
from ember_armor.ledger.gate import configured_shell_tools
from ember_armor.ledger.model import LedgerError, Rule
from ember_armor.ledger.store import load_rules

EXAMPLE_COMMANDS = 3
EXAMPLE_ARGS = 8
EXAMPLE_ARG_CHARS = 40
EXAMPLE_CHARS = 160


@dataclass
class ReplayReport:
    """Aggregates of one replay.  It never holds a full command."""

    files: int = 0
    lines: int = 0
    skipped_lines: int = 0
    calls: int = 0
    errors: int = 0
    tools: Counter[str] = field(default_factory=Counter)
    decisions: Counter[str] = field(default_factory=Counter)
    rules: Counter[str] = field(default_factory=Counter)
    effects: dict[str, str] = field(default_factory=dict)
    dynamic: Counter[str] = field(default_factory=Counter)
    examples: dict[str, list[str]] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        """The report as plain JSON data."""
        return {
            "files": self.files,
            "lines": self.lines,
            "skipped_lines": self.skipped_lines,
            "calls": self.calls,
            "errors": self.errors,
            "tools": dict(self.tools.most_common()),
            "decisions": dict(self.decisions.most_common()),
            "rules": {
                rule_id: {
                    "effect": self.effects[rule_id],
                    "count": count,
                    "examples": self.examples.get(rule_id, []),
                }
                for rule_id, count in self.rules.most_common()
            },
            "dynamic": dict(self.dynamic.most_common()),
        }


def transcript_files(paths: Iterable[str]) -> list[Path]:
    """The ``.jsonl`` files named by *paths*; directories are searched.

    Raises
    ------
    FileNotFoundError
        If a path does not exist.
    """
    files: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            files += sorted(path.rglob("*.jsonl"))
        elif path.is_file():
            files.append(path)
        else:
            raise FileNotFoundError(f"no such transcript file or directory: {raw}")
    return files


def _epoch(value: Any) -> float | None:
    if isinstance(value, str):
        with contextlib.suppress(ValueError):
            return datetime.fromisoformat(value).timestamp()
    return None


def tool_calls(
    path: Path, report: ReplayReport
) -> Iterator[tuple[str, dict[str, Any], float]]:
    """Recorded calls of one transcript.

    Yields
    ------
    tuple[str, dict[str, Any], float]
        The ``tool_use`` id (may be empty), the call in the gate's input
        shape, and when it was made (epoch seconds; the time of the previous
        call when the line has no timestamp).
    """
    when = 0.0
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.strip():
                continue
            report.lines += 1
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                entry = None
            if not isinstance(entry, dict):
                report.skipped_lines += 1
                continue
            message = entry.get("message")
            content = message.get("content") if isinstance(message, dict) else None
            when = _epoch(entry.get("timestamp")) or when
            for block in content if isinstance(content, list) else ():
                if not isinstance(block, dict) or block.get("type") != "tool_use":
                    continue
                name, tool_input = block.get("name"), block.get("input")
                if not isinstance(name, str) or not isinstance(tool_input, dict):
                    continue
                call = {
                    "session_id": str(entry.get("sessionId") or path.stem),
                    "cwd": str(entry.get("cwd") or ""),
                    "tool_name": name,
                    "tool_input": tool_input,
                }
                yield str(block.get("id") or ""), call, when


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def example(tool: str, summary: Mapping[str, Any]) -> str:
    """One line describing a call from its redacted summary.

    Arguments are truncated and the line is capped and ASCII only.  The
    simple commands of a shell call are joined with ``+``, because the
    parsed form no longer says whether a pipe or a ``;`` stood between them.
    """
    if "commands" in summary:
        shown = " + ".join(
            " ".join(
                _clip(" ".join(arg.split()), EXAMPLE_ARG_CHARS)
                for arg in command["argv"][:EXAMPLE_ARGS]
            )
            for command in summary["commands"][:EXAMPLE_COMMANDS]
        )
    elif "dynamic" in summary:
        shown = "(dynamic shell: " + ", ".join(d["kind"] for d in summary["dynamic"])
        shown += ")"
    else:
        shown = json.dumps(summary.get("args", {}), default=str)
    line = _clip(f"{tool}: {shown}", EXAMPLE_CHARS)
    return line.encode("ascii", "backslashreplace").decode("ascii")


def replay(
    paths: Iterable[str],
    *,
    env: Mapping[str, str] | None = None,
    windows: bool | None = None,
    examples: int = 3,
    repo_root: RepoFinder | None = None,
) -> ReplayReport:
    """Evaluate every recorded tool call and return the aggregates.

    Parameters
    ----------
    paths:
        Transcript files, or directories searched for ``*.jsonl``.
    env:
        Environment mapping selecting the ledger; defaults to the process
        environment.
    windows:
        Path flavour; defaults to the running platform.
    examples:
        Most example calls kept per rule.
    repo_root:
        Lookup of the nearest enclosing git repository of a directory, for
        ``repo_root`` scopes.  Defaults to the filesystem as it is today,
        which may differ from what it was when the call was recorded.

    Raises
    ------
    FileNotFoundError
        If a path does not exist.
    LedgerError
        If a ledger or the configuration cannot be loaded.
    """
    env = os.environ if env is None else env
    report = ReplayReport()
    carriers = configured_shell_tools(env)
    try:
        exceptions = rule_exceptions(env, date.today())
    except ConfigError as exc:
        raise LedgerError(str(exc)) from exc
    rules_by_cwd: dict[str, list[Rule]] = {}
    histories: dict[str, MemoryHistory] = {}
    seen: set[str] = set()
    for path in transcript_files(paths):
        report.files += 1
        for call_id, call, when in tool_calls(path, report):
            if call_id in seen:
                continue  # a resumed session repeats the earlier lines
            if call_id:
                seen.add(call_id)
            cwd = call["cwd"]
            if cwd not in rules_by_cwd:
                rules_by_cwd[cwd] = load_rules(cwd, env)
            history = histories.setdefault(call["session_id"], MemoryHistory())
            report.calls += 1
            report.tools[call["tool_name"]] += 1
            try:
                facts = extract(call, windows=windows, env=env, shell_tools=carriers)
                decision = evaluate(
                    rules_by_cwd[cwd],
                    facts,
                    history,
                    now=when,
                    exceptions=exceptions,
                    repo_root=repo_root,
                )
                summary = summarise(facts)
            except Exception:  # one bad call must not end the replay
                report.errors += 1
                continue
            # Keep for the history predicates what the audit log would hold.
            entry = {"tool": facts.tool, "cwd": facts.cwd, "session": facts.session}
            history.add(restore({**entry, "call": summary}), when)
            report.decisions[decision.effect] += 1
            report.dynamic.update({reason.kind for reason in facts.dynamic})
            for fired in decision.fired:
                report.rules[fired.id] += 1
                report.effects[fired.id] = fired.effect
                kept = report.examples.setdefault(fired.id, [])
                line = example(facts.tool, summary)
                if len(kept) < examples and line not in kept:
                    kept.append(line)
    return report


def render(report: ReplayReport) -> str:
    """The report as text for the terminal."""
    lines = [
        f"files: {report.files}   lines: {report.lines} "
        f"({report.skipped_lines} skipped)   tool calls: {report.calls}   "
        f"gate errors: {report.errors}"
    ]
    for title, counter in (
        ("calls by tool", report.tools),
        ("decisions", report.decisions),
        ("dynamic shell", report.dynamic),
    ):
        lines.append(f"{title}:")
        lines += [f"  {count:7}  {name}" for name, count in counter.most_common()]
    lines.append("rules that fired:")
    for rule_id, count in report.rules.most_common():
        lines.append(f"  {count:7}  {rule_id} [{report.effects[rule_id]}]")
        lines += [f"             e.g. {line}" for line in report.examples[rule_id]]
    return "\n".join(lines)
