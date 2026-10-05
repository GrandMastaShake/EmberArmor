"""``ember-gate`` command line.

Subcommands: ``check``, ``rules list|add|confirm|remove``, ``lint``,
``log tail|verify|stats``, ``replay``, ``hook`` (``--event pre-tool-use`` or
``session-start``) and ``install claude-code --print``.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
from collections import Counter
from collections.abc import Sequence
from datetime import date
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from ember_armor.ledger import hook, store
from ember_armor.ledger.config import MODES, ConfigError, rule_exceptions
from ember_armor.ledger.exceptions import RuleException
from ember_armor.ledger.gate import (
    IN_DECISION,
    REMINDED,
    GateResult,
    audit_log,
    check,
    configured_shell_tools,
)
from ember_armor.ledger.model import LedgerError, exceptable, parse_predicate

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_NO_SOLVER = 3
#: Interpreter arguments of the hook: isolated mode, then the hook module.
HOOK_ARGS = ("-I", "-m", "ember_armor.ledger.hook")
#: The same for the summary at the start of a session.
SESSION_ARGS = (*HOOK_ARGS, "--event", hook.SESSION_START)


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=True, default=str))


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------
def _call_from_args(args: argparse.Namespace) -> Any:
    if args.command is None and args.input is None:
        return json.loads(sys.stdin.read())
    tool_input = json.loads(args.input) if args.input else {"command": args.command}
    return {
        "session_id": args.session,
        "cwd": args.cwd or os.getcwd(),
        "tool_name": args.tool,
        "tool_input": tool_input,
    }


def _in_each_mode(call: Any, result: GateResult) -> dict[str, GateResult]:
    """The same dry run in every mode (*result* is the configured one)."""
    results = {}
    for mode in MODES:
        env = {**os.environ, "EMBER_GATE_MODE": mode}
        same = mode == result.mode
        results[mode] = result if same else check(call, env=env, record=False)
    return results


def _prints(result: GateResult) -> str:
    """What the hook prints for *result*: ``nothing``, a decision or a reminder."""
    if result.blocking:
        return "decision"
    return "reminder" if result.reminder and result.reminder.text else "nothing"


def _to_agent(result: GateResult) -> str:
    """One line: what the hook prints, and which rules stay in the log."""
    if result.mode == "observe":
        return "nothing is printed"
    told = result.delivery()

    def having(status: str) -> str:
        return ", ".join(rule for rule, state in told.items() if state == status)

    printed = _prints(result)
    if printed == "decision":
        line = f"the host is told to {result.decision.effect}"
        line += f", quoting {having(IN_DECISION)}" if having(IN_DECISION) else ""
    elif printed == "reminder":
        line = f"a reminder quoting {having(REMINDED)}"
    else:
        line = "nothing is printed"
    logged = [
        f"{rule} ({state.partition(': ')[2]})"
        for rule, state in told.items()
        if state not in (REMINDED, IN_DECISION)
    ]
    return f"{line}; logged only: {', '.join(logged)}" if logged else line


def _cmd_check(args: argparse.Namespace) -> int:
    """Dry run: evaluate a call and print the decision.  Nothing is logged.

    When a rule fired, what the hook would print in each mode is shown too.
    """
    try:
        call = _call_from_args(args)
    except ValueError as exc:
        print(f"ember-gate: input is not valid JSON: {exc}", file=sys.stderr)
        return EXIT_USAGE
    result = check(call, record=False)
    decision = result.decision
    modes = _in_each_mode(call, result) if decision.fired else {}
    if args.json:
        report = result.report()
        if modes:
            report["by_mode"] = {
                mode: {
                    "decision": other.decision.effect,
                    "prints": _prints(other),
                    "reminder": other.report()["reminder"],
                    "delivery": other.delivery(),
                }
                for mode, other in modes.items()
            }
        _print_json(report)
        return EXIT_OK
    print(f"decision: {decision.effect} (mode: {result.mode})")
    for rule in decision.fired:
        print(f"  {rule.id} [{rule.effect}] {rule.text} (source: {rule.source})")
    for dropped in decision.excepted:
        print(f"  excepted: {dropped.rule} (reason: {dropped.reason})")
    if decision.error:
        print(f"  gate failure: {decision.error}")
    if result.facts and result.facts.dynamic:
        reasons = ", ".join(sorted({d.kind for d in result.facts.dynamic}))
        print(f"  dynamic shell: {reasons}")
    if modes:
        print("  to the agent, by mode:")
        for mode, other in modes.items():
            print(f"    {mode}: {_to_agent(other)}")
        texts = [o.reminder.text for o in modes.values() if o.reminder]
        for text in [text for text in texts if text][:1]:
            print("  reminder text:")
            for line in text.splitlines():
                print(f"    {line}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------
def _target_ledger(args: argparse.Namespace) -> Path:
    """Ledger file an editing command works on."""
    if args.ledger:
        return Path(args.ledger)
    user = store.user_ledger_path(os.environ)
    if args.project:
        found = store.find_project_ledger(os.getcwd())
        if found is not None and found.resolve() != user.resolve():
            return found
        return Path(os.getcwd()) / ".ember" / store.LEDGER_NAME
    override = os.environ.get("EMBER_LEDGER")
    return Path(override) if override else user


def _owner_exceptions() -> tuple[RuleException, ...]:
    """Every exception of ``config.json``, expired ones included."""
    try:
        return rule_exceptions(os.environ)
    except ConfigError as exc:
        raise LedgerError(str(exc)) from exc


def _describe_exception(exception: RuleException) -> str:
    """One line saying where an exception holds, why, and until when."""
    places = [f"under {directory}" for directory in exception.cwd_under]
    places += [f"repository {directory}" for directory in exception.repo_root]
    parts = [" or ".join(places)] if places else []
    if exception.tools:
        parts.append(f"tools {', '.join(exception.tools)}")
    if exception.when is not None:
        parts.append("with a condition")
    until = ""
    if exception.expires is not None:
        past = date.today() > exception.expires
        until = f", {'expired' if past else 'expires'} {exception.expires}"
    return f"{'; '.join(parts)} (reason: {exception.reason}{until})"


def _cmd_rules_list(args: argparse.Namespace) -> int:
    rules = store.load_all(args.cwd or os.getcwd(), os.environ)
    exceptions = _owner_exceptions()

    def excepting(rule_id: str) -> list[RuleException]:
        if not exceptable(rule_id):
            return []
        return [e for e in exceptions if fnmatchcase(rule_id, e.rule)]

    if args.json:
        listed = []
        for rule in rules:
            entry = {**rule.raw, "origin": rule.origin, "confirmed": rule.confirmed}
            found = [dict(exception.raw) for exception in excepting(rule.id)]
            listed.append({**entry, "exceptions": found} if found else entry)
        _print_json(listed)
        return EXIT_OK
    for rule in rules:
        state = "confirmed" if rule.confirmed else "unconfirmed (warn only)"
        if not store.evaluated(rule):
            state = "unconfirmed, not evaluated: it holds a regular expression"
        expires = f", expires {rule.expires}" if rule.expires else ""
        print(f"{rule.id}  [{rule.effect}, {state}{expires}]  ({rule.origin})")
        print(f"    {rule.text}")
        for exception in excepting(rule.id):
            print(f"    exception: {_describe_exception(exception)}")
    unused = [
        e for e in exceptions if not any(fnmatchcase(r.id, e.rule) for r in rules)
    ]
    for exception in unused:
        print(f"exception for {exception.rule}, which names no rule in effect:")
        print(f"    {_describe_exception(exception)}")
    return EXIT_OK


def _rule_from_args(args: argparse.Namespace) -> dict[str, Any]:
    if args.file:
        from_stdin = args.file == "-"
        text = sys.stdin.read() if from_stdin else Path(args.file).read_text("utf-8")
        rule = json.loads(text)
        if not isinstance(rule, dict):
            raise LedgerError("the rule file must contain one JSON object")
        return rule
    missing = [n for n in ("id", "text", "effect") if getattr(args, n) is None]
    if missing or (args.when is None) == (args.require is None):
        raise LedgerError(
            "give --file, or --id, --text, --effect and exactly one of --when/--require"
        )
    key = "when" if args.when is not None else "require"
    rule = {
        "id": args.id,
        "text": args.text,
        "source": args.source or "added with ember-gate rules add",
        "effect": args.effect,
        key: json.loads(args.when if args.when is not None else args.require),
    }
    parse_predicate(rule[key], key)
    applies = {
        "tools": args.tools,
        "cwd_under": args.cwd_under,
        "cwd_not_under": args.cwd_not_under,
        "repo_root": args.repo_root,
    }
    if any(applies.values()):
        rule["applies"] = {k: v for k, v in applies.items() if v}
    if args.expires:
        rule["expires"] = args.expires
    return rule


def _cmd_rules_add(args: argparse.Namespace) -> int:
    path = _target_ledger(args)
    rule = store.add_rule(path, _rule_from_args(args))
    print(f"added {rule.id} to {path} (unconfirmed: it can only warn)")
    print(f"confirm it with: ember-gate rules confirm {rule.id}")
    return EXIT_OK


def _cmd_rules_confirm(args: argparse.Namespace) -> int:
    path = _target_ledger(args)
    if args.project and not args.ledger:
        # A project ledger is confirmed on this machine, not in the repository.
        store.confirm_project_rule(os.environ, path, args.rule_id)
        print(f"confirmed {args.rule_id} of {path} on this machine")
        return EXIT_OK
    store.confirm_rule(path, args.rule_id)
    print(f"confirmed {args.rule_id} in {path}")
    return EXIT_OK


def _cmd_rules_remove(args: argparse.Namespace) -> int:
    path = _target_ledger(args)
    store.remove_rule(path, args.rule_id)
    print(f"removed {args.rule_id} from {path}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# lint
# ---------------------------------------------------------------------------
def _cmd_lint(args: argparse.Namespace) -> int:
    """Check the ledger itself: 0 when clean, 1 with findings, 3 without Z3."""
    from ember_armor.ledger.lint import SolverUnavailableError, finding_data, lint

    rules = store.load_all(args.cwd or os.getcwd(), os.environ)
    try:
        findings = lint(rules, shell_tools=configured_shell_tools(os.environ))
    except SolverUnavailableError as exc:
        print(f"ember-gate: {exc}", file=sys.stderr)
        return EXIT_NO_SOLVER
    if args.json:
        _print_json(
            {"rules": len(rules), "findings": [finding_data(f) for f in findings]}
        )
    else:
        for finding in findings:
            print(f"{finding.kind}: {finding.message}")
        result = f"{len(findings)} finding(s)" if findings else "no findings"
        print(f"{len(rules)} rules checked: {result}")
    return EXIT_ERROR if findings else EXIT_OK


# ---------------------------------------------------------------------------
# log
# ---------------------------------------------------------------------------
def _cmd_log_tail(args: argparse.Namespace) -> int:
    entries = list(audit_log(os.environ).entries())[-args.lines :]
    for entry in entries:
        if args.json:
            print(json.dumps(entry, ensure_ascii=True))
            continue
        if "event" in entry:
            # A summary printed at the start of a session, not an evaluation.
            announced = ",".join(entry.get("announced", [])) or "-"
            print(
                f"{entry.get('ts', '?')}  {entry['event']}  "
                f"{entry.get('mode', '?'):7}  {entry.get('source', '?')}  "
                f"announced: {announced}"
            )
            continue
        rules = ",".join(entry.get("rules", [])) or "-"
        reminded = entry.get("reminded")
        told = "" if reminded is None else f"  reminded: {','.join(reminded) or '-'}"
        print(
            f"{entry.get('ts', '?')}  {entry.get('decision', '?'):5}  "
            f"{entry.get('mode', '?'):7}  {entry.get('tool', '?')}  {rules}{told}"
        )
    return EXIT_OK


def _cmd_log_verify(args: argparse.Namespace) -> int:
    result = audit_log(os.environ).verify()
    for problem in result.problems:
        print(problem)
    status = "ok" if result.ok else f"{len(result.problems)} problem(s)"
    print(f"{result.entries} entries checked: {status}")
    return EXIT_OK if result.ok else EXIT_ERROR


def _cmd_log_stats(args: argparse.Namespace) -> int:
    counters: dict[str, Counter[str]] = {
        "decision": Counter(),
        "mode": Counter(),
        "tool": Counter(),
        "rule": Counter(),
        "reminded": Counter(),
        "event": Counter(),
    }
    total = 0
    for entry in audit_log(os.environ).entries():
        total += 1
        if "event" in entry:
            counters["event"][str(entry["event"])] += 1
            continue
        for key in ("decision", "mode", "tool"):
            counters[key][str(entry.get(key, "?"))] += 1
        counters["rule"].update(entry.get("rules", []))
        counters["reminded"].update(entry.get("reminded", []))
    if args.json:
        _print_json({"entries": total, **{k: dict(v) for k, v in counters.items()}})
        return EXIT_OK
    print(f"entries: {total}")
    for key, counter in counters.items():
        for name, count in counter.most_common(20):
            print(f"  {key:8}  {count:6}  {name}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# replay
# ---------------------------------------------------------------------------
def _cmd_replay(args: argparse.Namespace) -> int:
    """Run recorded tool calls through the ledger and print aggregates."""
    from ember_armor.ledger.replay import render, replay

    report = replay(args.paths, examples=args.examples)
    if args.json:
        _print_json(report.as_dict())
    else:
        print(render(report))
    return EXIT_OK


# ---------------------------------------------------------------------------
# hook / install
# ---------------------------------------------------------------------------
def _cmd_hook(args: argparse.Namespace) -> int:
    return hook.main(["--event", args.event])


def claude_code_settings() -> dict[str, Any]:
    """Settings snippet that registers the gate's two hooks.

    PreToolUse checks every tool call.  SessionStart prints the summary of
    the standing rules (in ``remind`` and ``enforce`` mode, for the session
    sources named by ``announce_on``); it has no matcher, so the gate, not
    the settings file, decides which starts are announced.

    Both are started without a shell (the ``args`` form), and the
    interpreter runs isolated (``-I``): the working directory is not on the
    import path, so a repository that ships its own ``ember_armor`` package
    cannot stand in for the gate, and ``PYTHON*`` variables are ignored.
    """
    python = Path(sys.executable).as_posix()
    check_call = {"type": "command", "command": python, "args": [*HOOK_ARGS]}
    summary = {"type": "command", "command": python, "args": [*SESSION_ARGS]}
    return {
        "hooks": {
            "PreToolUse": [{"matcher": "*", "hooks": [check_call]}],
            "SessionStart": [{"hooks": [summary]}],
        }
    }


def _cmd_install(args: argparse.Namespace) -> int:
    if not args.print:
        print(
            "ember-gate does not edit settings. Run with --print and merge the "
            "snippet into your Claude Code settings.json yourself.",
            file=sys.stderr,
        )
        return EXIT_USAGE
    _print_json(claude_code_settings())
    return EXIT_OK


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------
def _add_ledger_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--ledger", help="ledger file to edit")
    parser.add_argument(
        "--project",
        action="store_true",
        help="the project ledger (.ember/); confirming records the approval "
        "in the Ember home, not in the repository",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the ``ember-gate`` argument parser."""
    parser = argparse.ArgumentParser(
        prog="ember-gate",
        description="Constraint ledger gate: check tool calls against stored rules.",
    )
    commands = parser.add_subparsers(dest="group", required=True)

    p_check = commands.add_parser("check", help="evaluate a call (dry run, not logged)")
    p_check.add_argument("command", nargs="?", help="shell command string to check")
    p_check.add_argument("--tool", default="Bash", help="tool name (default: Bash)")
    p_check.add_argument("--input", help="tool input as JSON, instead of a command")
    p_check.add_argument("--cwd", help="working directory of the call")
    p_check.add_argument("--session", default="", help="session id (for history rules)")
    p_check.add_argument("--json", action="store_true", help="print JSON")
    p_check.set_defaults(func=_cmd_check)

    rules = commands.add_parser("rules", help="list and edit ledger rules")
    rule_commands = rules.add_subparsers(dest="action", required=True)
    p_list = rule_commands.add_parser("list", help="show every rule in effect")
    p_list.add_argument("--cwd", help="directory whose project ledger to include")
    p_list.add_argument("--json", action="store_true", help="print JSON")
    p_list.set_defaults(func=_cmd_rules_list)
    p_add = rule_commands.add_parser("add", help="add an unconfirmed rule")
    p_add.add_argument("--file", help="JSON file with one rule ('-' for stdin)")
    p_add.add_argument("--id")
    p_add.add_argument("--text", help="the constraint as a person would say it")
    p_add.add_argument("--source", help="where the rule came from")
    p_add.add_argument("--effect", choices=("deny", "ask", "warn"))
    p_add.add_argument("--when", help="predicate JSON; the rule fires when true")
    p_add.add_argument("--require", help="predicate JSON; the rule fires when false")
    p_add.add_argument("--tools", nargs="+", help="tool names or globs")
    p_add.add_argument("--cwd-under", nargs="+", help="directories the rule covers")
    p_add.add_argument(
        "--cwd-not-under", nargs="+", help="directories the rule leaves out"
    )
    p_add.add_argument(
        "--repo-root",
        nargs="+",
        help="repositories the rule covers, by their top-level directory",
    )
    p_add.add_argument("--expires", help="ISO date after which the rule is ignored")
    _add_ledger_options(p_add)
    p_add.set_defaults(func=_cmd_rules_add)
    for name, func, text in (
        ("confirm", _cmd_rules_confirm, "mark a rule as approved by a human"),
        ("remove", _cmd_rules_remove, "delete a rule"),
    ):
        p_edit = rule_commands.add_parser(name, help=text)
        p_edit.add_argument("rule_id")
        _add_ledger_options(p_edit)
        p_edit.set_defaults(func=func)

    p_lint = commands.add_parser("lint", help="check the ledger itself (needs Z3)")
    p_lint.add_argument("--cwd", help="directory whose project ledger to include")
    p_lint.add_argument("--json", action="store_true", help="print JSON")
    p_lint.set_defaults(func=_cmd_lint)

    log = commands.add_parser("log", help="inspect the audit log")
    log_commands = log.add_subparsers(dest="action", required=True)
    p_tail = log_commands.add_parser("tail", help="show the latest entries")
    p_tail.add_argument("-n", "--lines", type=int, default=20)
    p_tail.add_argument("--json", action="store_true", help="print JSON lines")
    p_tail.set_defaults(func=_cmd_log_tail)
    p_verify = log_commands.add_parser("verify", help="recompute the hash chain")
    p_verify.set_defaults(func=_cmd_log_verify)
    p_stats = log_commands.add_parser("stats", help="count decisions, tools and rules")
    p_stats.add_argument("--json", action="store_true", help="print JSON")
    p_stats.set_defaults(func=_cmd_log_stats)

    p_replay = commands.add_parser(
        "replay", help="run Claude Code transcripts through the ledger (aggregates)"
    )
    p_replay.add_argument("paths", nargs="+", help="transcript .jsonl or directory")
    p_replay.add_argument(
        "--examples", type=int, default=3, help="example calls per rule (default: 3)"
    )
    p_replay.add_argument("--json", action="store_true", help="print JSON")
    p_replay.set_defaults(func=_cmd_replay)

    p_hook = commands.add_parser("hook", help="Claude Code hook (stdin)")
    # No ``choices``: an unknown event must not end in exit status 2, which
    # the host reads as "block this call".  The hook handles it as a failure.
    p_hook.add_argument(
        "--event",
        default=hook.PRE_TOOL_USE,
        metavar="EVENT",
        help="pre-tool-use checks a call (default); session-start prints the "
        "summary of the standing rules",
    )
    p_hook.set_defaults(func=_cmd_hook)

    install = commands.add_parser("install", help="show how to wire the gate in")
    install.add_argument("host", choices=("claude-code",))
    install.add_argument("--print", action="store_true", help="print the snippet")
    install.set_defaults(func=_cmd_install)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run ``ember-gate`` and return its exit code."""
    for stream in (sys.stdout, sys.stderr):
        # Rule text may hold characters the console encoding lacks (cp1252).
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(errors="backslashreplace")
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (LedgerError, OSError, json.JSONDecodeError) as exc:
        print(f"ember-gate: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
