"""``ember-gate`` command line.

Subcommands: ``check``, ``rules list|add|confirm|remove``,
``log tail|verify|stats``, ``hook`` and ``install claude-code --print``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from ember_armor.ledger import hook, store
from ember_armor.ledger.audit import summarise
from ember_armor.ledger.gate import audit_log, check
from ember_armor.ledger.model import LedgerError, parse_predicate

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2


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


def _cmd_check(args: argparse.Namespace) -> int:
    """Dry run: evaluate a call and print the decision.  Nothing is logged."""
    try:
        call = _call_from_args(args)
    except ValueError as exc:
        print(f"ember-gate: input is not valid JSON: {exc}", file=sys.stderr)
        return EXIT_USAGE
    result = check(call, record=False)
    decision = result.decision
    if args.json:
        _print_json(
            {
                "decision": decision.effect,
                "mode": result.mode,
                "rules": [vars(rule) for rule in decision.fired],
                "error": decision.error,
                "call": summarise(result.facts) if result.facts else None,
            }
        )
        return EXIT_OK
    print(f"decision: {decision.effect} (mode: {result.mode})")
    for rule in decision.fired:
        print(f"  {rule.id} [{rule.effect}] {rule.text} (source: {rule.source})")
    if decision.error:
        print(f"  gate failure: {decision.error}")
    if result.facts and result.facts.dynamic:
        reasons = ", ".join(sorted({d.kind for d in result.facts.dynamic}))
        print(f"  dynamic shell: {reasons}")
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


def _cmd_rules_list(args: argparse.Namespace) -> int:
    rules = store.load_all(args.cwd or os.getcwd(), os.environ)
    if args.json:
        _print_json([{**rule.raw, "origin": rule.origin} for rule in rules])
        return EXIT_OK
    for rule in rules:
        state = "confirmed" if rule.confirmed else "unconfirmed (warn only)"
        expires = f", expires {rule.expires}" if rule.expires else ""
        print(f"{rule.id}  [{rule.effect}, {state}{expires}]  ({rule.origin})")
        print(f"    {rule.text}")
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
    applies = {"tools": args.tools, "cwd_under": args.cwd_under}
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
    store.confirm_rule(path, args.rule_id)
    print(f"confirmed {args.rule_id} in {path}")
    return EXIT_OK


def _cmd_rules_remove(args: argparse.Namespace) -> int:
    path = _target_ledger(args)
    store.remove_rule(path, args.rule_id)
    print(f"removed {args.rule_id} from {path}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# log
# ---------------------------------------------------------------------------
def _cmd_log_tail(args: argparse.Namespace) -> int:
    entries = list(audit_log(os.environ).entries())[-args.lines :]
    for entry in entries:
        if args.json:
            print(json.dumps(entry, ensure_ascii=True))
            continue
        rules = ",".join(entry.get("rules", [])) or "-"
        print(
            f"{entry.get('ts', '?')}  {entry.get('decision', '?'):5}  "
            f"{entry.get('mode', '?'):7}  {entry.get('tool', '?')}  {rules}"
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
    }
    total = 0
    for entry in audit_log(os.environ).entries():
        total += 1
        for key in ("decision", "mode", "tool"):
            counters[key][str(entry.get(key, "?"))] += 1
        counters["rule"].update(entry.get("rules", []))
    if args.json:
        _print_json({"entries": total, **{k: dict(v) for k, v in counters.items()}})
        return EXIT_OK
    print(f"entries: {total}")
    for key, counter in counters.items():
        for name, count in counter.most_common(20):
            print(f"  {key:8}  {count:6}  {name}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# hook / install
# ---------------------------------------------------------------------------
def _cmd_hook(args: argparse.Namespace) -> int:
    return hook.main()


def claude_code_settings() -> dict[str, Any]:
    """Settings snippet that registers the gate as a PreToolUse hook.

    The interpreter path uses forward slashes and is quoted only when it
    contains a space, so the command reads the same in Git Bash, cmd and
    PowerShell whenever the path has none.
    """
    python = Path(sys.executable).as_posix()
    if " " in python:
        python = f'"{python}"'
    command = f"{python} -m ember_armor.ledger.hook"
    entry = {"matcher": "*", "hooks": [{"type": "command", "command": command}]}
    return {"hooks": {"PreToolUse": [entry]}}


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
        "--project", action="store_true", help="edit the project ledger (.ember/)"
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

    p_hook = commands.add_parser("hook", help="Claude Code PreToolUse hook (stdin)")
    p_hook.set_defaults(func=_cmd_hook)

    install = commands.add_parser("install", help="show how to wire the gate in")
    install.add_argument("host", choices=("claude-code",))
    install.add_argument("--print", action="store_true", help="print the snippet")
    install.set_defaults(func=_cmd_install)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run ``ember-gate`` and return its exit code."""
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (LedgerError, OSError, json.JSONDecodeError) as exc:
        print(f"ember-gate: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
