"""Claude Code PreToolUse hook adapter.

Reads the hook JSON (``session_id``, ``cwd``, ``tool_name``, ``tool_input``)
on standard input and prints at most one object:

- On ``deny`` or ``ask`` in ``enforce`` mode, ``hookSpecificOutput`` with
  ``permissionDecision`` and a reason that quotes the rule's text and source.
- In ``remind`` mode, and in ``enforce`` mode when the decision does not
  block, ``hookSpecificOutput`` with ``additionalContext`` and no
  ``permissionDecision``: a reminder of the rules that fired.  The host
  hands it to the agent and its own permission flow is untouched.
- In every other case, and always in ``observe`` mode, nothing.

Only a rule the owner vouches for is ever quoted, in a reason or in a
reminder.  The hook never prints ``allow`` and always exits 0.  A failure
of the gate itself is also reported on standard error, which the host does
not treat as a decision.

Run as ``ember-gate hook`` or ``python -m ember_armor.ledger.hook``.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping
from dataclasses import replace

from ember_armor.ledger.config import gate_mode
from ember_armor.ledger.gate import GateResult, check

TYPE_CHECKING = False
if TYPE_CHECKING:
    from typing import Any

    from ember_armor.ledger.model import Decision

BLOCKING_DECISIONS = ("deny", "ask")
#: Modes in which a failure of the gate lets the call proceed.
_PASSIVE = ("observe", "remind")


def _decision_object(decision: str, reason: str) -> str:
    return json.dumps(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": reason,
            }
        }
    )


def _context_object(event: str, text: str) -> str:
    """Text for the agent, with no decision: the permission flow is untouched."""
    return json.dumps(
        {"hookSpecificOutput": {"hookEventName": event, "additionalContext": text}}
    )


def _reason(decision: Decision) -> str:
    """The reason of a blocking decision, quoting confirmed rules only.

    A rule nobody confirmed can fire next to the rule that blocks.  Its
    words are not the owner's, so they stay in the log.
    """
    if not all(rule.confirmed for rule in decision.fired):
        vouched = tuple(rule for rule in decision.fired if rule.confirmed)
        decision = replace(decision, fired=vouched)
    return decision.reason() or f"EmberArmor ledger decision: {decision.effect}"


def hook_output(result: GateResult) -> str:
    """Text for standard output: a decision object, a reminder, or nothing."""
    effect = result.decision.effect
    if result.blocking and effect in BLOCKING_DECISIONS:
        return _decision_object(effect, _reason(result.decision))
    reminder = result.reminder
    if reminder is None or not reminder.text:
        return ""
    if result.mode == "observe" or result.blocking:
        return ""  # observe prints nothing, whatever the result holds
    return _context_object("PreToolUse", reminder.text)


def handle(raw: bytes, env: Mapping[str, str] | None = None) -> GateResult:
    """Evaluate one hook invocation.

    Parameters
    ----------
    raw:
        Bytes read from standard input.
    env:
        Environment mapping; defaults to the process environment.
    """
    call: Any = None
    problem: str | None = None
    try:
        call = json.loads(raw.decode("utf-8", errors="replace"))
    except (ValueError, RecursionError) as exc:
        problem = f"malformed hook input: {type(exc).__name__}: {exc}"
    return check(call, env=env, problem=problem)


def _passive() -> bool:
    """True only when the mode is positively known to let a failure pass."""
    try:
        return gate_mode(os.environ) in _PASSIVE
    except Exception:
        return False


def main() -> int:
    """Entry point: read standard input, print the output, exit 0."""
    try:
        result = handle(sys.stdin.buffer.read())
        output, error = hook_output(result), result.decision.error
    except Exception as exc:
        # Last resort.  Unless the gate is known to be observing or
        # reminding, ask: the mode may be enforce in a configuration this
        # failure kept unread.
        error = f"{type(exc).__name__}: {exc}"
        failure = f"EmberArmor gate failure: {error}"
        output = "" if _passive() else _decision_object("ask", failure)
    if error:
        sys.stderr.write(f"ember-gate: gate failure: {error}\n")
    if output:
        sys.stdout.write(output + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
