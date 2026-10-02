"""Claude Code PreToolUse hook adapter.

Reads the hook JSON (``session_id``, ``cwd``, ``tool_name``, ``tool_input``)
on standard input.  On ``deny`` or ``ask`` in ``enforce`` mode it prints a
``hookSpecificOutput`` object with ``permissionDecision`` and a reason that
quotes the rule's text and source.  In every other case it prints nothing, so
the host's normal permission flow is untouched.  It never prints ``allow``
and always exits 0.  A failure of the gate itself is also reported on
standard error, which the host does not treat as a decision.

Run as ``ember-gate hook`` or ``python -m ember_armor.ledger.hook``.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping
from typing import Any

from ember_armor.ledger.config import gate_mode
from ember_armor.ledger.gate import GateResult, check

BLOCKING_DECISIONS = ("deny", "ask")


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


def hook_output(result: GateResult) -> str:
    """Text for standard output: a decision object, or nothing."""
    effect = result.decision.effect
    if not result.blocking or effect not in BLOCKING_DECISIONS:
        return ""
    return _decision_object(effect, result.decision.reason())


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


def _observing() -> bool:
    """True only when the configured mode is positively known to be observe."""
    try:
        return gate_mode(os.environ) == "observe"
    except Exception:
        return False


def main() -> int:
    """Entry point: read standard input, print the decision, exit 0."""
    try:
        result = handle(sys.stdin.buffer.read())
        output, error = hook_output(result), result.decision.error
    except Exception as exc:
        # Last resort.  Unless the gate is known to be observing, ask: the
        # mode may be enforce in a configuration this failure kept unread.
        error = f"{type(exc).__name__}: {exc}"
        failure = f"EmberArmor gate failure: {error}"
        output = "" if _observing() else _decision_object("ask", failure)
    if error:
        sys.stderr.write(f"ember-gate: gate failure: {error}\n")
    if output:
        sys.stdout.write(output + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
