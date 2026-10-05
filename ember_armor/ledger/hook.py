"""Claude Code hook adapter: PreToolUse, and the summary at SessionStart.

PreToolUse (the default event) reads the hook JSON (``session_id``, ``cwd``,
``tool_name``, ``tool_input``) on standard input and prints at most one
object:

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

``--event session-start`` reads the SessionStart hook JSON (``session_id``,
``cwd``, ``source``) and prints, in ``remind`` and ``enforce`` mode, a
summary of the confirmed rules that can apply in that directory (see
:mod:`ember_armor.ledger.announce`).  It never fails the session: an error
goes to standard error and nothing is printed.

Run as ``ember-gate hook`` or ``python -m ember_armor.ledger.hook``.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import replace

from ember_armor.ledger.config import gate_mode
from ember_armor.ledger.gate import GateResult, check

TYPE_CHECKING = False
if TYPE_CHECKING:
    from typing import Any

    from ember_armor.ledger.model import Decision

BLOCKING_DECISIONS = ("deny", "ask")
PRE_TOOL_USE = "pre-tool-use"
SESSION_START = "session-start"
EVENTS = (PRE_TOOL_USE, SESSION_START)
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
    words are not the owner's, so they stay in the log.  The words that are
    quoted are put on one line each and stripped of what does not show, as
    in a reminder: the reason is read by the agent too.
    """
    from ember_armor.ledger.model import REASON_CHARS
    from ember_armor.ledger.remind import clean

    vouched = tuple(
        replace(
            rule,
            text=clean(rule.text, REASON_CHARS),
            source=clean(rule.source, REASON_CHARS),
        )
        for rule in decision.fired
        if rule.confirmed
    )
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


def handle(
    raw: bytes, env: Mapping[str, str] | None = None, problem: str | None = None
) -> GateResult:
    """Evaluate one hook invocation.

    Parameters
    ----------
    raw:
        Bytes read from standard input.
    env:
        Environment mapping; defaults to the process environment.
    problem:
        A failure that happened before the input was read.
    """
    call: Any = None
    if problem is None:
        try:
            call = json.loads(raw.decode("utf-8", errors="replace"))
        except (ValueError, RecursionError) as exc:
            problem = f"malformed hook input: {type(exc).__name__}: {exc}"
    return check(call, env=env, problem=problem)


def session_start(
    raw: bytes, env: Mapping[str, str] | None = None
) -> tuple[str, str | None]:
    """Standard output and the error, if any, for one SessionStart invocation.

    The output is a ``hookSpecificOutput`` object with ``additionalContext``,
    or nothing.  A ledger that could not be loaded is an error next to the
    summary of the others; with any other error the output is nothing.
    """
    try:
        from ember_armor.ledger.announce import announce

        start = json.loads(raw.decode("utf-8", errors="replace"))
        told = announce(start, env=env)
    except Exception as exc:
        return "", f"{type(exc).__name__}: {exc}"
    output = _context_object("SessionStart", told.text) if told.text else ""
    return output, "; ".join(told.problems) or None


def _passive() -> bool:
    """True only when the mode is positively known to let a failure pass."""
    try:
        return gate_mode(os.environ) in _PASSIVE
    except Exception:
        return False


def _event(argv: Sequence[str]) -> tuple[str, str | None]:
    """The event named on the command line, and what is wrong with the line.

    ``--event NAME`` or ``--event=NAME``; no argument means PreToolUse.
    Anything else is handled as a PreToolUse call the gate failed on, so a
    mistyped hook command asks in ``enforce`` mode instead of passing.
    """
    if not argv:
        return PRE_TOOL_USE, None
    name = None
    if len(argv) == 2 and argv[0] == "--event":
        name = argv[1]
    elif len(argv) == 1 and argv[0].startswith("--event="):
        name = argv[0].partition("=")[2]
    if name in EVENTS:
        return str(name), None
    expected = f"expected --event {' or --event '.join(EVENTS)}"
    return PRE_TOOL_USE, f"unknown hook arguments ({expected})"


def main(argv: Sequence[str] = ()) -> int:
    """Entry point: read standard input, print the output, exit 0.

    *argv* holds the arguments after the program name: none, or ``--event``
    with ``pre-tool-use`` or ``session-start``.
    """
    event, problem = _event(argv)
    if event == SESSION_START:
        try:
            output, error = session_start(sys.stdin.buffer.read())
        except Exception as exc:  # reading standard input failed
            output, error = "", f"{type(exc).__name__}: {exc}"
        if error:
            sys.stderr.write(f"ember-gate: session start: {error}\n")
        if output:
            sys.stdout.write(output + "\n")
        return 0
    try:
        result = handle(sys.stdin.buffer.read(), problem=problem)
        decision = result.decision
        # A project ledger's reason for not loading is not printed: see
        # ``Decision.said``.
        output, error = hook_output(result), decision.said or decision.error
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
    sys.exit(main(sys.argv[1:]))
