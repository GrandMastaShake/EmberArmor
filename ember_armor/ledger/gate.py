"""The gate: one proposed tool call in, one decision out, one audit entry.

:func:`check` ties the pieces together and owns the failure behaviour.  If
the gate itself fails, then in ``enforce`` mode the decision is ``ask`` with
the error as the reason, and in ``observe`` mode the call proceeds and the
error is recorded.  A failure is never silent approval in ``enforce`` mode
and never a hard block.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ember_armor.ledger.audit import AuditLog, summarise
from ember_armor.ledger.config import ConfigError, ember_home, gate_mode
from ember_armor.ledger.engine import History, evaluate
from ember_armor.ledger.facts import Facts, extract
from ember_armor.ledger.model import SEVERITY, Decision
from ember_armor.ledger.store import load_rules


@dataclass(frozen=True)
class GateResult:
    """Decision for one call, the mode it was made in, and the facts used."""

    decision: Decision
    mode: str
    facts: Facts | None = None

    @property
    def blocking(self) -> bool:
        """True when the host must act on the decision (deny or ask, enforced)."""
        severe = SEVERITY[self.decision.effect] >= SEVERITY["ask"]
        return self.mode == "enforce" and severe


def audit_log(env: Mapping[str, str]) -> AuditLog:
    """The audit log under the Ember home of *env*."""
    return AuditLog(ember_home(env) / "audit")


def _failure(mode: str, error: str, earlier: Decision | None = None) -> Decision:
    fired = earlier.fired if earlier else ()
    if mode != "enforce":
        effect = earlier.effect if earlier else "none"
        return Decision(effect=effect, fired=fired, error=error)
    if earlier and SEVERITY[earlier.effect] >= SEVERITY["ask"]:
        return Decision(effect=earlier.effect, fired=fired, error=error)
    return Decision(effect="ask", fired=fired, error=error)


def _record(
    call: Any, facts: Facts | None, decision: Decision, mode: str
) -> dict[str, Any]:
    source = call if isinstance(call, Mapping) else {}
    record: dict[str, Any] = {
        "session": str(source.get("session_id") or ""),
        "tool": str(source.get("tool_name") or ""),
        "cwd": facts.cwd if facts else str(source.get("cwd") or ""),
        "decision": decision.effect,
        "rules": [rule.id for rule in decision.fired],
        "mode": mode,
    }
    if facts is not None:
        record["call"] = summarise(facts)
    if decision.error:
        record["error"] = decision.error[:500]
    return record


def check(
    call: Any,
    *,
    env: Mapping[str, str] | None = None,
    windows: bool | None = None,
    history: History | None = None,
    record: bool = True,
    now: datetime | None = None,
    problem: str | None = None,
) -> GateResult:
    """Evaluate one proposed tool call against the ledger.

    Parameters
    ----------
    call:
        The call in Claude Code PreToolUse shape (``session_id``, ``cwd``,
        ``tool_name``, ``tool_input``).
    env:
        Environment mapping; defaults to the process environment.  It selects
        the Ember home, the ledger override, the mode and path variables.
    windows:
        Path flavour; defaults to the running platform.
    history:
        Earlier calls for the history predicates.  Defaults to the audit log.
    record:
        Append the evaluation to the audit log.  ``False`` gives a dry run.
    now:
        Time of the evaluation; defaults to the current time.
    problem:
        A failure that happened before the gate was reached (for example
        unreadable hook input).  It is handled like any other gate failure.

    Returns
    -------
    GateResult
        Never raises: every internal error becomes a decision.
    """
    env = os.environ if env is None else env
    moment = (now or datetime.now()).astimezone()
    facts: Facts | None = None
    try:
        mode = gate_mode(env)
    except ConfigError as exc:
        mode, problem = "enforce", problem or str(exc)
    log = audit_log(env)
    try:
        if problem:
            raise ValueError(problem)
        if not isinstance(call, Mapping):
            raise ValueError("tool call is not a JSON object")
        facts = extract(call, windows=windows, env=env)
        rules = load_rules(str(call.get("cwd") or ""), env, moment.date())
        decision = evaluate(
            rules, facts, log if history is None else history, now=moment.timestamp()
        )
    except Exception as exc:
        decision = _failure(mode, f"{type(exc).__name__}: {exc}")
    if record:
        try:
            log.append(_record(call, facts, decision, mode), moment)
        except Exception as exc:
            decision = _failure(mode, f"audit log: {exc}", decision)
    return GateResult(decision, mode, facts)
