"""The gate: one proposed tool call in, one decision out, one audit entry.

:func:`check` ties the pieces together and owns the failure behaviour.  If
the gate itself fails, then in ``enforce`` mode the decision is ``ask`` with
the error as the reason, and in ``observe`` mode the call proceeds and the
error is recorded.  A failure is never silent approval in ``enforce`` mode
and never a hard block.  A ledger that cannot be loaded is such a failure,
and it only ever adds an ``ask``: the rules of the other ledgers are still
evaluated and a ``deny`` among them stands.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import asdict, dataclass, replace
from datetime import date, datetime

from ember_armor.ledger.audit import AuditLog, summarise
from ember_armor.ledger.config import (
    ConfigError,
    ember_home,
    gate_mode,
    rule_exceptions,
    shell_tools,
)
from ember_armor.ledger.engine import History, RepoFinder, evaluate
from ember_armor.ledger.facts import Facts, ShellTool, extract, shell_tools_from
from ember_armor.ledger.model import SEVERITY, Decision, RuleException
from ember_armor.ledger.redact import MAX_TEXT
from ember_armor.ledger.store import active_rules, load_sources

TYPE_CHECKING = False
if TYPE_CHECKING:
    from typing import Any


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

    def report(self) -> dict[str, Any]:
        """The result as JSON data, with the call redacted as in the audit log.

        ``excepted`` is present when an owner's exception dropped a rule.
        """
        report = {
            "decision": self.decision.effect,
            "mode": self.mode,
            "rules": [asdict(rule) for rule in self.decision.fired],
            "error": self.decision.error,
            "call": summarise(self.facts) if self.facts else None,
        }
        if self.decision.excepted:
            report["excepted"] = _excepted(self.decision)
        return report


def audit_log(env: Mapping[str, str]) -> AuditLog:
    """The audit log under the Ember home of *env*."""
    return AuditLog(ember_home(env) / "audit")


def configured_shell_tools(env: Mapping[str, str]) -> dict[str, ShellTool]:
    """The user's shell-carrying tools; none when the configuration is unreadable.

    The unreadable configuration itself is reported where the rules are
    loaded, so it is not reported a second time here.
    """
    try:
        return shell_tools_from(shell_tools(env))
    except ConfigError:
        return {}


def configured_exceptions(
    env: Mapping[str, str], today: date
) -> tuple[RuleException, ...]:
    """The owner's exceptions in force; none when the configuration is unreadable.

    As for :func:`configured_shell_tools`, the unreadable configuration is
    reported where the mode is read.  Without it no rule is excepted.
    """
    try:
        return rule_exceptions(env, today)
    except ConfigError:
        return ()


def _excepted(decision: Decision) -> list[dict[str, str]]:
    """The exceptions a decision used, as they go into the audit entry."""
    return [
        {"rule": item.rule[:MAX_TEXT], "reason": item.reason[:MAX_TEXT]}
        for item in decision.excepted
    ]


def _failure(mode: str, error: str, earlier: Decision | None = None) -> Decision:
    if earlier is None:
        return Decision(effect="ask" if mode == "enforce" else "none", error=error)
    if mode != "enforce" or SEVERITY[earlier.effect] >= SEVERITY["ask"]:
        return replace(earlier, error=error)
    return replace(earlier, effect="ask", error=error)


def _record(
    call: Any, facts: Facts | None, decision: Decision, mode: str
) -> dict[str, Any]:
    source = call if isinstance(call, Mapping) else {}
    record: dict[str, Any] = {
        "session": str(source.get("session_id") or "")[:MAX_TEXT],
        "tool": str(source.get("tool_name") or "")[:MAX_TEXT],
        "cwd": (facts.cwd if facts else str(source.get("cwd") or ""))[: 4 * MAX_TEXT],
        "decision": decision.effect,
        "rules": [rule.id for rule in decision.fired],
        "mode": mode,
    }
    if facts is not None:
        record["call"] = summarise(facts)
    if decision.excepted:
        record["excepted"] = _excepted(decision)
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
    project: bool = True,
    repo_root: RepoFinder | None = None,
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
    project:
        Look for a project ledger above the call's working directory.
    repo_root:
        Lookup of the nearest enclosing git repository of a directory, for
        ``repo_root`` scopes.  Defaults to the filesystem (see
        :func:`ember_armor.ledger.engine.evaluate`).

    Returns
    -------
    GateResult
        Never raises: every internal error becomes a decision.
    """
    env = os.environ if env is None else env
    moment = (now or datetime.now()).astimezone()
    facts: Facts | None = None
    problems: list[str] = []
    try:
        mode = gate_mode(env)
    except Exception as exc:
        # A configuration nobody can read is treated as enforce: the owner
        # may have asked for it, and observe would hide the failure.
        mode = "enforce"
        problems.append(str(exc))
    log = audit_log(env)
    try:
        if problem:
            raise ValueError(problem)
        if not isinstance(call, Mapping):
            raise ValueError("tool call is not a JSON object")
        facts = extract(
            call, windows=windows, env=env, shell_tools=configured_shell_tools(env)
        )
        rules, unloaded = load_sources(str(call.get("cwd") or ""), env, project=project)
        decision = evaluate(
            active_rules(rules, moment.date()),
            facts,
            log if history is None else history,
            now=moment.timestamp(),
            exceptions=configured_exceptions(env, moment.date()),
            repo_root=repo_root,
        )
        # A repository lookup that failed is a gate failure like the others.
        failed = [decision.error] if decision.error else []
        problems = list(dict.fromkeys(problems + unloaded + failed))
        if problems:
            # What did load was evaluated; the failure can only add an ask.
            decision = _failure(mode, "; ".join(problems), decision)
    except Exception as exc:
        decision = _failure(mode, f"{type(exc).__name__}: {exc}")
    if record:
        try:
            log.append(_record(call, facts, decision, mode), moment)
        except Exception as exc:
            decision = _failure(mode, f"audit log: {exc}", decision)
    return GateResult(decision, mode, facts)
