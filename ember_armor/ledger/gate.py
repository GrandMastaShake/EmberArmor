"""The gate: one proposed tool call in, one decision out, one audit entry.

:func:`check` ties the pieces together and owns the failure behaviour.  If
the gate itself fails, then in ``enforce`` mode the decision is ``ask`` with
the error as the reason, and in ``observe`` and ``remind`` mode the call
proceeds and the error is recorded.  A failure is never silent approval in
``enforce`` mode and never a hard block.  A ledger that cannot be loaded is
such a failure, and it only ever adds an ``ask``: the rules of the other
ledgers are still evaluated and a ``deny`` among them stands.

In ``remind`` mode, and in ``enforce`` mode when the decision does not
block, the rules that fired are told to the agent as a reminder (see
:mod:`ember_armor.ledger.remind`, which is loaded only then).
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import asdict, dataclass, replace
from datetime import date, datetime

from ember_armor.ledger.audit import AuditLog, past_calls, summarise
from ember_armor.ledger.config import (
    ConfigError,
    ember_home,
    gate_mode,
    remind_interval,
    rule_exceptions,
    shell_tools,
)
from ember_armor.ledger.engine import History, PastCall, RepoFinder, evaluate
from ember_armor.ledger.facts import Facts, ShellTool, extract, shell_tools_from
from ember_armor.ledger.model import SEVERITY, Decision, FiredRule
from ember_armor.ledger.redact import MAX_TEXT
from ember_armor.ledger.store import active_rules, load_sources

TYPE_CHECKING = False
if TYPE_CHECKING:
    from typing import Any

    from ember_armor.ledger.exceptions import RuleException
    from ember_armor.ledger.remind import Reminder

#: How a fired rule reaches the agent, or why only the log has it.
REMINDED = "reminded"
IN_DECISION = "quoted in the decision"
LOGGED_OBSERVE = "logged only: observe mode"
LOGGED_UNCONFIRMED = "logged only: not confirmed"
LOGGED_RECENT = "logged only: reminded inside the interval"
LOGGED_LEFT_OUT = "logged only: the reminder was full"
LOGGED_FAILURE = "logged only: the gate failed"


@dataclass(frozen=True)
class GateResult:
    """Decision for one call, the mode it was made in, and the facts used.

    ``reminder`` is set when the rules that fired are told to the agent as
    a reminder instead of a decision (``remind`` mode, or ``enforce`` mode
    with a decision that does not block).  Its text is empty when nothing
    is sent.
    """

    decision: Decision
    mode: str
    facts: Facts | None = None
    reminder: Reminder | None = None

    @property
    def blocking(self) -> bool:
        """True when the host must act on the decision (deny or ask, enforced)."""
        severe = SEVERITY[self.decision.effect] >= SEVERITY["ask"]
        return self.mode == "enforce" and severe

    def delivery(self) -> dict[str, str]:
        """For each rule that fired: how it reaches the agent, or why not.

        Only a rule the owner vouches for is ever quoted, in a reminder or
        in the reason of a blocking decision.
        """
        reminder = self.reminder
        told: dict[str, str] = {}
        for rule in self.decision.fired:
            if self.mode == "observe":
                told[rule.id] = LOGGED_OBSERVE
            elif not rule.confirmed:
                told[rule.id] = LOGGED_UNCONFIRMED
            elif self.blocking:
                told[rule.id] = IN_DECISION
            elif reminder is None:
                told[rule.id] = LOGGED_FAILURE
            elif rule.id in reminder.quoted:
                told[rule.id] = REMINDED
            elif rule.id in reminder.recent:
                told[rule.id] = LOGGED_RECENT
            else:
                told[rule.id] = LOGGED_LEFT_OUT
        return told

    def report(self) -> dict[str, Any]:
        """The result as JSON data, with the call redacted as in the audit log.

        ``reminder`` is the text the hook would print for this call (``None``
        when it prints no reminder) and ``delivery`` says of each fired rule
        how it reaches the agent.  ``excepted`` is present when an owner's
        exception dropped a rule.
        """
        report = {
            "decision": self.decision.effect,
            "mode": self.mode,
            "rules": [_fired(rule) for rule in self.decision.fired],
            "error": self.decision.error,
            "call": summarise(self.facts) if self.facts else None,
            "reminder": (self.reminder.text or None) if self.reminder else None,
        }
        if self.decision.fired:
            report["delivery"] = self.delivery()
        if self.decision.excepted:
            report["excepted"] = _excepted(self.decision)
        return report


class _SessionLog:
    """The audit entries of the call's session, read at most once per call.

    The history predicates and the limit on reminders both look at them.
    (A plain class: every call loads this module.)
    """

    __slots__ = ("entries", "log")

    def __init__(self, log: AuditLog) -> None:
        self.log = log
        self.entries: list[dict[str, Any]] | None = None

    def read(self, session: str) -> list[dict[str, Any]]:
        """The entries of *session*, from the log the first time."""
        if self.entries is None:
            self.entries = self.log.session_entries(session)
        return self.entries

    def earlier(self, session: str) -> list[PastCall]:
        """Earlier calls of *session* that were proposed and not denied."""
        return past_calls(self.read(session))


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


def _fired(rule: FiredRule) -> dict[str, str]:
    """A fired rule as it is reported: without the ``confirmed`` flag."""
    return {key: value for key, value in asdict(rule).items() if key != "confirmed"}


def _failure(mode: str, error: str, earlier: Decision | None = None) -> Decision:
    if earlier is None:
        return Decision(effect="ask" if mode == "enforce" else "none", error=error)
    if mode != "enforce" or SEVERITY[earlier.effect] >= SEVERITY["ask"]:
        return replace(earlier, error=error)
    return replace(earlier, effect="ask", error=error)


def _also(decision: Decision, error: str) -> str:
    """*error* added to the failure the decision already carries, if any."""
    return f"{decision.error}; {error}" if decision.error else error


def _reminds(mode: str, decision: Decision) -> bool:
    """True when fired rules reach the agent as a reminder, not as a decision."""
    if mode == "remind":
        return True
    return mode == "enforce" and SEVERITY[decision.effect] < SEVERITY["ask"]


def _record(
    call: Any,
    facts: Facts | None,
    decision: Decision,
    mode: str,
    reminder: Reminder | None = None,
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
    if reminder is not None:
        # What the reminder quoted: nothing when no confirmed rule was due.
        record["reminded"] = list(reminder.quoted)
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
        The limit on reminders is always judged from the audit log.
    record:
        Append the evaluation to the audit log.  ``False`` gives a dry run:
        the result then holds the reminder that would be sent.
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
    past = _SessionLog(log)
    reminder: Reminder | None = None
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
            past if history is None else history,
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
    if decision.fired and facts is not None and _reminds(mode, decision):
        session = facts.session
        try:
            # Loaded here and nowhere else: a call no rule fires on, and the
            # whole of observe mode, never pays for it.
            from ember_armor.ledger.remind import remind

            reminder = remind(
                decision.fired,
                session=session,
                now=moment.timestamp(),
                interval=lambda: remind_interval(env),
                entries=lambda: past.read(session),
            )
        except Exception as exc:
            decision = _failure(mode, _also(decision, f"reminder: {exc}"), decision)
    if record:
        try:
            log.append(_record(call, facts, decision, mode, reminder), moment)
        except Exception as exc:
            decision = _failure(mode, _also(decision, f"audit log: {exc}"), decision)
            # What the log does not hold is not sent.
            reminder = None
    if not _reminds(mode, decision):
        reminder = None  # a failure made the decision blocking
    return GateResult(decision, mode, facts, reminder)
