"""The summary at the start of a session: the standing rules in their own words.

A session that starts again after its context was compacted has lost what
it was told.  ``ember-gate hook --event session-start`` hands the agent the
confirmed rules of the user ledger and of the project ledger that can apply
in the directory the session starts in.  The built-in pack is not listed:
its rules speak up when they fire.

The trust rule is the one of :mod:`ember_armor.ledger.remind`: only a rule
the owner vouches for is quoted, sanitised and capped in the same way.  The
summary is printed in ``remind`` and ``enforce`` mode, for the session
sources named by ``announce_on`` in ``config.json``.  A ledger that cannot
be loaded takes only its own rules out of the summary; any other failure is
raised to the caller, which prints nothing.

A start after which the agent no longer has what it was told (``compact``,
``clear``) leaves an audit entry whether or not a summary is printed: the
limit on reminders starts again there (see
:func:`ember_armor.ledger.remind.reminded_within`).
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime

from ember_armor.ledger.config import announce_on, gate_mode
from ember_armor.ledger.engine import RepoFinder, scope_reaches
from ember_armor.ledger.facts import Facts, extract
from ember_armor.ledger.gate import audit_log
from ember_armor.ledger.redact import MAX_TEXT, session_key
from ember_armor.ledger.remind import FORGETTING, SESSION_START, compose
from ember_armor.ledger.store import active_rules, load_sources, sayable

TYPE_CHECKING = False
if TYPE_CHECKING:
    from typing import Any

    from ember_armor.ledger.model import Rule

EVENT = SESSION_START
#: Most rules listed, and the cap on the whole text.
SUMMARY_RULES = 12
SUMMARY_CHARS = 3000
#: How the count of rules that did not fit ends, for one rule and for several.
_APPLY = ("applies here and is not listed", "apply here and are not listed")


@dataclass(frozen=True)
class Announcement:
    """What is printed when a session starts.

    ``text`` is empty when nothing is printed, ``rules`` are the keys of the
    rules listed and ``left_out`` counts the rules that apply and did not
    fit.  ``problems`` names the ledgers that could not be loaded, in the
    words that may be printed; their rules are missing from the summary.
    """

    text: str = ""
    rules: tuple[str, ...] = ()
    left_out: int = 0
    mode: str = "observe"
    problems: tuple[str, ...] = ()


def announce(
    start: Any,
    *,
    env: Mapping[str, str] | None = None,
    windows: bool | None = None,
    now: datetime | None = None,
    record: bool = True,
    repo_root: RepoFinder | None = None,
) -> Announcement:
    """The summary for one session start.

    Parameters
    ----------
    start:
        The SessionStart hook input: ``session_id``, ``cwd`` and ``source``
        (``startup``, ``resume``, ``clear`` or ``compact``).
    env:
        Environment mapping; defaults to the process environment.
    windows:
        Path flavour; defaults to the running platform.
    now:
        Time of the start; defaults to the current time.
    record:
        Append the start to the audit log: what was printed, and for
        ``compact`` and ``clear`` the start itself.
    repo_root:
        Lookup of the nearest enclosing git repository of a directory, for
        ``repo_root`` scopes.  Defaults to the filesystem.

    Returns
    -------
    Announcement
        Without text in ``observe`` mode, for a source that is not
        announced, and when no confirmed rule can apply in the directory.

    Raises
    ------
    Exception
        Whatever went wrong, apart from a ledger that could not be loaded:
        unreadable configuration, a repository lookup that failed, an audit
        log that cannot be written.  Nothing is printed then.
    """
    env = os.environ if env is None else env
    if not isinstance(start, Mapping):
        raise ValueError("session start input is not a JSON object")
    mode = gate_mode(env)
    source = start.get("source")
    if mode == "observe":
        return Announcement(mode=mode)
    announced = source in announce_on(env)
    forgetting = source in FORGETTING
    if not announced and not forgetting:
        return Announcement(mode=mode)
    moment = (now or datetime.now()).astimezone()
    cwd = start.get("cwd")
    session = session_key(start.get("session_id"))
    where = cwd if isinstance(cwd, str) else ""
    text, left_out = "", 0
    quoted: tuple[str, ...] = ()
    problems: list[str] = []
    failure: Exception | None = None
    try:
        if announced:
            place = {"tool_name": "SessionStart", "cwd": cwd, "session_id": session}
            facts = extract(place, windows=windows, env=env)
            where = facts.cwd
            listed, problems = _listed(cwd, facts, env, moment, repo_root)
            text, quoted = compose(
                listed, most=SUMMARY_RULES, limit=SUMMARY_CHARS, more=_APPLY
            )
            left_out = len(listed) - len(quoted)
    except Exception as exc:
        # Nothing is printed, and the start is still recorded below.
        failure, text, quoted = exc, "", ()
    if record and (text or (forgetting and session)):
        entry: dict[str, Any] = {
            "event": EVENT,
            "session": session,
            "cwd": where[: 4 * MAX_TEXT],
            "source": str(source)[:MAX_TEXT],
            "mode": mode,
            "announced": list(quoted),
        }
        if problems or failure is not None:
            reasons = [*problems, *([str(failure)] if failure is not None else [])]
            entry["error"] = "; ".join(reasons)[:500]
        audit_log(env).append(entry, moment)
    if failure is not None:
        raise failure
    return Announcement(text, quoted, left_out, mode, tuple(sayable(problems)))


def _listed(
    where_from: Any,
    facts: Facts,
    env: Mapping[str, str],
    moment: datetime,
    repo_root: RepoFinder | None,
) -> tuple[list[Rule], list[str]]:
    """The confirmed rules that can apply where the session starts.

    With them, one message per ledger that could not be loaded.  The rules
    of the ledgers that did load are listed all the same: a broken ledger
    in a repository must not take the owner's own rules out of the summary.
    """
    rules, problems = load_sources(
        where_from if isinstance(where_from, str) else "", env
    )
    failed: list[str] = []

    def lookup(directory: str) -> str | None:
        nonlocal repo_root
        if repo_root is None:
            from ember_armor.ledger.repo import finder

            repo_root = finder(facts.windows)
        try:
            return repo_root(directory)
        except Exception as exc:
            failed.append(f"repository lookup failed for {directory}: {exc}")
            raise

    listed = [
        rule
        for rule in active_rules(rules, moment.date())
        if rule.confirmed
        and rule.origin != "builtin"
        and scope_reaches(rule, facts, lookup)
    ]
    if failed:
        raise OSError("; ".join(dict.fromkeys(failed)))
    return listed, problems
