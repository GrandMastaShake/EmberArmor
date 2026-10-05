"""The summary at the start of a session: the standing rules in their own words.

A session that starts again after its context was compacted has lost what
it was told.  ``ember-gate hook --event session-start`` hands the agent the
confirmed rules of the user ledger and of the project ledger that can apply
in the directory the session starts in.  The built-in pack is not listed:
its rules speak up when they fire.

The trust rule is the one of :mod:`ember_armor.ledger.remind`: only a rule
the owner vouches for is quoted, sanitised and capped in the same way.  The
summary is printed in ``remind`` and ``enforce`` mode, for the session
sources named by ``announce_on`` in ``config.json``.  Any failure is raised
to the caller, which prints nothing.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime

from ember_armor.ledger.config import announce_on, gate_mode
from ember_armor.ledger.engine import RepoFinder, scope_reaches
from ember_armor.ledger.facts import extract
from ember_armor.ledger.gate import audit_log
from ember_armor.ledger.model import LedgerError
from ember_armor.ledger.redact import MAX_TEXT
from ember_armor.ledger.remind import compose
from ember_armor.ledger.store import active_rules, load_sources, sayable

TYPE_CHECKING = False
if TYPE_CHECKING:
    from typing import Any

EVENT = "session-start"
#: Most rules listed, and the cap on the whole text.
SUMMARY_RULES = 12
SUMMARY_CHARS = 3000
#: How the count of rules that did not fit ends, for one rule and for several.
_APPLY = ("applies here and is not listed", "apply here and are not listed")


@dataclass(frozen=True)
class Announcement:
    """What is printed when a session starts.

    ``text`` is empty when nothing is printed, ``rules`` are the ids of the
    rules listed and ``left_out`` counts the rules that apply and did not
    fit.
    """

    text: str = ""
    rules: tuple[str, ...] = ()
    left_out: int = 0
    mode: str = "observe"


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
        Append what was printed to the audit log.
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
        Whatever went wrong: unreadable configuration, a ledger that cannot
        be loaded, a repository lookup that failed, an audit log that cannot
        be written.  Nothing is printed then.
    """
    env = os.environ if env is None else env
    if not isinstance(start, Mapping):
        raise ValueError("session start input is not a JSON object")
    mode = gate_mode(env)
    source = start.get("source")
    if mode == "observe" or source not in announce_on(env):
        return Announcement(mode=mode)
    moment = (now or datetime.now()).astimezone()
    cwd = start.get("cwd")
    rules, problems = load_sources(cwd if isinstance(cwd, str) else "", env)
    if problems:
        # In the words that may be printed: the hook writes this error out.
        raise LedgerError("; ".join(sayable(problems)))
    place = {
        "tool_name": "SessionStart",
        "cwd": cwd,
        "session_id": start.get("session_id"),
    }
    facts = extract(place, windows=windows, env=env)
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
    text, quoted = compose(listed, most=SUMMARY_RULES, limit=SUMMARY_CHARS, more=_APPLY)
    if text and record:
        entry = {
            "event": EVENT,
            "session": facts.session[:MAX_TEXT],
            "cwd": facts.cwd[: 4 * MAX_TEXT],
            "source": str(source)[:MAX_TEXT],
            "mode": mode,
            "announced": list(quoted),
        }
        audit_log(env).append(entry, moment)
    return Announcement(text, quoted, len(listed) - len(quoted), mode)
