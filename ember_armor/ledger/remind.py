"""Reminders: a rule in its own words, told to the agent when the rule fires.

The gate exists for agents that drift from an instruction they were given.
A reminder repeats the instruction at the moment a call is about to break
it, without blocking the call and without asking anybody.

Only rules the owner vouches for are quoted (``confirmed`` on a fired rule:
the built-in pack, confirmed rules of the user ledger, project rules
confirmed on this machine).  An unconfirmed rule never adds a character to
what is printed, not even to a count.  What is quoted is put on one line,
without control characters, and capped; nothing of the call itself (no
command, no path, no argument) goes in.

The gate loads this module only when a rule fired and a reminder may be
sent, so a call no rule fires on pays nothing for it.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime

from ember_armor.ledger.model import SEVERITY, FiredRule, Rule

TYPE_CHECKING = False
if TYPE_CHECKING:
    from typing import Any

#: Most rules quoted in the reminder for one call.
MAX_RULES = 3
ID_CHARS = 80
TEXT_CHARS = 400
SOURCE_CHARS = 120
REMINDER_CHARS = 1500
#: The fixed last line of everything this module writes.
CLOSING = (
    "No tool call was blocked: this is a reminder of standing instructions, "
    "not a new request."
)
_ELLIPSIS = "..."
_NEVER = float("-inf")


@dataclass(frozen=True)
class Reminder:
    """What the agent is told about one call, and what only the log keeps.

    ``text`` is the reminder (empty when nothing is sent) and ``quoted`` the
    ids of the rules in it.  The other fired rules are logged only:
    ``unconfirmed`` ones because nobody vouches for their words, ``recent``
    ones because the session was reminded of them inside the interval, and
    ``left_out`` ones because the reminder was full.
    """

    text: str = ""
    quoted: tuple[str, ...] = ()
    unconfirmed: tuple[str, ...] = ()
    recent: tuple[str, ...] = ()
    left_out: tuple[str, ...] = ()


def clean(text: str, limit: int) -> str:
    """*text* on one line, printable, at most *limit* characters.

    Whitespace of any kind (a newline, a tab, a Unicode separator) becomes
    one blank.  Characters that do not print are removed: control and
    format characters, private-use and unassigned code points, lone
    surrogates.  A double quote becomes a single one, so the marks around a
    rule's text are the only double quotes on its line.  Text over the
    limit is cut and ends in ``...``.
    """
    kept = "".join(
        char if char.isprintable() else " " if char.isspace() else "" for char in text
    )
    flat = " ".join(kept.split()).replace('"', "'")
    if len(flat) <= limit:
        return flat
    return flat[: limit - len(_ELLIPSIS)].rstrip() + _ELLIPSIS


def quote(rule: FiredRule | Rule) -> str:
    """One rule as a line of a reminder: its id, its text and its source."""
    return (
        f"EmberArmor reminder, rule {clean(rule.id, ID_CHARS)}: "
        f'"{clean(rule.text, TEXT_CHARS)}" '
        f"(source: {clean(rule.source, SOURCE_CHARS)})."
    )


#: How the count of rules that did not fit ends, for one rule and for several.
_FIRED = (
    "fired on this call and is not quoted",
    "fired on this call and are not quoted",
)


def _more(count: int, what: tuple[str, str]) -> str:
    if count == 1:
        return f"1 more confirmed rule {what[0]}."
    return f"{count} more confirmed rules {what[1]}."


def compose(
    rules: Sequence[FiredRule | Rule],
    *,
    most: int = MAX_RULES,
    limit: int = REMINDER_CHARS,
    more: tuple[str, str] = _FIRED,
) -> tuple[str, tuple[str, ...]]:
    """The text that quotes *rules*, and the ids of the rules it quotes.

    The most restrictive effect comes first.  Whole rules are taken while
    they fit: at most *most* of them, and at most *limit* characters with
    the closing sentence.  The rules that did not fit are counted in one
    line.  A rule nobody confirmed is neither quoted nor counted, whatever
    the caller passes.

    Returns
    -------
    tuple[str, tuple[str, ...]]
        ``("", ())`` when there is nothing to quote.
    """
    vouched = [rule for rule in rules if rule.confirmed]
    ordered = sorted(vouched, key=lambda rule: -SEVERITY[rule.effect])
    lines: list[str] = []
    quoted: list[str] = []
    # Room is kept for the closing sentence and for the longest count line.
    used = len(CLOSING) + len(_more(max(2, len(ordered)), more)) + 1
    for rule in ordered:
        if len(quoted) == most:
            break
        line = quote(rule)
        if used + len(line) + 1 > limit:
            continue
        lines.append(line)
        quoted.append(rule.id)
        used += len(line) + 1
    if not quoted:
        return "", ()
    if len(ordered) > len(quoted):
        lines.append(_more(len(ordered) - len(quoted), more))
    lines.append(CLOSING)
    return "\n".join(lines)[:limit], tuple(quoted)


def last_reminded(entries: Iterable[Mapping[str, Any]]) -> dict[str, float]:
    """When each rule was last quoted in a reminder (epoch seconds).

    Read from the audit entries of one session: an entry names the rules
    its reminder quoted in ``reminded``.
    """
    last: dict[str, float] = {}
    for entry in entries:
        ids = entry.get("reminded")
        if not isinstance(ids, list) or not ids:
            continue
        try:
            when = datetime.fromisoformat(entry["ts"]).timestamp()
        except (KeyError, TypeError, ValueError):
            continue
        for rule_id in ids:
            if isinstance(rule_id, str) and when > last.get(rule_id, _NEVER):
                last[rule_id] = when
    return last


def remind(
    fired: Sequence[FiredRule],
    *,
    session: str,
    now: float,
    interval: Callable[[], float],
    entries: Callable[[], Iterable[Mapping[str, Any]]],
) -> Reminder:
    """Decide what the agent is reminded of for one call.

    Parameters
    ----------
    fired:
        The rules that fired.
    session:
        The session of the call.  A call without one is always reminded.
    now:
        Time of the call in epoch seconds.
    interval:
        Gives the seconds before the same rule is reminded again in one
        session (zero: every time).  Asked only when a confirmed rule fired
        in a session.
    entries:
        Gives the audit entries of the session.  Asked at most once, and
        only when a confirmed rule fired in a session and the interval is
        not zero.

    Returns
    -------
    Reminder
        With an empty ``text`` when no confirmed rule is due.
    """
    vouched = [rule for rule in fired if rule.confirmed]
    unconfirmed = tuple(rule.id for rule in fired if not rule.confirmed)
    due = vouched
    recent: list[FiredRule] = []
    window = interval() if vouched and session else 0.0
    if window > 0:
        last = last_reminded(entries())
        # An entry dated after this call (a clock set back) holds nothing back.
        recent = [r for r in vouched if 0 <= now - last.get(r.id, _NEVER) < window]
        due = [rule for rule in vouched if rule not in recent]
    text, quoted = compose(due)
    return Reminder(
        text=text,
        quoted=quoted,
        unconfirmed=unconfirmed,
        recent=tuple(rule.id for rule in recent),
        left_out=tuple(rule.id for rule in due if rule.id not in quoted),
    )


def limited(
    fired: Sequence[FiredRule], last: dict[str, float], now: float, window: float
) -> tuple[str, ...]:
    """The rules a replay counts as reminded for one call.

    *last* holds when each rule of the session was last quoted and is
    brought up to date.  The same choice as :func:`remind`, with the
    session's history kept in memory.
    """
    vouched = [rule for rule in fired if rule.confirmed]
    due = [r for r in vouched if not 0 <= now - last.get(r.id, _NEVER) < window]
    _, quoted = compose(due)
    last.update(dict.fromkeys(quoted, now))
    return quoted
