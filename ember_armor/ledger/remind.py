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

Rules are told apart by their key (:func:`ember_armor.ledger.model.rule_key`):
a project rule that uses the id of a user rule is another rule, with a
limit of its own.

The gate loads this module only when a rule fired and a reminder may be
sent, so a call no rule fires on pays nothing for it.
"""

from __future__ import annotations

import unicodedata
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
#: Session starts after which the agent no longer has what it was told
#: (``source`` of the SessionStart hook).  The limit starts again there.
FORGETTING = ("compact", "clear")
#: The ``event`` of the audit entry a session start leaves.
SESSION_START = "session-start"
#: Most combining marks kept in a row.  Writing systems stack a few on one
#: letter; a long run is a way to hide text or to smear the line.
MARKS_IN_A_ROW = 4
#: Code points that print as nothing, or as a blank that is not whitespace,
#: and that ``str.isprintable`` lets through: the combining grapheme joiner,
#: the Hangul fillers, two Khmer inherent vowels, the Mongolian and the
#: general variation selectors, and the empty Braille pattern.
INVISIBLE = frozenset(
    map(
        chr,
        (
            0x034F,
            0x115F,
            0x1160,
            0x17B4,
            0x17B5,
            0x2800,
            0x3164,
            0xFFA0,
            *range(0x180B, 0x1810),
            *range(0xFE00, 0xFE10),
            *range(0xE0100, 0xE01F0),
        ),
    )
)
_ELLIPSIS = "..."


@dataclass(frozen=True)
class Reminder:
    """What the agent is told about one call, and what only the log keeps.

    ``text`` is the reminder (empty when nothing is sent) and ``quoted`` the
    keys of the rules in it.  The other fired rules are logged only:
    ``unconfirmed`` ones because nobody vouches for their words, ``recent``
    ones because the session was reminded of them inside the interval, and
    ``left_out`` ones because the reminder was full.
    """

    text: str = ""
    quoted: tuple[str, ...] = ()
    unconfirmed: tuple[str, ...] = ()
    recent: tuple[str, ...] = ()
    left_out: tuple[str, ...] = ()


def _visible(text: str) -> Iterable[str]:
    """The characters of *text* that are kept, whitespace as blanks."""
    marks = 0
    for char in text:
        if char.isspace():
            marks = 0
            yield " "
        elif not char.isprintable() or char in INVISIBLE:
            continue
        elif char.isascii():
            marks = 0
            yield char
        elif unicodedata.category(char)[0] == "M":
            marks += 1
            if marks <= MARKS_IN_A_ROW:
                yield char
        else:
            marks = 0
            yield char


def clean(text: str, limit: int) -> str:
    """*text* on one line, visible, at most *limit* characters.

    Whitespace of any kind (a newline, a tab, a Unicode separator) becomes
    one blank.  Characters that do not show are removed: control and format
    characters, private-use and unassigned code points, lone surrogates,
    the code points of :data:`INVISIBLE`, and combining marks beyond
    :data:`MARKS_IN_A_ROW` in a row.  A double quote becomes a single one,
    so the marks around a rule's text are the only double quotes on its
    line.  Text over the limit is cut and ends in ``...``.
    """
    flat = " ".join("".join(_visible(text)).split()).replace('"', "'")
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
    """The text that quotes *rules*, and the keys of the rules it quotes.

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
        quoted.append(rule.key)
        used += len(line) + 1
    if not quoted:
        return "", ()
    if len(ordered) > len(quoted):
        lines.append(_more(len(ordered) - len(quoted), more))
    lines.append(CLOSING)
    return "\n".join(lines)[:limit], tuple(quoted)


def reminded_within(
    entries: Iterable[Mapping[str, Any]], now: float, window: float
) -> set[str]:
    """The rules a session was reminded of in the *window* seconds before *now*.

    Read from the audit entries of one session, oldest first: an entry
    names the rules its reminder quoted in ``reminded``.  An entry dated
    after *now* (a clock that was set back) holds nothing back, and neither
    does anything before the session's last start that left the agent
    without what it was told (:data:`FORGETTING`): the reminders before a
    compaction went with the context.  An entry that cannot be read as one
    is passed over.
    """
    held: set[str] = set()
    for entry in entries:
        if entry.get("event") == SESSION_START:
            if entry.get("source") in FORGETTING:
                held.clear()
            continue
        keys = entry.get("reminded")
        if not isinstance(keys, list) or not keys:
            continue
        try:
            when = datetime.fromisoformat(entry["ts"]).timestamp()
        except (KeyError, TypeError, ValueError, OSError, OverflowError):
            continue
        if 0 <= now - when < window:
            held.update(key for key in keys if isinstance(key, str))
    return held


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
    unconfirmed = tuple(rule.key for rule in fired if not rule.confirmed)
    due = vouched
    recent: list[FiredRule] = []
    window = interval() if vouched and session else 0.0
    if window > 0:
        held = reminded_within(entries(), now, window)
        recent = [rule for rule in vouched if rule.key in held]
        due = [rule for rule in vouched if rule.key not in held]
    text, quoted = compose(due)
    return Reminder(
        text=text,
        quoted=quoted,
        unconfirmed=unconfirmed,
        recent=tuple(rule.key for rule in recent),
        left_out=tuple(rule.key for rule in due if rule.key not in quoted),
    )


def limited(
    fired: Sequence[FiredRule], sent: dict[str, list[float]], now: float, window: float
) -> tuple[str, ...]:
    """The rules a replay counts as reminded for one call, by key.

    *sent* holds when each rule of the session was quoted and is brought
    up to date.  The same choice as :func:`remind`, with the session's
    history kept in memory.
    """
    vouched = [rule for rule in fired if rule.confirmed]
    due = [
        rule
        for rule in vouched
        if not any(0 <= now - when < window for when in sent.get(rule.key, ()))
    ]
    _, quoted = compose(due)
    for key in quoted:
        sent.setdefault(key, []).append(now)
    return quoted
