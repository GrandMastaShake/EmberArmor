"""Owner exceptions to rules: the data, apart from the rule model.

An exception is written in the owner's ``config.json`` and validated by
:func:`ember_armor.ledger.model.parse_exception`; the engine applies it (see
:func:`ember_armor.ledger.engine.evaluate`).  The two classes live in a
module of their own so that a call pays for them only when an exception is
configured: nothing here is loaded on the hook path otherwise.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

TYPE_CHECKING = False
if TYPE_CHECKING:
    from datetime import date
    from typing import Any

    from ember_armor.ledger.model import Predicate


@dataclass(frozen=True)
class RuleException:
    """An exception the owner made to rules (``exceptions`` in ``config.json``).

    ``rule`` is a rule id or a glob over ids.  The exception covers a
    command when the tool is one of ``tools`` (any tool when empty), the
    directory the command runs in is under one of ``cwd_under``, its nearest
    enclosing repository is one of ``repo_root`` and ``when`` holds for that
    command alone.  At least one of the last three is present.
    """

    rule: str
    reason: str
    cwd_under: tuple[str, ...] = ()
    repo_root: tuple[str, ...] = ()
    tools: tuple[str, ...] = ()
    when: Predicate | None = None
    expires: date | None = None
    raw: Mapping[str, Any] = field(default_factory=dict, compare=False, repr=False)


@dataclass(frozen=True)
class ExceptedRule:
    """A rule that would have fired and was dropped by an owner's exception."""

    rule: str
    reason: str
