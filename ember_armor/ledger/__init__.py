"""Constraint ledger: rules kept outside the model, and a gate that checks them.

The ledger stores the rules an AI agent was given as structured data.  The
gate checks every proposed tool call against that ledger before the call
runs.  See ``docs/constraint-ledger.md`` for the specification.

Everything importable from here uses only the Python standard library and
never imports the web application.  The names are loaded on first use, so
that the hook imports only what the call in hand needs.
"""

from __future__ import annotations

import importlib

TYPE_CHECKING = False
if TYPE_CHECKING:
    from ember_armor.ledger.engine import History, MemoryHistory, PastCall, evaluate
    from ember_armor.ledger.facts import Facts, extract
    from ember_armor.ledger.gate import GateResult, check
    from ember_armor.ledger.model import (
        Decision,
        FiredRule,
        LedgerError,
        Rule,
        parse_ledger,
        parse_rule,
    )
    from ember_armor.ledger.store import load_all, load_rules

__all__ = [
    "Decision",
    "Facts",
    "FiredRule",
    "GateResult",
    "History",
    "LedgerError",
    "MemoryHistory",
    "PastCall",
    "Rule",
    "check",
    "evaluate",
    "extract",
    "load_all",
    "load_rules",
    "parse_ledger",
    "parse_rule",
]

_HOMES = {
    "engine": ("History", "MemoryHistory", "PastCall", "evaluate"),
    "facts": ("Facts", "extract"),
    "gate": ("GateResult", "check"),
    "model": (
        "Decision",
        "FiredRule",
        "LedgerError",
        "Rule",
        "parse_ledger",
        "parse_rule",
    ),
    "store": ("load_all", "load_rules"),
}
_MODULE_OF = {name: module for module, names in _HOMES.items() for name in names}


def __getattr__(name: str) -> object:
    """Import the module that defines *name* on first use."""
    module = _MODULE_OF.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(importlib.import_module(f"{__name__}.{module}"), name)
    globals()[name] = value
    return value
