"""Constraint ledger: rules kept outside the model, and a gate that checks them.

The ledger stores the rules an AI agent was given as structured data.  The
gate checks every proposed tool call against that ledger before the call
runs.  See ``docs/constraint-ledger.md`` for the specification.

Everything importable from here uses only the Python standard library and
never imports the web application.
"""

from __future__ import annotations

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
