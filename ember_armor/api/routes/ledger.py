"""Constraint-ledger endpoints for EmberArmor v2.

``POST /v1/ledger/check`` evaluates one proposed tool call,
``GET /v1/ledger/rules`` lists the rules in effect and
``POST /v1/ledger/lint`` checks the ledger itself with the solver.  All
endpoints require authentication via ``Depends(get_current_auth)``.

The server reads the ledger file named by the ``EMBER_LEDGER_PATH`` setting.
Without it, the user ledger and the project ledger of the given working
directory are used, as on the command line.  A check over HTTP is a dry run:
it is not written to the audit log.
"""

from __future__ import annotations

import os
import threading
from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from ember_armor.api.auth import get_current_auth
from ember_armor.core.config import SETTINGS
from ember_armor.ledger import LedgerError, Rule, check, load_all
from ember_armor.ledger.lint import SolverUnavailableError, lint
from ember_armor.models.requests import LedgerCheckRequest

router = APIRouter()

# Z3's default context must not be used from two threads at once, and these
# handlers run in the server's thread pool.
_LINT_LOCK = threading.Lock()


def _ledger_env() -> dict[str, str]:
    """Process environment, with the configured ledger file as the override."""
    env = dict(os.environ)
    if SETTINGS.ledger_path:
        env["EMBER_LEDGER"] = SETTINGS.ledger_path
    return env


def _load(cwd: str) -> list[Rule]:
    """Every rule that applies in *cwd*; an unreadable ledger is a 500."""
    try:
        return load_all(cwd, _ledger_env())
    except LedgerError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        ) from exc


@router.post("/ledger/check", status_code=status.HTTP_200_OK)
def check_call(
    body: LedgerCheckRequest,
    auth: str = Depends(get_current_auth),
) -> dict[str, Any]:
    """Evaluate one proposed tool call against the ledger (dry run).

    Parameters
    ----------
    body:
        The call in Claude Code PreToolUse shape.
    auth:
        Validated API-key string (injected by ``get_current_auth``).

    Returns
    -------
    dict
        ``decision`` (``none``, ``warn``, ``ask`` or ``deny``), the gate
        ``mode``, the ``rules`` that fired with their text and source, the
        gate ``error`` if it failed, and the redacted ``call``.
    """
    return check(body.model_dump(), env=_ledger_env(), record=False).report()


@router.get("/ledger/rules", status_code=status.HTTP_200_OK)
def list_rules(
    cwd: str = Query(default="", max_length=4096),
    auth: str = Depends(get_current_auth),
) -> dict[str, Any]:
    """List every rule in effect, as written, with the ledger it came from.

    Parameters
    ----------
    cwd:
        Directory whose project ledger to include (ignored when the server
        has ``EMBER_LEDGER_PATH`` set).
    auth:
        Validated API-key string (injected by ``get_current_auth``).

    Returns
    -------
    dict
        ``rules``: each rule's JSON plus its ``origin``.
    """
    return {"rules": [{**rule.raw, "origin": rule.origin} for rule in _load(cwd)]}


@router.post("/ledger/lint", status_code=status.HTTP_200_OK)
def lint_ledger(
    cwd: str = Query(default="", max_length=4096),
    auth: str = Depends(get_current_auth),
) -> dict[str, Any]:
    """Check the ledger for dead, blanket, shadowed and contradictory rules.

    Parameters
    ----------
    cwd:
        Directory whose project ledger to include (ignored when the server
        has ``EMBER_LEDGER_PATH`` set).
    auth:
        Validated API-key string (injected by ``get_current_auth``).

    Returns
    -------
    dict
        ``rules`` (how many were checked) and ``findings``.

    Raises
    ------
    HTTPException
        ``501 Not Implemented`` when the Z3 solver is not installed, so a
        missing solver is never mistaken for a clean ledger.
    """
    rules = _load(cwd)
    try:
        with _LINT_LOCK:
            findings = lint(rules)
    except SolverUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=str(exc)
        ) from exc
    return {"rules": len(rules), "findings": [asdict(f) for f in findings]}
