"""Constraint-ledger endpoints for EmberArmor v2.

``POST /v1/ledger/check`` evaluates one proposed tool call,
``GET /v1/ledger/rules`` lists the rules in effect and
``POST /v1/ledger/lint`` checks the ledger itself with the solver.  All
endpoints require authentication via ``Depends(get_current_auth)``.

The server reads the ledger file named by the ``EMBER_LEDGER_PATH`` setting,
or else the user ledger.  It never looks for a project ledger: the working
directory of a call comes from the request, and no file path is taken from
a request.  A check over HTTP is a dry run: it is not written to the audit
log.  When the ledger cannot be loaded, the response says so in fixed words
and the details go to the server log.
"""

from __future__ import annotations

import os
import threading
from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from ember_armor.api.auth import get_current_auth
from ember_armor.core.config import SETTINGS
from ember_armor.ledger import LedgerError, Rule, check, load_all
from ember_armor.ledger.gate import configured_shell_tools
from ember_armor.ledger.lint import SolverUnavailableError, lint
from ember_armor.models.requests import LedgerCheckRequest
from ember_armor.utils.logging import logger

router = APIRouter()

LOAD_FAILURE = "The ledger could not be loaded. See the server log."
GATE_FAILURE = "The gate failed. See the server log."

# Z3's default context must not be used from two threads at once, and these
# handlers run in the server's thread pool.
_LINT_LOCK = threading.Lock()


def _ledger_env() -> dict[str, str]:
    """Process environment, with the configured ledger file as the override."""
    env = dict(os.environ)
    if SETTINGS.ledger_path:
        env["EMBER_LEDGER"] = SETTINGS.ledger_path
    return env


def _load() -> list[Rule]:
    """Every rule in effect on the server; an unreadable ledger is a 500."""
    try:
        return load_all("", _ledger_env(), project=False)
    except LedgerError as exc:
        logger.error("ledger.load_failed", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=LOAD_FAILURE
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
        The call in Claude Code PreToolUse shape.  Its ``cwd`` is only data
        for path resolution and ``cwd_under`` scopes.
    auth:
        Validated API-key string (injected by ``get_current_auth``).

    Returns
    -------
    dict
        ``decision`` (``none``, ``warn``, ``ask`` or ``deny``), the gate
        ``mode``, the ``rules`` that fired with their text and source, a
        fixed ``error`` message if the gate failed, and the redacted ``call``.
    """
    result = check(body.model_dump(), env=_ledger_env(), record=False, project=False)
    report = result.report()
    if result.decision.error:
        logger.error("ledger.gate_failed", error=result.decision.error)
        report["error"] = GATE_FAILURE
    return report


@router.get("/ledger/rules", status_code=status.HTTP_200_OK)
def list_rules(auth: str = Depends(get_current_auth)) -> dict[str, Any]:
    """List every rule in effect, as written, with the ledger it came from.

    Parameters
    ----------
    auth:
        Validated API-key string (injected by ``get_current_auth``).

    Returns
    -------
    dict
        ``rules``: each rule's JSON plus its ``origin``.
    """
    return {"rules": [{**rule.raw, "origin": rule.origin} for rule in _load()]}


@router.post("/ledger/lint", status_code=status.HTTP_200_OK)
def lint_ledger(auth: str = Depends(get_current_auth)) -> dict[str, Any]:
    """Check the ledger for dead, blanket, shadowed and contradictory rules.

    Parameters
    ----------
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
    rules = _load()
    try:
        with _LINT_LOCK:
            carriers = configured_shell_tools(_ledger_env())
            findings = lint(rules, shell_tools=carriers)
    except SolverUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=str(exc)
        ) from exc
    return {"rules": len(rules), "findings": [asdict(f) for f in findings]}
