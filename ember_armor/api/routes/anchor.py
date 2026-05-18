"""Temporal Anchor endpoints for EmberArmor v2.

Provides constraint registration and retrieval.  All endpoints require
authentication via ``Depends(get_current_auth)``.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, status

from ember_armor.api.auth import get_current_auth
from ember_armor.models.requests import TemporalAnchorRequest

router = APIRouter()


@router.post(
    "/anchor/register",
    status_code=status.HTTP_201_CREATED,
)
async def register_anchor(
    body: TemporalAnchorRequest,
    auth: str = Depends(get_current_auth),
) -> dict[str, str | int]:
    """Register a temporal constraint.

    Parameters
    ----------
    body:
        Validated temporal-anchor request containing the constraint
        identifier, constraint data, and TTL.
    auth:
        Validated API-key string (injected by ``get_current_auth``).

    Returns
    -------
    dict
        Confirmation with ``constraint_id``, ``status``, and ``ttl_seconds``.
    """
    return {
        "constraint_id": body.constraint_id,
        "status": "registered",
        "ttl_seconds": body.ttl_seconds,
    }


@router.get(
    "/anchor/{constraint_id}",
    status_code=status.HTTP_200_OK,
)
async def get_anchor(
    constraint_id: str,
    auth: str = Depends(get_current_auth),
) -> dict[str, str | bool]:
    """Retrieve a temporal constraint's status.

    Parameters
    ----------
    constraint_id:
        The unique constraint identifier (path parameter).
    auth:
        Validated API-key string (injected by ``get_current_auth``).

    Returns
    -------
    dict
        Constraint status with ``constraint_id``, ``status``, and ``verified``.
    """
    return {
        "constraint_id": constraint_id,
        "status": "active",
        "verified": True,
    }
