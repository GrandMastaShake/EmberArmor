"""DissonanceGuard check endpoint for EmberArmor v2.

Wrapped by the detector circuit breaker so that cascading failures are
isolated.  Failures are classified as:

* ``CircuitBreakerOpen`` → ``503 Service Unavailable``
* Any other exception    → ``500 Internal Server Error``

All error paths emit structured log lines for SIEM ingestion.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status

from ember_armor.api.auth import get_current_auth
from ember_armor.core.circuit_breaker import CircuitBreakerOpen
from ember_armor.models.requests import DissonanceCheckRequest
from ember_armor.models.responses import DissonanceCheckResponse
from ember_armor.utils.logging import logger

router = APIRouter()


@router.post(
    "/dissonance/check",
    response_model=DissonanceCheckResponse,
    status_code=status.HTTP_200_OK,
)
async def check_dissonance(
    request: Request,
    body: DissonanceCheckRequest,
    auth: str = Depends(get_current_auth),
) -> DissonanceCheckResponse:
    """Check input text for behavioral contradictions.

    Parameters
    ----------
    request:
        The incoming ASGI request (used to reach ``app.state`` components).
    body:
        Validated dissonance-check request payload.
    auth:
        Validated API-key string (injected by ``get_current_auth``).

    Returns
    -------
    DissonanceCheckResponse
        Safety classification, contradiction score, and metadata.

    Raises
    ------
    HTTPException
        * ``503`` when the circuit breaker is OPEN.
        * ``500`` on any unexpected internal error.
    """
    detector = request.app.state.detector
    cb = request.app.state.cb_detector

    try:
        result = await cb.call(detector.check, body.input_text, body.context_id)
        return result
    except CircuitBreakerOpen:
        logger.error("dissonance.circuit_open")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Safety check service temporarily unavailable",
        )
    except HTTPException:
        # Re-raise FastAPI HTTPExceptions unchanged (e.g. validation errors).
        raise
    except Exception as exc:
        logger.error("dissonance.error", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Safety check failed",
        )
