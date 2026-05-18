"""EnsembleConductor — weighted ensemble voting for safety decisions.

Replaces the complex Kuramoto phase-coherence model with a simpler,
production-practical weighted voting scheme while keeping the biological
"thalamic conductor" metaphor.

Fail-closed design
------------------
* Any agent error → ``ConsensusDecision.REVIEW`` (never SAFE).
* Zero votes collected → ``ConsensusDecision.REVIEW`` (never SAFE).
* Weighted veto: if the fraction of UNSAFE-weight exceeds
  *veto_threshold* (default 0.34) the overall decision is UNSAFE.
* Otherwise, only a unanimous SAFE returns SAFE; anything else returns REVIEW.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from ember_armor.utils.logging import logger


class ConsensusDecision(str, Enum):
    """Final safety decision produced by the ensemble."""

    SAFE = "SAFE"
    REVIEW = "REVIEW"
    UNSAFE = "UNSAFE"


@dataclass
class AgentVote:
    """A single agent's vote within the ensemble.

    Attributes
    ----------
    agent_name:
        Registered name of the voting agent.
    decision:
        The agent's individual decision.
    confidence:
        Agent confidence in [0.0, 1.0].
    reasoning:
        Optional human-readable explanation.
    """

    agent_name: str
    decision: ConsensusDecision
    confidence: float = 0.5
    reasoning: str = ""


class EnsembleConductor:
    """Weighted ensemble voting conductor.

    Parameters
    ----------
    veto_threshold:
        Fraction of total weight that must vote UNSAFE before the ensemble
        returns UNSAFE.  Default 0.34 means one strong agent out of three
        can trigger an UNSAFE decision.
    """

    def __init__(self, veto_threshold: float = 0.34) -> None:
        self.veto_threshold: float = veto_threshold
        self._agents: dict[str, Callable[..., Any]] = {}
        self._weights: dict[str, float] = {}

        # Health tracking
        self._total_orchestrations: int = 0
        self._total_violations: int = 0
        self._last_orchestration_time: float | None = None

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_agent(
        self,
        name: str,
        agent_fn: Callable[..., Any],
        weight: float = 1.0,
    ) -> None:
        """Register a safety agent.

        Parameters
        ----------
        name:
            Unique identifier for the agent.
        agent_fn:
            Callable (sync or async) that accepts *input_data* and returns a
            dict-like object with keys ``decision``, ``confidence``, and
            optionally ``reasoning``.
        weight:
            Voting weight for this agent (default 1.0).
        """
        self._agents[name] = agent_fn
        self._weights[name] = weight
        logger.info("conductor.agent_registered", agent=name, weight=weight)

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------

    async def orchestrate(self, input_data: Any) -> ConsensusDecision:
        """Run ensemble voting across all registered agents.

        1. Spawn parallel vote-collection tasks (``asyncio.gather``).
        2. Each task is fail-closed: errors produce a REVIEW vote.
        3. Resolve the collected votes with weighted veto logic.

        Returns
        -------
        ConsensusDecision
            The ensemble's collective decision.
        """
        self._total_orchestrations += 1
        self._last_orchestration_time = time.time()

        if not self._agents:
            logger.warning("conductor.no_agents", decision="REVIEW")
            return ConsensusDecision.REVIEW

        tasks: list[asyncio.Task[AgentVote]] = [
            asyncio.create_task(self._collect_vote(name, fn, input_data))
            for name, fn in self._agents.items()
        ]

        results: list[Any] = await asyncio.gather(*tasks, return_exceptions=True)

        votes: list[AgentVote] = []
        for result in results:
            if isinstance(result, Exception):
                # Log the error but continue — the individual agent already
                # failed closed (returned REVIEW), so nothing is lost.
                logger.error("conductor.agent_error", error=str(result))
                continue
            votes.append(result)

        decision = self._resolve(votes)
        if decision == ConsensusDecision.UNSAFE:
            self._total_violations += 1

        return decision

    # ------------------------------------------------------------------
    # Vote collection (private)
    # ------------------------------------------------------------------

    async def _collect_vote(
        self,
        name: str,
        fn: Callable[..., Any],
        data: Any,
    ) -> AgentVote:
        """Collect a single agent's vote.

        CRITICAL: any error → REVIEW (fail-closed, never SAFE).
        """
        try:
            result: Any = await fn(data)

            # Normalise the result whether it is a dict or an object.
            if hasattr(result, "get"):
                decision_val: str = result.get(
                    "decision", ConsensusDecision.REVIEW.value
                )
                confidence: float = float(result.get("confidence", 0.5))
                reasoning: str = result.get("reasoning", "")
            else:
                decision_val = getattr(
                    result, "decision", ConsensusDecision.REVIEW.value
                )
                confidence = float(getattr(result, "confidence", 0.5))
                reasoning = getattr(result, "reasoning", "")

            decision: ConsensusDecision = (
                ConsensusDecision(decision_val)
                if decision_val in {d.value for d in ConsensusDecision}
                else ConsensusDecision.REVIEW
            )

            return AgentVote(
                agent_name=name,
                decision=decision,
                confidence=max(0.0, min(1.0, confidence)),
                reasoning=reasoning,
            )

        except Exception as exc:
            # FAIL-CLOSED: any agent error resolves to REVIEW, never SAFE.
            logger.warning(
                "conductor.agent_failed",
                agent=name,
                error=str(exc),
            )
            return AgentVote(
                agent_name=name,
                decision=ConsensusDecision.REVIEW,
                confidence=0.0,
                reasoning=f"Agent failed: {exc}",
            )

    # ------------------------------------------------------------------
    # Resolution (private)
    # ------------------------------------------------------------------

    def _resolve(self, votes: list[AgentVote]) -> ConsensusDecision:
        """Resolve votes with weighted veto threshold.

        Logic
        -----
        1. No votes → REVIEW (fail-closed).
        2. If UNSAFE-weight / total-weight >= *veto_threshold* → UNSAFE.
        3. If **all** votes are SAFE → SAFE.
        4. Otherwise → REVIEW.
        """
        if not votes:
            logger.warning("conductor.no_votes", decision="REVIEW")
            return ConsensusDecision.REVIEW

        total_weight: float = sum(
            self._weights.get(v.agent_name, 1.0) for v in votes
        )
        unsafe_weight: float = sum(
            self._weights.get(v.agent_name, 1.0)
            for v in votes
            if v.decision == ConsensusDecision.UNSAFE
        )

        veto_ratio: float = (
            unsafe_weight / total_weight if total_weight > 0 else 0.0
        )

        logger.info(
            "conductor.resolve",
            total_votes=len(votes),
            total_weight=round(total_weight, 2),
            unsafe_weight=round(unsafe_weight, 2),
            veto_ratio=round(veto_ratio, 3),
            threshold=self.veto_threshold,
        )

        # Weighted veto check
        if veto_ratio >= self.veto_threshold:
            logger.warning(
                "conductor.veto_triggered",
                veto_ratio=round(veto_ratio, 3),
            )
            return ConsensusDecision.UNSAFE

        # Unanimous SAFE check
        safe_count: int = sum(
            1 for v in votes if v.decision == ConsensusDecision.SAFE
        )
        if safe_count == len(votes):
            return ConsensusDecision.SAFE

        # Default: anything ambiguous → REVIEW
        return ConsensusDecision.REVIEW

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    def health_check(self) -> dict[str, Any]:
        """Return health status for the consensus engine.

        Returns a dict suitable for constructing a ComponentHealth record.
        Status is "healthy" when agents are registered, "degraded" when
        no agents are registered (consensus will always return REVIEW),
        and "unhealthy" if orchestrations are failing at a high rate.
        """
        start: float = time.perf_counter()
        agent_count: int = len(self._agents)
        elapsed_ms: float = (time.perf_counter() - start) * 1000

        # Determine status
        if agent_count == 0:
            status = "degraded"
            detail = "No consensus agents registered — decisions will default to REVIEW"
        elif (
            self._total_orchestrations > 0
            and self._total_violations / self._total_orchestrations > 0.5
        ):
            status = "degraded"
            detail = (
                f"High violation rate: {self._total_violations}/"
                f"{self._total_orchestrations} orchestrations returned UNSAFE"
            )
        else:
            status = "healthy"
            detail = (
                f"Consensus engine active with {agent_count} agents; "
                f"{self._total_orchestrations} orchestrations, "
                f"{self._total_violations} violations"
            )

        return {
            "name": "consensus",
            "status": status,
            "response_time_ms": round(elapsed_ms, 2),
            "detail": detail,
            "metadata": {
                "agent_count": agent_count,
                "agents": list(self._agents.keys()),
                "veto_threshold": self.veto_threshold,
                "total_orchestrations": self._total_orchestrations,
                "total_violations": self._total_violations,
                "last_orchestration_time": self._last_orchestration_time,
            },
        }
