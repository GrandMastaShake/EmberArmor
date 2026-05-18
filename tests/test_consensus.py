"""Comprehensive tests for the EnsembleConductor consensus system.

Tests cover weighted ensemble voting, veto thresholds, fail-closed behavior,
vote resolution logic, and agent error handling.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from ember_armor.core.consensus import (
    AgentVote,
    ConsensusDecision,
    EnsembleConductor,
)


# ---------------------------------------------------------------------------
# Agent helpers — async callables that simulate voting agents.
# ---------------------------------------------------------------------------
async def _safe_agent(_input: Any) -> dict:
    """Agent that always votes SAFE."""
    return {"decision": ConsensusDecision.SAFE, "confidence": 0.9}


async def _unsafe_agent(_input: Any) -> dict:
    """Agent that always votes UNSAFE."""
    return {"decision": ConsensusDecision.UNSAFE, "confidence": 0.9}


async def _review_agent(_input: Any) -> dict:
    """Agent that always votes REVIEW."""
    return {"decision": ConsensusDecision.REVIEW, "confidence": 0.5}


async def _failing_agent(_input: Any) -> dict:
    """Agent that always raises an exception."""
    raise RuntimeError("Simulated agent failure")


async def _zero_confidence_safe_agent(_input: Any) -> dict:
    """Agent that votes SAFE with zero confidence."""
    return {"decision": ConsensusDecision.SAFE, "confidence": 0.0}


async def _slow_safe_agent(_input: Any) -> dict:
    """Agent that votes SAFE after a short delay."""
    await asyncio.sleep(0.01)
    return {"decision": ConsensusDecision.SAFE, "confidence": 0.8}


# ---------------------------------------------------------------------------
# Test Class 1: Ensemble Voting (10 tests)
# ---------------------------------------------------------------------------
class TestEnsembleVoting:
    """Tests for EnsembleConductor voting logic and decision resolution."""

    @pytest.mark.asyncio
    async def test_unanimous_safe_returns_safe(self) -> None:
        """When all agents vote SAFE, the result must be SAFE."""
        conductor = EnsembleConductor()
        conductor.register_agent("agent_a", _safe_agent)
        conductor.register_agent("agent_b", _safe_agent)
        conductor.register_agent("agent_c", _safe_agent)

        result = await conductor.orchestrate("test input")

        assert result == ConsensusDecision.SAFE

    @pytest.mark.asyncio
    async def test_single_unsafe_with_veto_threshold(self) -> None:
        """A single UNSAFE vote (100% weight) exceeds veto_threshold=0.34 → UNSAFE."""
        conductor = EnsembleConductor(veto_threshold=0.34)
        conductor.register_agent("unsafe_only", _unsafe_agent)

        result = await conductor.orchestrate("test input")

        # 1 unsafe / 1 total = 1.0 >= 0.34 → UNSAFE
        assert result == ConsensusDecision.UNSAFE

    @pytest.mark.asyncio
    async def test_one_safe_one_unsafe_returns_review(self) -> None:
        """1 SAFE + 1 UNSAFE with 3 agents (2 SAFE, 1 UNSAFE) → REVIEW.

        veto_ratio = 1/3 ≈ 0.333 < 0.34 (threshold not met).
        Not unanimous SAFE (only 2/3) → REVIEW.
        """
        conductor = EnsembleConductor(veto_threshold=0.34)
        conductor.register_agent("safe1", _safe_agent)
        conductor.register_agent("safe2", _safe_agent)
        conductor.register_agent("unsafe1", _unsafe_agent)

        result = await conductor.orchestrate("test input")

        assert result == ConsensusDecision.REVIEW

    @pytest.mark.asyncio
    async def test_all_unsafe_returns_unsafe(self) -> None:
        """When all agents vote UNSAFE, the result must be UNSAFE."""
        conductor = EnsembleConductor()
        conductor.register_agent("unsafe_a", _unsafe_agent)
        conductor.register_agent("unsafe_b", _unsafe_agent)
        conductor.register_agent("unsafe_c", _unsafe_agent)

        result = await conductor.orchestrate("test input")

        assert result == ConsensusDecision.UNSAFE

    @pytest.mark.asyncio
    async def test_empty_votes_returns_review(self) -> None:
        """No registered agents (zero votes collected) → REVIEW (fail-closed)."""
        conductor = EnsembleConductor()

        result = await conductor.orchestrate("test input")

        assert result == ConsensusDecision.REVIEW

    @pytest.mark.asyncio
    async def test_zero_confidence_safe_votes(self) -> None:
        """Agents with confidence=0.0 but SAFE decision still yield SAFE when unanimous.

        Confidence does not affect the decision — only the vote type matters.
        """
        conductor = EnsembleConductor()
        conductor.register_agent("zc1", _zero_confidence_safe_agent)
        conductor.register_agent("zc2", _zero_confidence_safe_agent)

        result = await conductor.orchestrate("test input")

        assert result == ConsensusDecision.SAFE

    @pytest.mark.asyncio
    async def test_veto_threshold_34_percent(self) -> None:
        """Test the 34% veto threshold boundary precisely.

        * 1 UNSAFE / 3 total = 0.333… < 0.34 → does NOT veto → REVIEW.
        * 1 UNSAFE / 2 total = 0.5   >= 0.34 → vetoes    → UNSAFE.
        """
        # Case A: 3 agents, 1 UNSAFE → below threshold → REVIEW
        conductor_a = EnsembleConductor(veto_threshold=0.34)
        conductor_a.register_agent("safe1", _safe_agent)
        conductor_a.register_agent("safe2", _safe_agent)
        conductor_a.register_agent("unsafe1", _unsafe_agent)

        result_a = await conductor_a.orchestrate("test")
        assert result_a == ConsensusDecision.REVIEW

        # Case B: 2 agents, 1 UNSAFE → above threshold → UNSAFE
        conductor_b = EnsembleConductor(veto_threshold=0.34)
        conductor_b.register_agent("safe1", _safe_agent)
        conductor_b.register_agent("unsafe1", _unsafe_agent)

        result_b = await conductor_b.orchestrate("test")
        assert result_b == ConsensusDecision.UNSAFE

    @pytest.mark.asyncio
    async def test_mixed_votes_review(self) -> None:
        """A mix of SAFE and REVIEW votes (no UNSAFE) → REVIEW (not unanimous)."""
        conductor = EnsembleConductor()
        conductor.register_agent("safe", _safe_agent)
        conductor.register_agent("review", _review_agent)

        result = await conductor.orchestrate("test input")

        # 1 SAFE, 1 REVIEW → not unanimous SAFE → REVIEW
        assert result == ConsensusDecision.REVIEW

    @pytest.mark.asyncio
    async def test_agent_vote_creation(self) -> None:
        """AgentVote dataclass must be constructible with all fields."""
        vote = AgentVote(
            agent_name="test_agent",
            decision=ConsensusDecision.SAFE,
            confidence=0.75,
            reasoning="Looks fine",
        )

        assert vote.agent_name == "test_agent"
        assert vote.decision == ConsensusDecision.SAFE
        assert vote.confidence == 0.75
        assert vote.reasoning == "Looks fine"

    @pytest.mark.asyncio
    async def test_timeout_handling(self) -> None:
        """Orchestration must complete even when some agents are slow.

        asyncio.gather waits for all tasks; slow agents should not
        prevent resolution within a reasonable timeframe.
        """
        conductor = EnsembleConductor()
        conductor.register_agent("fast", _safe_agent)
        conductor.register_agent("slow", _slow_safe_agent)

        # Should complete quickly despite the slow agent (10ms delay).
        result = await conductor.orchestrate("test input")

        # Both vote SAFE → unanimous SAFE → SAFE
        assert result == ConsensusDecision.SAFE
        assert conductor._total_orchestrations == 1
