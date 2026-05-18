"""SonarConsensusAgent — Live-web threat intelligence vote for the EnsembleConductor.

This module is a **load-bearing** integration with the Perplexity Sonar API.
It registers as a named voting agent inside EmberArmor's EnsembleConductor
and provides a live-world signal that the local detection layers (NLI,
regex, circuit breaker) cannot produce on their own.

Why Sonar is load-bearing here
-------------------------------
EmberArmor's EnsembleConductor aggregates votes from multiple agents using
weighted consensus. The local detection layers know what *looks like* an
attack based on patterns and NLI contradiction scores. What they cannot know:

  * Is this attack pattern currently being used in real campaigns?
  * Has this specific technique been weaponized against this domain recently?
  * Are there open CVEs that make this pattern more dangerous right now?

Sonar provides that live-world signal. Its vote is weighted at 0.4 in the
ensemble (same as the primary NLI detector). When Sonar is unavailable, the
conductor logs SONAR_UNAVAILABLE and falls back to local-only consensus —
it never silently degrades or promotes a REVIEW to SAFE without Sonar's vote.

Audit trail
-----------
Every Sonar vote is written to the structured audit log with its citations,
confidence, and reasoning. This provides:

  1. Explainability — why did the system block this request?
  2. Forensics — what was the live threat landscape at decision time?
  3. Compliance evidence — grounded, citable web sources for every block.
"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from ember_armor.utils.logging import logger

# ---------------------------------------------------------------------------
# Sonar API configuration
# ---------------------------------------------------------------------------

SONAR_BASE_URL: str = "https://api.perplexity.ai"
SONAR_ENDPOINT: str = "/v1/sonar"
SONAR_MODEL: str = "sonar-pro"
SONAR_TIMEOUT_SECONDS: float = 12.0    # Must be fast enough for real-time enforcement
MAX_RETRIES: int = 1                   # Single retry — latency budget is tight

# Agent weight in EnsembleConductor (must be set when registering)
SONAR_AGENT_WEIGHT: float = 0.40


# ---------------------------------------------------------------------------
# Domain context map (aligns with EmberBench test domains)
# ---------------------------------------------------------------------------

_DOMAIN_CONTEXT: dict[str, str] = {
    "legal": "targeting law firms, legal databases, court systems, or legal AI assistants",
    "financial": "targeting financial institutions, trading systems, portfolio management AI, or fintech",
    "medical": "targeting healthcare providers, medical AI, patient record systems, or diagnostic tools",
    "general": "targeting enterprise AI deployments or general-purpose AI assistants",
}


# ---------------------------------------------------------------------------
# Vote result
# ---------------------------------------------------------------------------

@dataclass
class SonarVoteResult:
    """Structured result of a Sonar consensus vote.

    This is what the EnsembleConductor receives. The ``decision`` field maps
    directly to ``ConsensusDecision`` values: SAFE, REVIEW, or UNSAFE.
    """
    decision: str                           # "SAFE" | "REVIEW" | "UNSAFE"
    confidence: float                       # 0.0–1.0
    reasoning: str                          # First 500 chars of Sonar's response
    citations: list[str] = field(default_factory=list)
    sonar_status: str = "SUCCESS"           # SonarStatus enum value
    latency_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Return a dict compatible with EnsembleConductor's AgentVote parsing."""
        return {
            "decision": self.decision,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "citations": self.citations,
            "sonar_status": self.sonar_status,
            "latency_ms": round(self.latency_ms, 2),
        }


# ---------------------------------------------------------------------------
# Sonar consensus agent
# ---------------------------------------------------------------------------

class SonarConsensusAgent:
    """Perplexity Sonar-backed voting agent for the EnsembleConductor.

    Usage
    -----
    Register once at app startup::

        from ember_armor.core.sonar_agent import SonarConsensusAgent, SONAR_AGENT_WEIGHT

        agent = SonarConsensusAgent()
        conductor.register_agent("sonar_live_intel", agent.vote, weight=SONAR_AGENT_WEIGHT)

    The conductor will then call ``agent.vote(input_data)`` as part of every
    ensemble orchestration.

    Parameters
    ----------
    api_key:
        Perplexity API key. Falls back to ``PERPLEXITY_API_KEY`` env var.
    model:
        Sonar model to use. Default: ``sonar-pro``.
    timeout:
        HTTP timeout per request (seconds). Keep tight — this is on the
        hot path of every enforcement decision.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str = SONAR_MODEL,
        timeout: float = SONAR_TIMEOUT_SECONDS,
    ) -> None:
        self._api_key: str = api_key or os.environ.get("PERPLEXITY_API_KEY", "")
        self._model: str = model
        self._timeout: float = timeout

        if not self._api_key:
            logger.warning(
                "sonar_agent.no_api_key",
                detail=(
                    "PERPLEXITY_API_KEY not configured. Sonar consensus agent will "
                    "vote REVIEW on every call (fail-closed). Set the env var to "
                    "enable live web intelligence."
                ),
            )

        self._http: httpx.AsyncClient = httpx.AsyncClient(
            base_url=SONAR_BASE_URL,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            timeout=self._timeout,
        )

        # Telemetry
        self._votes_cast: int = 0
        self._votes_unsafe: int = 0
        self._votes_review: int = 0
        self._votes_safe: int = 0
        self._sonar_errors: int = 0

    async def close(self) -> None:
        """Close the HTTP client. Call at app shutdown."""
        await self._http.aclose()

    # ------------------------------------------------------------------
    # Core vote method (called by EnsembleConductor)
    # ------------------------------------------------------------------

    async def vote(self, input_data: Any) -> dict[str, Any]:
        """Cast a Sonar-backed consensus vote on the provided input.

        This is the method registered with ``EnsembleConductor.register_agent()``.
        It is called with whatever ``input_data`` was passed to
        ``conductor.orchestrate()``. Expected structure::

            {
                "input_text": str,          # The text being evaluated
                "domain": str,              # "legal" | "financial" | "medical" | "general"
                "attack_context": str,      # Optional: what the local detectors flagged
                "session_id": str | None,   # Optional correlation ID
            }

        Returns
        -------
        dict
            Keys: ``decision``, ``confidence``, ``reasoning``, ``citations``,
            ``sonar_status``, ``latency_ms``.
        """
        start = time.perf_counter()
        self._votes_cast += 1

        # Normalize input
        if isinstance(input_data, dict):
            text: str = input_data.get("input_text", str(input_data))
            domain: str = input_data.get("domain", "general")
            attack_context: str = input_data.get("attack_context", "")
            session_id: str | None = input_data.get("session_id")
        else:
            text = str(input_data)
            domain = "general"
            attack_context = ""
            session_id = None

        result = await self._query_sonar(text, domain, attack_context)
        result.latency_ms = (time.perf_counter() - start) * 1000

        # Update telemetry
        if result.decision == "UNSAFE":
            self._votes_unsafe += 1
        elif result.decision == "REVIEW":
            self._votes_review += 1
        else:
            self._votes_safe += 1

        logger.info(
            "sonar_agent.voted",
            decision=result.decision,
            confidence=round(result.confidence, 3),
            sonar_status=result.sonar_status,
            citations=len(result.citations),
            latency_ms=round(result.latency_ms, 2),
            session_id=session_id,
        )

        return result.to_dict()

    # ------------------------------------------------------------------
    # Internal Sonar query
    # ------------------------------------------------------------------

    async def _query_sonar(
        self,
        text: str,
        domain: str,
        attack_context: str,
    ) -> SonarVoteResult:
        """Query Sonar and return a structured vote result."""
        if not self._api_key:
            return SonarVoteResult(
                decision="REVIEW",
                confidence=0.0,
                reasoning="Sonar unavailable — no API key. Defaulting to REVIEW (fail-closed).",
                sonar_status="SONAR_UNAVAILABLE",
            )

        prompt = self._build_vote_prompt(text, domain, attack_context)

        try:
            response = await self._call_sonar(prompt)
            return self._parse_vote_response(response)

        except httpx.TimeoutException:
            self._sonar_errors += 1
            logger.warning("sonar_agent.timeout", domain=domain)
            return SonarVoteResult(
                decision="REVIEW",
                confidence=0.0,
                reasoning="Sonar timed out. Defaulting to REVIEW (fail-closed).",
                sonar_status="SONAR_TIMEOUT",
            )
        except _AuthError:
            self._sonar_errors += 1
            logger.error("sonar_agent.auth_error")
            return SonarVoteResult(
                decision="REVIEW",
                confidence=0.0,
                reasoning="Sonar auth error. Check PERPLEXITY_API_KEY. Defaulting to REVIEW.",
                sonar_status="SONAR_INVALID_KEY",
            )
        except _RateLimitError:
            self._sonar_errors += 1
            logger.warning("sonar_agent.rate_limited")
            return SonarVoteResult(
                decision="REVIEW",
                confidence=0.0,
                reasoning="Sonar rate limited. Defaulting to REVIEW (fail-closed).",
                sonar_status="SONAR_RATE_LIMITED",
            )
        except Exception as exc:
            self._sonar_errors += 1
            logger.error("sonar_agent.error", error=str(exc))
            return SonarVoteResult(
                decision="REVIEW",
                confidence=0.0,
                reasoning=f"Sonar error: {exc}. Defaulting to REVIEW.",
                sonar_status="SONAR_ERROR",
            )

    async def _call_sonar(self, prompt: str) -> dict[str, Any]:
        """Single Sonar API call with one retry on transient failure."""
        for attempt in range(MAX_RETRIES + 1):
            if attempt > 0:
                await asyncio.sleep(1.0)

            resp = await self._http.post(
                SONAR_ENDPOINT,
                json={
                    "model": self._model,
                    "messages": [
                        {
                            "role": "system",
                            "content": (
                                "You are a real-time AI security analyst. Your job is to "
                                "determine whether a flagged AI system interaction matches "
                                "known attack patterns currently observed in the wild. "
                                "Be concise, accurate, and always cite your sources."
                            ),
                        },
                        {"role": "user", "content": prompt},
                    ],
                    "search_recency_filter": "month",
                    "temperature": 0.1,
                    "max_tokens": 512,
                },
            )

            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 429:
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(2.0)
                    continue
                raise _RateLimitError(resp.text)
            elif resp.status_code in (401, 403):
                raise _AuthError(f"HTTP {resp.status_code}")
            else:
                if attempt < MAX_RETRIES:
                    continue
                raise Exception(f"Sonar returned HTTP {resp.status_code}: {resp.text[:200]}")

        raise Exception("All retry attempts exhausted")

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    def _build_vote_prompt(
        self,
        text: str,
        domain: str,
        attack_context: str,
    ) -> str:
        domain_desc = _DOMAIN_CONTEXT.get(domain, _DOMAIN_CONTEXT["general"])
        ctx_block = (
            f"\n\nLocal detector context (what our static analysis flagged):\n{attack_context}"
            if attack_context
            else ""
        )
        # Truncate text to avoid runaway prompts
        safe_text = text[:800] if len(text) > 800 else text

        return (
            f"An AI safety system has flagged the following text for potential adversarial "
            f"manipulation in an AI deployment {domain_desc}:\n\n"
            f"---\n{safe_text}\n---\n"
            f"{ctx_block}\n\n"
            f"Search the web for recent (last 30 days) reports of similar AI system attacks, "
            f"jailbreaks, prompt injection patterns, or adversarial manipulation targeting "
            f"this domain. Then answer:\n\n"
            f"1. Does this pattern match any known, recently-reported attack technique? "
            f"(yes/no/unclear)\n"
            f"2. What is your verdict? Respond with exactly one of: UNSAFE / REVIEW / SAFE\n"
            f"3. Confidence level (0.0–1.0)\n"
            f"4. Brief reasoning (2-3 sentences)\n\n"
            f"Format your response as:\n"
            f"VERDICT: [UNSAFE|REVIEW|SAFE]\n"
            f"CONFIDENCE: [0.0-1.0]\n"
            f"REASONING: [your reasoning]\n\n"
            f"Cite your sources."
        )

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_vote_response(self, raw: dict[str, Any]) -> SonarVoteResult:
        """Parse Sonar API response into a SonarVoteResult."""
        try:
            content: str = (
                raw.get("choices", [{}])[0]
                .get("message", {})
                .get("content", "")
            )
            citations: list[str] = raw.get("citations", [])

            # Extract structured fields if present
            verdict = self._extract_field(content, "VERDICT")
            confidence_str = self._extract_field(content, "CONFIDENCE")
            reasoning = self._extract_field(content, "REASONING")

            # Normalize decision
            decision = "REVIEW"
            if verdict:
                v_upper = verdict.upper().strip()
                if "UNSAFE" in v_upper:
                    decision = "UNSAFE"
                elif "SAFE" in v_upper and "UNSAFE" not in v_upper:
                    decision = "SAFE"
                else:
                    decision = "REVIEW"
            else:
                # Fallback: scan full content
                content_upper = content.upper()
                if "UNSAFE" in content_upper:
                    decision = "UNSAFE"
                elif "SAFE" in content_upper:
                    decision = "SAFE"

            # Parse confidence
            confidence = 0.5
            if confidence_str:
                try:
                    confidence = float(confidence_str.strip())
                    confidence = max(0.0, min(1.0, confidence))
                except ValueError:
                    pass

            # Boost confidence when Sonar finds recent real-world examples
            if any(
                phrase in content.lower()
                for phrase in [
                    "recently observed", "active campaign", "last month",
                    "this week", "currently exploited", "in the wild",
                    "ongoing", "actively used",
                ]
            ):
                confidence = min(0.95, confidence + 0.12)

            return SonarVoteResult(
                decision=decision,
                confidence=confidence,
                reasoning=(reasoning or content)[:500],
                citations=citations,
                sonar_status="SUCCESS",
            )

        except Exception as exc:
            logger.error("sonar_agent.parse_failed", error=str(exc))
            return SonarVoteResult(
                decision="REVIEW",
                confidence=0.0,
                reasoning=f"Parse failed: {exc}",
                sonar_status="SONAR_ERROR",
            )

    @staticmethod
    def _extract_field(content: str, field_name: str) -> str | None:
        """Extract a structured field from a formatted Sonar response."""
        import re
        pattern = rf"{field_name}:\s*(.+?)(?:\n|$)"
        match = re.search(pattern, content, re.IGNORECASE)
        return match.group(1).strip() if match else None

    # ------------------------------------------------------------------
    # Health / telemetry
    # ------------------------------------------------------------------

    @property
    def stats(self) -> dict[str, Any]:
        """Return vote statistics for monitoring."""
        total = max(1, self._votes_cast)
        return {
            "votes_cast": self._votes_cast,
            "votes_unsafe": self._votes_unsafe,
            "votes_review": self._votes_review,
            "votes_safe": self._votes_safe,
            "sonar_errors": self._sonar_errors,
            "unsafe_rate": round(self._votes_unsafe / total, 4),
            "error_rate": round(self._sonar_errors / total, 4),
            "model": self._model,
            "api_key_configured": bool(self._api_key),
            "agent_weight": SONAR_AGENT_WEIGHT,
        }

    def health_check(self) -> dict[str, Any]:
        """Return health status compatible with EmberArmor's health endpoint."""
        stats = self.stats

        if not self._api_key:
            status = "degraded"
            detail = "PERPLEXITY_API_KEY not set — Sonar agent voting REVIEW on all calls"
        elif stats["error_rate"] > 0.5 and self._votes_cast > 5:
            status = "degraded"
            detail = f"High Sonar error rate: {stats['error_rate']:.1%} ({self._sonar_errors}/{self._votes_cast} calls)"
        else:
            status = "healthy"
            detail = (
                f"Sonar agent active — {self._votes_cast} votes cast, "
                f"{stats['unsafe_rate']:.1%} UNSAFE rate, "
                f"{stats['error_rate']:.1%} error rate"
            )

        return {
            "name": "sonar_consensus_agent",
            "status": status,
            "detail": detail,
            "metadata": stats,
        }


# ---------------------------------------------------------------------------
# Private exceptions
# ---------------------------------------------------------------------------

class _AuthError(Exception):
    """Raised on 401/403 from Sonar."""


class _RateLimitError(Exception):
    """Raised on 429 from Sonar."""
