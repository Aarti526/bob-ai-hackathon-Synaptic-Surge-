"""LLM provider abstraction (Section 39-41). The rest of the app only ever calls
generate_structured() - it never knows or cares whether Anthropic or the mock
fallback answered. This is what lets the dashboard keep working with no API key."""
from __future__ import annotations

import json
import logging
import re
from abc import ABC, abstractmethod

from config.settings import ANTHROPIC_API_KEY, ANTHROPIC_MODEL, LLM_TEMPERATURE, LLM_TIMEOUT_SECONDS

logger = logging.getLogger("threatlens.ai")


class LLMProvider(ABC):
    @abstractmethod
    def generate(self, system: str, prompt: str) -> str:
        ...

    def generate_structured(self, system: str, prompt: str, required_keys: list[str]) -> dict | None:
        """Calls generate(), parses JSON, retries once on malformed output, then gives
        up (never raises) - the caller must have a deterministic fallback ready."""
        for attempt in range(2):
            try:
                raw = self.generate(system, prompt if attempt == 0 else prompt + "\n\nReturn ONLY valid JSON, no prose, no markdown fences.")
                data = _extract_json(raw)
                if data and all(k in data for k in required_keys):
                    return data
                logger.warning("LLM structured output missing required keys on attempt %d", attempt + 1)
            except Exception as exc:
                logger.error("LLM call failed on attempt %d: %s", attempt + 1, exc)
        return None


def _extract_json(text: str) -> dict | None:
    text = text.strip()
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return None


class AnthropicProvider(LLMProvider):
    def __init__(self):
        import anthropic
        self._client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY, timeout=LLM_TIMEOUT_SECONDS)

    def generate(self, system: str, prompt: str) -> str:
        response = self._client.messages.create(
            model=ANTHROPIC_MODEL,
            max_tokens=1500,
            temperature=LLM_TEMPERATURE,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(block.text for block in response.content if block.type == "text")


class MockLLMProvider(LLMProvider):
    """Deterministic, template-based fallback. Used automatically when no API key is
    configured, or if the real provider fails - the demo never goes blank."""

    def generate(self, system: str, prompt: str) -> str:
        return json.dumps(_mock_response_from_prompt(prompt))


def _mock_response_from_prompt(prompt: str) -> dict:
    has_chain = "attack progression" in prompt.lower() or "multi-stage" in prompt.lower()
    has_ti = "threat intelligence match" in prompt.lower() and "no threat intelligence" not in prompt.lower()
    has_mitre = "mitre technique" in prompt.lower() and "no supported mitre" not in prompt.lower()

    if has_chain and (has_ti or has_mitre):
        assessment = "The correlated events show a multi-stage progression consistent with credential compromise followed by hands-on-keyboard activity."
    elif has_chain:
        assessment = "Multiple correlated events form a plausible attack progression, though supporting threat intelligence is limited."
    else:
        assessment = "A single or loosely-related set of events was observed. There is insufficient corroborating evidence to confirm malicious intent."

    return {
        "assessment": assessment,
        "key_findings": [
            "Deterministic correlation grouped these events based on shared identity, timing, and behavioral progression.",
            "Risk and confidence levels were computed from transparent, weighted factors (see Risk Contributors).",
        ],
        "attack_progression_narrative": "Events are ordered chronologically in the Timeline panel; see correlation reasons for why each step was linked to the next.",
        "threat_intelligence_summary": "See the Threat Intelligence panel for retrieved supporting documents." if has_ti else "No sufficiently relevant threat intelligence was found for this incident.",
        "uncertainties": [
            "AI synthesis is running in offline/mock mode - no live LLM call was made.",
            "This narrative is template-based; treat it as a placeholder until a live model is configured.",
        ],
        "recommended_actions": [
            "Review the raw event evidence for each correlated event ID.",
            "Validate affected user/account activity against expected behavior.",
            "Escalate if additional corroborating signals appear.",
        ],
    }


def get_llm_provider() -> LLMProvider:
    if ANTHROPIC_API_KEY:
        try:
            return AnthropicProvider()
        except Exception as exc:
            logger.error("Failed to initialize Anthropic provider, falling back to mock: %s", exc)
    return MockLLMProvider()
