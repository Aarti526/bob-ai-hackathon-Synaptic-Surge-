from datetime import datetime, timezone

from core.ai.bluf import generate_bluf
from core.ai.llm import LLMProvider, MockLLMProvider
from core.ai.reasoning import REQUIRED_KEYS, run_reasoning
from core.data.models import Event, Incident

NOW = datetime(2026, 9, 15, tzinfo=timezone.utc)


class _MalformedProvider(LLMProvider):
    def generate(self, system, prompt):
        return "this is not json at all"


class _AlwaysFailsProvider(LLMProvider):
    def generate(self, system, prompt):
        raise RuntimeError("simulated timeout")


def _incident_and_events():
    e = Event(event_id="E1", source="siem", timestamp=NOW, event_type="failed_login", hostname="h1")
    inc = Incident(incident_id="INC-1", event_ids=["E1"], hosts=["h1"], risk_score=20, risk_level="LOW",
                    confidence="LOW", risk_contributors=["- Highest severity: low"])
    return inc, [e]


def test_mock_provider_returns_all_required_keys():
    provider = MockLLMProvider()
    inc, events = _incident_and_events()
    narrative = run_reasoning(provider, inc, events, {"matches": [], "conflict": None})
    assert narrative is not None
    assert all(k in narrative for k in REQUIRED_KEYS)


def test_malformed_llm_output_falls_back_to_none():
    provider = _MalformedProvider()
    inc, events = _incident_and_events()
    narrative = run_reasoning(provider, inc, events, {"matches": [], "conflict": None})
    assert narrative is None


def test_provider_exception_never_crashes_caller():
    provider = _AlwaysFailsProvider()
    inc, events = _incident_and_events()
    narrative = run_reasoning(provider, inc, events, {"matches": [], "conflict": None})
    assert narrative is None


def test_bluf_falls_back_deterministically_when_llm_unavailable():
    inc, events = _incident_and_events()
    bluf = generate_bluf(inc, events, {"matches": [], "conflict": None}, llm_narrative=None)
    assert bluf["ai_generated"] is False
    assert bluf["risk_level"] == "LOW"
    assert "AI narrative synthesis was unavailable" in bluf["uncertainties"][0]


def test_bluf_never_overrides_deterministic_risk_with_llm_opinion():
    inc, events = _incident_and_events()
    fake_narrative = {
        "assessment": "test", "key_findings": [], "attack_progression_narrative": "",
        "threat_intelligence_summary": "", "uncertainties": [], "recommended_actions": [],
    }
    bluf = generate_bluf(inc, events, {"matches": [], "conflict": None}, llm_narrative=fake_narrative)
    assert bluf["risk_level"] == inc.risk_level
    assert bluf["risk_score"] == inc.risk_score
