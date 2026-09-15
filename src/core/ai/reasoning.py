"""Assembles restricted, per-incident evidence and calls the LLM (Section 39-41)."""
from __future__ import annotations

from datetime import datetime, timezone

from core.ai.llm import LLMProvider
from core.ai.prompts import SYSTEM_PROMPT, build_incident_prompt
from core.data.models import Event, Incident

REQUIRED_KEYS = [
    "assessment", "key_findings", "attack_progression_narrative",
    "threat_intelligence_summary", "uncertainties", "recommended_actions",
]

_MIN_TS = datetime.min.replace(tzinfo=timezone.utc)


def build_evidence(incident: Incident, events: list[Event], ti_result: dict) -> dict:
    ordered = sorted(events, key=lambda e: e.timestamp or _MIN_TS)
    timeline = [
        f"{e.timestamp.isoformat() if e.timestamp else 'unknown time'} - {e.event_type or 'unknown'} "
        f"(host={e.hostname or '?'}, user={e.username or '?'}, src={e.source_ip or '?'})"
        for e in ordered
    ]
    return {
        "incident_id": incident.incident_id,
        "risk_level": incident.risk_level,
        "risk_score": incident.risk_score,
        "confidence": incident.confidence,
        "event_count": len(events),
        "hosts": incident.hosts,
        "users": incident.users,
        "source_ips": incident.source_ips,
        "correlation_reasons": incident.correlation_reasons,
        "risk_contributors": incident.risk_contributors,
        "timeline": timeline,
        "mitre_techniques": incident.mitre_techniques,
        "ti_matches": ti_result.get("matches", []),
        "ti_conflict": ti_result.get("conflict"),
    }


def run_reasoning(llm: LLMProvider, incident: Incident, events: list[Event], ti_result: dict) -> dict | None:
    evidence = build_evidence(incident, events, ti_result)
    prompt = build_incident_prompt(evidence)
    return llm.generate_structured(SYSTEM_PROMPT, prompt, REQUIRED_KEYS)
