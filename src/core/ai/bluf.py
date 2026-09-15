"""BLUF assembly (Sections 43-44). Merges deterministic fields (risk, confidence,
assets, MITRE, evidence IDs) with the LLM's narrative fields. If the LLM produced
nothing usable, falls back to a fully deterministic BLUF - the dashboard never
shows a blank or crashed assessment (Section 51)."""
from __future__ import annotations

from core.ai.reasoning import build_evidence
from core.data.models import Event, Incident


def _fallback_narrative(evidence: dict) -> dict:
    if evidence["event_count"] <= 1 and not evidence["mitre_techniques"] and not evidence["ti_matches"]:
        assessment = "Insufficient evidence to determine whether this activity represents a genuine threat."
    else:
        assessment = (
            f"{evidence['event_count']} correlated event(s) across {len(evidence['hosts'])} host(s) "
            f"were grouped based on shared identity, timing, and behavioral progression."
        )
    return {
        "assessment": assessment,
        "key_findings": [c for c in evidence["risk_contributors"][:3]],
        "attack_progression_narrative": "See the Timeline panel for the chronological event sequence.",
        "threat_intelligence_summary": (
            "; ".join(m["title"] for m in evidence["ti_matches"]) if evidence["ti_matches"]
            else "No sufficiently relevant threat intelligence was found."
        ),
        "uncertainties": ["AI narrative synthesis was unavailable; this summary is deterministic only."],
        "recommended_actions": ["Review the correlated event evidence and affected assets/users directly."],
    }


def generate_bluf(incident: Incident, events: list[Event], ti_result: dict, llm_narrative: dict | None) -> dict:
    evidence = build_evidence(incident, events, ti_result)
    narrative = llm_narrative or _fallback_narrative(evidence)

    return {
        "threat": narrative["assessment"],
        "risk_level": incident.risk_level,
        "risk_score": incident.risk_score,
        "confidence": incident.confidence,
        "why": evidence["risk_contributors"][:3],
        "affected_assets": evidence["hosts"],
        "affected_users": evidence["users"],
        "mitre_techniques": evidence["mitre_techniques"],
        "threat_intelligence": narrative["threat_intelligence_summary"],
        "threat_intelligence_matches": evidence["ti_matches"],
        "threat_intelligence_conflict": evidence["ti_conflict"],
        "attack_progression": narrative["attack_progression_narrative"],
        "recommended_investigation": narrative["recommended_actions"],
        "supporting_evidence": incident.event_ids,
        "key_findings": narrative["key_findings"],
        "uncertainties": narrative["uncertainties"],
        "ai_generated": llm_narrative is not None,
    }
