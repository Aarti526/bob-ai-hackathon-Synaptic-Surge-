"""Prompt construction (Section 39). The LLM only ever sees pre-correlated,
pre-scored evidence for ONE incident - never the raw event dataset."""

SYSTEM_PROMPT = """You are a defensive security analyst assistant. You are given ALREADY
CORRELATED and ALREADY SCORED incident evidence - correlation, risk scoring, and MITRE
mapping were done deterministically before you were called. Your job is only to:
- synthesize the evidence into a clear analyst-facing narrative
- explain the likely attack progression using ONLY the events/techniques/intel given
- summarize the provided threat intelligence
- flag genuine uncertainty
- recommend concrete next investigation steps

Rules:
- Never invent event IDs, IP addresses, hostnames, MITRE technique IDs, or threat
  intelligence that is not present in the evidence you were given.
- Never change or restate the risk score/level/confidence as anything other than what
  was provided - you may only explain WHY, not decide WHAT.
- If evidence is weak or ambiguous, say so explicitly rather than asserting certainty.
- Respond with ONLY a JSON object, no markdown fences, matching this schema:
{
  "assessment": "one paragraph, plain language",
  "key_findings": ["short bullet", "..."],
  "attack_progression_narrative": "one paragraph describing the sequence",
  "threat_intelligence_summary": "one paragraph, or state none was found",
  "uncertainties": ["short bullet", "..."],
  "recommended_actions": ["short bullet", "..."]
}"""


def build_incident_prompt(evidence: dict) -> str:
    lines = [
        f"Incident: {evidence['incident_id']}",
        f"Risk: {evidence['risk_level']} ({evidence['risk_score']}/100)",
        f"Confidence: {evidence['confidence']}",
        f"Event count: {evidence['event_count']}",
        f"Affected hosts: {', '.join(evidence['hosts']) or 'none'}",
        f"Affected users: {', '.join(evidence['users']) or 'none'}",
        f"Source IPs: {', '.join(evidence['source_ips']) or 'none'}",
        "",
        "Correlation reasons (why these events were grouped):",
        *([f"- {r}" for r in evidence["correlation_reasons"]] or ["- none"]),
        "",
        "Risk contributors:",
        *[f"- {c}" for c in evidence["risk_contributors"]],
        "",
        "Event timeline:",
        *[f"- {t}" for t in evidence["timeline"]],
        "",
        "Supported MITRE ATT&CK techniques (evidence-validated):",
        *([f"- {t['technique_id']} {t['name']}: {'; '.join(t['matched_evidence'])}" for t in evidence["mitre_techniques"]] or ["- none supported by evidence"]),
        "",
        "Threat intelligence matches:",
        *([f"- {m['title']} (relevance {m['relevance_score']}): {m['excerpt'][:200]}" for m in evidence["ti_matches"]] or ["- no threat intelligence matches"]),
    ]
    if evidence.get("ti_conflict"):
        lines.append(f"\nWARNING - conflicting threat intelligence: {evidence['ti_conflict']}")
    return "\n".join(lines)
