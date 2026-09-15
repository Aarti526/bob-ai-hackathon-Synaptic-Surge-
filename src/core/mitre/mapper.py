"""Evidence-based MITRE ATT&CK mapping (Section 33). Candidate techniques are derived
only from observed event_type/process values - never invented or chosen by an LLM."""
from __future__ import annotations

from collections import Counter

from core.data.models import Event
from core.mitre.knowledge import load_techniques

# Minimum repeated occurrences required before a technique that implies repetition
# (e.g. brute force) is considered supported by evidence (Section 19 - a single
# suspicious event should not be over-classified).
MIN_REPETITION = {"T1110": 3}


def map_techniques(events: list[Event]) -> list[dict]:
    """Returns a list of {technique_id, name, tactic, description, matched_evidence}
    for techniques whose trigger conditions are actually satisfied by these events."""
    event_type_counts = Counter(e.event_type for e in events if e.event_type)
    matches: list[dict] = []

    for technique in load_techniques():
        matched_evidence: list[str] = []

        for etype in technique.get("trigger_event_types", []):
            count = event_type_counts.get(etype, 0)
            required = MIN_REPETITION.get(technique["technique_id"], 1)
            if count >= required:
                matched_evidence.append(f"{count}x '{etype}' event(s)")

        process_keywords = technique.get("trigger_process_keywords", [])
        if process_keywords:
            hits = [e for e in events if e.process and any(k in e.process.lower() for k in process_keywords)]
            if hits and not matched_evidence:
                continue  # process-gated technique with no event_type match either
            if hits:
                matched_evidence.append(f"process '{hits[0].process}' observed on {len(hits)} event(s)")
            elif matched_evidence:
                matched_evidence = []  # event_type matched but required process keyword didn't

        if matched_evidence:
            matches.append({
                "technique_id": technique["technique_id"],
                "name": technique["name"],
                "tactic": technique["tactic"],
                "description": technique["description"],
                "matched_evidence": matched_evidence,
            })

    return matches
