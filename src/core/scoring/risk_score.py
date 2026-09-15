"""Transparent, weighted risk scoring (Sections 28-31, 42). Every factor that
contributes is returned as a human-readable string alongside the score - the
analyst must never see a bare number (Section 30)."""
from __future__ import annotations

from datetime import datetime

from config.risk_weights import FALSE_POSITIVE_DAMPENERS, RISK_WEIGHTS
from config.settings import KNOWN_VULN_SCANNERS, MAINTENANCE_WINDOW_HOURS, RISK_THRESHOLDS
from core.correlation.rules import ATTACK_STAGES
from core.data.models import Event, Incident
from core.scoring.severity import max_asset_criticality, max_severity_score


def _risk_level(score: float) -> str:
    for level, (lo, hi) in RISK_THRESHOLDS.items():
        if lo <= score <= hi:
            return level
    return "LOW"


def _temporal_density_score(incident: Incident) -> float:
    if len(incident.event_ids) <= 1 or not incident.start_time or not incident.end_time:
        # A single event has nothing to be "clustered" against - density is undefined,
        # not maximal.
        return 0.0
    span_minutes = max((incident.end_time - incident.start_time).total_seconds() / 60.0, 0.01)
    density = len(incident.event_ids) / span_minutes
    return min(100.0, density * 100)


def _behavior_chain_score(events: list[Event]) -> float:
    stages = {ATTACK_STAGES[e.event_type] for e in events if e.event_type in ATTACK_STAGES}
    if len(stages) <= 1:
        return 0.0
    max_stage_span = max(ATTACK_STAGES.values())
    return min(100.0, (len(stages) - 1) / max_stage_span * 100 * 1.6)


def _recency_score(incident: Incident, dataset_now: datetime) -> float:
    if not incident.end_time:
        return 0.0
    age_hours = max((dataset_now - incident.end_time).total_seconds() / 3600.0, 0.0)
    return max(0.0, 100.0 - (age_hours / 48.0) * 100.0)


def _false_positive_dampener(events: list[Event], asset_lookup: dict[str, str]) -> tuple[float, list[str]]:
    notes = []
    multiplier = 1.0
    if any((e.source_ip in KNOWN_VULN_SCANNERS or e.hostname in KNOWN_VULN_SCANNERS) for e in events):
        multiplier *= FALSE_POSITIVE_DAMPENERS["known_scanner"]
        notes.append("Source matches a known internal vulnerability scanner - risk reduced")

    lo_hr, hi_hr = MAINTENANCE_WINDOW_HOURS
    in_window = [e for e in events if e.timestamp and lo_hr <= e.timestamp.hour < hi_hr]
    if in_window and len(in_window) == len(events):
        multiplier *= FALSE_POSITIVE_DAMPENERS["maintenance_window"]
        notes.append(f"All activity occurred within the {lo_hr}:00-{hi_hr}:00 maintenance window - risk reduced")

    return multiplier, notes


def _confidence(events: list[Event], mitre_hits: int, ti_hits: int) -> str:
    points = 0
    if len(events) >= 3:
        points += 1
    stages = {ATTACK_STAGES[e.event_type] for e in events if e.event_type in ATTACK_STAGES}
    if len(stages) >= 3:
        points += 1
    if mitre_hits:
        points += 1
    if ti_hits:
        points += 1
    if points >= 3:
        return "HIGH"
    if points == 2:
        return "MEDIUM"
    return "LOW"


def score_incident(
    incident: Incident,
    events: list[Event],
    asset_lookup: dict[str, str],
    mitre_technique_count: int,
    ti_match_count: int,
    dataset_now: datetime,
) -> dict:
    """Returns dict with score, level, confidence, and ordered contributor explanations."""
    sev_score, sev_label = max_severity_score(events)
    crit_score, crit_label = max_asset_criticality(incident.hosts, asset_lookup)
    event_count_score = min(100.0, (len(events) / 6.0) * 100)
    temporal_score = _temporal_density_score(incident)
    ti_score = min(100.0, ti_match_count * 50.0)
    mitre_score = min(100.0, mitre_technique_count * 60.0)
    behavior_score = _behavior_chain_score(events)
    recency_score = _recency_score(incident, dataset_now)

    factors = {
        "severity": (sev_score, f"Highest alert severity: {sev_label.upper()}"),
        "asset_criticality": (crit_score, f"Most critical affected asset: {crit_label.upper()}"),
        "event_count": (event_count_score, f"{len(events)} correlated event(s) in this incident"),
        "temporal_density": (temporal_score, "Events are tightly clustered in time" if temporal_score > 40 else "Events are spread out in time"),
        "threat_intel": (ti_score, f"{ti_match_count} threat intelligence match(es)" if ti_match_count else "No threat intelligence matches"),
        "mitre": (mitre_score, f"{mitre_technique_count} supported MITRE ATT&CK technique(s)" if mitre_technique_count else "No supported MITRE techniques"),
        "behavior_chain": (behavior_score, "Multi-stage attack progression observed" if behavior_score > 40 else "No clear multi-stage progression"),
        "recency": (recency_score, "Recent activity" if recency_score > 50 else "Older activity"),
    }

    weighted_score = sum(RISK_WEIGHTS[k] * v[0] for k, v in factors.items())
    multiplier, dampener_notes = _false_positive_dampener(events, asset_lookup)
    final_score = round(min(100.0, weighted_score * multiplier), 1)

    contributors = [
        f"{'+' if v[0] >= 50 else '-'} {v[1]} (weight {RISK_WEIGHTS[k]:.0%}, contributed {v[0]:.0f}/100)"
        for k, v in sorted(factors.items(), key=lambda kv: -kv[1][0])
    ]
    contributors.extend(dampener_notes)

    return {
        "risk_score": final_score,
        "risk_level": _risk_level(final_score),
        "confidence": _confidence(events, mitre_technique_count, ti_match_count),
        "contributors": contributors,
    }
