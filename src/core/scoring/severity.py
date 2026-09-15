"""Small helpers for turning event/asset attributes into numeric scores."""
from config.risk_weights import ASSET_CRITICALITY_SCORES, SEVERITY_SCORES
from core.data.models import Event


def max_severity_score(events: list[Event]) -> tuple[int, str]:
    scored = [(SEVERITY_SCORES.get(e.severity or "unknown", SEVERITY_SCORES["unknown"]), e.severity or "unknown") for e in events]
    return max(scored, key=lambda x: x[0]) if scored else (SEVERITY_SCORES["unknown"], "unknown")


def max_asset_criticality(hosts: list[str], asset_lookup: dict[str, str]) -> tuple[int, str]:
    if not hosts:
        return ASSET_CRITICALITY_SCORES["unknown"], "unknown"
    criticalities = [asset_lookup.get(h, "unknown") for h in hosts]
    scored = [(ASSET_CRITICALITY_SCORES.get(c, ASSET_CRITICALITY_SCORES["unknown"]), c) for c in criticalities]
    return max(scored, key=lambda x: x[0])
