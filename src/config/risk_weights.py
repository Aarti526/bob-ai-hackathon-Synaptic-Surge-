"""Risk scoring weights. Tune here, not in scoring code. Weights sum to 1.0."""

RISK_WEIGHTS = {
    "severity": 0.20,
    "asset_criticality": 0.15,
    "event_count": 0.10,
    "temporal_density": 0.10,
    "threat_intel": 0.15,
    "mitre": 0.10,
    "behavior_chain": 0.15,
    "recency": 0.05,
}

assert abs(sum(RISK_WEIGHTS.values()) - 1.0) < 1e-6, "RISK_WEIGHTS must sum to 1.0"

# Multiplicative dampeners applied after the weighted score, for known-benign context.
FALSE_POSITIVE_DAMPENERS = {
    "known_scanner": 0.5,       # halves score if source is a known vuln scanner
    "maintenance_window": 0.7,  # reduces score for admin activity in maintenance window
}

SEVERITY_SCORES = {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25,
    "unknown": 40,
}

ASSET_CRITICALITY_SCORES = {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25,
    "unknown": 50,
}
