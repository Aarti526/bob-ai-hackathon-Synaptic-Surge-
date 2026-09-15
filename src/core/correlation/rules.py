"""Pairwise correlation signals (Section 24). Each signal returns a 0-1 strength plus a
human-readable reason. Signals are combined (never a single if-same-ip shortcut - Section 25)
by the engine in correlation/engine.py."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from core.data.models import Event

# Attack-chain stage ordering used for the behavioral signal. Events not listed are
# treated as neutral (no stage) rather than forced into the ladder.
ATTACK_STAGES: dict[str, int] = {
    "failed_login": 1,
    "successful_login": 2,
    "privileged_login": 3,
    "suspicious_process": 4,
    "suspicious_network_connection": 5,
    "data_exfiltration_attempt": 6,
}

SIGNAL_WEIGHTS = {
    "identity": 0.30,
    "temporal": 0.25,
    "behavioral": 0.35,
    "threat_intel": 0.10,
}


def identity_signal(a: Event, b: Event) -> tuple[float, list[str]]:
    reasons = []
    score = 0.0
    if a.source_ip and a.source_ip == b.source_ip:
        score += 0.4
        reasons.append(f"Same source IP ({a.source_ip})")
    if a.hostname and a.hostname == b.hostname:
        score += 0.3
        reasons.append(f"Same destination host ({a.hostname})")
    if a.username and a.username == b.username:
        score += 0.3
        reasons.append(f"Same user account ({a.username})")
    return min(score, 1.0), reasons


def temporal_signal(a: Event, b: Event, window_minutes: int) -> tuple[float, list[str]]:
    if not a.timestamp or not b.timestamp:
        return 0.0, []
    delta_minutes = abs((b.timestamp - a.timestamp).total_seconds()) / 60.0
    if delta_minutes > window_minutes:
        return 0.0, []
    # Linear decay: 1.0 at delta=0, 0.0 at delta=window
    strength = 1.0 - (delta_minutes / window_minutes)
    return strength, [f"Occurred within {delta_minutes:.1f} minutes of each other"]


def behavioral_signal(a: Event, b: Event) -> tuple[float, list[str]]:
    stage_a = ATTACK_STAGES.get(a.event_type or "")
    stage_b = ATTACK_STAGES.get(b.event_type or "")
    if stage_a is None or stage_b is None:
        return 0.0, []
    if stage_a == stage_b:
        return 0.4, [f"Repeated '{a.event_type}' activity (possible brute force)"]
    earlier, later = (stage_a, stage_b) if stage_a < stage_b else (stage_b, stage_a)
    if later == earlier + 1:
        return 1.0, [f"'{a.event_type}' followed by '{b.event_type}' matches an attack progression"]
    if later > earlier:
        return 0.6, [f"'{a.event_type}' and '{b.event_type}' both fall on the same attack progression"]
    return 0.0, []


def threat_intel_signal(a: Event, b: Event, ti_indicators: set[str]) -> tuple[float, list[str]]:
    shared = {a.source_ip, a.destination_ip} & {b.source_ip, b.destination_ip} & ti_indicators
    shared = {s for s in shared if s}
    if shared:
        return 1.0, [f"Indicator {', '.join(shared)} matches known threat intelligence"]
    return 0.0, []


def pairwise_correlation(
    a: Event, b: Event, window_minutes: int, ti_indicators: Optional[set[str]] = None
) -> tuple[float, list[str]]:
    """Combined correlation strength in [0, 1] plus explanation reasons."""
    ti_indicators = ti_indicators or set()
    id_score, id_reasons = identity_signal(a, b)
    if id_score == 0.0:
        # No shared identity at all -> these events cannot plausibly be related,
        # regardless of timing. Prevents e.g. two unrelated hosts merging on time alone.
        return 0.0, []

    if a.timestamp and b.timestamp:
        delta_minutes = abs((b.timestamp - a.timestamp).total_seconds()) / 60.0
        if delta_minutes > window_minutes:
            # Large time gap -> not the same incident even if IP/host/user and threat
            # intel line up (Section 15: same IP != same incident across a big gap).
            return 0.0, []

    temp_score, temp_reasons = temporal_signal(a, b, window_minutes)
    beh_score, beh_reasons = behavioral_signal(a, b)
    ti_score, ti_reasons = threat_intel_signal(a, b, ti_indicators)

    total = (
        SIGNAL_WEIGHTS["identity"] * id_score
        + SIGNAL_WEIGHTS["temporal"] * temp_score
        + SIGNAL_WEIGHTS["behavioral"] * beh_score
        + SIGNAL_WEIGHTS["threat_intel"] * ti_score
    )
    reasons = id_reasons + temp_reasons + beh_reasons + ti_reasons
    return total, reasons
