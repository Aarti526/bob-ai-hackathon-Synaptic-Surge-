"""Correlation engine: clusters events into incidents using multi-signal evidence
(Section 24-26). Uses identity indexes to avoid comparing every event against every
other event (Section 53) - only events that already share an IP/host/user are ever
compared pairwise.
"""
from __future__ import annotations

from collections import defaultdict

from config.settings import CORRELATION_MIN_SCORE, CORRELATION_TIME_WINDOW_MINUTES
from core.correlation.rules import pairwise_correlation
from core.data.models import Event, Incident


class _UnionFind:
    def __init__(self, ids: list[str]):
        self.parent = {i: i for i in ids}

    def find(self, x: str) -> str:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb


def _candidate_pairs(events: list[Event]) -> set[tuple[str, str]]:
    """Blocks events by shared identity field so only plausibly-related events are
    ever compared, instead of an O(n^2) scan over the whole dataset."""
    buckets: dict[str, list[str]] = defaultdict(list)
    for e in events:
        for field, val in (("ip", e.source_ip), ("host", e.hostname), ("user", e.username)):
            if val:
                buckets[f"{field}:{val}"].append(e.event_id)

    pairs: set[tuple[str, str]] = set()
    for ids in buckets.values():
        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                pairs.add(tuple(sorted((ids[i], ids[j]))))
    return pairs


def correlate(
    events: list[Event],
    ti_indicators: set[str] | None = None,
    time_window_minutes: int = CORRELATION_TIME_WINDOW_MINUTES,
    min_score: float = CORRELATION_MIN_SCORE,
) -> list[Incident]:
    """Clusters events into incidents. Every event ends up in exactly one incident,
    even if that incident has a single event (Section 19)."""
    if not events:
        return []

    by_id = {e.event_id: e for e in events}
    uf = _UnionFind(list(by_id.keys()))
    pair_reasons: dict[tuple[str, str], list[str]] = {}

    for a_id, b_id in _candidate_pairs(events):
        score, reasons = pairwise_correlation(
            by_id[a_id], by_id[b_id], time_window_minutes, ti_indicators
        )
        if score >= min_score:
            uf.union(a_id, b_id)
            pair_reasons[(a_id, b_id)] = reasons

    clusters: dict[str, list[str]] = defaultdict(list)
    for event_id in by_id:
        clusters[uf.find(event_id)].append(event_id)

    incidents: list[Incident] = []
    for idx, (_, event_ids) in enumerate(sorted(clusters.items()), start=1):
        incident_events = [by_id[eid] for eid in event_ids]
        incidents.append(_build_incident(f"INC-{idx:04d}", incident_events, pair_reasons))

    return incidents


def _build_incident(incident_id: str, events: list[Event], pair_reasons: dict) -> Incident:
    reasons: list[str] = []
    ids = {e.event_id for e in events}
    for (a, b), r in pair_reasons.items():
        if a in ids and b in ids:
            reasons.extend(r)
    # de-dupe while preserving order
    seen = set()
    unique_reasons = [r for r in reasons if not (r in seen or seen.add(r))]

    timestamps = [e.timestamp for e in events if e.timestamp]
    return Incident(
        incident_id=incident_id,
        event_ids=sorted(e.event_id for e in events),
        hosts=sorted({e.hostname for e in events if e.hostname}),
        users=sorted({e.username for e in events if e.username}),
        source_ips=sorted({e.source_ip for e in events if e.source_ip}),
        event_types=sorted({e.event_type for e in events if e.event_type}),
        start_time=min(timestamps) if timestamps else None,
        end_time=max(timestamps) if timestamps else None,
        correlation_reasons=unique_reasons,
    )
