"""Duplicate detection (Section 23). Runs before correlation so duplicates never
inflate event counts / risk. Deduplication is exact-match only - similar-but-distinct
events must never be merged (Section 16)."""
from __future__ import annotations

import hashlib
from core.data.models import Event

FINGERPRINT_FIELDS = ("timestamp_raw", "source_ip", "destination_ip", "username", "event_type", "hostname")


def fingerprint(event: Event) -> str:
    parts = [str(getattr(event, f) or "") for f in FINGERPRINT_FIELDS]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def deduplicate(events: list[Event]) -> tuple[list[Event], list[Event]]:
    """Returns (unique_events, duplicate_events). Duplicates are kept (not discarded)
    but excluded from downstream correlation, with is_duplicate_of set for traceability."""
    seen_ids: dict[str, Event] = {}
    seen_fingerprints: dict[str, Event] = {}
    unique: list[Event] = []
    duplicates: list[Event] = []

    for event in events:
        event.fingerprint = fingerprint(event)

        if event.event_id in seen_ids:
            event.is_duplicate_of = seen_ids[event.event_id].event_id
            duplicates.append(event)
            continue

        if event.fingerprint in seen_fingerprints:
            event.is_duplicate_of = seen_fingerprints[event.fingerprint].event_id
            duplicates.append(event)
            continue

        seen_ids[event.event_id] = event
        seen_fingerprints[event.fingerprint] = event
        unique.append(event)

    return unique, duplicates
