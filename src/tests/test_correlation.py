from datetime import datetime, timedelta, timezone

from core.correlation.engine import correlate
from core.data.models import Event


def _event(event_id, minutes_offset, event_type, source_ip=None, hostname=None, username=None):
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return Event(
        event_id=event_id, source="siem", timestamp=base + timedelta(minutes=minutes_offset),
        event_type=event_type, source_ip=source_ip, hostname=hostname, username=username,
    )


def test_attack_chain_merges_into_one_incident():
    events = [
        _event("E1", 0, "failed_login", source_ip="1.2.3.4", hostname="h1"),
        _event("E2", 1, "failed_login", source_ip="1.2.3.4", hostname="h1"),
        _event("E3", 3, "successful_login", source_ip="1.2.3.4", hostname="h1", username="admin"),
        _event("E4", 5, "privileged_login", source_ip="1.2.3.4", hostname="h1", username="admin"),
    ]
    incidents = correlate(events)
    assert len(incidents) == 1
    assert set(incidents[0].event_ids) == {"E1", "E2", "E3", "E4"}


def test_same_ip_large_time_gap_does_not_merge():
    events = [
        _event("E1", 0, "failed_login", source_ip="1.2.3.4", hostname="h1", username="carol"),
        _event("E2", 60 * 24 * 4, "successful_login", source_ip="1.2.3.4", hostname="h2", username="admin"),
    ]
    incidents = correlate(events)
    assert len(incidents) == 2
    ids = {frozenset(i.event_ids) for i in incidents}
    assert frozenset({"E1"}) in ids
    assert frozenset({"E2"}) in ids


def test_no_shared_identity_never_merges_regardless_of_time():
    events = [
        _event("E1", 0, "failed_login", source_ip="1.2.3.4", hostname="h1", username="alice"),
        _event("E2", 1, "failed_login", source_ip="9.9.9.9", hostname="h2", username="bob"),
    ]
    incidents = correlate(events)
    assert len(incidents) == 2


def test_distributed_attack_correlates_across_hosts_via_shared_ip():
    events = []
    idx = 0
    for host in ("h1", "h2", "h3"):
        for _ in range(3):
            events.append(_event(f"E{idx}", idx, "failed_login", source_ip="6.6.6.6", hostname=host))
            idx += 1
    incidents = correlate(events)
    assert len(incidents) == 1
    assert len(incidents[0].hosts) == 3


def test_isolated_event_forms_its_own_singleton_incident():
    events = [_event("E1", 0, "suspicious_process", hostname="h1", username="dave")]
    incidents = correlate(events)
    assert len(incidents) == 1
    assert incidents[0].event_ids == ["E1"]


def test_empty_input_returns_no_incidents():
    assert correlate([]) == []
