from datetime import datetime, timezone

from core.data.models import Event, Incident
from core.scoring.risk_score import score_incident

NOW = datetime(2026, 9, 15, tzinfo=timezone.utc)


def _incident_and_events(event_type="failed_login", severity="high", source_ip="1.2.3.4", hostname="h1"):
    e = Event(event_id="E1", source="siem", timestamp=NOW, event_type=event_type,
              severity=severity, source_ip=source_ip, hostname=hostname)
    inc = Incident(incident_id="INC-1", event_ids=["E1"], hosts=[hostname], start_time=NOW, end_time=NOW)
    return inc, [e]


def test_single_event_gets_zero_temporal_density_not_maximal():
    inc, events = _incident_and_events()
    result = score_incident(inc, events, asset_lookup={}, mitre_technique_count=0, ti_match_count=0, dataset_now=NOW)
    density_note = [c for c in result["contributors"] if "clustered" in c or "spread out" in c]
    assert any("spread out" in c for c in density_note)


def test_known_scanner_dampens_risk():
    inc, events = _incident_and_events(event_type="vulnerability_scan", severity="high", source_ip="scanner.internal")
    result_scanner = score_incident(inc, events, asset_lookup={}, mitre_technique_count=0, ti_match_count=0, dataset_now=NOW)

    inc2, events2 = _incident_and_events(event_type="vulnerability_scan", severity="high", source_ip="9.9.9.9")
    result_normal = score_incident(inc2, events2, asset_lookup={}, mitre_technique_count=0, ti_match_count=0, dataset_now=NOW)

    assert result_scanner["risk_score"] < result_normal["risk_score"]


def test_risk_level_thresholds():
    inc, events = _incident_and_events(severity="critical")
    result = score_incident(
        inc, events, asset_lookup={"h1": "critical"}, mitre_technique_count=2, ti_match_count=2, dataset_now=NOW
    )
    assert result["risk_score"] >= 60
    assert result["risk_level"] in ("HIGH", "CRITICAL")


def test_confidence_is_low_for_single_weak_event():
    inc, events = _incident_and_events()
    result = score_incident(inc, events, asset_lookup={}, mitre_technique_count=0, ti_match_count=0, dataset_now=NOW)
    assert result["confidence"] == "LOW"


def test_contributors_are_human_readable_not_bare_numbers():
    inc, events = _incident_and_events()
    result = score_incident(inc, events, asset_lookup={}, mitre_technique_count=0, ti_match_count=0, dataset_now=NOW)
    assert all(isinstance(c, str) and len(c) > 5 for c in result["contributors"])
