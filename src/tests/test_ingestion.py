from pathlib import Path

from core.data.deduplication import deduplicate
from core.ingestion.loaders import load_events
from core.ingestion.validators import validate_record


def test_missing_event_id_is_invalid():
    status, issues = validate_record({"event_id": None, "timestamp": None})
    assert status == "INVALID"
    assert "missing_event_id" in issues


def test_missing_optional_field_is_partially_valid_not_invalid():
    status, issues = validate_record({
        "event_id": "E1", "timestamp": None, "timestamp_raw": None,
        "source_ip": "10.0.0.1", "hostname": "h1", "username": "bob", "severity": "low",
    })
    assert status == "PARTIALLY_VALID"
    assert "missing_timestamp" in issues


def test_invalid_ip_flagged_but_not_discarded():
    status, issues = validate_record({
        "event_id": "E1", "timestamp": "2026-01-01T00:00:00Z",
        "source_ip": "999.999.999.999", "hostname": "h1", "username": "bob", "severity": "low",
    })
    assert status == "PARTIALLY_VALID"
    assert "invalid_source_ip" in issues


def test_no_identifiers_at_all_is_invalid():
    status, issues = validate_record({
        "event_id": "E1", "timestamp": "2026-01-01T00:00:00Z",
        "source_ip": None, "hostname": None, "username": None, "severity": "low",
    })
    assert status == "INVALID"


def test_load_events_handles_missing_file_gracefully(tmp_path: Path):
    events = load_events(tmp_path / "does_not_exist.csv", source="siem")
    assert events == []


def test_deduplication_removes_exact_and_fingerprint_duplicates():
    events = load_events(Path("data/raw/siem_alerts.csv"), source="siem")
    unique, duplicates = deduplicate(events)
    assert len(duplicates) > 0
    assert len(unique) + len(duplicates) == len(events)
    unique_ids = {e.event_id for e in unique}
    assert len(unique_ids) == len(unique)
