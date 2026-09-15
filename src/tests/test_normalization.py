from core.data.normalization import normalize_record, normalize_severity, normalize_timestamp


def test_field_aliases_map_to_canonical_names():
    row = {"src_ip": "1.2.3.4", "computer_name": "host-1", "account": "bob", "id": "E1"}
    canonical = normalize_record(row, source="edr")
    assert canonical["source_ip"] == "1.2.3.4"
    assert canonical["hostname"] == "host-1"
    assert canonical["username"] == "bob"
    assert canonical["event_id"] == "E1"


def test_unknown_severity_defaults_safely():
    assert normalize_severity("extreme") == "unknown"
    assert normalize_severity(None) == "unknown"
    assert normalize_severity("High") == "high"


def test_invalid_timestamp_does_not_raise():
    parsed, raw = normalize_timestamp("not-a-timestamp")
    assert parsed is None
    assert raw == "not-a-timestamp"


def test_missing_timestamp_returns_none_none():
    parsed, raw = normalize_timestamp("")
    assert parsed is None and raw is None
