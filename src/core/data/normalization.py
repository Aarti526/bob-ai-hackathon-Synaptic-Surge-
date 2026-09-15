"""Maps heterogeneous source field names onto the canonical Event schema (Section 21)."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

# Canonical field <- accepted source aliases
FIELD_ALIASES: dict[str, list[str]] = {
    "event_id": ["event_id", "id", "alert_id"],
    "timestamp": ["timestamp", "time", "event_time", "ts"],
    "source_ip": ["source_ip", "src_ip", "client_ip", "remote_ip"],
    "destination_ip": ["destination_ip", "dest_ip", "dst_ip", "target_ip"],
    "hostname": ["hostname", "host", "asset", "computer_name"],
    "username": ["username", "user", "account", "principal"],
    "event_type": ["event_type", "type", "action"],
    "severity": ["severity", "priority", "level"],
    "process": ["process", "process_name", "image"],
    "network_connection": ["network_connection", "connection", "conn_ip"],
}

VALID_SEVERITIES = {"low", "medium", "high", "critical"}


def _first_present(row: dict[str, Any], aliases: list[str]) -> Any:
    for key in aliases:
        if key in row and row[key] not in (None, "", "nan"):
            return row[key]
    return None


def normalize_severity(value: Any) -> str:
    if value is None:
        return "unknown"
    v = str(value).strip().lower()
    return v if v in VALID_SEVERITIES else "unknown"


def normalize_timestamp(value: Any) -> tuple[Optional[datetime], Optional[str]]:
    """Returns (parsed_datetime_or_None, raw_string). Never raises."""
    if value is None or str(value).strip() == "":
        return None, None
    raw = str(value)
    try:
        # pandas.Timestamp already parsed upstream may arrive as datetime
        if isinstance(value, datetime):
            return value, raw
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return parsed, raw
    except (ValueError, TypeError):
        return None, raw


def normalize_record(row: dict[str, Any], source: str) -> dict[str, Any]:
    """Maps a raw source record to canonical field names. Does not validate -
    validation happens separately (Section 22) so normalization never crashes."""
    canonical: dict[str, Any] = {"source": source, "raw_data": dict(row)}

    for field, aliases in FIELD_ALIASES.items():
        canonical[field] = _first_present(row, aliases)

    canonical["severity"] = normalize_severity(canonical.get("severity"))
    ts, ts_raw = normalize_timestamp(canonical.get("timestamp"))
    canonical["timestamp"] = ts
    canonical["timestamp_raw"] = ts_raw

    for key in ("event_id", "source_ip", "destination_ip", "hostname", "username", "event_type", "process", "network_connection"):
        if canonical.get(key) is not None:
            canonical[key] = str(canonical[key]).strip()

    return canonical
