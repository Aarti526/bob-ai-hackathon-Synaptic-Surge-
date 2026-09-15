"""Data quality validation (Section 22). Never raises; always returns a status + issues
so the pipeline can keep going instead of crashing on one bad record."""
from __future__ import annotations

import ipaddress
from typing import Any


def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def validate_record(canonical: dict[str, Any]) -> tuple[str, list[str]]:
    """Returns (validation_status, issues). Status is one of VALID/PARTIALLY_VALID/INVALID."""
    issues: list[str] = []

    if not canonical.get("event_id"):
        return "INVALID", ["missing_event_id"]

    if canonical.get("timestamp") is None:
        if canonical.get("timestamp_raw"):
            issues.append("unparseable_timestamp")
        else:
            issues.append("missing_timestamp")

    identifiers = [canonical.get("source_ip"), canonical.get("hostname"), canonical.get("username")]
    if not any(identifiers):
        issues.append("missing_all_identifiers")

    for field in ("source_ip", "destination_ip"):
        val = canonical.get(field)
        if val and not _is_valid_ip(val):
            issues.append(f"invalid_{field}")

    if canonical.get("severity") == "unknown":
        issues.append("unknown_severity")

    if not issues:
        return "VALID", issues
    if "missing_all_identifiers" in issues:
        return "INVALID", issues
    return "PARTIALLY_VALID", issues
