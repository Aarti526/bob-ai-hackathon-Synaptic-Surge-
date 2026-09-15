"""Canonical data models shared across the pipeline (Section 21)."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class ValidationStatus(str, Enum):
    VALID = "VALID"
    PARTIALLY_VALID = "PARTIALLY_VALID"
    INVALID = "INVALID"


class Event(BaseModel):
    """Canonical, normalized security event. `raw_data` preserves the original
    record for traceability (Section 54 - data lineage)."""

    event_id: str
    source: str  # "siem" | "edr"
    timestamp: Optional[datetime] = None
    timestamp_raw: Optional[str] = None

    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    event_type: Optional[str] = None
    severity: Optional[str] = None
    process: Optional[str] = None
    network_connection: Optional[str] = None

    raw_data: dict[str, Any] = Field(default_factory=dict)

    validation_status: ValidationStatus = ValidationStatus.VALID
    validation_issues: list[str] = Field(default_factory=list)
    fingerprint: Optional[str] = None
    is_duplicate_of: Optional[str] = None

    model_config = {"arbitrary_types_allowed": True}


class Incident(BaseModel):
    """A cluster of correlated events representing a possible attack chain."""

    incident_id: str
    event_ids: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    source_ips: list[str] = Field(default_factory=list)
    event_types: list[str] = Field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    correlation_reasons: list[str] = Field(default_factory=list)

    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    risk_contributors: list[str] = Field(default_factory=list)
    confidence: Optional[str] = None

    mitre_techniques: list[dict[str, Any]] = Field(default_factory=list)
    threat_intel_matches: list[dict[str, Any]] = Field(default_factory=list)

    bluf: Optional[dict[str, Any]] = None

    model_config = {"arbitrary_types_allowed": True}
