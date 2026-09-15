"""Loads raw multi-source data and turns each row into a validated, normalized Event
(Sections 9, 21, 22). Missing files or unreadable rows never crash the pipeline."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pandas as pd

from core.data.models import Event
from core.data.normalization import normalize_record
from core.ingestion.validators import validate_record

logger = logging.getLogger("threatlens.ingestion")


def _read_csv_rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        logger.warning("Source file not found: %s", path)
        return []
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    df = df.replace({"": None})
    return df.to_dict(orient="records")


def load_events(path: Path, source: str) -> list[Event]:
    """Loads one source CSV into canonical, validated Event objects."""
    rows = _read_csv_rows(path)
    events: list[Event] = []
    for row in rows:
        canonical = normalize_record(row, source=source)
        status, issues = validate_record(canonical)
        canonical["validation_status"] = status
        canonical["validation_issues"] = issues
        try:
            events.append(Event(**canonical))
        except Exception as exc:  # pydantic validation edge case - quarantine, don't crash
            logger.error("Failed to build Event from row %s: %s", row.get("event_id"), exc)
    logger.info("Loaded %d events from %s (source=%s)", len(events), path.name, source)
    return events


def load_reference_csv(path: Path) -> pd.DataFrame:
    """Loads a reference table (assets, users) as a DataFrame; empty DataFrame if missing."""
    if not path.exists():
        logger.warning("Reference file not found: %s", path)
        return pd.DataFrame()
    return pd.read_csv(path, dtype=str, keep_default_na=False).replace({"": None})
