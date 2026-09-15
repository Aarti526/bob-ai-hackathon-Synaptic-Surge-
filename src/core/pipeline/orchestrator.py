"""End-to-end pipeline: raw files -> normalized events -> incidents -> risk -> MITRE
-> RAG -> LLM -> BLUF (Section 5). This is the one place that wires every module
together; everything else stays independently testable."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from config.settings import RAW_DIR
from core.ai.bluf import generate_bluf
from core.ai.llm import LLMProvider, get_llm_provider
from core.ai.reasoning import run_reasoning
from core.correlation.engine import correlate
from core.data.deduplication import deduplicate
from core.data.models import Event, Incident
from core.ingestion.loaders import load_events, load_reference_csv
from core.mitre.mapper import map_techniques
from core.rag.ingestion import build_index
from core.rag.retriever import retrieve

logger = logging.getLogger("threatlens.pipeline")


class PipelineResult:
    def __init__(self):
        self.incidents: list[Incident] = []
        self.events_by_id: dict[str, Event] = {}
        self.quarantined: list[Event] = []
        self.duplicates: list[Event] = []
        self.total_raw_events = 0
        self.rag_available = False

    @property
    def summary(self) -> dict:
        by_level = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        ti_matches = 0
        for inc in self.incidents:
            by_level[inc.risk_level or "LOW"] += 1
            if inc.threat_intel_matches:
                ti_matches += 1
        return {
            "total_alerts": self.total_raw_events,
            "duplicates_removed": len(self.duplicates),
            "quarantined_invalid": len(self.quarantined),
            "correlated_incidents": len(self.incidents),
            "critical_incidents": by_level["CRITICAL"],
            "high_incidents": by_level["HIGH"],
            "medium_incidents": by_level["MEDIUM"],
            "low_incidents": by_level["LOW"],
            "threat_intel_matches": ti_matches,
            "rag_available": self.rag_available,
        }


def _asset_lookup() -> dict[str, str]:
    df = load_reference_csv(RAW_DIR / "assets.csv")
    if df.empty:
        return {}
    return dict(zip(df["hostname"], df["criticality"].str.lower()))


def _all_ti_indicators() -> set[str]:
    from core.rag.ingestion import load_threat_reports
    indicators = set()
    for report in load_threat_reports():
        indicators.update(report.get("indicators", []))
    return indicators


def run_pipeline(llm: LLMProvider | None = None) -> PipelineResult:
    result = PipelineResult()
    llm = llm or get_llm_provider()

    siem_events = load_events(RAW_DIR / "siem_alerts.csv", source="siem")
    edr_events = load_events(RAW_DIR / "sensor_events.csv", source="edr")
    all_events = siem_events + edr_events
    result.total_raw_events = len(all_events)

    if not all_events:
        logger.warning("No security events available for analysis")
        return result

    unique_events, duplicates = deduplicate(all_events)
    result.duplicates = duplicates

    quarantined = [e for e in unique_events if e.validation_status == "INVALID"]
    processable = [e for e in unique_events if e.validation_status != "INVALID"]
    result.quarantined = quarantined
    result.events_by_id = {e.event_id: e for e in unique_events}

    asset_lookup = _asset_lookup()
    ti_indicators = _all_ti_indicators()
    store, embedder = build_index()
    result.rag_available = store is not None

    valid_timestamps = [e.timestamp for e in processable if e.timestamp]
    dataset_now = max(valid_timestamps) if valid_timestamps else datetime.now(timezone.utc)

    incidents = correlate(processable, ti_indicators=ti_indicators)

    from core.scoring.risk_score import score_incident

    for incident in incidents:
        incident_events = [result.events_by_id[eid] for eid in incident.event_ids]

        mitre_matches = map_techniques(incident_events)
        incident.mitre_techniques = mitre_matches

        ti_result = retrieve(incident, store, embedder)
        incident.threat_intel_matches = ti_result["matches"]

        scoring = score_incident(
            incident, incident_events, asset_lookup,
            mitre_technique_count=len(mitre_matches),
            ti_match_count=len(ti_result["matches"]),
            dataset_now=dataset_now,
        )
        incident.risk_score = scoring["risk_score"]
        incident.risk_level = scoring["risk_level"]
        incident.confidence = scoring["confidence"]
        incident.risk_contributors = scoring["contributors"]

        llm_narrative = run_reasoning(llm, incident, incident_events, ti_result)
        incident.bluf = generate_bluf(incident, incident_events, ti_result, llm_narrative)

    incidents.sort(key=lambda i: -(i.risk_score or 0))
    result.incidents = incidents
    return result
