"""Threat intelligence retrieval for an incident (Sections 35-38). Retrieved documents
are supporting evidence, never proof - callers must display them as such."""
from __future__ import annotations

from config.settings import RAG_SIMILARITY_THRESHOLD, RAG_TOP_K
from core.data.models import Incident
from core.rag.embeddings import Embedder
from core.rag.vector_store import VectorStore


def build_query_text(incident: Incident) -> str:
    parts = [
        " ".join(incident.event_types),
        " ".join(incident.source_ips),
        " ".join(incident.hosts),
        " ".join(t["technique_id"] for t in incident.mitre_techniques),
        " ".join(t["name"] for t in incident.mitre_techniques),
    ]
    return " ".join(p for p in parts if p)


def retrieve(
    incident: Incident,
    store: VectorStore | None,
    embedder: Embedder | None,
    top_k: int = RAG_TOP_K,
    similarity_threshold: float = RAG_SIMILARITY_THRESHOLD,
) -> dict:
    """Returns {matches: [...], conflict: str|None, unavailable: bool}."""
    if store is None or embedder is None or store.is_empty():
        return {"matches": [], "conflict": None, "unavailable": True}

    query_text = build_query_text(incident)
    if not query_text.strip():
        return {"matches": [], "conflict": None, "unavailable": False}

    query_vector = embedder.embed(query_text)
    results = store.query(query_vector, top_k=top_k * 3)  # over-fetch, then dedupe by report

    seen_reports: set[str] = set()
    matches = []
    for r in results:
        if r["score"] < similarity_threshold:
            continue
        report_id = r["metadata"]["report_id"]
        if report_id in seen_reports:
            continue
        seen_reports.add(report_id)
        matches.append({
            "report_id": report_id,
            "title": r["metadata"]["title"],
            "relevance_score": round(r["score"], 3),
            "matched_indicators": [i for i in r["metadata"]["indicators"] if i in query_text],
            "excerpt": r["text"],
            "published_date": r["metadata"]["published_date"],
            "indicator_verdicts": r["metadata"]["indicator_verdicts"],
        })
        if len(matches) >= top_k:
            break

    conflict = _detect_conflict(matches)
    return {"matches": matches, "conflict": conflict, "unavailable": False}


def _detect_conflict(matches: list[dict]) -> str | None:
    """Section 38: if two retrieved reports assign different verdicts to the same
    indicator, surface the conflict instead of silently picking one."""
    indicator_verdicts: dict[str, set[str]] = {}
    for m in matches:
        for indicator, verdict in m.get("indicator_verdicts", {}).items():
            indicator_verdicts.setdefault(indicator, set()).add(verdict)

    conflicting = {ind: verdicts for ind, verdicts in indicator_verdicts.items() if len(verdicts) > 1}
    if not conflicting:
        return None
    details = "; ".join(f"{ind}: {'/'.join(sorted(v))}" for ind, v in conflicting.items())
    return f"Threat intelligence conflict detected ({details}). Analyst review recommended."
