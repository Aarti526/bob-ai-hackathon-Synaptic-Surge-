from core.data.models import Incident
from core.rag.embeddings import Embedder
from core.rag.retriever import retrieve
from core.rag.vector_store import VectorStore


def _build_store():
    docs = [
        "PowerShell encoded command execution following account takeover from 203.0.113.10",
        "Weather forecast for the northern region predicts rain this weekend",
        "Vulnerability scanning activity from scanner.internal is routine and authorized",
    ]
    embedder = Embedder()
    vectors = embedder.embed_documents(docs)
    store = VectorStore()
    store.add(
        ids=["d0", "d1", "d2"], texts=docs,
        metadata=[
            {"report_id": "R0", "title": "PowerShell Report", "indicators": ["203.0.113.10"], "techniques": ["T1059.001"], "published_date": "2026-01-01", "indicator_verdicts": {"203.0.113.10": "malicious"}},
            {"report_id": "R1", "title": "Weather", "indicators": [], "techniques": [], "published_date": "2026-01-01", "indicator_verdicts": {}},
            {"report_id": "R2", "title": "Scanner Report", "indicators": ["scanner.internal"], "techniques": [], "published_date": "2026-01-01", "indicator_verdicts": {}},
        ],
        vectors=vectors,
    )
    return store, embedder


def test_retrieval_finds_relevant_document_above_threshold():
    store, embedder = _build_store()
    incident = Incident(incident_id="INC-1", event_types=["suspicious_process"], source_ips=["203.0.113.10"], hosts=["h1"])
    result = retrieve(incident, store, embedder, top_k=3, similarity_threshold=0.05)
    assert not result["unavailable"]
    titles = [m["title"] for m in result["matches"]]
    assert "PowerShell Report" in titles


def test_low_similarity_returns_no_matches_not_fabricated():
    store, embedder = _build_store()
    incident = Incident(incident_id="INC-2", event_types=["totally_unrelated_topic_xyz"], hosts=[], source_ips=[])
    result = retrieve(incident, store, embedder, top_k=3, similarity_threshold=0.9)
    assert result["matches"] == []


def test_missing_store_reports_unavailable_not_crash():
    incident = Incident(incident_id="INC-3")
    result = retrieve(incident, None, None)
    assert result["unavailable"] is True
    assert result["matches"] == []


def test_conflicting_verdicts_are_surfaced():
    store, embedder = _build_store()
    incident = Incident(incident_id="INC-4", source_ips=["203.0.113.10"])
    result = retrieve(incident, store, embedder, top_k=3, similarity_threshold=0.01)
    # Manually construct a conflict scenario via the internal helper for determinism
    from core.rag.retriever import _detect_conflict
    matches = [
        {"indicator_verdicts": {"203.0.113.10": "malicious"}},
        {"indicator_verdicts": {"203.0.113.10": "outdated"}},
    ]
    assert _detect_conflict(matches) is not None
    assert _detect_conflict([{"indicator_verdicts": {"1.1.1.1": "malicious"}}]) is None
