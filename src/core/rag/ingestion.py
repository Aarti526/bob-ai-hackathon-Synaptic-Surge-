"""Threat report ingestion: clean -> chunk -> embed -> index (Section 34)."""
from __future__ import annotations

import json
import logging

from config.settings import THREAT_REPORTS_DIR
from core.rag.embeddings import Embedder
from core.rag.vector_store import VectorStore

logger = logging.getLogger("threatlens.rag")

CHUNK_CHARS = 400


def _chunk_text(text: str, chunk_chars: int = CHUNK_CHARS) -> list[str]:
    sentences = [s.strip() for s in text.replace("\n", " ").split(". ") if s.strip()]
    chunks: list[str] = []
    current = ""
    for sentence in sentences:
        candidate = f"{current}. {sentence}" if current else sentence
        if len(candidate) > chunk_chars and current:
            chunks.append(current.strip())
            current = sentence
        else:
            current = candidate
    if current:
        chunks.append(current.strip())
    return chunks or [text]


def load_threat_reports() -> list[dict]:
    if not THREAT_REPORTS_DIR.exists():
        return []
    reports = []
    for path in sorted(THREAT_REPORTS_DIR.glob("*.json")):
        with open(path, encoding="utf-8") as f:
            reports.append(json.load(f))
    return reports


def build_index() -> tuple[VectorStore, Embedder] | tuple[None, None]:
    """Builds the in-memory RAG index from all threat reports. Returns (None, None)
    if there are no reports to index, so callers can degrade gracefully (Section 51)."""
    reports = load_threat_reports()
    if not reports:
        logger.warning("No threat reports found - RAG retrieval will be unavailable")
        return None, None

    ids, texts, metadata = [], [], []
    for report in reports:
        for i, chunk in enumerate(_chunk_text(report.get("content", ""))):
            ids.append(f"{report['report_id']}-chunk{i}")
            texts.append(chunk)
            metadata.append({
                "report_id": report["report_id"],
                "title": report.get("title", ""),
                "indicators": report.get("indicators", []),
                "techniques": report.get("techniques", []),
                "published_date": report.get("published_date"),
                "indicator_verdicts": report.get("indicator_verdicts", {}),
            })

    embedder = Embedder()
    vectors = embedder.embed_documents(texts)
    store = VectorStore()
    store.add(ids, texts, metadata, vectors)
    logger.info("Indexed %d chunks from %d threat reports", len(ids), len(reports))
    return store, embedder
