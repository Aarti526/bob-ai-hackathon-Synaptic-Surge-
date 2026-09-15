"""Lightweight local vector store (Section 34). Kept behind a small interface
(add/query) so ChromaDB/FAISS could be dropped in later without touching callers."""
from __future__ import annotations

import numpy as np


class VectorStore:
    def __init__(self):
        self._ids: list[str] = []
        self._texts: list[str] = []
        self._metadata: list[dict] = []
        self._vectors: np.ndarray | None = None

    def add(self, ids: list[str], texts: list[str], metadata: list[dict], vectors: np.ndarray) -> None:
        self._ids = ids
        self._texts = texts
        self._metadata = metadata
        self._vectors = vectors

    def is_empty(self) -> bool:
        return self._vectors is None or len(self._ids) == 0

    def query(self, query_vector: np.ndarray, top_k: int) -> list[dict]:
        """Returns top_k {id, text, metadata, score} sorted by cosine similarity desc.
        Vectors are pre-normalized so dot product == cosine similarity."""
        if self.is_empty():
            return []
        scores = self._vectors @ query_vector
        top_idx = np.argsort(scores)[::-1][:top_k]
        return [
            {"id": self._ids[i], "text": self._texts[i], "metadata": self._metadata[i], "score": float(scores[i])}
            for i in top_idx
        ]
