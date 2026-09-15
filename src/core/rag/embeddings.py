"""Embedding abstraction (Section 34). Uses TF-IDF instead of a downloaded transformer
model: same embed()/embed_documents() contract, but with zero network dependency and
no heavyweight torch install - important for a reliable one-shot hackathon demo. The
vector store only ever sees vectors through this interface, so the backend can be
swapped for sentence-transformers later without touching any other module."""
from __future__ import annotations

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import normalize


class Embedder:
    def __init__(self):
        self._vectorizer = TfidfVectorizer(stop_words="english", max_features=4096)
        self._fitted = False

    def embed_documents(self, documents: list[str]) -> np.ndarray:
        matrix = self._vectorizer.fit_transform(documents)
        self._fitted = True
        return normalize(matrix).toarray()

    def embed(self, text: str) -> np.ndarray:
        if not self._fitted:
            raise RuntimeError("Embedder must embed_documents() first to fit the vocabulary")
        matrix = self._vectorizer.transform([text])
        return normalize(matrix).toarray()[0]
