"""Loads the curated local MITRE ATT&CK knowledge base (Section 32)."""
import json
from functools import lru_cache

from config.settings import MITRE_DIR


@lru_cache(maxsize=1)
def load_techniques() -> list[dict]:
    path = MITRE_DIR / "techniques.json"
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def technique_by_id(technique_id: str) -> dict | None:
    for t in load_techniques():
        if t["technique_id"] == technique_id:
            return t
    return None
