"""Centralized configuration. All tunables live here or in .env - never scattered as magic numbers."""
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
GROUND_TRUTH_DIR = DATA_DIR / "ground_truth"
KNOWLEDGE_DIR = DATA_DIR / "knowledge"
THREAT_REPORTS_DIR = KNOWLEDGE_DIR / "threat_reports"
MITRE_DIR = KNOWLEDGE_DIR / "mitre"


def _env_float(name: str, default: float) -> float:
    return float(os.getenv(name, default))


def _env_int(name: str, default: int) -> int:
    return int(os.getenv(name, default))


# --- Correlation ---
CORRELATION_TIME_WINDOW_MINUTES = _env_int("CORRELATION_TIME_WINDOW_MINUTES", 15)
CORRELATION_MIN_SCORE = _env_float("CORRELATION_MIN_SCORE", 0.45)

# --- Risk scoring thresholds (0-100) ---
RISK_THRESHOLDS = {
    "LOW": (0, 29),
    "MEDIUM": (30, 59),
    "HIGH": (60, 79),
    "CRITICAL": (80, 100),
}

# --- RAG ---
RAG_TOP_K = _env_int("RAG_TOP_K", 3)
RAG_SIMILARITY_THRESHOLD = _env_float("RAG_SIMILARITY_THRESHOLD", 0.15)

# --- LLM ---
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "").strip()
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5")
LLM_TIMEOUT_SECONDS = _env_int("LLM_TIMEOUT_SECONDS", 20)
LLM_TEMPERATURE = _env_float("LLM_TEMPERATURE", 0.2)

# Known-benign infrastructure used to dampen false positives (Section 31/13).
# In a real deployment this would come from a CMDB / allowlist feed.
KNOWN_VULN_SCANNERS = {"scanner.internal", "vscan01.internal"}
MAINTENANCE_WINDOW_HOURS = (2, 4)  # 02:00-04:00 local, used for benign-admin scenario
