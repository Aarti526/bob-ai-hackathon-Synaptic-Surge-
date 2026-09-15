# Solution Overview

## Core mechanism

ThreatLens runs a deterministic pipeline — normalize → deduplicate → correlate →
score → map to MITRE ATT&CK → retrieve threat intelligence — and only then hands the
already-evidenced result to an LLM to write a plain-language BLUF (Bottom Line Up
Front). The LLM never decides risk, never invents IOCs, and is never the only thing
standing between raw data and the analyst.

```
SIEM + EDR + Assets + Users  ->  Ingestion & Normalization  ->  Deduplication
   ->  Correlation Engine (multi-signal, not "same IP = same incident")
   ->  Incident Clustering  ->  Risk Scoring (transparent, weighted)
   ->  MITRE ATT&CK Mapping (evidence-gated)  +  Threat-Intel RAG Retrieval
   ->  LLM Reasoning (restricted to the incident's own evidence)
   ->  BLUF Generator  ->  Streamlit Dashboard
```

## What makes it different from naive alternatives

- **Multi-signal correlation, not "same IP = same incident"**: `src/core/correlation/rules.py`
  scores every candidate pair of events on four independent signals — shared identity
  (IP/host/user), temporal proximity, behavioral attack-stage progression, and
  threat-intel overlap. No shared identity → never correlated, regardless of timing. A
  large time gap hard-gates correlation even for the same IP and the same threat-intel
  indicator, which is what keeps "same IP, unrelated event 4 days later" from merging
  into a live incident.
- **Evidence-gated MITRE mapping**: `src/core/mitre/mapper.py` only marks a technique as
  "supported" when the incident's actual events satisfy its trigger condition — the LLM
  is never asked to choose or invent technique IDs.
- **Transparent, explainable scoring**: `src/core/scoring/risk_score.py` computes a
  weighted 0–100 score from 8 factors, each rendered as a human-readable contributor
  string. The analyst never sees a bare, unexplained number.
- **LLM as narrator, not decision-maker**: `src/core/ai/llm.py` / `reasoning.py` /
  `prompts.py` give the LLM only one incident's already-correlated, already-scored
  evidence, and instruct it to synthesize/explain, not decide. Its JSON output is
  schema-validated with one retry; on failure the BLUF falls back to a fully
  deterministic narrative, so the dashboard never shows a blank or crashed assessment.

## Key design decisions

- **TF-IDF embeddings instead of sentence-transformers**: zero network dependency, no
  multi-GB model download, deterministic — a hackathon demo must not depend on
  downloading a model live. Swappable behind `src/core/rag/embeddings.py`.
- **In-memory numpy cosine vector store instead of ChromaDB/FAISS**: avoids a
  native-build dependency on Windows; same `add()/query()` contract, swappable via
  `src/core/rag/vector_store.py`.
- **Mock LLM fallback**: without `ANTHROPIC_API_KEY`, ThreatLens still runs end-to-end
  using a deterministic mock narrative, so the demo never depends on live API access.

## User experience

Analysts open a Streamlit dashboard with two views:

- **Overview** — KPI row, risk-level distribution, top affected hosts, incidents-over-time.
- **Incidents & Investigation** — filterable/sortable incident table; clicking a row
  opens the full BLUF, risk-contributor chart, timeline, MITRE badges, threat intel,
  and raw evidence table.
