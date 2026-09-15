# ThreatLens

**AI Threat Intelligence Correlation & Alert Prioritisation Assistant** — a hackathon
POC that turns hundreds of noisy, heterogeneous security alerts into a small number of
explainable, prioritized, intelligence-enriched incidents.

## Team

- **Team name:** Synaptic Surge
- **Track:** AI
- **Lead:** Aarti Jain
- **Members:** Jaini Solanki, Kavya Patel, Hemang Kalavadia

## Problem Statement

Analysts face alert overload: SIEM, EDR, and threat-intel feeds each speak a different
schema, most alerts are noise or duplicates, and the events that actually matter are
buried. Analysts need incident-level understanding, not a wall of individual alerts.
See [docs/problem-statement.md](docs/problem-statement.md) for the full write-up.

## Solution

ThreatLens runs a deterministic pipeline — normalize → deduplicate → correlate → score
→ map to MITRE ATT&CK → retrieve threat intelligence — and only then hands the
already-evidenced result to an LLM to write a plain-language BLUF. The LLM never
decides risk, never invents IOCs, and is never the only thing standing between raw data
and the analyst. See [docs/solution-overview.md](docs/solution-overview.md).

## Key Features

- Multi-signal correlation engine (identity, timing, behavior progression, threat
  intel) instead of naive same-IP matching
- Transparent, weighted 0–100 risk scoring with human-readable contributor
  explanations
- Evidence-gated MITRE ATT&CK technique mapping
- Threat-intel retrieval (RAG) over synthetic reports, with conflicting verdicts
  surfaced rather than silently resolved
- LLM-generated BLUF narratives with a deterministic offline fallback when no API key
  is set

## Tech Stack

| Concern | Choice | Why |
|---|---|---|
| Language | Python 3.12 | ecosystem fit for data + ML + Streamlit |
| UI | Streamlit | fastest path to an interactive analyst dashboard for a 1-day build |
| Data | pandas / pydantic | canonical `Event`/`Incident` models, safe CSV handling |
| Storage | CSV / JSON | no infra needed for a POC of this size |
| Embeddings | TF-IDF (scikit-learn) | zero network dependency, no multi-GB model download, deterministic |
| Vector store | In-memory numpy cosine store | avoids a native-build dependency; swappable via `src/core/rag/vector_store.py` |
| LLM | Anthropic Claude, via `src/core/ai/llm.py` | abstracted behind `LLMProvider`; falls back to a deterministic `MockLLMProvider` with no API key |
| Tests | pytest | unit + integration + end-to-end (43 tests) |

## How to Run

Full instructions: [docs/setup-guide.md](docs/setup-guide.md)

```bash
cd src
pip install -r requirements.txt
python scripts/generate_data.py     # generates data/raw, data/knowledge, data/ground_truth
pytest -q                           # 43 tests
streamlit run app/main.py           # dashboard at http://localhost:8501
```

Optional: copy `src/.env.example` to `src/.env` and set `ANTHROPIC_API_KEY` for live
LLM-generated BLUFs. Without it, ThreatLens runs fully offline using a deterministic
mock narrative.

## Architecture

See [docs/architecture.md](docs/architecture.md) for the full diagram, component
table, and data flow. Source code layout: [src/README.md](src/README.md).

## Known Limitations

- No persistent incident lifecycle/triage state — the dashboard's "Status" column is
  always `OPEN`; there's no database backing analyst actions across sessions.
- Embeddings are TF-IDF, not a semantic transformer model — retrieval works on lexical
  overlap, not deep semantic similarity.
- Vector store is in-memory and rebuilt each run — fine at 15 reports, would need a
  real vector DB at scale.
- Correlation/scoring weights are hand-tuned illustrative defaults, not statistically
  fit to real incident data.
- Single-process, single-machine — no streaming ingestion, no concurrent-analyst
  state.

## What We're Most Proud Of

The correlation engine (`src/core/correlation/`) and its test coverage
(`src/tests/test_correlation.py`): it correctly merges a genuine multi-stage attack
chain and a distributed single-IP attack across hosts, while correctly refusing to
merge a known vulnerability scanner's noise or same-IP-but-4-days-apart unrelated
events — the exact false-positive/false-negative tradeoffs that make naive
"same IP = same incident" correlation unusable in a real SOC.

## Testing

`pytest` (43 tests, run from `src/`): normalization, ingestion (missing/invalid/
duplicate data), correlation (attack-chain merge, same-IP-large-gap non-merge,
no-shared-identity non-merge, distributed-attack cross-host merge, isolated-event
singleton), scoring, MITRE mapping, RAG (retrieval, threshold, conflict), BLUF (mock
provider, malformed LLM output, provider exception, deterministic fallback), and a
full end-to-end run against the generated dataset checked against
`src/data/ground_truth/scenarios.json`.

## Presentation Link 

https://docs.google.com/presentation/d/1Gabmvzbx7q2z3DQSwGamsJhk5nYo1hqx/edit?usp=drive_link&ouid=109360303401366573121&rtpof=true&sd=true
