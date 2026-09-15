# src/ layout

All source code and runnable artifacts live here. See `docs/setup-guide.md` (repo root)
for full run instructions.

```
src/
├── app/            Streamlit dashboard (UI)
├── config/         Centralized settings and tunable weights
├── core/           Pipeline logic: ingestion, correlation, scoring, MITRE, RAG, LLM
├── data/           Synthetic datasets (raw, processed, knowledge, ground truth)
├── scripts/        generate_data.py — builds the synthetic dataset
├── tests/          pytest suite (43 tests)
├── .env.example    Environment variable template
├── .streamlit/     Streamlit config
├── pytest.ini
└── requirements.txt
```

Run everything with `src/` as the working directory (`cd src`).
