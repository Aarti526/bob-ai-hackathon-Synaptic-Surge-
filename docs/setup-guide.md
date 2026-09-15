# Setup Guide

Tested on Python 3.12.8, Windows.

## Prerequisites

- Python 3.10+ (tested on 3.12)
- pip
- (Optional) An Anthropic API key, for live LLM-generated BLUFs

## 1. Clone and enter the source directory

All source code lives under `src/`.

```bash
git clone <your-repo-url>
cd <repo-name>/src
```

## 2. Install dependencies

```bash
pip install -r requirements.txt
```

## 3. Configure environment variables

Copy `.env.example` to `.env` and fill in as needed:

| Variable | Description | Default |
|---|---|---|
| `ANTHROPIC_API_KEY` | Anthropic API key for live LLM narratives. Leave blank to use the deterministic mock provider. | (empty) |
| `ANTHROPIC_MODEL` | Claude model id | `claude-sonnet-5` |
| `CORRELATION_TIME_WINDOW_MINUTES` | Max time gap for correlating events | `15` |
| `CORRELATION_MIN_SCORE` | Minimum pairwise correlation score to merge events | `0.45` |
| `RAG_TOP_K` | Number of threat-intel chunks retrieved per incident | `3` |
| `RAG_SIMILARITY_THRESHOLD` | Minimum similarity to count as a match | `0.15` |
| `LLM_TIMEOUT_SECONDS` | LLM call timeout | `20` |
| `LLM_TEMPERATURE` | LLM sampling temperature | `0.2` |

```bash
cp .env.example .env
```

## 4. Generate the synthetic dataset

```bash
python scripts/generate_data.py
```

This populates `data/raw`, `data/knowledge`, and `data/ground_truth`.

## 5. Run the tests

```bash
pytest -q
```

Expect `43 passed`.

## 6. Run the dashboard

```bash
streamlit run app/main.py
```

Open `http://localhost:8501`. Without `ANTHROPIC_API_KEY` set, ThreatLens runs fully
offline using a deterministic mock narrative — every other part of the pipeline
(correlation, scoring, MITRE, RAG) is unaffected.

## Verifying it's working

- `pytest -q` reports `43 passed`.
- The Streamlit app loads an **Overview** page with a non-zero incident count and a
  risk-level distribution chart.
- Clicking a row in **Incidents & Investigation** shows a populated BLUF (Threat,
  Risk, Confidence, Why, MITRE, Threat Intel, Recommended Investigation).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: No module named 'app'` / `'core'` / `'config'` | Running from the repo root instead of `src/` | `cd src` before running any command |
| Dashboard shows "no incidents" | Dataset not generated yet | Run `python scripts/generate_data.py` |
| BLUF text looks generic/templated | No `ANTHROPIC_API_KEY` set | Expected — mock provider is deterministic by design. Set the key in `.env` for live narratives |
| `pytest` fails with import errors | Dependencies not installed, or wrong Python version | `pip install -r requirements.txt`, confirm Python 3.10+ |
