# Bob Sessions

Exported IBM Bob chat history for this project — prompts and responses, for
evaluation purposes.

Paste each session below in order, using this format:

```
## Session <n> — <date> — <short topic>

**Prompt:**
<what was typed into Bob>

**Response:**
<Bob's response>
```

---

## Session 1 — 2026-09-16 — Correlation engine logic

**Prompt:**
Explain how the correlation engine in this codebase decides whether two security
events belong to the same incident, and what stops it from merging unrelated events
that just happen to share an IP address.

**Response:**
Let me explore the codebase to understand the correlation engine before answering.

Now I have a thorough picture of the entire correlation engine. Here's the full explanation:

### How the Correlation Engine Groups Events into Incidents

The engine lives across two files — `engine.py` and `rules.py` — and works in three distinct stages.

#### Stage 1 — Candidate Blocking (not O(n²))

`_candidate_pairs()` avoids comparing every event against every other event. Instead
it builds identity buckets keyed on `ip:<value>`, `host:<value>`, and `user:<value>`.
Only events that land in the same bucket are ever compared as a pair. This means two
events that share absolutely no IP, hostname, or username are never even scored —
they cannot be merged no matter how close together in time they occur.

```
buckets["ip:10.0.0.5"]  → [EVT-001, EVT-007, EVT-012]
buckets["host:dc01"]    → [EVT-007, EVT-019]
buckets["user:jdoe"]    → [EVT-001, EVT-019]
```

Candidate pairs are the union of all within-bucket combinations (de-duped as a set).

#### Stage 2 — Four-Signal Scoring

For each candidate pair, `pairwise_correlation()` runs four independent signals, then
combines them as a weighted sum. The weights are defined in `SIGNAL_WEIGHTS`:

| Signal | Weight | What it measures |
|---|---|---|
| Identity | 30% | Shared IP (+0.4), shared hostname (+0.3), shared username (+0.3) |
| Temporal | 25% | Linear decay from 1.0 → 0.0 across the configured time window |
| Behavioral | 35% | Attack-chain stage progression (see below) |
| Threat Intel | 10% | Either event's IP appears in the TI indicator feed |

The behavioral signal is the heaviest weight. It maps `event_type` against a
hard-coded attack-chain ladder in `ATTACK_STAGES`:

```
failed_login(1) → successful_login(2) → privileged_login(3)
  → suspicious_process(4) → suspicious_network_connection(5)
      → data_exfiltration_attempt(6)
```

- Adjacent stages (e.g. `failed_login` → `successful_login`) → 1.0 strength ("attack progression")
- Same stage repeated → 0.4 ("possible brute force")
- Non-adjacent but still ascending → 0.6 ("same attack progression")
- Any event whose `event_type` is not in the ladder → 0.0 (the signal contributes nothing)

The total score must reach ≥ 0.45 (the `CORRELATION_MIN_SCORE` default, overridable
via `$CORRELATION_MIN_SCORE`) for the pair to be merged.

#### Stage 3 — Union-Find Clustering

Pairs that pass the threshold are joined using a path-compressed `_UnionFind`. This
gives transitive grouping: if A merges with B and B merges with C, all three end up
in one incident — even if A and C were never a candidate pair. Every event ends up in
exactly one `Incident`, even events that correlated with nothing (they become
single-event incidents).

### What stops two events that merely share an IP from merging?

There are three independent gates, each of which can veto a merge on its own:

1. **Zero identity score hard-stop** — `pairwise_correlation()` returns `(0.0, [])`
   immediately if `id_score == 0.0`. Events with no shared identity field are
   excluded before any other signal runs.

2. **Time-window hard-stop** — even after the identity check passes, if
   `|Δt| > window_minutes` (default 15 minutes, env-tunable), the function also
   returns `(0.0, [])` immediately. A shared IP seen at 9 AM and again at 11 PM
   simply cannot correlate, because the temporal gate kills the score before the
   weighted sum is even computed.

3. **Minimum score threshold** — sharing only an IP gives an identity sub-score of
   `0.4 × 0.30 = 0.12` at most. The behavioral signal requires matching `event_type`
   values on the known attack-chain ladder. Two unrelated events that happen to use
   the same IP but have no matching stage (e.g. one is a `failed_login` and the other
   is an unknown/unlisted type) score `0.12 + (temporal contribution up to 0.25) = 0.37`
   maximum — still below the 0.45 floor. A merge only happens when identity + timing +
   behavioral alignment combine to clear the threshold.
