# Problem Statement

## Who is affected

Security analysts (SOC/SIEM operators) triaging alerts from multiple, heterogeneous
sources: SIEM, EDR, asset inventories, and identity/user directories.

## The problem

Analysts face alert overload. SIEM, EDR, and threat-intel feeds each speak a different
schema, most alerts are noise or exact/near-duplicates, and the events that actually
matter — a real multi-stage attack — are buried among thousands of unrelated ones.
Analysts need incident-level understanding ("what is happening, how bad is it, what do
I do next"), not a wall of individual alerts they have to manually correlate.

## Why existing approaches fall short

- Naive correlation ("same IP = same incident") produces false merges: a known
  vulnerability scanner or a shared NAT gateway looks identical to a real attacker
  unless correlation also considers timing, behavior progression, and threat intel.
- Raw alert scoring (e.g. plain CVSS/severity) doesn't account for asset criticality,
  event repetition, or whether the pattern matches a known attack chain, so it can't
  distinguish a single noisy false positive from an escalating incident.
- Feeding raw alerts straight to an LLM risks hallucinated IOCs, invented MITRE
  technique IDs, and a black-box "trust me" risk score with no reproducible evidence
  trail — unacceptable for a SOC decision.

## Why this matters now

Alert volume keeps growing faster than analyst headcount. Every hour spent manually
correlating raw logs across tools is an hour not spent on the incidents that are
actually escalating — and alert fatigue is a leading cause of missed real attacks.

## Quantified pain (illustrative, POC scope)

The synthetic dataset used for this build sends ~hundreds of raw SIEM/EDR events
through the pipeline and reduces them to a handful of scored incidents — see
`src/data/ground_truth/scenarios.json` for the exact scenarios the pipeline is
validated against, including genuine attack chains, benign-admin activity, scanner
noise, and same-IP-but-unrelated events that must NOT be merged.
