import json

from config.settings import GROUND_TRUTH_DIR
from core.ai.llm import MockLLMProvider
from core.pipeline.orchestrator import run_pipeline


def _load_ground_truth(scenario_id: str) -> dict:
    with open(GROUND_TRUTH_DIR / "scenarios.json", encoding="utf-8") as f:
        scenarios = json.load(f)
    return next(s for s in scenarios if s["scenario_id"] == scenario_id)


def test_pipeline_runs_end_to_end_and_produces_incidents():
    result = run_pipeline(llm=MockLLMProvider())
    assert result.total_raw_events > 400
    assert len(result.incidents) > 0
    assert result.summary["correlated_incidents"] == len(result.incidents)


def test_attack_chain_scenario_is_top_priority_and_correctly_mapped():
    gt = _load_ground_truth("ATTACK-001")
    result = run_pipeline(llm=MockLLMProvider())
    top = result.incidents[0]

    assert top.risk_level == gt["expected_priority"]
    assert set(top.event_ids) == set(gt["expected_event_ids"])
    mapped_ids = {t["technique_id"] for t in top.mitre_techniques}
    assert set(gt["expected_techniques"]).issubset(mapped_ids)
    assert top.bluf is not None
    assert top.bluf["risk_level"] == "CRITICAL"


def test_benign_admin_scenario_does_not_become_high_priority():
    gt = _load_ground_truth("BENIGN-ADMIN-001")
    result = run_pipeline(llm=MockLLMProvider())
    incident = next(i for i in result.incidents if "SIEM-B00" in i.event_ids)
    assert incident.risk_level in ("LOW", "MEDIUM")
    assert incident.risk_level != "CRITICAL"


def test_scanner_scenario_stays_low_priority():
    result = run_pipeline(llm=MockLLMProvider())
    incident = next(i for i in result.incidents if "SIEM-C00" in i.event_ids)
    assert incident.risk_level == "LOW"


def test_same_ip_unrelated_event_never_merges_into_attack_chain():
    result = run_pipeline(llm=MockLLMProvider())
    attack_incident = next(i for i in result.incidents if "SIEM-A00" in i.event_ids)
    assert "SIEM-E00" not in attack_incident.event_ids


def test_distributed_attack_correlates_across_hosts():
    gt = _load_ground_truth("DISTRIBUTED-001")
    result = run_pipeline(llm=MockLLMProvider())
    incident = next(i for i in result.incidents if gt["expected_event_ids"][0] in i.event_ids)
    assert set(gt["expected_event_ids"]).issubset(set(incident.event_ids))
    assert len(incident.hosts) >= 3


def test_isolated_suspicious_event_stays_low_priority():
    result = run_pipeline(llm=MockLLMProvider())
    incident = next(i for i in result.incidents if "EDR-I00" in i.event_ids)
    assert incident.risk_level == "LOW"
    assert incident.event_ids == ["EDR-I00"]


def test_empty_dataset_is_handled_gracefully(tmp_path, monkeypatch):
    import core.pipeline.orchestrator as orch
    monkeypatch.setattr(orch, "RAW_DIR", tmp_path)
    result = run_pipeline(llm=MockLLMProvider())
    assert result.total_raw_events == 0
    assert result.incidents == []
