from core.data.models import Event
from core.mitre.mapper import map_techniques


def _event(event_id, event_type, process=None):
    return Event(event_id=event_id, source="edr", event_type=event_type, process=process)


def test_single_failed_login_does_not_trigger_brute_force():
    events = [_event("E1", "failed_login")]
    matches = map_techniques(events)
    assert "T1110" not in {m["technique_id"] for m in matches}


def test_three_failed_logins_trigger_brute_force():
    events = [_event(f"E{i}", "failed_login") for i in range(3)]
    matches = map_techniques(events)
    assert "T1110" in {m["technique_id"] for m in matches}


def test_powershell_process_triggers_scripting_technique():
    events = [_event("E1", "suspicious_process", process="powershell.exe -enc AB==")]
    matches = map_techniques(events)
    assert "T1059.001" in {m["technique_id"] for m in matches}


def test_non_powershell_process_does_not_trigger_powershell_technique():
    events = [_event("E1", "suspicious_process", process="notepad.exe")]
    matches = map_techniques(events)
    assert "T1059.001" not in {m["technique_id"] for m in matches}


def test_every_match_carries_evidence():
    events = [_event(f"E{i}", "failed_login") for i in range(3)] + [_event("E9", "successful_login")]
    matches = map_techniques(events)
    assert all(m["matched_evidence"] for m in matches)
