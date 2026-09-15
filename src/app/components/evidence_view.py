import pandas as pd
import streamlit as st

from core.data.models import Event


def render_evidence_table(event_ids: list[str], events_by_id: dict[str, Event]) -> None:
    rows = []
    for eid in event_ids:
        e = events_by_id.get(eid)
        if not e:
            continue
        rows.append({
            "event_id": e.event_id, "source": e.source, "timestamp": e.timestamp,
            "event_type": e.event_type, "hostname": e.hostname, "username": e.username,
            "source_ip": e.source_ip, "severity": e.severity, "process": e.process,
            "validation": e.validation_status,
        })
    if not rows:
        st.info("No raw evidence available for this incident.")
        return
    df = pd.DataFrame(rows).sort_values("timestamp", na_position="last")
    st.dataframe(df, use_container_width=True, hide_index=True)
