import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import streamlit as st

from app.components.dashboard import render_incident_timeline, render_risk_distribution, render_top_hosts
from app.components.incident_view import apply_filters, render_incident_detail, render_incident_table
from app.components.metrics import render_overview_metrics
from app.state import get_pipeline_result
from app.styles import CSS

st.set_page_config(page_title="ThreatLens", page_icon="🛡️", layout="wide")
st.markdown(CSS, unsafe_allow_html=True)

st.markdown('<div class="tl-hero">🛡️ ThreatLens</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="tl-subtitle">AI Threat Intelligence Correlation &amp; Alert Prioritisation Assistant</div>',
    unsafe_allow_html=True,
)
st.write("")

try:
    result = get_pipeline_result()
except Exception as exc:
    st.error(f"Pipeline failed to run: {exc}")
    st.stop()

if result.total_raw_events == 0:
    st.info("No security events are currently available for analysis. Run `python scripts/generate_data.py` to generate the synthetic dataset.")
    st.stop()

with st.sidebar:
    st.markdown("### Navigation")
    view = st.radio("View", ["Overview", "Incidents & Investigation"], label_visibility="collapsed")
    st.markdown("---")
    st.caption(f"RAG retrieval: {'🟢 available' if result.rag_available else '🔴 unavailable (deterministic analysis only)'}")
    st.caption(f"Quarantined invalid events: {result.summary['quarantined_invalid']}")
    st.caption(f"Duplicates removed: {result.summary['duplicates_removed']}")
    if st.button("🔄 Re-run pipeline"):
        get_pipeline_result.clear()
        st.rerun()

if view == "Overview":
    render_overview_metrics(result.summary)
    st.write("")
    c1, c2 = st.columns([1, 1])
    with c1:
        render_risk_distribution(result.incidents)
    with c2:
        render_top_hosts(result.incidents)
    render_incident_timeline(result.incidents)

else:
    st.markdown('<div class="tl-section-title">Correlated Incidents</div>', unsafe_allow_html=True)
    filtered = apply_filters(result.incidents)
    st.caption(f"Showing {len(filtered)} of {len(result.incidents)} incidents. Click a row to open the full investigation view.")
    selected_id = render_incident_table(filtered)

    if selected_id:
        st.session_state["selected_incident_id"] = selected_id
    incident_id = st.session_state.get("selected_incident_id")

    if incident_id:
        incident = next((i for i in result.incidents if i.incident_id == incident_id), None)
        if incident:
            st.write("")
            st.markdown("---")
            render_incident_detail(incident, result.events_by_id)
    else:
        st.info("Select an incident above to open its full investigation view (BLUF, timeline, MITRE, threat intel, evidence).")
