import streamlit as st


def render_overview_metrics(summary: dict) -> None:
    cols = st.columns(6)
    items = [
        ("Total Alerts", summary["total_alerts"], None),
        ("Correlated Incidents", summary["correlated_incidents"], f"from {summary['total_alerts']} raw events"),
        ("Critical", summary["critical_incidents"], "needs immediate attention"),
        ("High", summary["high_incidents"], None),
        ("Duplicates Removed", summary["duplicates_removed"], "noise reduction"),
        ("Threat Intel Matches", summary["threat_intel_matches"], None),
    ]
    for col, (label, value, help_text) in zip(cols, items):
        col.metric(label, value, help=help_text)

    reduction_pct = 0
    if summary["total_alerts"]:
        reduction_pct = round(100 * (1 - summary["correlated_incidents"] / summary["total_alerts"]))
    st.caption(
        f"ThreatLens reduced **{summary['total_alerts']}** raw alerts to **{summary['correlated_incidents']}** "
        f"explainable incidents ({reduction_pct}% noise reduction) - "
        f"{summary['quarantined_invalid']} invalid record(s) quarantined."
    )
