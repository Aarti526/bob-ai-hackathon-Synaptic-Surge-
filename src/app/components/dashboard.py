from collections import Counter

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from app.styles import RISK_COLORS
from core.data.models import Incident

CHART_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color="#E6EDF3"), margin=dict(l=10, r=10, t=40, b=10),
)


def render_risk_distribution(incidents: list[Incident]) -> None:
    counts = Counter(i.risk_level for i in incidents)
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    fig = go.Figure(go.Bar(
        x=[counts.get(level, 0) for level in order], y=order, orientation="h",
        marker_color=[RISK_COLORS[level] for level in order],
        text=[counts.get(level, 0) for level in order], textposition="outside",
    ))
    fig.update_layout(**CHART_LAYOUT, title="Incidents by Risk Level", height=280,
                       xaxis=dict(gridcolor="rgba(255,255,255,0.06)"))
    st.plotly_chart(fig, use_container_width=True)


def render_top_hosts(incidents: list[Incident]) -> None:
    host_risk: dict[str, float] = {}
    for inc in incidents:
        for host in inc.hosts:
            host_risk[host] = max(host_risk.get(host, 0), inc.risk_score or 0)
    top = sorted(host_risk.items(), key=lambda kv: -kv[1])[:8]
    if not top:
        st.info("No affected hosts to display yet.")
        return
    fig = go.Figure(go.Bar(
        x=[v for _, v in top][::-1], y=[h for h, _ in top][::-1], orientation="h",
        marker_color="#00E5C7",
    ))
    fig.update_layout(**CHART_LAYOUT, title="Highest-Risk Hosts", height=300,
                       xaxis=dict(title="Max incident risk score", gridcolor="rgba(255,255,255,0.06)"))
    st.plotly_chart(fig, use_container_width=True)


def render_incident_timeline(incidents: list[Incident]) -> None:
    rows = [
        {"incident": i.incident_id, "start": i.start_time, "end": i.end_time or i.start_time,
         "risk": i.risk_level, "score": i.risk_score}
        for i in incidents if i.start_time
    ]
    if not rows:
        st.info("No timestamped incidents to plot.")
        return
    df = pd.DataFrame(rows).sort_values("start").tail(40)
    fig = go.Figure()
    for level, color in RISK_COLORS.items():
        subset = df[df["risk"] == level]
        if subset.empty:
            continue
        fig.add_trace(go.Scatter(
            x=subset["start"], y=subset["score"], mode="markers", name=level,
            marker=dict(color=color, size=10, line=dict(width=1, color="#0B0F19")),
            text=subset["incident"], hovertemplate="%{text}<br>%{x}<br>score=%{y}<extra></extra>",
        ))
    fig.update_layout(**CHART_LAYOUT, title="Incidents Over Time (most recent 40)", height=320,
                       xaxis=dict(gridcolor="rgba(255,255,255,0.06)"),
                       yaxis=dict(title="Risk score", gridcolor="rgba(255,255,255,0.06)"))
    st.plotly_chart(fig, use_container_width=True)
