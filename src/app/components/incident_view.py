from __future__ import annotations

from datetime import datetime, timezone

import pandas as pd
import streamlit as st

from app.components.dashboard import CHART_LAYOUT
from app.components.evidence_view import render_evidence_table
from app.styles import RISK_COLORS, confidence_badge, outline_badge, risk_badge
from core.data.models import Event, Incident

RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def apply_filters(incidents: list[Incident]) -> list[Incident]:
    with st.expander("Filters", expanded=False):
        c1, c2, c3 = st.columns(3)
        risk_sel = c1.multiselect("Risk level", ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                                   default=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        conf_sel = c2.multiselect("Confidence", ["HIGH", "MEDIUM", "LOW"],
                                   default=["HIGH", "MEDIUM", "LOW"])
        all_techniques = sorted({t["technique_id"] for i in incidents for t in i.mitre_techniques})
        mitre_sel = c3.multiselect("MITRE technique", all_techniques)

        c4, c5 = st.columns(2)
        host_query = c4.text_input("Host contains")
        user_query = c5.text_input("User contains")

    filtered = [
        i for i in incidents
        if i.risk_level in risk_sel and i.confidence in conf_sel
        and (not mitre_sel or any(t["technique_id"] in mitre_sel for t in i.mitre_techniques))
        and (not host_query or any(host_query.lower() in h.lower() for h in i.hosts))
        and (not user_query or any(user_query.lower() in u.lower() for u in i.users))
    ]
    return filtered


def render_incident_table(incidents: list[Incident]) -> str | None:
    if not incidents:
        st.warning("No incidents match the current filters.")
        return None

    rows = [{
        "Incident": i.incident_id, "Risk": i.risk_level, "Score": i.risk_score,
        "Confidence": i.confidence, "Events": len(i.event_ids),
        "Hosts": ", ".join(i.hosts[:3]) + ("…" if len(i.hosts) > 3 else ""),
        "User(s)": ", ".join(i.users[:2]) + ("…" if len(i.users) > 2 else ""),
        "Source IP(s)": ", ".join(i.source_ips[:2]),
        "MITRE": ", ".join(t["technique_id"] for t in i.mitre_techniques) or "-",
        "Status": "OPEN",
    } for i in incidents]

    df = pd.DataFrame(rows).sort_values(
        by=["Risk", "Score"], key=lambda col: col.map(RISK_ORDER) if col.name == "Risk" else col,
        ascending=[True, False],
    ).reset_index(drop=True)

    event = st.dataframe(
        df, use_container_width=True, hide_index=True, height=min(46 * (len(df) + 1), 520),
        on_select="rerun", selection_mode="single-row", key="incident_table",
    )
    selected_rows = event.selection.rows if event and event.selection else []
    if selected_rows:
        return df.iloc[selected_rows[0]]["Incident"]
    return None


def _risk_contributor_chart(incident: Incident) -> None:
    import plotly.graph_objects as go
    labels, values, colors = [], [], []
    for c in incident.risk_contributors:
        if not c.startswith(("+", "-")):
            continue
        is_positive = c.startswith("+")
        label = c[1:].split("(weight")[0].strip()
        labels.append(label)
        values.append(1 if is_positive else 0.15)
        colors.append("#00E5C7" if is_positive else "#4A5568")
    if not labels:
        return
    fig = go.Figure(go.Bar(x=values[::-1], y=labels[::-1], orientation="h", marker_color=colors[::-1]))
    fig.update_layout(**CHART_LAYOUT, height=max(180, 34 * len(labels)), showlegend=False,
                       xaxis=dict(visible=False), title="Risk Contributors")
    st.plotly_chart(fig, use_container_width=True)


def render_incident_detail(incident: Incident, events_by_id: dict[str, Event]) -> None:
    bluf = incident.bluf or {}
    header_class = "tl-critical" if incident.risk_level == "CRITICAL" else ""

    st.markdown(f"""
    <div class="tl-card {header_class}">
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
            <div>
                <span style="font-size:1.3rem; font-weight:800;">{incident.incident_id}</span>
                &nbsp; {risk_badge(incident.risk_level)} &nbsp; {confidence_badge(incident.confidence)}
                &nbsp; <span style="color:#94A3B8;">confidence</span>
            </div>
            <div style="font-size:1.6rem; font-weight:800;">{incident.risk_score:.0f}<span style="font-size:0.9rem; color:#94A3B8;">/100</span></div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="tl-section-title">BLUF - Bottom Line Up Front</div>', unsafe_allow_html=True)
    ai_tag = "🤖 AI-synthesized" if bluf.get("ai_generated") else "⚙️ deterministic (AI unavailable)"
    st.markdown(f"""
    <div class="tl-bluf-box">
        <b>Threat:</b> {bluf.get('threat', 'n/a')}<br><br>
        <b>Why:</b> {'; '.join(bluf.get('why', [])) or 'insufficient evidence'}<br><br>
        <b>Attack progression:</b> {bluf.get('attack_progression', 'n/a')}<br><br>
        <b>Threat intelligence:</b> {bluf.get('threat_intelligence', 'n/a')}<br><br>
        <b>Recommended investigation:</b> {'; '.join(bluf.get('recommended_investigation', [])) or 'n/a'}<br><br>
        <b>Uncertainties:</b> {'; '.join(bluf.get('uncertainties', [])) or 'none noted'}
        <div style="margin-top:10px; color:#94A3B8; font-size:0.78rem;">{ai_tag}</div>
    </div>
    """, unsafe_allow_html=True)

    if bluf.get("threat_intelligence_conflict"):
        st.warning(f"⚠️ {bluf['threat_intelligence_conflict']}")

    col1, col2 = st.columns([1, 1])
    with col1:
        _risk_contributor_chart(incident)
    with col2:
        st.markdown('<div class="tl-section-title">MITRE ATT&CK Techniques</div>', unsafe_allow_html=True)
        if incident.mitre_techniques:
            for t in incident.mitre_techniques:
                st.markdown(
                    f"{outline_badge(t['technique_id'] + ' · ' + t['name'])}", unsafe_allow_html=True,
                )
                st.caption(f"{t['tactic']} — {'; '.join(t['matched_evidence'])}")
        else:
            st.caption("No MITRE techniques were supported by the observed evidence.")

    st.markdown('<div class="tl-section-title">Timeline</div>', unsafe_allow_html=True)
    min_ts = datetime.min.replace(tzinfo=timezone.utc)
    ordered = sorted(
        [events_by_id[eid] for eid in incident.event_ids if eid in events_by_id],
        key=lambda e: e.timestamp or min_ts,
    ) if incident.event_ids else []
    for e in ordered:
        t = e.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if e.timestamp else "unknown time"
        st.markdown(
            f'<div class="tl-timeline-item"><b>{t}</b> — {e.event_type or "unknown"} '
            f'(host={e.hostname or "?"}, user={e.username or "?"}, src={e.source_ip or "?"})</div>',
            unsafe_allow_html=True,
        )

    st.markdown('<div class="tl-section-title">Threat Intelligence</div>', unsafe_allow_html=True)
    if incident.threat_intel_matches:
        for m in incident.threat_intel_matches:
            st.markdown(f"**{m['title']}** &nbsp; relevance: `{m['relevance_score']}` &nbsp; published: {m.get('published_date', 'unknown')}")
            st.caption(m["excerpt"])
    else:
        st.caption("No sufficiently relevant threat intelligence was found for this incident.")

    st.markdown('<div class="tl-section-title">Affected Assets & Users</div>', unsafe_allow_html=True)
    st.write(f"**Hosts:** {', '.join(incident.hosts) or 'none'}")
    st.write(f"**Users:** {', '.join(incident.users) or 'none'}")

    st.markdown('<div class="tl-section-title">Correlation Reasoning</div>', unsafe_allow_html=True)
    for r in incident.correlation_reasons[:8]:
        st.caption(f"• {r}")

    st.markdown('<div class="tl-section-title">Supporting Evidence (raw events)</div>', unsafe_allow_html=True)
    render_evidence_table(incident.event_ids, events_by_id)
