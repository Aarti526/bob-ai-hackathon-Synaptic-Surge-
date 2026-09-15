"""Custom CSS on top of Streamlit's native dark theme (.streamlit/config.toml) - just
card polish, risk badges, and subtle motion. The theme colors themselves are native
Streamlit config, not reimplemented here."""

RISK_COLORS = {
    "CRITICAL": "#FF3B5C",
    "HIGH": "#FF9F45",
    "MEDIUM": "#FFD93D",
    "LOW": "#3DDC97",
}

CONFIDENCE_COLORS = {"HIGH": "#00E5C7", "MEDIUM": "#8AA6FF", "LOW": "#94A3B8"}

CSS = """
<style>
@keyframes fadeInUp {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
}
@keyframes pulseGlow {
    0%, 100% { box-shadow: 0 0 0 rgba(255,59,92,0); }
    50% { box-shadow: 0 0 18px rgba(255,59,92,0.55); }
}

.block-container { animation: fadeInUp 0.4s ease-out; padding-top: 2rem; }

.tl-hero {
    background: linear-gradient(120deg, #00E5C7 0%, #6C5CE7 50%, #FF3B5C 100%);
    -webkit-background-clip: text; background-clip: text; color: transparent;
    font-size: 2.4rem; font-weight: 800; letter-spacing: -0.02em; margin-bottom: 0;
}
.tl-subtitle { color: #94A3B8; font-size: 1.02rem; margin-top: -8px; }

.tl-card {
    background: #141B2D; border: 1px solid rgba(255,255,255,0.06);
    border-radius: 14px; padding: 18px 20px; transition: transform 0.18s ease, box-shadow 0.18s ease;
}
.tl-card:hover { transform: translateY(-3px); box-shadow: 0 8px 24px rgba(0,229,199,0.12); }

.tl-metric-label { color: #94A3B8; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.06em; }
.tl-metric-value { font-size: 2rem; font-weight: 800; color: #E6EDF3; }

.tl-badge {
    display: inline-block; padding: 3px 12px; border-radius: 999px;
    font-size: 0.78rem; font-weight: 700; letter-spacing: 0.03em; color: #0B0F19;
}
.tl-badge-outline {
    display: inline-block; padding: 2px 10px; border-radius: 8px; margin: 2px 4px 2px 0;
    font-size: 0.75rem; border: 1px solid rgba(255,255,255,0.18); color: #E6EDF3;
    background: rgba(255,255,255,0.04);
}

.tl-critical { animation: pulseGlow 2.2s ease-in-out infinite; }

.tl-timeline-item {
    border-left: 2px solid rgba(0,229,199,0.4); padding: 4px 0 4px 16px; margin-bottom: 2px;
    font-size: 0.88rem; color: #C9D4E0;
}
.tl-section-title {
    font-size: 1.05rem; font-weight: 700; color: #E6EDF3; margin: 1.2rem 0 0.4rem 0;
    border-bottom: 1px solid rgba(255,255,255,0.08); padding-bottom: 6px;
}
.tl-bluf-box {
    background: linear-gradient(135deg, rgba(0,229,199,0.08), rgba(108,92,231,0.08));
    border: 1px solid rgba(0,229,199,0.25); border-radius: 14px; padding: 20px 24px;
}
.tl-evidence-chip {
    font-family: monospace; font-size: 0.78rem; background: rgba(255,255,255,0.05);
    padding: 2px 8px; border-radius: 6px; margin: 2px 4px 2px 0; display: inline-block;
}
div[data-testid="stMetric"] {
    background: #141B2D; border: 1px solid rgba(255,255,255,0.06); border-radius: 14px;
    padding: 14px 16px; transition: transform 0.18s ease;
}
div[data-testid="stMetric"]:hover { transform: translateY(-2px); }
</style>
"""


def badge(text: str, color: str) -> str:
    return f'<span class="tl-badge" style="background:{color}">{text}</span>'


def outline_badge(text: str) -> str:
    return f'<span class="tl-badge-outline">{text}</span>'


def risk_badge(level: str) -> str:
    return badge(level, RISK_COLORS.get(level, "#94A3B8"))


def confidence_badge(level: str) -> str:
    return badge(level, CONFIDENCE_COLORS.get(level, "#94A3B8"))
