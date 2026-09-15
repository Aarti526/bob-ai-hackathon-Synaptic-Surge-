"""Runs the pipeline once per Streamlit session and caches the result."""
import streamlit as st

from core.pipeline.orchestrator import PipelineResult, run_pipeline


@st.cache_resource(show_spinner="Running ThreatLens pipeline: correlating events, scoring risk, retrieving intel...")
def get_pipeline_result() -> PipelineResult:
    return run_pipeline()
