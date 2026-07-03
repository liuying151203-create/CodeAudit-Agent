from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.agent.graph import run_audit

st.set_page_config(page_title="CodeAudit-Agent", layout="wide")
st.title("CodeAudit-Agent")

mode_label = st.radio("Audit mode", ["Local repo scan", "Git diff scan"], horizontal=True)
repo_path = st.text_input("Repository path", value=str(Path("data/sample_repos/small_python_app").resolve()))
diff_text = ""
diff_mode = "cached"

if mode_label == "Git diff scan":
    diff_mode = st.selectbox("Diff source", ["cached", "head"])
    diff_text = st.text_area("Paste unified diff text", value=Path("data/sample_repos/sample.diff").read_text(encoding="utf-8") if Path("data/sample_repos/sample.diff").exists() else "", height=220)

if st.button("Run Audit Agent", type="primary"):
    with st.spinner("Running scanner, analyzer, reviewer, fix advisor and reporter..."):
        state = run_audit(
            {
                "mode": "diff_scan" if mode_label == "Git diff scan" else "repo_scan",
                "repo_path": repo_path,
                "diff_text": diff_text or None,
                "diff_mode": diff_mode,
                "traces": [],
                "errors": [],
            }
        )
    report = state["final_report"]
    st.success(report.summary)

    col1, col2 = st.columns([1, 2])
    with col1:
        st.subheader("Project Profile")
        if report.project_profile:
            st.json(report.project_profile.model_dump())
        st.subheader("Vulnerability Knowledge")
        st.write([item.title for item in report.vuln_knowledge])
        st.subheader("Tool Plan")
        if report.tool_plan:
            st.json(report.tool_plan.model_dump())
        st.subheader("Tool Results")
        st.dataframe([item.model_dump() for item in report.tool_results], use_container_width=True)
        st.subheader("Audit Stages")
        st.dataframe([item.model_dump() for item in report.audit_stage_results], use_container_width=True)
        st.subheader("Risk Stats")
        st.json(report.risk_stats)
        st.subheader("Agent Trace")
        st.dataframe([trace.model_dump() for trace in report.traces], use_container_width=True)
    with col2:
        st.subheader("Findings")
        risk_map = {item.finding_id: item for item in state.get("risk_analyses", [])}
        review_map = {item.finding_id: item for item in state.get("review_results", [])}
        for finding in report.findings:
            with st.expander(f"{finding.severity.upper()} · {finding.rule_id} · {finding.file_path}:{finding.line_start}", expanded=True):
                st.code(finding.evidence_text, language="python")
                st.write(finding.message)
                risk = risk_map.get(finding.finding_id)
                review = review_map.get(finding.finding_id)
                if risk:
                    st.caption(f"Analysis source: {risk.analysis_source}")
                    st.write(risk.risk_reason)
                if review:
                    st.write(f"False positive: {review.is_false_positive}. {review.reason}")
                suggestions = [item for item in state.get("fix_suggestions", []) if item.finding_id == finding.finding_id]
                if suggestions:
                    st.markdown(f"**Fix:** {suggestions[0].suggestion}")
                    st.code(suggestions[0].safe_code_example, language="python")

    st.subheader("Markdown Report")
    st.code(Path(report.markdown_path).read_text(encoding="utf-8"), language="markdown")
