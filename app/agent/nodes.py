from __future__ import annotations

from app.agent.tools import (
    ContextExtractorTool,
    FixSuggestTool,
    GitDiffTool,
    RepoLoaderTool,
    ReportWriterTool,
    RiskAnalyzeTool,
    StaticScanTool,
    FalsePositiveReviewTool,
)
from app.utils.trace import trace_tool


def router_node(state: dict) -> dict:
    state.setdefault("traces", [])
    state.setdefault("errors", [])
    state["mode"] = "diff_scan" if state.get("diff_text") else state.get("mode") or "repo_scan"
    if state["mode"] == "diff_scan" and not state.get("diff_text") and not state.get("repo_path"):
        raise ValueError("diff_scan requires diff_text or repo_path")
    if state["mode"] == "repo_scan" and not state.get("repo_path"):
        raise ValueError("repo_scan requires repo_path")
    return state


def repo_loader_node(state: dict) -> dict:
    files = trace_tool(state, "repo_loader_node", "RepoLoaderTool", str(state.get("repo_path")), lambda: RepoLoaderTool().run(state["repo_path"]))
    state["scanned_files"] = files
    return state


def diff_loader_node(state: dict) -> dict:
    diff_text, files = trace_tool(
        state,
        "diff_loader_node",
        "GitDiffTool",
        "provided diff_text" if state.get("diff_text") else str(state.get("repo_path")),
        lambda: GitDiffTool().run(state.get("repo_path"), state.get("diff_text"), state.get("diff_mode") or "cached"),
    )
    state["diff_text"] = diff_text
    state["changed_files"] = files
    state["scanned_files"] = files
    return state


def static_scan_node(state: dict) -> dict:
    state["candidate_findings"] = trace_tool(
        state,
        "static_scan_node",
        "StaticScanTool",
        f"{len(state.get('scanned_files', []))} files",
        lambda: StaticScanTool().run(state.get("scanned_files", [])),
    )
    return state


def context_extract_node(state: dict) -> dict:
    state["evidences"] = trace_tool(
        state,
        "context_extract_node",
        "ContextExtractorTool",
        f"{len(state.get('candidate_findings', []))} findings",
        lambda: ContextExtractorTool().run(state.get("candidate_findings", []), state.get("scanned_files", [])),
    )
    return state


def risk_analyze_node(state: dict) -> dict:
    state["risk_analyses"] = trace_tool(
        state,
        "risk_analyze_node",
        "RiskAnalyzeTool",
        f"{len(state.get('candidate_findings', []))} findings",
        lambda: RiskAnalyzeTool().run(state.get("candidate_findings", [])),
    )
    return state


def false_positive_review_node(state: dict) -> dict:
    state["review_results"] = trace_tool(
        state,
        "false_positive_review_node",
        "FalsePositiveReviewTool",
        f"{len(state.get('candidate_findings', []))} findings",
        lambda: FalsePositiveReviewTool().run(state.get("candidate_findings", [])),
    )
    return state


def fix_suggest_node(state: dict) -> dict:
    state["fix_suggestions"] = trace_tool(
        state,
        "fix_suggest_node",
        "FixSuggestTool",
        f"{len(state.get('candidate_findings', []))} findings",
        lambda: FixSuggestTool().run(state.get("candidate_findings", []), state.get("review_results", [])),
    )
    return state


def report_node(state: dict) -> dict:
    state["final_report"] = trace_tool(state, "report_node", "ReportWriterTool", "write report", lambda: ReportWriterTool().run(state))
    return state
