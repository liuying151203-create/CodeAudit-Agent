from __future__ import annotations

from app.agent.tools import (
    ContextExtractorTool,
    FixSuggestTool,
    FindingMergerTool,
    GitDiffTool,
    ProjectReaderTool,
    RepoLoaderTool,
    ReportWriterTool,
    RiskAnalyzeTool,
    StaticScanTool,
    FalsePositiveReviewTool,
    ToolExecutorTool,
    ToolSelectorTool,
    VulnKBRetrieverTool,
)
from app.agent.state import normalize_audit_state, sync_audit_state
from app.utils.trace import trace_tool


def router_node(state: dict) -> dict:
    state = normalize_audit_state(state)
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


def project_reader_node(state: dict) -> dict:
    profile, files = trace_tool(
        state,
        "project_reader_node",
        "ProjectReaderTool",
        str(state.get("repo_path") or f"{len(state.get('scanned_files', []))} loaded files"),
        lambda: ProjectReaderTool().run(state.get("repo_path"), state.get("scanned_files", [])),
    )
    state["project_profile"] = profile
    state["scanned_files"] = files
    return state


def vulnkb_retriever_node(state: dict) -> dict:
    state["vuln_knowledge"] = trace_tool(
        state,
        "vulnkb_retriever_node",
        "VulnKBRetrieverTool",
        f"{len(state.get('project_profile', {}).risk_surfaces if state.get('project_profile') else [])} risk surfaces",
        lambda: VulnKBRetrieverTool().run(state.get("project_profile"), state.get("mode", "")),
    )
    return state


def tool_selector_node(state: dict) -> dict:
    state["tool_plan"] = trace_tool(
        state,
        "tool_selector_node",
        "ToolSelectorTool",
        state.get("mode", "repo_scan"),
        lambda: ToolSelectorTool().run(
            state.get("project_profile"),
            state.get("vuln_knowledge", []),
            state.get("mode", "repo_scan"),
            state.get("scanned_files", []),
        ),
    )
    return state


def tool_executor_node(state: dict) -> dict:
    tool_results, stage_results = trace_tool(
        state,
        "tool_executor_node",
        "ToolExecutorTool",
        ",".join(state.get("tool_plan").selected_tools if state.get("tool_plan") else []),
        lambda: ToolExecutorTool().run(state.get("tool_plan"), state.get("scanned_files", []), state.get("mode", "repo_scan")),
    )
    state["tool_results"] = tool_results
    state["audit_stage_results"] = stage_results
    return state


def finding_merger_node(state: dict) -> dict:
    state["candidate_findings"] = trace_tool(
        state,
        "finding_merger_node",
        "FindingMergerTool",
        f"{len(state.get('tool_results', []))} tool results",
        lambda: FindingMergerTool().run(state.get("tool_results", [])),
    )
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
    evidences = trace_tool(
        state,
        "context_extract_node",
        "ContextExtractorTool",
        f"{len(state.get('candidate_findings', []))} findings",
        lambda: ContextExtractorTool().run(state.get("candidate_findings", []), state.get("scanned_files", [])),
    )
    state["evidences"] = evidences
    evidence_ids = {evidence.finding_id: evidence.evidence_id for evidence in evidences}
    for finding in state.get("candidate_findings", []):
        if finding.finding_id in evidence_ids:
            finding.evidence_ids = [evidence_ids[finding.finding_id]]
    return state


def risk_analyze_node(state: dict) -> dict:
    state["risk_analyses"] = trace_tool(
        state,
        "risk_analyze_node",
        "RiskAnalyzeTool",
        f"{len(state.get('candidate_findings', []))} findings",
        lambda: RiskAnalyzeTool().run(state.get("candidate_findings", []), state.get("evidences", [])),
    )
    return state


def false_positive_review_node(state: dict) -> dict:
    state["review_results"] = trace_tool(
        state,
        "false_positive_review_node",
        "FalsePositiveReviewTool",
        f"{len(state.get('candidate_findings', []))} findings",
        lambda: FalsePositiveReviewTool().run(state.get("candidate_findings", []), state.get("evidences", [])),
    )
    return state


def fix_suggest_node(state: dict) -> dict:
    state["fix_suggestions"] = trace_tool(
        state,
        "fix_suggest_node",
        "FixSuggestTool",
        f"{len(state.get('candidate_findings', []))} findings",
        lambda: FixSuggestTool().run(state.get("candidate_findings", []), state.get("review_results", []), state.get("evidences", [])),
    )
    return state


def report_node(state: dict) -> dict:
    state = sync_audit_state(state)
    state["final_report"] = trace_tool(state, "report_node", "ReportWriterTool", "write report", lambda: ReportWriterTool().run(state))
    return state
