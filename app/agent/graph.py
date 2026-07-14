from __future__ import annotations

try:
    from langgraph.graph import END, StateGraph
except Exception:  # pragma: no cover - dependency fallback
    END = None
    StateGraph = None

from app.agent.nodes import (
    audit_planner_node,
    context_extract_node,
    diff_loader_node,
    finding_merger_node,
    false_positive_review_node,
    fix_suggest_node,
    project_reader_node,
    repo_loader_node,
    report_node,
    risk_analyze_node,
    router_node,
    static_scan_node,
    tool_executor_node,
    tool_selector_node,
    vulnkb_retriever_node,
)
from app.agent.state import AuditState, normalize_audit_state, sync_audit_state


def _route(state: AuditState) -> str:
    return "diff_loader" if state.get("mode") == "diff_scan" else "repo_loader"


def build_graph():
    if StateGraph is None:
        return None
    graph = StateGraph(AuditState)
    graph.add_node("router", router_node)
    graph.add_node("repo_loader", repo_loader_node)
    graph.add_node("diff_loader", diff_loader_node)
    graph.add_node("project_reader", project_reader_node)
    graph.add_node("vulnkb_retriever", vulnkb_retriever_node)
    graph.add_node("audit_planner", audit_planner_node)
    graph.add_node("tool_selector", tool_selector_node)
    graph.add_node("tool_executor", tool_executor_node)
    graph.add_node("finding_merger", finding_merger_node)
    graph.add_node("static_scan", static_scan_node)
    graph.add_node("context_extract", context_extract_node)
    graph.add_node("risk_analyze", risk_analyze_node)
    graph.add_node("false_positive_review", false_positive_review_node)
    graph.add_node("fix_suggest", fix_suggest_node)
    graph.add_node("report", report_node)
    graph.set_entry_point("router")
    graph.add_conditional_edges("router", _route, {"repo_loader": "repo_loader", "diff_loader": "diff_loader"})
    graph.add_edge("repo_loader", "project_reader")
    graph.add_edge("diff_loader", "project_reader")
    graph.add_edge("project_reader", "vulnkb_retriever")
    graph.add_edge("vulnkb_retriever", "audit_planner")
    graph.add_edge("audit_planner", "tool_selector")
    graph.add_edge("tool_selector", "tool_executor")
    graph.add_edge("tool_executor", "finding_merger")
    graph.add_edge("finding_merger", "context_extract")
    graph.add_edge("context_extract", "risk_analyze")
    graph.add_edge("risk_analyze", "false_positive_review")
    graph.add_edge("false_positive_review", "fix_suggest")
    graph.add_edge("fix_suggest", "report")
    graph.add_edge("report", END)
    return graph.compile()


def run_audit(initial_state: AuditState) -> AuditState:
    normalized_state = normalize_audit_state(initial_state)
    app = build_graph()
    if app is not None:
        return sync_audit_state(app.invoke(normalized_state))
    state = router_node(dict(normalized_state))
    if state.get("mode") == "diff_scan":
        state = diff_loader_node(state)
    for node in [
        project_reader_node,
        vulnkb_retriever_node,
        audit_planner_node,
        tool_selector_node,
        tool_executor_node,
        finding_merger_node,
        context_extract_node,
        risk_analyze_node,
        false_positive_review_node,
        fix_suggest_node,
        report_node,
    ]:
        state = node(state)
    return sync_audit_state(state)
