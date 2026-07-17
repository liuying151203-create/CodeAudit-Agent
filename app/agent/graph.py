from __future__ import annotations

try:
    from langgraph.graph import END, StateGraph
except Exception:  # pragma: no cover - dependency fallback
    END = None
    StateGraph = None

from app.agent.nodes import (
    audit_planner_node,
    audit_reasoner_node,
    diff_loader_node,
    evidence_builder_node,
    finding_assessor_node,
    finding_builder_node,
    finding_merger_node,
    fix_suggest_node,
    project_reader_node,
    repo_loader_node,
    report_node,
    route_audit_decision,
    route_stage_completion,
    router_node,
    stage_finalize_node,
    stage_scheduler_node,
    tool_executor_node,
    tool_selector_node,
    vulnkb_retriever_node,
)
from app.agent.state import AuditState, normalize_audit_state, sync_audit_state
from app.schemas.enums import AuditDecisionType


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
    graph.add_node("stage_scheduler", stage_scheduler_node)
    graph.add_node("tool_selector", tool_selector_node)
    graph.add_node("tool_executor", tool_executor_node)
    graph.add_node("evidence_builder", evidence_builder_node)
    graph.add_node("audit_reasoner", audit_reasoner_node)
    graph.add_node("finding_builder", finding_builder_node)
    graph.add_node("stage_finalize", stage_finalize_node)
    graph.add_node("finding_merger", finding_merger_node)
    graph.add_node("finding_assessor", finding_assessor_node)
    graph.add_node("fix_suggest", fix_suggest_node)
    graph.add_node("report", report_node)
    graph.set_entry_point("router")
    graph.add_conditional_edges("router", _route, {"repo_loader": "repo_loader", "diff_loader": "diff_loader"})
    graph.add_edge("repo_loader", "project_reader")
    graph.add_edge("diff_loader", "project_reader")
    graph.add_edge("project_reader", "vulnkb_retriever")
    graph.add_edge("vulnkb_retriever", "audit_planner")
    graph.add_edge("audit_planner", "stage_scheduler")
    graph.add_edge("stage_scheduler", "tool_selector")
    graph.add_edge("tool_selector", "tool_executor")
    graph.add_edge("tool_executor", "evidence_builder")
    graph.add_edge("evidence_builder", "audit_reasoner")
    graph.add_conditional_edges(
        "audit_reasoner",
        route_audit_decision,
        {"call_tool": "tool_selector", "emit_finding": "finding_builder", "finish_stage": "stage_finalize"},
    )
    graph.add_edge("finding_builder", "audit_reasoner")
    graph.add_conditional_edges(
        "stage_finalize",
        route_stage_completion,
        {"has_next_stage": "stage_scheduler", "all_finished": "finding_merger"},
    )
    graph.add_edge("finding_merger", "finding_assessor")
    graph.add_edge("finding_assessor", "fix_suggest")
    graph.add_edge("fix_suggest", "report")
    graph.add_edge("report", END)
    return graph.compile()


def run_audit(initial_state: AuditState) -> AuditState:
    normalized_state = normalize_audit_state(initial_state)
    app = build_graph()
    if app is not None:
        return sync_audit_state(app.invoke(normalized_state, config={"recursion_limit": 250}))
    state = router_node(dict(normalized_state))
    state = diff_loader_node(state) if state.get("mode") == "diff_scan" else repo_loader_node(state)
    for node in (project_reader_node, vulnkb_retriever_node, audit_planner_node):
        state = node(state)
    while state.get("stage_queue"):
        state = stage_scheduler_node(state)
        while state.get("current_stage") is not None:
            state = tool_selector_node(state)
            state = tool_executor_node(state)
            state = evidence_builder_node(state)
            state = audit_reasoner_node(state)
            decision = state.get("audit_decision")
            if decision and decision.decision == AuditDecisionType.CALL_TOOL:
                continue
            if decision and decision.decision == AuditDecisionType.EMIT_FINDING:
                state = finding_builder_node(state)
                continue
            state = stage_finalize_node(state)
    for node in (finding_merger_node, finding_assessor_node, fix_suggest_node, report_node):
        state = node(state)
    return sync_audit_state(state)
