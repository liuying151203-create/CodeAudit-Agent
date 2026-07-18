from __future__ import annotations

from collections.abc import Iterator

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
from app.schemas.enums import AuditDecisionType, AuditStageName
from app.schemas.runtime import AuditProgressEvent


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


def stream_audit(initial_state: AuditState) -> Iterator[tuple[AuditProgressEvent, AuditState]]:
    normalized_state = normalize_audit_state(initial_state)
    app = build_graph()
    last_progress = 0.0
    if app is not None:
        for sequence, update in enumerate(
            app.stream(normalized_state, config={"recursion_limit": 250}, stream_mode="updates"), start=1
        ):
            node_name, node_state = next(iter(update.items()))
            state = sync_audit_state(node_state)
            event = _progress_event(sequence, node_name, state)
            event.progress = max(last_progress, event.progress)
            last_progress = event.progress
            yield event, state
        return
    for event, state in _stream_without_langgraph(normalized_state):
        event.progress = max(last_progress, event.progress)
        last_progress = event.progress
        yield event, state


def run_audit(initial_state: AuditState) -> AuditState:
    final_state: AuditState | None = None
    for _, state in stream_audit(initial_state):
        final_state = state
    if final_state is None:
        raise RuntimeError("Audit workflow completed without emitting state.")
    return sync_audit_state(final_state)


def _stream_without_langgraph(normalized_state: AuditState) -> Iterator[tuple[AuditProgressEvent, AuditState]]:
    sequence = 0
    state = router_node(dict(normalized_state))
    sequence += 1
    yield _progress_event(sequence, "router", state), state
    state = diff_loader_node(state) if state.get("mode") == "diff_scan" else repo_loader_node(state)
    sequence += 1
    yield _progress_event(sequence, "diff_loader" if state.get("mode") == "diff_scan" else "repo_loader", state), state
    for node_name, node in (
        ("project_reader", project_reader_node),
        ("vulnkb_retriever", vulnkb_retriever_node),
        ("audit_planner", audit_planner_node),
    ):
        state = node(state)
        sequence += 1
        yield _progress_event(sequence, node_name, state), state
    while state.get("stage_queue"):
        state = stage_scheduler_node(state)
        sequence += 1
        yield _progress_event(sequence, "stage_scheduler", state), state
        while state.get("current_stage") is not None:
            state = tool_selector_node(state)
            sequence += 1
            yield _progress_event(sequence, "tool_selector", state), state
            state = tool_executor_node(state)
            sequence += 1
            yield _progress_event(sequence, "tool_executor", state), state
            state = evidence_builder_node(state)
            sequence += 1
            yield _progress_event(sequence, "evidence_builder", state), state
            state = audit_reasoner_node(state)
            sequence += 1
            yield _progress_event(sequence, "audit_reasoner", state), state
            decision = state.get("audit_decision")
            if decision and decision.decision == AuditDecisionType.CALL_TOOL:
                continue
            if decision and decision.decision == AuditDecisionType.EMIT_FINDING:
                state = finding_builder_node(state)
                sequence += 1
                yield _progress_event(sequence, "finding_builder", state), state
                continue
            state = stage_finalize_node(state)
            sequence += 1
            yield _progress_event(sequence, "stage_finalize", state), state
    for node_name, node in (
        ("finding_merger", finding_merger_node),
        ("finding_assessor", finding_assessor_node),
        ("fix_suggest", fix_suggest_node),
        ("report", report_node),
    ):
        state = node(state)
        sequence += 1
        yield _progress_event(sequence, node_name, state), state


def _progress_event(sequence: int, node_name: str, state: AuditState) -> AuditProgressEvent:
    phase_by_node = {
        "router": "understanding",
        "repo_loader": "understanding",
        "diff_loader": "understanding",
        "project_reader": "understanding",
        "vulnkb_retriever": "planning",
        "audit_planner": "planning",
        "finding_merger": "review",
        "finding_assessor": "review",
        "fix_suggest": "review",
        "report": "reporting",
    }
    phase = phase_by_node.get(node_name, "auditing")
    current_stage = state.get("current_stage")
    stage = current_stage.stage if current_stage else None
    if node_name == "stage_finalize" and state.get("audit_stage_results"):
        stage = AuditStageName(state["audit_stage_results"][-1].stage_name)
    tool_names = []
    if state.get("current_tool_plan"):
        tool_names = list(state["current_tool_plan"].selected_tools)
    elif node_name == "tool_executor" and state.get("round_tool_results"):
        tool_names = list(dict.fromkeys(item.tool_name for item in state["round_tool_results"]))
    decision = state["audit_decision"].decision.value if state.get("audit_decision") else None
    progress = _progress_value(node_name, state)
    stage_warning = (
        node_name == "stage_finalize"
        and bool(state.get("audit_stage_results"))
        and str(getattr(state["audit_stage_results"][-1].status, "value", state["audit_stage_results"][-1].status))
        != "completed"
    )
    status = "completed" if node_name == "report" else "warning" if stage_warning else "running"
    return AuditProgressEvent(
        sequence=sequence,
        node_name=node_name,
        phase=phase,
        stage=stage,
        progress=progress,
        message=_progress_message(node_name, stage.value if stage else None, tool_names, decision),
        tool_names=tool_names,
        decision=decision,
        status=status,
    )


def _progress_value(node_name: str, state: AuditState) -> float:
    fixed = {
        "router": 0.02,
        "repo_loader": 0.08,
        "diff_loader": 0.08,
        "project_reader": 0.16,
        "vulnkb_retriever": 0.23,
        "audit_planner": 0.30,
        "finding_merger": 0.84,
        "finding_assessor": 0.90,
        "fix_suggest": 0.96,
        "report": 1.0,
    }
    if node_name in fixed:
        return fixed[node_name]
    completed = len(state.get("audit_stage_results", []))
    remaining = len(state.get("stage_queue", []))
    current = 1 if state.get("current_stage") is not None else 0
    total = max(1, completed + remaining + current)
    within = {
        "stage_scheduler": 0.05,
        "tool_selector": 0.18,
        "tool_executor": 0.42,
        "evidence_builder": 0.60,
        "audit_reasoner": 0.78,
        "finding_builder": 0.88,
        "stage_finalize": 1.0,
    }.get(node_name, 0.0)
    completed_before = max(0, completed - (1 if node_name == "stage_finalize" else 0))
    return min(0.82, 0.30 + 0.52 * ((completed_before + within) / total))


def _progress_message(node_name: str, stage: str | None, tools: list[str], decision: str | None) -> str:
    messages = {
        "router": "Validated audit request.",
        "repo_loader": "Loaded repository source files.",
        "diff_loader": "Parsed Git diff and changed lines.",
        "project_reader": "Built the project security profile.",
        "vulnkb_retriever": "Retrieved relevant vulnerability knowledge.",
        "audit_planner": "Created the staged audit plan.",
        "stage_scheduler": f"Started {stage or 'audit'} stage.",
        "tool_selector": f"Selected {', '.join(tools) or 'fallback tools'}.",
        "tool_executor": f"Executed {', '.join(tools) or 'selected tools'}.",
        "evidence_builder": "Built bounded source evidence.",
        "audit_reasoner": f"Audit decision: {decision or 'completed'}.",
        "finding_builder": "Validated and added an evidence-backed finding.",
        "stage_finalize": f"Finalized {stage or 'audit'} stage.",
        "finding_merger": "Merged duplicate findings and provenance.",
        "finding_assessor": "Assessed risk and false-positive likelihood.",
        "fix_suggest": "Generated remediation guidance.",
        "report": "Wrote Markdown, JSON and SARIF reports.",
    }
    return messages.get(node_name, node_name.replace("_", " ").title())
