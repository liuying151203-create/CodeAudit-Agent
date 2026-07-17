from __future__ import annotations

from time import monotonic
from uuid import uuid4

from app.agent.evidence_builder import build_stage_evidence
from app.agent.state import normalize_audit_state, sync_audit_state
from app.agent.tools import (
    AuditPlannerTool,
    AuditReasonerTool,
    FalsePositiveReviewTool,
    FindingMergerTool,
    FixSuggestTool,
    GitDiffTool,
    ProjectReaderTool,
    RepoLoaderTool,
    ReportWriterTool,
    RiskAnalyzeTool,
    ToolExecutorTool,
    ToolSelectorTool,
    VulnKBRetrieverTool,
)
from app.schemas.enums import AuditDecisionType, FindingStatus, StageStatus
from app.schemas.finding import Finding
from app.schemas.planning import AuditPlan
from app.schemas.project import ToolPlan
from app.schemas.runtime import AuditError, AuditHypothesis, AuditLoopRuntime, AuditStageResult, FallbackRecord
from app.schemas.execution import ToolRequest
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
    state["scanned_files"] = trace_tool(
        state,
        "repo_loader_node",
        "RepoLoaderTool",
        str(state.get("repo_path")),
        lambda: RepoLoaderTool().run(state["repo_path"]),
    )
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
        f"{len(state.get('project_profile').risk_surfaces if state.get('project_profile') else [])} risk surfaces",
        lambda: VulnKBRetrieverTool().run(state.get("project_profile"), state.get("user_task") or ""),
    )
    return state


def audit_planner_node(state: dict) -> dict:
    state["audit_plan"] = trace_tool(
        state,
        "audit_planner_node",
        "AuditPlannerTool",
        f"{len(state.get('vuln_knowledge', []))} knowledge entries",
        lambda: AuditPlannerTool().run(
            state.get("project_profile"),
            state.get("vuln_knowledge", []),
            state.get("user_task") or "",
            state.get("mode", "repo_scan"),
        ),
    )
    state["stage_queue"] = list(state["audit_plan"].stages)
    state["loop_runtime"] = AuditLoopRuntime(audit_started_at=monotonic())
    return state


def stage_scheduler_node(state: dict) -> dict:
    queue = list(state.get("stage_queue", []))
    if not queue:
        state["current_stage"] = None
        return state
    stage = queue.pop(0)
    state["stage_queue"] = queue
    state["current_stage"] = stage
    previous_loop = state.get("loop_runtime") or AuditLoopRuntime()
    state["loop_runtime"] = AuditLoopRuntime(
        audit_started_at=previous_loop.audit_started_at or monotonic(),
        stage_started_at=monotonic(),
    )
    state["budget"].used_tokens = 0
    requests = [
        ToolRequest(
            stage=stage.stage,
            required_capability=capability,
            target_files=stage.target_files[: state["budget"].max_files_per_call],
            risk_types=stage.risk_types,
            reason=f"Initial capability required by {stage.stage.value} stage.",
        )
        for capability in stage.required_capabilities
    ]
    state["pending_tool_requests"] = requests
    state["tool_requests"] = [*state.get("tool_requests", []), *requests]
    state["current_tool_plan"] = None
    state["round_tool_results"] = []
    state["audit_decision"] = None
    state["pending_finding"] = None
    _append_trace(state, "stage_scheduler_node", stage=stage.stage.value, decision="START_STAGE", output=f"{len(requests)} initial requests")
    return state


def tool_selector_node(state: dict) -> dict:
    stage = state.get("current_stage")
    requests = list(state.get("pending_tool_requests", []))
    if stage is None:
        state["current_tool_plan"] = ToolPlan()
        return state
    if state["loop_runtime"].current_round >= state["budget"].max_tool_rounds_per_stage:
        state["current_tool_plan"] = ToolPlan(selection_reason="Stage tool-round budget exhausted.")
        state["pending_tool_requests"] = []
        _append_trace(state, "tool_selector_node", stage=stage.stage.value, decision="BUDGET_REJECTED", output="No additional tool calls allowed.")
        return state
    request_stage = stage.model_copy(
        update={
            "required_capabilities": list(dict.fromkeys(request.required_capability for request in requests)) or stage.required_capabilities,
            "target_files": list(dict.fromkeys(path for request in requests for path in request.target_files)) or stage.target_files,
            "risk_types": list(dict.fromkeys(risk for request in requests for risk in request.risk_types)) or stage.risk_types,
        }
    )
    request_plan = AuditPlan(summary=f"Current {stage.stage.value} stage", stages=[request_stage], planner_source="stage_scheduler")
    try:
        round_plan = trace_tool(
            state,
            "tool_selector_node",
            "ToolSelectorTool",
            ",".join(request_stage.required_capabilities),
            lambda: ToolSelectorTool().run(
                state.get("project_profile"),
                state.get("vuln_knowledge", []),
                state.get("mode", "repo_scan"),
                state.get("scanned_files", []),
                request_plan,
                state.get("repo_path"),
                state.get("budget"),
                True,
            ),
        )
    except Exception as exc:  # pragma: no cover - defensive stage recovery
        _record_stage_error(state, "tool_selector", exc)
        round_plan = ToolPlan(selection_reason=f"Tool selection failed: {exc}")

    loop = state["loop_runtime"]
    unseen_calls = [call for call in round_plan.tool_calls if _call_signature(call) not in set(loop.executed_call_signatures)]
    unseen_calls = unseen_calls[: state["budget"].max_tool_calls_per_round]
    actual_tools = list(dict.fromkeys(call.tool_name for call in unseen_calls))
    current_plan = round_plan.model_copy(update={"tool_calls": unseen_calls, "selected_tools": actual_tools})
    state["current_tool_plan"] = current_plan
    state["validated_tool_calls"] = [*state.get("validated_tool_calls", []), *unseen_calls]
    state["pending_tool_requests"] = []
    state["tool_plan"] = _merge_tool_plans(state.get("tool_plan"), current_plan)
    _annotate_latest_trace(state, stage.stage.value, tool_calls=[call.tool_name for call in unseen_calls])
    return state


def tool_executor_node(state: dict) -> dict:
    stage = state.get("current_stage")
    plan = state.get("current_tool_plan") or ToolPlan()
    try:
        results = trace_tool(
            state,
            "tool_executor_node",
            "ToolExecutorTool",
            ",".join(plan.selected_tools),
            lambda: ToolExecutorTool().run(plan, state.get("scanned_files", []), state.get("mode", "repo_scan"), state.get("repo_path")),
        )
    except Exception as exc:  # pragma: no cover - defensive stage recovery
        _record_stage_error(state, "tool_executor", exc)
        results = []
    state["round_tool_results"] = results
    state["tool_results"] = [*state.get("tool_results", []), *results]
    loop = state["loop_runtime"]
    if plan.tool_calls:
        loop.current_round += 1
        stage_key = stage.stage.value if stage else "unknown"
        state["budget"].used_tool_rounds[stage_key] = loop.current_round
        state["budget"].used_tool_calls += len(plan.tool_calls)
        loop.executed_call_signatures.extend(_call_signature(call) for call in plan.tool_calls)
    for reason in plan.fallback_reasons:
        if reason not in loop.fallback_reasons:
            loop.fallback_reasons.append(reason)
    for result in results:
        if result.error_message:
            loop.errors.append(f"{result.tool_name}: {result.error_message}")
    if stage:
        _annotate_latest_trace(state, stage.stage.value, tool_calls=[call.tool_name for call in plan.tool_calls])
    return state


def evidence_builder_node(state: dict) -> dict:
    stage = state.get("current_stage")
    if stage is None:
        return state
    try:
        evidences, new_count = trace_tool(
            state,
            "evidence_builder_node",
            "EvidenceBuilder",
            f"{len(state.get('round_tool_results', []))} tool results",
            lambda: build_stage_evidence(
                state.get("round_tool_results", []),
                state.get("scanned_files", []),
                stage.stage,
                stage.risk_types,
                state.get("evidences", []),
                state["budget"].max_context_lines_per_file,
            ),
        )
    except Exception as exc:  # pragma: no cover - defensive stage recovery
        _record_stage_error(state, "evidence_builder", exc)
        evidences, new_count = state.get("evidences", []), 0
    state["evidences"] = evidences
    loop = state["loop_runtime"]
    loop.new_evidence_count = new_count
    if state.get("current_tool_plan") and state["current_tool_plan"].tool_calls:
        loop.no_progress_rounds = 0 if new_count else loop.no_progress_rounds + 1
    _annotate_latest_trace(state, stage.stage.value, output=f"{new_count} new evidence items")
    return state


def audit_reasoner_node(state: dict) -> dict:
    stage = state.get("current_stage")
    if stage is None:
        return state
    try:
        decision = trace_tool(
            state,
            "audit_reasoner_node",
            "AuditReasonerTool",
            f"stage={stage.stage.value} round={state['loop_runtime'].current_round}",
            lambda: AuditReasonerTool().run(
                stage,
                state.get("tool_results", []),
                state.get("evidences", []),
                state.get("candidate_findings", []),
                state.get("scanned_files", []),
                state.get("budget"),
                state.get("loop_runtime"),
                state.get("vuln_knowledge", []),
            ),
        )
    except Exception as exc:  # pragma: no cover - defensive stage recovery
        _record_stage_error(state, "audit_reasoner", exc)
        from app.schemas.runtime import AuditDecision

        decision = AuditDecision(decision=AuditDecisionType.FINISH_STAGE, reason=f"Reasoner failed: {exc}", decision_source="error")
    state["audit_decision"] = decision
    loop = state["loop_runtime"]
    loop.decision_count += 1
    state["budget"].used_tokens += decision.token_usage
    state["metrics"].total_tokens += decision.token_usage
    if decision.fallback_reason and decision.fallback_reason not in loop.fallback_reasons:
        loop.fallback_reasons.append(decision.fallback_reason)
    if decision.decision == AuditDecisionType.CALL_TOOL and decision.tool_request:
        state["pending_tool_requests"] = [decision.tool_request]
        state["tool_requests"] = [*state.get("tool_requests", []), decision.tool_request]
    elif decision.decision == AuditDecisionType.EMIT_FINDING:
        state["pending_finding"] = decision.finding
    else:
        if decision.decision_source in {"budget", "budget_exhausted"} or "budget exhausted" in decision.reason.lower():
            loop.termination_reason = "budget_exhausted"
        else:
            loop.termination_reason = decision.reason
    _annotate_latest_trace(
        state,
        stage.stage.value,
        decision=decision.decision.value,
        llm_used=decision.decision_source == "llm",
        token_usage=decision.token_usage,
        fallback_reason=decision.fallback_reason,
    )
    return state


def finding_builder_node(state: dict) -> dict:
    draft = state.get("pending_finding")
    stage = state.get("current_stage")
    if draft is None or stage is None:
        return state
    evidence_map = {item.evidence_id: item for item in state.get("evidences", [])}
    fingerprint = f"{draft.risk_type.lower()}:{draft.file_path}:{draft.line_start}:{draft.line_end}"
    valid_evidence = [evidence_map[evidence_id] for evidence_id in draft.evidence_ids if evidence_id in evidence_map]
    duplicate = fingerprint in {f"{(item.risk_type or item.category).lower()}:{item.file_path}:{item.line_start}:{item.line_end}" for item in state.get("candidate_findings", [])}
    if valid_evidence and not duplicate:
        finding = Finding(
            finding_id=f"agent:{draft.rule_id}:{draft.file_path}:{draft.line_start}:{uuid4().hex[:8]}",
            rule_id=draft.rule_id,
            file_path=draft.file_path,
            line_start=draft.line_start,
            line_end=draft.line_end,
            severity=draft.severity.value,
            category=draft.risk_type,
            risk_type=draft.risk_type,
            message=draft.message,
            evidence_text=valid_evidence[0].code_snippet or valid_evidence[0].code_context,
            evidence_ids=draft.evidence_ids,
            stage=draft.stage,
            source=draft.source,
            sources=[draft.source],
            source_rule_ids=[draft.rule_id],
            confidence=draft.confidence,
            status=FindingStatus.CANDIDATE,
            analysis_source=state.get("audit_decision").decision_source if state.get("audit_decision") else "template",
        )
        state["candidate_findings"] = [*state.get("candidate_findings", []), finding]
        state["loop_runtime"].emitted_finding_fingerprints.append(fingerprint)
        _append_trace(state, "finding_builder_node", stage=stage.stage.value, decision="FINDING_ACCEPTED", output=finding.finding_id)
    elif not duplicate:
        hypothesis = AuditHypothesis(
            hypothesis_id=f"hypothesis-{uuid4().hex[:10]}",
            stage=stage.stage,
            risk_type=draft.risk_type,
            description=f"Rejected finding draft without valid evidence: {draft.message}",
            target_files=[draft.file_path],
            evidence_ids=draft.evidence_ids,
            status="rejected",
        )
        state["audit_hypotheses"] = [*state.get("audit_hypotheses", []), hypothesis]
        _append_trace(state, "finding_builder_node", stage=stage.stage.value, decision="FINDING_REJECTED", output=hypothesis.hypothesis_id)
    state["pending_finding"] = None
    return state


def stage_finalize_node(state: dict) -> dict:
    stage = state.get("current_stage")
    if stage is None:
        return state
    loop = state["loop_runtime"]
    stage_results = [result for result in state.get("tool_results", []) if result.stage == stage.stage]
    stage_evidence = [item for item in state.get("evidences", []) if item.stage == stage.stage]
    stage_findings = [item for item in state.get("candidate_findings", []) if item.stage == stage.stage or item.category in stage.risk_types]
    finding_fingerprints = {
        f"{(item.risk_type or item.category).lower()}:{item.file_path}:{item.line_start}:{item.line_end}"
        for item in stage_findings
    }
    finding_fingerprints.update(
        f"{(item.risk_type or item.category).lower()}:{item.file_path}:{item.line_start}:{item.line_end}"
        for tool_result in stage_results
        for item in tool_result.findings
    )
    hypotheses = [item for item in state.get("audit_hypotheses", []) if item.stage == stage.stage]
    status = StageStatus.BUDGET_EXHAUSTED if loop.termination_reason == "budget_exhausted" else StageStatus.PARTIAL if loop.errors else StageStatus.COMPLETED
    result = AuditStageResult(
        stage_name=stage.stage.value,
        status=status,
        findings_count=len(finding_fingerprints),
        summary=loop.termination_reason or "Stage completed.",
        tool_call_ids=[item.call_id for item in stage_results if item.call_id],
        evidence_ids=[item.evidence_id for item in stage_evidence],
        hypothesis_ids=[item.hypothesis_id for item in hypotheses],
        fallback_reasons=loop.fallback_reasons,
        errors=loop.errors,
        metrics={
            "tool_rounds": loop.current_round,
            "decisions": loop.decision_count,
            "new_evidence": len(stage_evidence),
            "elapsed_ms": int((monotonic() - loop.stage_started_at) * 1000),
        },
    )
    state["audit_stage_results"] = [*state.get("audit_stage_results", []), result]
    for reason in loop.fallback_reasons:
        record = FallbackRecord(component="audit_reasoner", reason=reason, strategy="template", stage=stage.stage)
        if record not in state.get("fallbacks", []):
            state["fallbacks"] = [*state.get("fallbacks", []), record]
    _append_trace(state, "stage_finalize_node", stage=stage.stage.value, decision=status.value, output=result.summary)
    state["current_stage"] = None
    state["current_tool_plan"] = None
    state["round_tool_results"] = []
    state["audit_decision"] = None
    state["pending_tool_requests"] = []
    state["pending_finding"] = None
    return state


def finding_merger_node(state: dict) -> dict:
    merged = trace_tool(
        state,
        "finding_merger_node",
        "FindingMergerTool",
        f"{len(state.get('tool_results', []))} tool results",
        lambda: FindingMergerTool().run(state.get("tool_results", []), state.get("candidate_findings", [])),
    )
    state["merged_findings"] = merged
    state["candidate_findings"] = merged
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


def route_audit_decision(state: dict) -> str:
    decision = state.get("audit_decision")
    if decision and decision.decision == AuditDecisionType.CALL_TOOL:
        return "call_tool"
    if decision and decision.decision == AuditDecisionType.EMIT_FINDING:
        return "emit_finding"
    return "finish_stage"


def route_stage_completion(state: dict) -> str:
    return "has_next_stage" if state.get("stage_queue") else "all_finished"


def _merge_tool_plans(existing: ToolPlan | None, current: ToolPlan) -> ToolPlan:
    if existing is None:
        return current
    return ToolPlan(
        selected_tools=list(dict.fromkeys([*existing.selected_tools, *current.selected_tools])),
        selected_risk_types=list(dict.fromkeys([*existing.selected_risk_types, *current.selected_risk_types])),
        target_files=list(dict.fromkeys([*existing.target_files, *current.target_files])),
        selection_reason="; ".join(value for value in (existing.selection_reason, current.selection_reason) if value),
        tool_calls=[*existing.tool_calls, *current.tool_calls],
        unavailable_tools=list(dict.fromkeys([*existing.unavailable_tools, *current.unavailable_tools])),
        rejected_targets=list(dict.fromkeys([*existing.rejected_targets, *current.rejected_targets])),
        fallback_reasons=list(dict.fromkeys([*existing.fallback_reasons, *current.fallback_reasons])),
    )


def _call_signature(call: object) -> str:
    return f"{getattr(call, 'tool_name', '')}|{','.join(getattr(call, 'target_files', []))}"


def _record_stage_error(state: dict, component: str, exc: Exception) -> None:
    stage = state.get("current_stage")
    message = f"{type(exc).__name__}: {exc}"
    state.setdefault("errors", []).append(AuditError(component=component, message=message, stage=stage.stage if stage else None))
    state["loop_runtime"].errors.append(f"{component}: {message}")


def _append_trace(state: dict, node: str, stage: str | None = None, decision: str | None = None, output: str = "completed") -> None:
    from app.schemas.report import AgentTrace

    state.setdefault("traces", []).append(AgentTrace(node_name=node, stage=stage, decision=decision, output_summary=output))


def _annotate_latest_trace(
    state: dict,
    stage: str,
    decision: str | None = None,
    tool_calls: list[str] | None = None,
    output: str | None = None,
    llm_used: bool = False,
    token_usage: int = 0,
    fallback_reason: str | None = None,
) -> None:
    if not state.get("traces"):
        return
    trace = state["traces"][-1]
    trace.stage = stage
    trace.decision = decision
    trace.tool_calls = tool_calls or trace.tool_calls
    trace.llm_used = llm_used
    trace.token_usage = token_usage
    trace.fallback_used = bool(fallback_reason)
    trace.fallback_reason = fallback_reason
    if output is not None:
        trace.output_summary = output
