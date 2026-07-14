from __future__ import annotations

from enum import Enum
from typing import Any, TypedDict, cast

from app.schemas.evidence import Evidence
from app.schemas.execution import ToolRequest, ToolRunResult, ValidatedToolCall
from app.schemas.finding import Finding, FixSuggestion, ReviewResult, RiskAnalysis
from app.schemas.planning import AuditPlan, AuditStagePlan
from app.schemas.project import AuditStageResult, ProjectProfile, ToolPlan, VulnKnowledge
from app.schemas.report import AgentTrace, AuditReport
from app.schemas.runtime import AuditBudget, AuditError, AuditHypothesis, AuditMetrics, FallbackRecord


class RequestSection(TypedDict, total=False):
    mode: str
    repo_path: str | None
    diff_text: str | None
    diff_mode: str | None
    user_task: str | None


class ProjectContextSection(TypedDict, total=False):
    scanned_files: list[dict[str, Any]]
    changed_files: list[dict[str, Any]]
    project_profile: ProjectProfile | None
    retrieved_knowledge: list[VulnKnowledge]


class PlanningSection(TypedDict, total=False):
    audit_plan: AuditPlan | None
    stage_queue: list[AuditStagePlan]
    current_stage: AuditStagePlan | None
    stage_results: list[AuditStageResult]
    legacy_tool_plan: ToolPlan | None


class ExecutionSection(TypedDict, total=False):
    tool_requests: list[ToolRequest]
    validated_tool_calls: list[ValidatedToolCall]
    tool_results: list[ToolRunResult]
    evidence_pool: list[Evidence]
    audit_hypotheses: list[AuditHypothesis]


class FindingSection(TypedDict, total=False):
    candidate_findings: list[Finding]
    merged_findings: list[Finding]
    risk_analyses: list[RiskAnalysis]
    review_results: list[ReviewResult]
    confirmed_findings: list[Finding]
    fix_suggestions: list[FixSuggestion]


class RuntimeSection(TypedDict, total=False):
    budget: AuditBudget
    metrics: AuditMetrics
    fallbacks: list[FallbackRecord]
    errors: list[AuditError | str]
    traces: list[AgentTrace]


class AuditState(TypedDict, total=False):
    request: RequestSection
    project_context: ProjectContextSection
    planning: PlanningSection
    execution: ExecutionSection
    findings: FindingSection
    runtime: RuntimeSection

    # Compatibility fields used by the current linear workflow.
    mode: str
    repo_path: str | None
    diff_text: str | None
    diff_mode: str | None
    user_task: str | None
    changed_files: list[dict[str, Any]]
    scanned_files: list[dict[str, Any]]
    project_profile: ProjectProfile | None
    vuln_knowledge: list[VulnKnowledge]
    audit_plan: AuditPlan | None
    stage_queue: list[AuditStagePlan]
    current_stage: AuditStagePlan | None
    tool_plan: ToolPlan | None
    tool_requests: list[ToolRequest]
    validated_tool_calls: list[ValidatedToolCall]
    tool_results: list[ToolRunResult]
    audit_stage_results: list[AuditStageResult]
    audit_hypotheses: list[AuditHypothesis]
    candidate_findings: list[Finding]
    merged_findings: list[Finding]
    evidences: list[Evidence]
    risk_analyses: list[RiskAnalysis]
    review_results: list[ReviewResult]
    confirmed_findings: list[Finding]
    fix_suggestions: list[FixSuggestion]
    budget: AuditBudget
    metrics: AuditMetrics
    fallbacks: list[FallbackRecord]
    final_report: AuditReport
    traces: list[AgentTrace]
    errors: list[AuditError | str]


def normalize_audit_state(initial_state: AuditState | dict[str, Any]) -> AuditState:
    state = cast(AuditState, dict(initial_state))
    request = dict(state.get("request") or {})
    for key in ("mode", "repo_path", "diff_text", "diff_mode", "user_task"):
        if key not in state and key in request:
            state[key] = request[key]  # type: ignore[literal-required]

    project_context = dict(state.get("project_context") or {})
    _hydrate_flat_fields(
        state,
        project_context,
        {
            "scanned_files": "scanned_files",
            "changed_files": "changed_files",
            "project_profile": "project_profile",
            "vuln_knowledge": "retrieved_knowledge",
        },
    )
    planning = dict(state.get("planning") or {})
    _hydrate_flat_fields(
        state,
        planning,
        {
            "audit_plan": "audit_plan",
            "stage_queue": "stage_queue",
            "current_stage": "current_stage",
            "audit_stage_results": "stage_results",
            "tool_plan": "legacy_tool_plan",
        },
    )
    execution = dict(state.get("execution") or {})
    _hydrate_flat_fields(
        state,
        execution,
        {
            "tool_requests": "tool_requests",
            "validated_tool_calls": "validated_tool_calls",
            "tool_results": "tool_results",
            "evidences": "evidence_pool",
            "audit_hypotheses": "audit_hypotheses",
        },
    )
    finding_state = dict(state.get("findings") or {})
    _hydrate_flat_fields(
        state,
        finding_state,
        {
            "candidate_findings": "candidate_findings",
            "merged_findings": "merged_findings",
            "risk_analyses": "risk_analyses",
            "review_results": "review_results",
            "confirmed_findings": "confirmed_findings",
            "fix_suggestions": "fix_suggestions",
        },
    )
    runtime = dict(state.get("runtime") or {})
    _hydrate_flat_fields(
        state,
        runtime,
        {
            "budget": "budget",
            "metrics": "metrics",
            "fallbacks": "fallbacks",
            "errors": "errors",
            "traces": "traces",
        },
    )

    state.setdefault("changed_files", [])
    state.setdefault("scanned_files", [])
    state.setdefault("vuln_knowledge", [])
    state.setdefault("stage_queue", [])
    state.setdefault("tool_requests", [])
    state.setdefault("validated_tool_calls", [])
    state.setdefault("tool_results", [])
    state.setdefault("audit_stage_results", [])
    state.setdefault("audit_hypotheses", [])
    state.setdefault("candidate_findings", [])
    state.setdefault("merged_findings", [])
    state.setdefault("evidences", [])
    state.setdefault("risk_analyses", [])
    state.setdefault("review_results", [])
    state.setdefault("confirmed_findings", [])
    state.setdefault("fix_suggestions", [])
    state.setdefault("fallbacks", [])
    state.setdefault("traces", [])
    state.setdefault("errors", [])
    state["project_profile"] = _coerce_optional_model(state.get("project_profile"), ProjectProfile)
    state["vuln_knowledge"] = _coerce_model_list(state.get("vuln_knowledge", []), VulnKnowledge)
    state["audit_plan"] = _coerce_optional_model(state.get("audit_plan"), AuditPlan)
    state["stage_queue"] = _coerce_model_list(state.get("stage_queue", []), AuditStagePlan)
    state["current_stage"] = _coerce_optional_model(state.get("current_stage"), AuditStagePlan)
    state["tool_plan"] = _coerce_optional_model(state.get("tool_plan"), ToolPlan)
    state["tool_requests"] = _coerce_model_list(state.get("tool_requests", []), ToolRequest)
    state["validated_tool_calls"] = _coerce_model_list(state.get("validated_tool_calls", []), ValidatedToolCall)
    state["tool_results"] = _coerce_model_list(state.get("tool_results", []), ToolRunResult)
    state["audit_stage_results"] = _coerce_model_list(state.get("audit_stage_results", []), AuditStageResult)
    state["audit_hypotheses"] = _coerce_model_list(state.get("audit_hypotheses", []), AuditHypothesis)
    state["candidate_findings"] = _coerce_model_list(state.get("candidate_findings", []), Finding)
    state["merged_findings"] = _coerce_model_list(state.get("merged_findings", []), Finding)
    state["evidences"] = _coerce_model_list(state.get("evidences", []), Evidence)
    state["risk_analyses"] = _coerce_model_list(state.get("risk_analyses", []), RiskAnalysis)
    state["review_results"] = _coerce_model_list(state.get("review_results", []), ReviewResult)
    state["confirmed_findings"] = _coerce_model_list(state.get("confirmed_findings", []), Finding)
    state["fix_suggestions"] = _coerce_model_list(state.get("fix_suggestions", []), FixSuggestion)
    state["fallbacks"] = _coerce_model_list(state.get("fallbacks", []), FallbackRecord)
    state["traces"] = _coerce_model_list(state.get("traces", []), AgentTrace)
    state["budget"] = _coerce_model(state.get("budget"), AuditBudget)
    state["metrics"] = _coerce_model(state.get("metrics"), AuditMetrics)
    return sync_audit_state(state)


def sync_audit_state(state: AuditState) -> AuditState:
    request = dict(state.get("request") or {})
    request.update(
        {
            "mode": state.get("mode", request.get("mode", "repo_scan")),
            "repo_path": state.get("repo_path", request.get("repo_path")),
            "diff_text": state.get("diff_text", request.get("diff_text")),
            "diff_mode": state.get("diff_mode", request.get("diff_mode")),
            "user_task": state.get("user_task", request.get("user_task")),
        }
    )
    state["request"] = cast(RequestSection, request)

    project_context = dict(state.get("project_context") or {})
    project_context.update(
        {
            "scanned_files": state.get("scanned_files", []),
            "changed_files": state.get("changed_files", []),
            "project_profile": state.get("project_profile"),
            "retrieved_knowledge": state.get("vuln_knowledge", []),
        }
    )
    state["project_context"] = cast(ProjectContextSection, project_context)

    planning = dict(state.get("planning") or {})
    planning.update(
        {
            "audit_plan": state.get("audit_plan"),
            "stage_queue": state.get("stage_queue", []),
            "current_stage": state.get("current_stage"),
            "stage_results": state.get("audit_stage_results", []),
            "legacy_tool_plan": state.get("tool_plan"),
        }
    )
    state["planning"] = cast(PlanningSection, planning)

    execution = dict(state.get("execution") or {})
    execution.update(
        {
            "tool_requests": state.get("tool_requests", []),
            "validated_tool_calls": state.get("validated_tool_calls", []),
            "tool_results": state.get("tool_results", []),
            "evidence_pool": state.get("evidences", []),
            "audit_hypotheses": state.get("audit_hypotheses", []),
        }
    )
    state["execution"] = cast(ExecutionSection, execution)

    finding_state = dict(state.get("findings") or {})
    finding_state.update(
        {
            "candidate_findings": state.get("candidate_findings", []),
            "merged_findings": state.get("merged_findings", []),
            "risk_analyses": state.get("risk_analyses", []),
            "review_results": state.get("review_results", []),
            "confirmed_findings": state.get("confirmed_findings", []),
            "fix_suggestions": state.get("fix_suggestions", []),
        }
    )
    state["findings"] = cast(FindingSection, finding_state)

    runtime = dict(state.get("runtime") or {})
    runtime.update(
        {
            "budget": _coerce_model(state.get("budget") or runtime.get("budget"), AuditBudget),
            "metrics": _coerce_model(state.get("metrics") or runtime.get("metrics"), AuditMetrics),
            "fallbacks": state.get("fallbacks", []),
            "errors": state.get("errors", []),
            "traces": state.get("traces", []),
        }
    )
    state["budget"] = runtime["budget"]
    state["metrics"] = runtime["metrics"]
    state["runtime"] = cast(RuntimeSection, runtime)
    return state


def serialize_audit_state(state: AuditState) -> dict[str, Any]:
    synced = sync_audit_state(state)
    sections = {key: synced[key] for key in ("request", "project_context", "planning", "execution", "findings", "runtime")}
    snapshot = cast(dict[str, Any], _serialize_value(sections))
    if snapshot["request"].get("diff_text"):
        snapshot["request"]["diff_text"] = "<omitted from report snapshot>"
    for key in ("scanned_files", "changed_files"):
        snapshot["project_context"][key] = [_serialize_file_reference(item) for item in snapshot["project_context"].get(key, [])]
    return snapshot


def _coerce_model(value: Any, model_type: type[Any]) -> Any:
    if isinstance(value, model_type):
        return value
    if isinstance(value, dict) and hasattr(model_type, "model_validate"):
        return model_type.model_validate(value)
    return model_type()


def _coerce_optional_model(value: Any, model_type: type[Any]) -> Any:
    if value is None or isinstance(value, model_type):
        return value
    if isinstance(value, dict) and hasattr(model_type, "model_validate"):
        return model_type.model_validate(value)
    return value


def _coerce_model_list(values: list[Any], model_type: type[Any]) -> list[Any]:
    return [_coerce_optional_model(value, model_type) for value in values]


def _hydrate_flat_fields(state: AuditState, section: dict[str, Any], mapping: dict[str, str]) -> None:
    for flat_key, section_key in mapping.items():
        if flat_key not in state and section_key in section:
            state[flat_key] = section[section_key]  # type: ignore[literal-required]


def _serialize_value(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        try:
            return value.model_dump(mode="json")
        except TypeError:  # pragma: no cover - lightweight runtime fallback
            return value.model_dump()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {key: _serialize_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_serialize_value(item) for item in value]
    return value


def _serialize_file_reference(item: dict[str, Any]) -> dict[str, Any]:
    content = item.get("content", "")
    return {
        "path": item.get("path", ""),
        "source": item.get("source", ""),
        "changed_lines": item.get("changed_lines", []),
        "content_length": len(content),
    }
