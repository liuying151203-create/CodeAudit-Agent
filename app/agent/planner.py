from __future__ import annotations

from typing import Any

from app.schemas.enums import AuditStageName, Severity
from app.schemas.planning import AuditPlan, AuditStagePlan
from app.schemas.project import ProjectProfile, VulnKnowledge

PLANNER_CAPABILITIES = {
    "extract_call_chain",
    "extract_file_context",
    "extract_route_auth_context",
    "inspect_access_control",
    "scan_command_execution",
    "scan_deserialization",
    "scan_file_paths",
    "scan_secrets",
    "scan_sql_patterns",
}


def build_template_audit_plan(
    profile: ProjectProfile,
    knowledge: list[VulnKnowledge],
    user_task: str = "",
    fallback_reason: str | None = None,
) -> AuditPlan:
    risk_types = set(profile.risk_surfaces) | {item.risk_type for item in knowledge if item.risk_type}
    knowledge_by_risk = {item.risk_type: item for item in knowledge if item.risk_type}
    signals = set(profile.security_signals)
    stages: list[AuditStagePlan] = []

    stages.append(_stage_plan(AuditStageName.SECRET, profile, knowledge_by_risk, signals, user_task))
    if "SQL Injection" in risk_types:
        stages.append(_stage_plan(AuditStageName.INJECTION, profile, knowledge_by_risk, signals, user_task))
    if "Command Execution" in risk_types:
        stages.append(_stage_plan(AuditStageName.COMMAND, profile, knowledge_by_risk, signals, user_task))
    if risk_types & {"Path Traversal", "Unsafe Deserialization"}:
        stages.append(_stage_plan(AuditStageName.FILE, profile, knowledge_by_risk, signals, user_task))
    if "Broken Access Control" in risk_types:
        stages.append(_stage_plan(AuditStageName.AUTH, profile, knowledge_by_risk, signals, user_task))

    names = ", ".join(stage.stage.value for stage in stages)
    return AuditPlan(
        summary=f"Planned {len(stages)} audit stages: {names}.",
        stages=stages,
        planner_source="template",
        fallback_reason=fallback_reason,
    )


def build_planner_payload(
    profile: ProjectProfile,
    knowledge: list[VulnKnowledge],
    user_task: str,
    scan_mode: str,
) -> dict[str, Any]:
    return {
        "task": "Create a focused security audit plan. Select only relevant stages and registered capabilities. Do not produce findings.",
        "scan_mode": scan_mode,
        "user_task": user_task,
        "project_profile": profile.model_dump(mode="json"),
        "knowledge": [
            {
                "knowledge_id": item.knowledge_id,
                "risk_type": item.risk_type,
                "recommended_capabilities": item.recommended_capabilities,
                "audit_focus": item.audit_focus,
                "relevance_score": item.relevance_score,
            }
            for item in knowledge
        ],
        "allowed_stages": [stage.value for stage in AuditStageName],
        "allowed_capabilities": sorted(PLANNER_CAPABILITIES),
        "schema": {
            "summary": "string",
            "stages": [
                {
                    "stage": "secret|injection|command|file|auth",
                    "priority": "low|medium|high|critical",
                    "risk_types": ["string"],
                    "target_files": ["project-relative path"],
                    "required_capabilities": ["allowed capability"],
                    "evidence_goals": ["string"],
                    "reason": "string",
                }
            ],
        },
    }


def parse_llm_audit_plan(data: dict[str, Any], fallback: AuditPlan, profile: ProjectProfile) -> AuditPlan | None:
    raw_stages = data.get("stages")
    if not isinstance(raw_stages, list):
        return None
    fallback_by_stage = {stage.stage: stage for stage in fallback.stages}
    allowed_files = set(_all_profile_files(profile))
    stages: list[AuditStagePlan] = []
    seen: set[AuditStageName] = set()
    for item in raw_stages:
        if not isinstance(item, dict):
            continue
        try:
            stage_name = AuditStageName(str(item.get("stage")))
            priority = Severity(str(item.get("priority") or "medium"))
        except ValueError:
            continue
        if stage_name in seen:
            continue
        default_stage = fallback_by_stage.get(stage_name)
        capabilities = [str(value) for value in item.get("required_capabilities", []) if str(value) in PLANNER_CAPABILITIES]
        targets = [str(value).replace("\\", "/") for value in item.get("target_files", [])]
        if allowed_files:
            targets = [value for value in targets if value in allowed_files]
        stages.append(
            AuditStagePlan(
                stage=stage_name,
                priority=priority,
                risk_types=[str(value) for value in item.get("risk_types", [])] or (default_stage.risk_types if default_stage else []),
                target_files=targets or (default_stage.target_files if default_stage else []),
                required_capabilities=capabilities or (default_stage.required_capabilities if default_stage else []),
                evidence_goals=[str(value) for value in item.get("evidence_goals", [])] or (default_stage.evidence_goals if default_stage else []),
                reason=str(item.get("reason") or (default_stage.reason if default_stage else "LLM-planned audit stage.")),
            )
        )
        seen.add(stage_name)
    if not stages:
        return None
    return AuditPlan(summary=str(data.get("summary") or fallback.summary), stages=stages, planner_source="llm")


def _stage_plan(
    stage: AuditStageName,
    profile: ProjectProfile,
    knowledge_by_risk: dict[str | None, VulnKnowledge],
    signals: set[str],
    user_task: str,
) -> AuditStagePlan:
    spec = _STAGE_SPECS[stage]
    risk_types = list(spec["risk_types"])
    targets = _targets_for_stage(stage, profile)
    capabilities = list(spec["capabilities"])
    for risk_type in risk_types:
        item = knowledge_by_risk.get(risk_type)
        if item:
            capabilities.extend(item.recommended_capabilities)
    direct_signals = signals & set(spec["signals"])
    priority = Severity.HIGH if direct_signals or _task_mentions(user_task, risk_types) else Severity.MEDIUM
    reason_parts = [str(spec["reason"])]
    if direct_signals:
        reason_parts.append(f"Matched signals: {', '.join(sorted(direct_signals))}.")
    return AuditStagePlan(
        stage=stage,
        priority=priority,
        risk_types=risk_types,
        target_files=targets,
        required_capabilities=_dedupe([value for value in capabilities if value in PLANNER_CAPABILITIES]),
        evidence_goals=list(spec["evidence_goals"]),
        reason=" ".join(reason_parts),
    )


def _targets_for_stage(stage: AuditStageName, profile: ProjectProfile) -> list[str]:
    if stage == AuditStageName.SECRET:
        return _dedupe(profile.dependency_files + profile.entrypoints + profile.auth_files)
    if stage == AuditStageName.INJECTION:
        return _dedupe(profile.db_files + profile.route_files)
    if stage == AuditStageName.COMMAND:
        return _dedupe(profile.entrypoints + profile.route_files)
    if stage == AuditStageName.FILE:
        return _dedupe(profile.upload_files + profile.route_files)
    return _dedupe(profile.auth_files + profile.route_files)


def _all_profile_files(profile: ProjectProfile) -> list[str]:
    return _dedupe(
        profile.dependency_files
        + profile.entrypoints
        + profile.route_files
        + profile.auth_files
        + profile.db_files
        + profile.upload_files
    )


def _task_mentions(user_task: str, risk_types: list[str]) -> bool:
    normalized = user_task.lower()
    return any(risk_type.lower() in normalized for risk_type in risk_types)


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


_STAGE_SPECS: dict[AuditStageName, dict[str, Any]] = {
    AuditStageName.SECRET: {
        "risk_types": ("Secrets",),
        "capabilities": ("scan_secrets",),
        "signals": ("secret_like_identifier",),
        "evidence_goals": ("Locate hardcoded credentials and distinguish real values from placeholders.",),
        "reason": "Secret scanning is a baseline stage for every repository.",
    },
    AuditStageName.INJECTION: {
        "risk_types": ("SQL Injection",),
        "capabilities": ("scan_sql_patterns", "extract_call_chain"),
        "signals": ("dynamic_sql_construction",),
        "evidence_goals": ("Verify whether user-controlled input reaches a dynamically constructed query.",),
        "reason": "Database-related files or SQL construction signals are present.",
    },
    AuditStageName.COMMAND: {
        "risk_types": ("Command Execution",),
        "capabilities": ("scan_command_execution", "extract_call_chain"),
        "signals": ("command_execution_api",),
        "evidence_goals": ("Verify whether untrusted input reaches a process or shell execution API.",),
        "reason": "Command execution APIs are present in the project.",
    },
    AuditStageName.FILE: {
        "risk_types": ("Path Traversal", "Unsafe Deserialization"),
        "capabilities": ("scan_file_paths", "scan_deserialization", "extract_file_context"),
        "signals": ("filesystem_input", "unsafe_deserialization_api"),
        "evidence_goals": ("Verify path confinement, upload validation, and the trust boundary of deserialized data.",),
        "reason": "File handling or unsafe deserialization surfaces are present.",
    },
    AuditStageName.AUTH: {
        "risk_types": ("Broken Access Control",),
        "capabilities": ("inspect_access_control", "extract_route_auth_context"),
        "signals": (),
        "evidence_goals": ("Verify authentication, role checks, and object-level authorization on sensitive routes.",),
        "reason": "Routes or authentication-related files require access-control review.",
    },
}
