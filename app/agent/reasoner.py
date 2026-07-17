from __future__ import annotations

from typing import Any

from app.agent.evidence_builder import redact_sensitive_text
from app.agent.planner import PLANNER_CAPABILITIES
from app.schemas.enums import AuditDecisionType, AuditStageName, Severity
from app.schemas.evidence import Evidence
from app.schemas.execution import ToolRequest, ToolRunResult
from app.schemas.finding import Finding, FindingDraft
from app.schemas.planning import AuditStagePlan
from app.schemas.runtime import AuditBudget, AuditDecision, AuditLoopRuntime

EXTRACTION_CAPABILITIES = {
    AuditStageName.SECRET: "extract_file_context",
    AuditStageName.INJECTION: "extract_call_chain",
    AuditStageName.COMMAND: "extract_call_chain",
    AuditStageName.FILE: "extract_file_context",
    AuditStageName.AUTH: "extract_route_auth_context",
}


def build_reasoner_payload(
    stage: AuditStagePlan,
    tool_results: list[ToolRunResult],
    evidences: list[Evidence],
    findings: list[Finding],
    budget: AuditBudget,
    loop: AuditLoopRuntime,
    knowledge: list[Any],
) -> dict[str, Any]:
    stage_evidence = [item for item in evidences if item.stage == stage.stage]
    stage_results = [item for item in tool_results if item.stage == stage.stage]
    return {
        "task": "Decide the next action for this single security audit stage. Use only supplied evidence.",
        "current_stage": stage.model_dump(mode="json"),
        "remaining_budget": {
            "tool_rounds": max(0, budget.max_tool_rounds_per_stage - loop.current_round),
            "tool_calls": max(0, budget.max_tool_calls_per_round),
            "tokens": max(0, budget.max_stage_tokens - budget.used_tokens),
            "decisions": max(0, budget.max_decisions_per_stage - loop.decision_count),
        },
        "tool_results": [
            {
                "tool_name": item.tool_name,
                "status": str(getattr(item.status, "value", item.status)),
                "summary": item.output_summary,
                "capabilities": item.metadata.get("capabilities", []),
                "finding_ids": [finding.finding_id for finding in item.findings],
            }
            for item in stage_results
        ],
        "evidence": [
            {
                "evidence_id": item.evidence_id,
                "file_path": item.file_path,
                "start_line": item.start_line,
                "end_line": item.end_line,
                "code_context": redact_sensitive_text(item.code_context)[:4000],
                "source_tool": item.source_tool,
            }
            for item in stage_evidence
        ],
        "existing_findings": [
            {
                "rule_id": item.rule_id,
                "file_path": item.file_path,
                "line_start": item.line_start,
                "risk_type": item.risk_type,
            }
            for item in findings
            if item.stage == stage.stage or item.category in stage.risk_types
        ],
        "knowledge": [
            {
                "knowledge_id": item.knowledge_id,
                "risk_type": item.risk_type,
                "audit_focus": item.audit_focus,
                "dangerous_patterns": item.dangerous_patterns,
            }
            for item in knowledge
            if item.risk_type in stage.risk_types
        ],
        "allowed_decisions": ["CALL_TOOL", "EMIT_FINDING", "FINISH_STAGE"],
        "allowed_capabilities": sorted(PLANNER_CAPABILITIES),
        "schema": {
            "decision": "CALL_TOOL|EMIT_FINDING|FINISH_STAGE",
            "reason": "string",
            "tool_request": {
                "required_capability": "allowed capability",
                "target_files": ["project-relative path"],
                "risk_types": ["string"],
                "reason": "string",
            },
            "finding": {
                "rule_id": "string",
                "risk_type": "string",
                "severity": "info|low|medium|high|critical",
                "confidence": "0..1",
                "file_path": "project-relative path",
                "line_start": "positive integer",
                "line_end": "positive integer",
                "message": "string",
                "evidence_ids": ["existing evidence id"],
            },
        },
    }


def parse_reasoner_decision(
    data: dict[str, Any],
    stage: AuditStagePlan,
    evidences: list[Evidence],
    available_files: list[str],
    budget: AuditBudget,
    loop: AuditLoopRuntime,
    token_usage: int = 0,
) -> AuditDecision | None:
    try:
        decision_type = AuditDecisionType(str(data.get("decision")))
    except ValueError:
        return None
    reason = str(data.get("reason") or "LLM audit decision.")
    if decision_type == AuditDecisionType.CALL_TOOL:
        if loop.current_round >= budget.max_tool_rounds_per_stage:
            return AuditDecision(
                decision=AuditDecisionType.FINISH_STAGE,
                reason="Tool-round budget exhausted after analyzing available evidence.",
                decision_source="budget",
                token_usage=token_usage,
            )
        item = data.get("tool_request")
        if not isinstance(item, dict):
            return None
        capability = str(item.get("required_capability") or "")
        if capability not in PLANNER_CAPABILITIES:
            return None
        targets = _validated_targets(item.get("target_files"), available_files, budget.max_files_per_call)
        return AuditDecision(
            decision=decision_type,
            reason=reason,
            tool_request=ToolRequest(
                stage=stage.stage,
                required_capability=capability,
                target_files=targets or stage.target_files[: budget.max_files_per_call],
                risk_types=[str(value) for value in item.get("risk_types") or stage.risk_types],
                reason=str(item.get("reason") or reason),
            ),
            decision_source="llm",
            token_usage=token_usage,
        )
    if decision_type == AuditDecisionType.EMIT_FINDING:
        item = data.get("finding")
        if not isinstance(item, dict):
            return None
        evidence_map = {evidence.evidence_id: evidence for evidence in evidences if evidence.stage == stage.stage}
        evidence_ids = [str(value) for value in item.get("evidence_ids") or [] if str(value) in evidence_map]
        file_path = str(item.get("file_path") or "").replace("\\", "/")
        if not evidence_ids or file_path not in set(available_files):
            return None
        try:
            line_start = int(item.get("line_start") or 0)
            line_end = int(item.get("line_end") or line_start)
            severity = Severity(str(item.get("severity") or "medium"))
            confidence = float(item.get("confidence") or 0.5)
        except (TypeError, ValueError):
            return None
        if not _evidence_supports_location(evidence_ids, evidence_map, file_path, line_start, line_end):
            return None
        try:
            draft = FindingDraft(
                rule_id=str(item.get("rule_id") or f"LLM_{stage.stage.value.upper()}"),
                risk_type=str(item.get("risk_type") or stage.risk_types[0]),
                severity=severity,
                confidence=confidence,
                file_path=file_path,
                line_start=line_start,
                line_end=line_end,
                message=str(item.get("message") or reason),
                evidence_ids=evidence_ids,
                stage=stage.stage,
                source="llm",
            )
        except ValueError:
            return None
        return AuditDecision(decision=decision_type, reason=reason, finding=draft, decision_source="llm", token_usage=token_usage)
    return AuditDecision(decision=decision_type, reason=reason, decision_source="llm", token_usage=token_usage)


def fallback_reasoner_decision(
    stage: AuditStagePlan,
    tool_results: list[ToolRunResult],
    evidences: list[Evidence],
    findings: list[Finding],
    available_files: list[str],
    budget: AuditBudget,
    loop: AuditLoopRuntime,
    fallback_reason: str | None,
) -> AuditDecision:
    stage_results = [item for item in tool_results if item.stage == stage.stage]
    existing = {_finding_fingerprint(item) for item in findings}
    evidence_by_finding = {item.finding_id: item.evidence_id for item in evidences if item.stage == stage.stage}
    for result in stage_results:
        for finding in result.findings:
            if _finding_fingerprint(finding) in existing or finding.finding_id not in evidence_by_finding:
                continue
            draft = FindingDraft(
                rule_id=finding.rule_id,
                risk_type=finding.risk_type or finding.category,
                severity=Severity(finding.severity),
                confidence=finding.confidence,
                file_path=finding.file_path,
                line_start=finding.line_start,
                line_end=finding.line_end,
                message=finding.message,
                evidence_ids=[evidence_by_finding[finding.finding_id]],
                stage=stage.stage,
                source=finding.source,
            )
            return AuditDecision(
                decision=AuditDecisionType.EMIT_FINDING,
                reason="Promote a scanner finding backed by extracted evidence.",
                finding=draft,
                decision_source="template",
                fallback_reason=fallback_reason,
            )

    if loop.no_progress_rounds >= 2:
        return _finish("Consecutive tool rounds produced no new evidence.", "no_new_evidence", fallback_reason)
    executed = {str(capability) for result in stage_results for capability in result.metadata.get("capabilities", [])}
    requested_capabilities = list(stage.required_capabilities)
    extraction = EXTRACTION_CAPABILITIES[stage.stage]
    if extraction not in requested_capabilities:
        requested_capabilities.append(extraction)
    missing = [capability for capability in requested_capabilities if capability not in executed]
    if missing and loop.current_round < budget.max_tool_rounds_per_stage:
        return AuditDecision(
            decision=AuditDecisionType.CALL_TOOL,
            reason=f"Collect missing evidence with capability {missing[0]}.",
            tool_request=ToolRequest(
                stage=stage.stage,
                required_capability=missing[0],
                target_files=(stage.target_files or available_files)[: budget.max_files_per_call],
                risk_types=stage.risk_types,
                reason="Complete the current stage evidence goal.",
            ),
            decision_source="template",
            fallback_reason=fallback_reason,
        )
    if missing and loop.current_round >= budget.max_tool_rounds_per_stage:
        return _finish("Tool-round budget exhausted; finish with available evidence.", "budget_exhausted", fallback_reason)
    return _finish("Current stage evidence goals are complete.", "completed", fallback_reason)


def _finish(reason: str, source: str, fallback_reason: str | None) -> AuditDecision:
    return AuditDecision(
        decision=AuditDecisionType.FINISH_STAGE,
        reason=reason,
        decision_source=source,
        fallback_reason=fallback_reason,
    )


def _validated_targets(values: Any, available_files: list[str], limit: int) -> list[str]:
    available = set(available_files)
    if not isinstance(values, list):
        return []
    return list(dict.fromkeys(str(value).replace("\\", "/") for value in values if str(value).replace("\\", "/") in available))[:limit]


def _evidence_supports_location(evidence_ids: list[str], evidence_map: dict[str, Evidence], file_path: str, line_start: int, line_end: int) -> bool:
    for evidence_id in evidence_ids:
        evidence = evidence_map[evidence_id]
        if evidence.file_path != file_path:
            continue
        start = evidence.start_line or line_start
        end = evidence.end_line or line_end
        if start <= line_start <= end and start <= line_end <= end:
            return True
    return False


def _finding_fingerprint(finding: Finding) -> str:
    return f"{(finding.risk_type or finding.category).lower()}:{finding.file_path}:{finding.line_start}:{finding.line_end}"
