from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
import uuid
from collections import Counter
from pathlib import Path
from time import monotonic
from typing import Any

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover - dependency fallback
    def load_dotenv() -> bool:
        return False

class BaseTool:
    name = ""
    description = ""

from app.diff.diff_parser import parse_unified_diff
from app.diff.git_diff_loader import load_git_diff
from app.knowledge.retriever import rerank_knowledge, retrieve_vulnerability_knowledge
from app.project.reader import build_project_profile
from app.reporting import build_sarif, render_markdown
from app.agent.reasoner import build_reasoner_payload, fallback_reasoner_decision, parse_reasoner_decision
from app.agent.prompt_context import DEFAULT_SANITIZER, redact_sensitive_text
from app.security_tools.gateway import execute_tool_plan, select_tool_plan
from app.schemas.enums import FindingStatus
from app.schemas.finding import Finding, FindingAssessmentBatch, FindingProvenance, FixSuggestion, ReviewResult, RiskAnalysis
from app.schemas.evidence import Evidence
from app.schemas.planning import AuditPlan, AuditStagePlan
from app.schemas.project import ProjectProfile, ToolExecutionResult, ToolPlan, VulnKnowledge
from app.schemas.report import AuditReport
from app.schemas.runtime import AuditBudget, AuditDecision, AuditLoopRuntime, AuditMetrics, FallbackRecord
from app.agent.planner import build_planner_payload, build_template_audit_plan, parse_llm_audit_plan
from app.utils.file_filter import should_scan_file

load_dotenv()


class RepoLoaderTool(BaseTool):
    name: str = "repo_loader"
    description: str = "Load supported source files from a local repository without executing code."

    def run(self, repo_path: str) -> list[dict[str, Any]]:
        root = Path(repo_path).resolve()
        if not root.exists() or not root.is_dir():
            raise ValueError(f"repo_path does not exist or is not a directory: {repo_path}")
        files: list[dict[str, Any]] = []
        for path in root.rglob("*"):
            if path.is_file() and not path.is_symlink() and should_scan_file(path):
                rel = path.relative_to(root).as_posix()
                files.append({"path": rel, "content": path.read_text(encoding="utf-8", errors="ignore"), "source": "repo"})
        return files


class GitDiffTool(BaseTool):
    name: str = "git_diff_loader"
    description: str = "Load or parse git unified diff text."

    def run(self, repo_path: str | None = None, diff_text: str | None = None, diff_mode: str = "cached") -> tuple[str, list[dict[str, Any]]]:
        text = diff_text or load_git_diff(repo_path or ".", diff_mode)
        return text, parse_unified_diff(text)


class ProjectReaderTool(BaseTool):
    name: str = "project_reader"
    description: str = "Read project structure and build a security-oriented project profile without executing code."

    def run(self, repo_path: str | None = None, files: list[dict[str, Any]] | None = None) -> tuple[ProjectProfile, list[dict[str, Any]]]:
        source_files = files or []
        if repo_path and not source_files:
            source_files = RepoLoaderTool().run(repo_path)
        return build_project_profile(repo_path, source_files), source_files


class VulnKBRetrieverTool(BaseTool):
    name: str = "vulnkb_retriever"
    description: str = "Retrieve relevant vulnerability knowledge documents for the project profile and user task."

    def run(self, profile: ProjectProfile, task: str = "") -> list[VulnKnowledge]:
        knowledge = retrieve_vulnerability_knowledge(profile, task)
        if knowledge and _llm_enabled() and os.getenv("LLM_VULNKB_RERANK", "false").lower() == "true":
            data, _ = _call_llm_json(
                "Rank vulnerability knowledge for the supplied project. Return only compact JSON.",
                {
                    "task": task,
                    "project_profile": profile.model_dump(mode="json"),
                    "candidates": [
                        {
                            "knowledge_id": item.knowledge_id,
                            "risk_type": item.risk_type,
                            "score": item.relevance_score,
                            "match_reasons": item.match_reasons,
                        }
                        for item in knowledge
                    ],
                    "schema": {"ordered_ids": ["knowledge_id"]},
                },
            )
            if data and isinstance(data.get("ordered_ids"), list):
                knowledge = rerank_knowledge(knowledge, [str(item) for item in data["ordered_ids"]])
        return knowledge


class AuditPlannerTool(BaseTool):
    name: str = "audit_planner"
    description: str = "Plan risk stages, target files, capabilities and evidence goals from project context."

    def run(
        self,
        profile: ProjectProfile,
        knowledge: list[VulnKnowledge],
        user_task: str = "",
        scan_mode: str = "repo_scan",
    ) -> AuditPlan:
        template_plan = build_template_audit_plan(profile, knowledge, user_task)
        if not _llm_enabled():
            return template_plan
        data, fallback_reason = _call_llm_json(
            "You are a security audit planner. Return only compact JSON that follows the supplied schema.",
            build_planner_payload(profile, knowledge, user_task, scan_mode),
        )
        if data:
            llm_plan = parse_llm_audit_plan(data, template_plan, profile)
            if llm_plan:
                return llm_plan
            fallback_reason = "LLM audit plan did not contain any valid stages."
        template_plan.fallback_reason = fallback_reason
        return template_plan


class AuditReasonerTool(BaseTool):
    name: str = "audit_reasoner"
    description: str = "Choose the next evidence-backed action for the current audit stage."

    def run(
        self,
        stage: AuditStagePlan,
        tool_results: list[ToolExecutionResult],
        evidences: list[Evidence],
        findings: list[Finding],
        files: list[dict[str, Any]],
        budget: AuditBudget,
        loop: AuditLoopRuntime,
        knowledge: list[VulnKnowledge],
    ) -> AuditDecision:
        stage_elapsed = monotonic() - loop.stage_started_at if loop.stage_started_at else 0
        total_elapsed = monotonic() - loop.audit_started_at if loop.audit_started_at else 0
        if loop.decision_count >= budget.max_decisions_per_stage:
            return AuditDecision(decision="FINISH_STAGE", reason="Stage decision budget exhausted.", decision_source="budget")
        if budget.used_tokens >= budget.max_stage_tokens:
            return AuditDecision(decision="FINISH_STAGE", reason="Stage token budget exhausted.", decision_source="budget")
        if stage_elapsed >= budget.max_stage_seconds or total_elapsed >= budget.max_total_seconds:
            return AuditDecision(decision="FINISH_STAGE", reason="Audit time budget exhausted.", decision_source="budget")

        fallback_reason = None
        if _llm_enabled():
            payload = build_reasoner_payload(stage, tool_results, evidences, findings, budget, loop, knowledge)
            data, fallback_reason, token_usage = _call_llm_json_with_usage(
                "You are an evidence-driven code security audit agent. Return one valid JSON decision. Never invent files, evidence IDs, or tool capabilities.",
                payload,
            )
            if data:
                decision = parse_reasoner_decision(
                    data,
                    stage,
                    evidences,
                    [str(item.get("path") or "") for item in files],
                    budget,
                    loop,
                    token_usage,
                )
                if decision:
                    return decision
                fallback_reason = "LLM audit decision failed schema or evidence validation."
        else:
            fallback_reason = "LLM API key is not configured."
        return fallback_reasoner_decision(
            stage,
            tool_results,
            evidences,
            findings,
            [str(item.get("path") or "") for item in files],
            budget,
            loop,
            fallback_reason,
        )


class ToolSelectorTool(BaseTool):
    name: str = "tool_selector"
    description: str = "Select security tools based on project profile, retrieved vulnerability knowledge and scan mode."

    def run(
        self,
        profile: ProjectProfile,
        knowledge: list[VulnKnowledge],
        scan_mode: str,
        files: list[dict[str, Any]],
        audit_plan: AuditPlan | None = None,
        repo_path: str | None = None,
        budget: AuditBudget | None = None,
        strict_capabilities: bool = False,
    ) -> ToolPlan:
        return select_tool_plan(profile, knowledge, scan_mode, files, audit_plan, repo_path, budget, strict_capabilities=strict_capabilities)


class ToolExecutorTool(BaseTool):
    name: str = "tool_executor"
    description: str = "Execute selected security tools safely. External tools are skipped when unavailable."

    def run(self, plan: ToolPlan, files: list[dict[str, Any]], mode: str, repo_path: str | None = None) -> list[ToolExecutionResult]:
        return execute_tool_plan(plan, files, repo_path, mode)


class FindingMergerTool(BaseTool):
    name: str = "finding_merger"
    description: str = "Merge and deduplicate findings emitted by selected tools."

    def run(self, tool_results: list[ToolExecutionResult], additional_findings: list[Finding] | None = None) -> list[Finding]:
        merged: dict[tuple[str, str, int, int], Finding] = {}
        for result in tool_results:
            for finding in result.findings:
                _merge_finding(merged, finding, result.tool_name, result.call_id)
        for finding in additional_findings or []:
            key = _finding_key(finding)
            if key in merged and _source_type(finding, finding.source) not in {"llm", "mcp"}:
                existing = merged[key]
                merged[key] = existing.model_copy(
                    update={"evidence_ids": list(dict.fromkeys([*existing.evidence_ids, *finding.evidence_ids]))}
                )
                continue
            _merge_finding(merged, finding, finding.source, None)
        return list(merged.values())


class FindingAssessorTool(BaseTool):
    name: str = "finding_assessor"
    description: str = "Batch risk analysis and false-positive review in one evidence-bound decision."

    def run(self, findings: list[Finding], evidences: list[Evidence] | None = None) -> FindingAssessmentBatch:
        evidence_items = evidences or []
        fallback_reason = None
        if _llm_enabled():
            assessed, fallback_reason = _llm_batch_finding_assessment(findings, evidence_items)
            if assessed is not None:
                return assessed
        elif findings:
            fallback_reason = "LLM API key is not configured."
        return _template_finding_assessment(findings, evidence_items, fallback_reason)


class FixSuggestTool(BaseTool):
    name: str = "fix_advisor"
    description: str = "Generate remediation guidance and patch hints."

    def run(
        self,
        findings: list[Finding],
        evidences: list[Evidence] | None = None,
        knowledge: list[VulnKnowledge] | None = None,
    ) -> list[FixSuggestion]:
        active_findings = [finding for finding in findings if finding.status == FindingStatus.CONFIRMED]
        fallback_reason = None
        if _llm_enabled():
            llm_suggestions, fallback_reason = _llm_batch_fix_suggestions(active_findings, evidences or [])
            if llm_suggestions is not None:
                return llm_suggestions
        elif active_findings:
            fallback_reason = "LLM API key is not configured."
        suggestions: list[FixSuggestion] = []
        for finding in active_findings:
            suggestion, safe_code, hint = _fix_for(finding, knowledge or [])
            suggestions.append(
                FixSuggestion(
                    finding_id=finding.finding_id,
                    suggestion=suggestion,
                    safe_code_example=safe_code,
                    patch_hint=hint,
                    analysis_source="template",
                    fallback_reason=fallback_reason,
                    evidence_ids=finding.evidence_ids,
                )
            )
        return suggestions


class ReportWriterTool(BaseTool):
    name: str = "report_writer"
    description: str = "Write Markdown and JSON audit reports."

    def run(self, state: dict[str, Any]) -> AuditReport:
        report_id = str(uuid.uuid4())[:8]
        report_dir = Path(os.getenv("CODEAUDIT_REPORT_DIR", "data/reports"))
        report_dir.mkdir(parents=True, exist_ok=True)
        all_findings: list[Finding] = state.get("candidate_findings", [])
        risk_analyses: list[RiskAnalysis] = state.get("risk_analyses", [])
        review_results: list[ReviewResult] = state.get("review_results", [])
        fix_suggestions: list[FixSuggestion] = state.get("fix_suggestions", [])
        evidence_ids = {item.evidence_id for item in state.get("evidences", [])}
        confirmed_findings = [item for item in all_findings if item.status == FindingStatus.CONFIRMED]
        dismissed_findings = [item for item in all_findings if item.status == FindingStatus.DISMISSED]
        needs_review_findings = [item for item in all_findings if item.status == FindingStatus.NEEDS_REVIEW]
        active_findings = [
            item
            for item in [*confirmed_findings, *needs_review_findings]
            if item.evidence_ids and any(value in evidence_ids for value in item.evidence_ids)
        ]
        active_findings = [_mark_reported(item) for item in active_findings]
        dismissed_findings = [_mark_reported(item) for item in dismissed_findings]
        needs_review_findings = [_mark_reported(item) for item in needs_review_findings]
        stats = Counter(f.severity for f in active_findings)
        recommendations = [item.suggestion for item in fix_suggestions]
        analysis_items = [*risk_analyses, *review_results, *fix_suggestions]
        analysis_summary = Counter(item.analysis_source for item in analysis_items if getattr(item, "analysis_source", None))
        fallback_reasons = sorted({item.fallback_reason for item in analysis_items if getattr(item, "fallback_reason", None)})
        audit_plan: AuditPlan | None = state.get("audit_plan")
        tool_plan: ToolPlan | None = state.get("tool_plan")
        if audit_plan and audit_plan.fallback_reason:
            fallback_reasons = sorted({*fallback_reasons, audit_plan.fallback_reason})
        if tool_plan and tool_plan.fallback_reasons:
            fallback_reasons = sorted({*fallback_reasons, *tool_plan.fallback_reasons})
        fallback_records: list[FallbackRecord] = list(state.get("fallbacks", []))
        fallback_reasons = sorted({*fallback_reasons, *(record.reason for record in fallback_records)})
        recorded_reasons = {record.reason for record in fallback_records}
        for reason in fallback_reasons:
            if reason in recorded_reasons:
                continue
            fallback_records.append(
                FallbackRecord(
                    component=(
                        "audit_planner"
                        if audit_plan and reason == audit_plan.fallback_reason
                        else "tool_selector"
                        if tool_plan and reason in tool_plan.fallback_reasons
                        else "llm_analysis"
                    ),
                    reason=reason,
                    strategy="builtin_tool" if tool_plan and reason in tool_plan.fallback_reasons else "template",
                )
            )
        metrics = state.get("metrics") or AuditMetrics()
        metrics.detected_findings = len(all_findings)
        metrics.confirmed_findings = len(confirmed_findings)
        metrics.dismissed_findings = len(dismissed_findings)
        metrics.tool_call_count = len(state.get("validated_tool_calls", []))
        metrics.llm_call_count = sum(
            [
                bool(audit_plan and audit_plan.planner_source == "llm"),
                sum(1 for trace in state.get("traces", []) if trace.node_name == "audit_reasoner_node" and trace.llm_used),
                any(trace.node_name == "finding_assessor_node" and trace.llm_used for trace in state.get("traces", [])),
                any(item.analysis_source == "llm" for item in fix_suggestions),
            ]
        )
        metrics.fallback_count = len(fallback_records)
        metrics.total_latency_ms = sum(getattr(trace, "elapsed_ms", 0) for trace in state.get("traces", []))
        metrics.stage_coverage = {item.stage_name: str(getattr(item.status, "value", item.status)) for item in state.get("audit_stage_results", [])}
        state["confirmed_findings"] = confirmed_findings
        state["fallbacks"] = fallback_records
        state["metrics"] = metrics
        from app.agent.state import serialize_audit_state, sync_audit_state

        sync_audit_state(state)
        summary = (
            f"Scanned {len(state.get('scanned_files', []))} files: {len(confirmed_findings)} confirmed, "
            f"{len(needs_review_findings)} needs review, {len(dismissed_findings)} dismissed."
        )
        markdown_path = report_dir / f"{report_id}.md"
        json_path = report_dir / f"{report_id}.json"
        sarif_path = report_dir / f"{report_id}.sarif"
        report = AuditReport(
            report_id=report_id,
            mode=state.get("mode", "repo_scan"),
            repo_path=state.get("repo_path"),
            summary=summary,
            risk_stats=dict(stats),
            project_profile=state.get("project_profile"),
            vuln_knowledge=state.get("vuln_knowledge", []),
            audit_plan=state.get("audit_plan"),
            stage_queue=state.get("stage_queue", []),
            tool_plan=state.get("tool_plan"),
            tool_results=state.get("tool_results", []),
            audit_stage_results=state.get("audit_stage_results", []),
            evidences=state.get("evidences", []),
            findings=active_findings,
            dismissed_findings=dismissed_findings,
            needs_review_findings=needs_review_findings,
            risk_analyses=risk_analyses,
            review_results=review_results,
            fix_suggestions=fix_suggestions,
            analysis_summary=dict(analysis_summary),
            fallback_reasons=fallback_reasons,
            fallback_records=fallback_records,
            budget=state.get("budget"),
            metrics=metrics,
            recommendations=recommendations,
            traces=state.get("traces", []),
            state_snapshot=DEFAULT_SANITIZER.sanitize_value(serialize_audit_state(state)),
            markdown_path=str(markdown_path),
            json_path=str(json_path),
            sarif_path=str(sarif_path),
        )
        report = AuditReport.model_validate(DEFAULT_SANITIZER.sanitize_value(report.model_dump(mode="json")))
        sarif = build_sarif(report)
        from app.reporting.sarif import assert_valid_sarif
        from app.storage.retention import prune_reports

        assert_valid_sarif(sarif)
        markdown_path.write_text(render_markdown(report), encoding="utf-8")
        json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        sarif_path.write_text(json.dumps(sarif, ensure_ascii=False, indent=2), encoding="utf-8")
        retention = prune_reports(report_dir, protected_report_ids={report_id})
        metrics = metrics.model_copy(
            update={
                "sarif_result_count": len(sarif["runs"][0]["results"]),
                "retained_report_count": retention.retained_reports,
                "pruned_report_count": retention.pruned_reports,
            }
        )
        for _ in range(3):
            report = report.model_copy(update={"metrics": metrics})
            markdown_path.write_text(render_markdown(report), encoding="utf-8")
            json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
            report_bytes = sum(path.stat().st_size for path in (markdown_path, json_path, sarif_path))
            if report_bytes == metrics.report_file_bytes:
                break
            metrics = metrics.model_copy(update={"report_file_bytes": report_bytes})
        report = report.model_copy(update={"metrics": metrics})
        state["metrics"] = metrics
        json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        return report


def _mark_reported(finding: Finding) -> Finding:
    return finding.model_copy(
        update={"status_history": list(dict.fromkeys([*finding.status_history, FindingStatus.REPORTED]))}
    )


def _merge_finding(
    merged: dict[tuple[str, str, int, int], Finding],
    finding: Finding,
    source_name: str,
    call_id: str | None,
) -> None:
    severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    key = _finding_key(finding)
    source_type = _source_type(finding, source_name)
    provenance = FindingProvenance(
        source_type=source_type,
        source_name=source_name,
        source_rule_id=finding.rule_id,
        source_finding_id=finding.finding_id,
        tool_call_id=call_id,
        evidence_ids=finding.evidence_ids,
    )
    history = list(dict.fromkeys([*finding.status_history, FindingStatus.MERGED]))
    sanitized = finding.model_copy(
        update={
            "message": redact_sensitive_text(finding.message),
            "evidence_text": redact_sensitive_text(finding.evidence_text),
            "status": FindingStatus.MERGED,
            "status_history": history,
            "provenance": _dedupe_provenance([*finding.provenance, provenance]),
        }
    )
    if key not in merged:
        merged[key] = sanitized
        return
    existing = merged[key]
    severity = sanitized.severity if severity_rank[sanitized.severity] > severity_rank[existing.severity] else existing.severity
    merged[key] = existing.model_copy(
        update={
            "line_end": max(existing.line_end, sanitized.line_end),
            "severity": severity,
            "confidence": max(existing.confidence, sanitized.confidence),
            "sources": list(dict.fromkeys([*existing.sources, *sanitized.sources, source_name])),
            "source_rule_ids": list(dict.fromkeys([*existing.source_rule_ids, *sanitized.source_rule_ids])),
            "evidence_ids": list(dict.fromkeys([*existing.evidence_ids, *sanitized.evidence_ids])),
            "provenance": _dedupe_provenance([*existing.provenance, *sanitized.provenance]),
            "status_history": list(dict.fromkeys([*existing.status_history, *sanitized.status_history])),
            "change_scope": (
                "changed_line_finding"
                if "changed_line_finding" in {existing.change_scope, sanitized.change_scope}
                else existing.change_scope
            ),
        }
    )


def _source_type(finding: Finding, source_name: str) -> str:
    value = f"{source_name} {finding.source} {finding.analysis_source}".lower()
    if "mcp" in value:
        return "mcp"
    if "llm" in value or "agent" in value:
        return "llm"
    if source_name in {"semgrep", "bandit", "gitleaks"}:
        return "external_tool"
    return "builtin_tool"


def _finding_key(finding: Finding) -> tuple[str, str, int, int]:
    return ((finding.risk_type or finding.category).lower(), finding.file_path.lower(), finding.line_start, finding.line_start)


def _dedupe_provenance(items: list[FindingProvenance]) -> list[FindingProvenance]:
    result: list[FindingProvenance] = []
    seen: set[str] = set()
    for item in items:
        key = item.model_dump_json()
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _template_finding_assessment(
    findings: list[Finding], evidences: list[Evidence], fallback_reason: str | None
) -> FindingAssessmentBatch:
    evidence_map = {item.evidence_id: item for item in evidences}
    assessed: list[Finding] = []
    analyses: list[RiskAnalysis] = []
    reviews: list[ReviewResult] = []
    for finding in findings:
        evidence_ids = [value for value in finding.evidence_ids if value in evidence_map]
        evidence_text = " ".join(
            f"{evidence_map[value].code_snippet} {evidence_map[value].code_context}" for value in evidence_ids
        ).lower()
        normalized_path = finding.file_path.lower().replace("\\", "/")
        test_fixture = normalized_path.startswith("tests/") or "/tests/" in f"/{normalized_path}" or Path(normalized_path).name.startswith("test_")
        placeholder = finding.category == "Secrets" and (
            test_fixture
            or any(marker in evidence_text for marker in ("example", "dummy", "placeholder", "fake-secret", "test-secret"))
        )
        if placeholder:
            status = FindingStatus.DISMISSED
            reason = "Evidence indicates example or placeholder secret data."
        elif not evidence_ids:
            status = FindingStatus.NEEDS_REVIEW
            reason = "Available evidence is insufficient for deterministic confirmation."
        else:
            status = FindingStatus.CONFIRMED
            reason = "The finding is supported by a concrete source location and scanner evidence."
        final_severity = "low" if status == FindingStatus.DISMISSED else finding.severity
        assessed.append(_with_finding_status(finding, status, "template", fallback_reason))
        analyses.append(
            RiskAnalysis(
                finding_id=finding.finding_id,
                risk_type=finding.risk_type or finding.category,
                risk_reason=finding.message,
                exploit_scenario=_scenario_for(finding),
                confidence=finding.confidence,
                severity=final_severity,
                analysis_source="template",
                fallback_reason=fallback_reason,
                evidence_ids=evidence_ids,
            )
        )
        reviews.append(
            ReviewResult(
                finding_id=finding.finding_id,
                is_false_positive=status == FindingStatus.DISMISSED,
                reason=reason,
                final_severity=final_severity,
                status=status,
                analysis_source="template",
                fallback_reason=fallback_reason,
                evidence_ids=evidence_ids,
            )
        )
    return FindingAssessmentBatch(
        findings=assessed,
        risk_analyses=analyses,
        review_results=reviews,
        analysis_source="template",
        fallback_reason=fallback_reason,
    )


def _with_finding_status(
    finding: Finding,
    status: FindingStatus,
    analysis_source: str,
    fallback_reason: str | None = None,
) -> Finding:
    return finding.model_copy(
        update={
            "status": status,
            "status_history": list(dict.fromkeys([*finding.status_history, status])),
            "analysis_source": analysis_source,
            "fallback_reason": fallback_reason,
        }
    )


def _valid_severity(value: Any, default: str) -> str:
    candidate = str(value or default).lower()
    return candidate if candidate in {"info", "low", "medium", "high", "critical"} else default


def _scenario_for(finding: Finding) -> str:
    scenarios = {
        "Secrets": "An attacker reads repository history or logs and reuses exposed credentials.",
        "Dangerous Function": "Untrusted input reaches dynamic execution or unsafe deserialization.",
        "Command Execution": "User-controlled command text is executed by the shell.",
        "SQL Injection": "Input changes query structure and reads or modifies unintended data.",
        "Path Traversal": "Input escapes an intended directory and accesses sensitive files.",
    }
    return scenarios.get(finding.category, "The flagged code may become exploitable depending on input control.")


def _fix_for(finding: Finding, knowledge: list[VulnKnowledge] | None = None) -> tuple[str, str, str]:
    knowledge_guidance = next(
        (
            item.fix_guidance[0]
            for item in knowledge or []
            if item.fix_guidance and (item.risk_type or "").lower() == (finding.risk_type or finding.category).lower()
        ),
        None,
    )
    if finding.category == "Secrets":
        return (knowledge_guidance or "Move secrets to environment variables or a secret manager.", "password = os.getenv('APP_PASSWORD')", "Rotate the exposed value and replace literals with env lookups.")
    if finding.category == "Unsafe Deserialization":
        return (knowledge_guidance or "Avoid native object deserialization and unsafe loaders; use a typed parser or safe_load.", "data = yaml.safe_load(raw_text)", "Replace unsafe deserialization with a constrained data format and schema validation.")
    if finding.category == "Command Execution":
        if finding.rule_id == "PY_DANGEROUS_FUNCTION":
            return (
                knowledge_guidance or "Replace eval/exec with an allowlisted operation or a typed parser.",
                "handlers[action](validated_payload)",
                "Map validated action names to explicit functions instead of evaluating input.",
            )
        return (knowledge_guidance or "Avoid shell=True and pass arguments as a list.", "subprocess.run(['ls', target], check=True)", "Validate input and call subprocess without a shell.")
    if finding.category == "SQL Injection":
        return (knowledge_guidance or "Use parameterized queries.", "cursor.execute('SELECT * FROM users WHERE name = ?', (name,))", "Replace string-built SQL with bound parameters.")
    if finding.category == "Path Traversal":
        return (knowledge_guidance or "Normalize paths and enforce an allowed base directory.", "safe = (base / user_path).resolve(); assert safe.is_relative_to(base)", "Resolve and verify paths before reading files.")
    return (knowledge_guidance or "Review the risky pattern and apply least-privilege validation.", "", "Refactor the flagged line.")


def _llm_enabled() -> bool:
    return bool(os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY"))


def _findings_with_evidence(findings: list[Finding], evidences: list[Any]) -> list[dict[str, Any]]:
    evidence_map = {item.evidence_id: item for item in evidences if hasattr(item, "evidence_id")}
    payload: list[dict[str, Any]] = []
    for finding in findings:
        item = {
            "finding_id": finding.finding_id,
            "rule_id": finding.rule_id,
            "risk_type": finding.risk_type or finding.category,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "file_path": finding.file_path,
            "line_start": finding.line_start,
            "line_end": finding.line_end,
            "message": finding.message,
            "sources": finding.sources,
            "evidence_ids": finding.evidence_ids,
            "evidence": [
                evidence_map[evidence_id].model_dump(mode="json")
                for evidence_id in finding.evidence_ids
                if evidence_id in evidence_map
            ],
        }
        payload.append(DEFAULT_SANITIZER.sanitize_value(item))
    return payload


def _llm_batch_finding_assessment(findings: list[Finding], evidences: list[Evidence]) -> tuple[FindingAssessmentBatch | None, str | None]:
    if not findings:
        return FindingAssessmentBatch(analysis_source="llm"), None
    data, fallback_reason, token_usage = _call_llm_json_with_usage(
        "You are an evidence-driven code security assessor. Use only supplied evidence and return compact JSON.",
        {
            "task": "For every finding, analyze risk and review false-positive likelihood in one decision. Never invent evidence or omit a finding_id.",
            "schema": {
                "assessments": [
                    {
                        "finding_id": "string",
                        "risk_type": "string",
                        "risk_reason": "string",
                        "exploit_scenario": "string",
                        "confidence": "number from 0 to 1",
                        "severity": "info|low|medium|high|critical",
                        "status": "confirmed|dismissed|needs_review",
                        "review_reason": "string",
                    }
                ]
            },
            "findings": _findings_with_evidence(findings, evidences),
        },
    )
    if not data:
        return None, fallback_reason
    items = data.get("assessments")
    if not isinstance(items, list):
        return None, "LLM response missing assessments list."
    finding_map = {finding.finding_id: finding for finding in findings}
    evidence_map = {item.evidence_id: item for item in evidences}
    seen: set[str] = set()
    assessed_findings: list[Finding] = []
    analyses: list[RiskAnalysis] = []
    reviews: list[ReviewResult] = []
    try:
        for item in items:
            if not isinstance(item, dict):
                return None, "LLM assessment item is not an object."
            finding_id = str(item.get("finding_id") or "")
            finding = finding_map.get(finding_id)
            if not finding:
                continue
            seen.add(finding_id)
            evidence_ids = [value for value in finding.evidence_ids if value in evidence_map]
            status_value = str(item.get("status") or "needs_review").lower()
            if status_value not in {"confirmed", "dismissed", "needs_review"}:
                status_value = "needs_review"
            if not evidence_ids and status_value == "confirmed":
                status_value = "needs_review"
            status = FindingStatus(status_value)
            severity = _valid_severity(item.get("severity"), finding.severity)
            assessed_findings.append(_with_finding_status(finding, status, "llm"))
            analyses.append(
                RiskAnalysis(
                    finding_id=finding_id,
                    risk_type=str(item.get("risk_type") or finding.category),
                    risk_reason=str(item.get("risk_reason") or finding.message),
                    exploit_scenario=str(item.get("exploit_scenario") or _scenario_for(finding)),
                    confidence=max(0.0, min(1.0, float(item.get("confidence", 0.75)))),
                    severity=severity,
                    analysis_source="llm",
                    evidence_ids=evidence_ids,
                )
            )
            reviews.append(
                ReviewResult(
                    finding_id=finding_id,
                    is_false_positive=status == FindingStatus.DISMISSED,
                    reason=str(item.get("review_reason") or "LLM evidence review completed."),
                    final_severity=severity,
                    status=status,
                    analysis_source="llm",
                    evidence_ids=evidence_ids,
                )
            )
    except (TypeError, ValueError):
        return None, "LLM assessment failed schema coercion."
    missing = set(finding_map) - seen
    if missing:
        return None, f"LLM assessment missing finding_ids: {', '.join(sorted(missing))}."
    return (
        FindingAssessmentBatch(
            findings=assessed_findings,
            risk_analyses=analyses,
            review_results=reviews,
            analysis_source="llm",
            token_usage=token_usage,
        ),
        None,
    )


def _llm_batch_fix_suggestions(findings: list[Finding], evidences: list[Any]) -> tuple[list[FixSuggestion] | None, str | None]:
    if not findings:
        return [], None
    data, fallback_reason = _call_llm_json(
        "You are a secure coding advisor. Return only compact JSON.",
        {
            "task": "Suggest remediations. Do not modify code automatically. Return one result per finding_id.",
            "schema": {
                "fix_suggestions": [
                    {
                        "finding_id": "string",
                        "suggestion": "string",
                        "safe_code_example": "string",
                        "patch_hint": "string",
                    }
                ]
            },
            "findings": _findings_with_evidence(findings, evidences),
        },
    )
    if not data:
        return None, fallback_reason
    items = data.get("fix_suggestions")
    if not isinstance(items, list):
        return None, "LLM response missing fix_suggestions list."
    finding_map = {finding.finding_id: finding for finding in findings}
    seen: set[str] = set()
    suggestions: list[FixSuggestion] = []
    for item in items:
        if not isinstance(item, dict):
            return None, "LLM fix suggestion item is not an object."
        finding_id = str(item.get("finding_id") or "")
        finding = finding_map.get(finding_id)
        if not finding:
            continue
        seen.add(finding_id)
        template_suggestion, template_code, template_hint = _fix_for(finding)
        suggestions.append(
            FixSuggestion(
                finding_id=finding_id,
                suggestion=redact_sensitive_text(str(item.get("suggestion") or template_suggestion)),
                safe_code_example=DEFAULT_SANITIZER.sanitize_code(str(item.get("safe_code_example") or template_code)),
                patch_hint=redact_sensitive_text(str(item.get("patch_hint") or template_hint)),
                analysis_source="llm",
                evidence_ids=finding.evidence_ids,
            )
        )
    missing = set(finding_map) - seen
    if missing:
        return None, f"LLM fix suggestions missing finding_ids: {', '.join(sorted(missing))}."
    return suggestions, None


def _call_llm_json(system_prompt: str, payload: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    parsed, error, _ = _call_llm_json_with_usage(system_prompt, payload)
    return parsed, error


def _call_llm_json_with_usage(system_prompt: str, payload: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None, int]:
    api_key = os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None, "LLM API key is not configured.", 0
    base_url = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = os.getenv("LLM_MODEL", "gpt-4o-mini")
    timeout = int(os.getenv("LLM_TIMEOUT_SECONDS", "30"))
    body = {
        "model": model,
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
        ],
    }
    request = urllib.request.Request(
        f"{base_url}/chat/completions",
        data=json.dumps(body).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = json.loads(response.read().decode("utf-8"))
        content = raw["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        if not isinstance(parsed, dict):
            return None, "LLM response JSON is not an object.", 0
        usage = raw.get("usage") or {}
        return parsed, None, int(usage.get("total_tokens") or 0)
    except KeyError:
        return None, "LLM response missing expected chat completion fields.", 0
    except json.JSONDecodeError:
        return None, "LLM response is not valid JSON.", 0
    except TimeoutError:
        return None, "LLM request timed out.", 0
    except urllib.error.URLError as exc:
        return None, f"LLM request failed: {exc.reason}.", 0
    except OSError as exc:
        return None, f"LLM request failed: {exc}.", 0
