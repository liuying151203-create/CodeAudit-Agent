from __future__ import annotations

import hashlib
from typing import Any

from app.agent.prompt_context import DEFAULT_SANITIZER
from app.schemas.finding import Finding
from app.schemas.report import AuditReport


def render_markdown(report: AuditReport) -> str:
    fix_map = {item.finding_id: item for item in report.fix_suggestions}
    risk_map = {item.finding_id: item for item in report.risk_analyses}
    review_map = {item.finding_id: item for item in report.review_results}
    lines = [
        f"# CodeAudit Report {report.report_id}",
        "",
        f"- Mode: {report.mode}",
        f"- Summary: {report.summary}",
        f"- Confirmed: {report.metrics.confirmed_findings}",
        f"- Needs review: {len(report.needs_review_findings)}",
        f"- Dismissed: {report.metrics.dismissed_findings}",
        "",
        "## Risk Stats",
    ]
    for key, value in report.risk_stats.items():
        lines.append(f"- {key}: {value}")
    if report.project_profile:
        profile = report.project_profile
        lines.extend(
            [
                "",
                "## Project Profile",
                f"- Languages: {', '.join(profile.languages) or 'N/A'}",
                f"- Frameworks: {', '.join(profile.frameworks) or 'N/A'}",
                f"- Profile scope: {profile.profile_scope.value}",
                f"- Profile confidence: {profile.profile_confidence:.2f}",
                f"- Entrypoints: {', '.join(profile.entrypoints) or 'N/A'}",
                f"- Route files: {', '.join(profile.route_files) or 'N/A'}",
                f"- Auth files: {', '.join(profile.auth_files) or 'N/A'}",
                f"- DB files: {', '.join(profile.db_files) or 'N/A'}",
                f"- Upload files: {', '.join(profile.upload_files) or 'N/A'}",
                f"- Risk surfaces: {', '.join(profile.risk_surfaces) or 'N/A'}",
            ]
        )
    if report.vuln_knowledge:
        lines.extend(["", "## Vulnerability Knowledge"])
        for item in report.vuln_knowledge:
            lines.append(f"- {item.title} (`{item.knowledge_id}`): {', '.join(item.matched_risk_types)}")
    if report.audit_plan:
        lines.extend(
            [
                "",
                "## Audit Plan",
                f"- Planner source: {report.audit_plan.planner_source}",
                f"- Summary: {report.audit_plan.summary}",
            ]
        )
        if report.audit_plan.fallback_reason:
            lines.append(f"- Fallback reason: {report.audit_plan.fallback_reason}")
        for stage in report.audit_plan.stages:
            lines.extend(
                [
                    f"### {stage.stage.value}",
                    f"- Priority: {stage.priority.value}",
                    f"- Risk types: {', '.join(stage.risk_types) or 'N/A'}",
                    f"- Target files: {', '.join(stage.target_files) or 'N/A'}",
                    f"- Required capabilities: {', '.join(stage.required_capabilities) or 'N/A'}",
                    f"- Evidence goals: {', '.join(stage.evidence_goals) or 'N/A'}",
                    f"- Reason: {stage.reason}",
                ]
            )
    if report.tool_plan:
        lines.extend(
            [
                "",
                "## Tool Plan",
                f"- Selected tools: {', '.join(report.tool_plan.selected_tools) or 'N/A'}",
                f"- Selected risk types: {', '.join(report.tool_plan.selected_risk_types) or 'N/A'}",
                f"- Target files: {', '.join(report.tool_plan.target_files) or 'N/A'}",
                f"- Validated calls: {len(report.tool_plan.tool_calls)}",
                f"- Unavailable tools: {', '.join(report.tool_plan.unavailable_tools) or 'N/A'}",
                f"- Rejected targets: {', '.join(report.tool_plan.rejected_targets) or 'N/A'}",
                f"- Reason: {report.tool_plan.selection_reason}",
            ]
        )
    if report.tool_results:
        lines.extend(["", "## Tool Execution"])
        for result in report.tool_results:
            suffix = f" skipped: {result.skipped_reason}" if result.skipped_reason else ""
            fallback = f" fallback: {result.fallback_tool}" if result.fallback_used else ""
            lines.append(f"- {result.tool_name}: {result.status}, {len(result.findings)} findings.{suffix}{fallback}")
    if report.audit_stage_results:
        lines.extend(["", "## Audit Stages"])
        for stage in report.audit_stage_results:
            status = str(getattr(stage.status, "value", stage.status))
            lines.append(
                f"- {stage.stage_name}: {status}, findings={stage.findings_count}, "
                f"rounds={stage.metrics.get('tool_rounds', 0)}, decisions={stage.metrics.get('decisions', 0)}"
            )
    lines.extend(["", "## Analysis Source"])
    if report.analysis_summary:
        for key, value in report.analysis_summary.items():
            lines.append(f"- {key}: {value}")
    else:
        lines.append("- No analysis results.")
    if report.fallback_reasons:
        lines.extend(["", "## Fallback Reasons"])
        lines.extend(f"- {reason}" for reason in report.fallback_reasons)
    lines.extend(
        [
            "",
            "## Integration Metrics",
            f"- Tool calls: {report.metrics.tool_call_count}",
            f"- LLM calls: {report.metrics.llm_call_count}",
            f"- SARIF results: {report.metrics.sarif_result_count}",
            f"- Report bytes: {report.metrics.report_file_bytes}",
            f"- Retained reports: {report.metrics.retained_report_count}",
            f"- Pruned reports: {report.metrics.pruned_report_count}",
        ]
    )
    lines.extend(["", "## Findings"])
    if not report.findings:
        lines.append("- No evidence-backed active findings.")
    for finding in report.findings:
        _append_finding(lines, finding, risk_map, review_map, fix_map)
    if report.needs_review_findings:
        lines.extend(["", "## Needs Review"])
        for finding in report.needs_review_findings:
            review = review_map.get(finding.finding_id)
            lines.append(f"- `{finding.file_path}:{finding.line_start}` {finding.category}: {review.reason if review else finding.message}")
    if report.dismissed_findings:
        lines.extend(["", "## Dismissed Findings"])
        for finding in report.dismissed_findings:
            review = review_map.get(finding.finding_id)
            lines.append(f"- `{finding.file_path}:{finding.line_start}` {finding.category}: {review.reason if review else 'Dismissed by review.'}")
    lines.extend(["", "## Agent Trace"])
    for trace in report.traces:
        details = [f"stage={trace.stage}" if trace.stage else "", f"decision={trace.decision}" if trace.decision else ""]
        if trace.tool_calls:
            details.append(f"tools={','.join(trace.tool_calls)}")
        if trace.llm_used:
            details.append(f"llm=true tokens={trace.token_usage}")
        if trace.fallback_used:
            details.append(f"fallback={trace.fallback_reason}")
        suffix = f" ({'; '.join(item for item in details if item)})" if any(details) else ""
        lines.append(f"- {trace.node_name} via {trace.tool_name}: {trace.status} in {trace.elapsed_ms}ms{suffix}")
    return DEFAULT_SANITIZER.redact_text("\n".join(lines))


def _append_finding(
    lines: list[str],
    finding: Finding,
    risk_map: dict[str, Any],
    review_map: dict[str, Any],
    fix_map: dict[str, Any],
) -> None:
    risk = risk_map.get(finding.finding_id)
    review = review_map.get(finding.finding_id)
    fix = fix_map.get(finding.finding_id)
    provenance = ", ".join(f"{item.source_type}:{item.source_name}" for item in finding.provenance) or ", ".join(finding.sources)
    lines.extend(
        [
            f"### {finding.rule_id} ({finding.severity}, {finding.status.value})",
            f"- File: `{finding.file_path}:{finding.line_start}`",
            f"- Category: {finding.category}",
            f"- Change scope: {finding.change_scope}",
            f"- Sources: {provenance}",
            f"- Source rule IDs: {', '.join(finding.source_rule_ids)}",
            f"- Evidence IDs: {', '.join(finding.evidence_ids) or 'N/A'}",
            f"- Evidence: `{finding.evidence_text}`",
            f"- Analysis source: {risk.analysis_source if risk else finding.analysis_source}",
            f"- Review status: {review.status.value if review and review.status else finding.status.value}",
            f"- Review reason: {review.reason if review else 'N/A'}",
            f"- Risk: {risk.risk_reason if risk else finding.message}",
            f"- Exploit scenario: {risk.exploit_scenario if risk else 'N/A'}",
            f"- Fix: {fix.suggestion if fix else 'Manual review required before remediation.'}",
            "",
        ]
    )


def build_sarif(report: AuditReport) -> dict[str, Any]:
    risk_map = {item.finding_id: item for item in report.risk_analyses}
    review_map = {item.finding_id: item for item in report.review_results}
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in report.findings:
        rules.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "name": finding.rule_id.replace("-", "_").replace(".", "_"),
                "shortDescription": {"text": finding.category},
                "fullDescription": {"text": finding.message},
                "properties": {"security-severity": str(_security_score(finding.severity)), "tags": ["security", finding.category]},
            },
        )
        risk = risk_map.get(finding.finding_id)
        review = review_map.get(finding.finding_id)
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _sarif_level(finding.severity),
                "message": {"text": risk.risk_reason if risk else finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file_path.replace("\\", "/")},
                            "region": {"startLine": finding.line_start, "endLine": finding.line_end},
                        }
                    }
                ],
                "partialFingerprints": {
                    "codeaudit/v1": hashlib.sha256(
                        f"{finding.rule_id}:{finding.file_path}:{finding.category}:{finding.evidence_text}".encode("utf-8")
                    ).hexdigest()
                },
                "properties": {
                    "finding_id": finding.finding_id,
                    "risk_type": finding.risk_type or finding.category,
                    "confidence": finding.confidence,
                    "status": finding.status.value,
                    "change_scope": finding.change_scope,
                    "sources": finding.sources,
                    "evidence_ids": finding.evidence_ids,
                    "analysis_source": risk.analysis_source if risk else finding.analysis_source,
                    "review_reason": review.reason if review else "",
                },
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeAudit-Agent",
                        "semanticVersion": "0.1.0",
                        "informationUri": "https://github.com/liuying151203-create/CodeAudit-Agent",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return DEFAULT_SANITIZER.sanitize_value(sarif)


def _sarif_level(severity: str) -> str:
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}.get(severity, "warning")


def _security_score(severity: str) -> float:
    return {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0, "info": 0.0}.get(severity, 5.0)
