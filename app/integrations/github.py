from __future__ import annotations

from app.agent.prompt_context import DEFAULT_SANITIZER
from app.schemas.report import AuditReport

COMMENT_MARKER = "<!-- codeaudit-agent -->"


def render_pr_comment(report: AuditReport, max_findings: int = 10) -> str:
    """Render a bounded PR summary without source snippets or LLM prompt content."""
    findings = sorted(report.findings, key=_finding_sort_key)[:max_findings]
    lines = [
        COMMENT_MARKER,
        "## CodeAudit-Agent 审计摘要",
        "",
        f"- 模式：`{_cell(report.mode)}`",
        f"- 结果：{_cell(report.summary)}",
        f"- 已确认：{report.metrics.confirmed_findings}",
        f"- 待人工复核：{len(report.needs_review_findings)}",
        f"- 已排除：{report.metrics.dismissed_findings}",
        f"- 工具调用：{report.metrics.tool_call_count}，LLM 调用：{report.metrics.llm_call_count}，fallback：{report.metrics.fallback_count}",
        "",
    ]
    if findings:
        lines.extend(
            [
                "| 等级 | 风险类型 | 位置 | 规则 | 状态 |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for finding in findings:
            lines.append(
                f"| {_cell(finding.severity)} | {_cell(finding.category)} | "
                f"`{_cell(finding.file_path)}:{finding.line_start}` | {_cell(finding.rule_id)} | {_cell(finding.status.value)} |"
            )
        remaining = len(report.findings) - len(findings)
        if remaining > 0:
            lines.extend(["", f"另有 {remaining} 条结果，请在 Code Scanning 或报告产物中查看。"])
    else:
        lines.append("未发现有证据支撑的活动风险。")

    if report.fallback_reasons:
        lines.extend(
            [
                "",
                "### 降级说明",
                f"- 本次审计记录了 {len(report.fallback_reasons)} 条降级原因，详细信息仅保留在完整报告产物中。",
            ]
        )
    lines.extend(
        [
            "",
            f"报告 ID：`{_cell(report.report_id)}`。完整 Markdown、JSON 和 SARIF 已作为工作流产物保存。",
            "",
            "> 评论仅包含风险元数据，不包含代码片段、密钥内容或 LLM 上下文。",
        ]
    )
    return DEFAULT_SANITIZER.redact_text("\n".join(lines))[:60_000]


def _cell(value: object) -> str:
    return str(value or "N/A").replace("|", "\\|").replace("\r", " ").replace("\n", " ").strip()


def _finding_sort_key(finding: object) -> tuple[int, str, int]:
    severity = str(getattr(finding, "severity", "medium"))
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return rank.get(severity, 2), str(getattr(finding, "file_path", "")), int(getattr(finding, "line_start", 1))
