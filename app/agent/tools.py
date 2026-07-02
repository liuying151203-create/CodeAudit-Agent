from __future__ import annotations

import json
import os
import uuid
from collections import Counter
from pathlib import Path
from typing import Any

class BaseTool:
    name = ""
    description = ""

from app.context.context_extractor import extract_evidence
from app.diff.diff_parser import parse_unified_diff
from app.diff.git_diff_loader import load_git_diff
from app.scanners.builtin_rules import scan_files
from app.schemas.finding import Finding, FixSuggestion, ReviewResult, RiskAnalysis
from app.schemas.report import AuditReport
from app.utils.file_filter import should_scan_file


class RepoLoaderTool(BaseTool):
    name: str = "repo_loader"
    description: str = "Load supported source files from a local repository without executing code."

    def run(self, repo_path: str) -> list[dict[str, Any]]:
        root = Path(repo_path).resolve()
        if not root.exists() or not root.is_dir():
            raise ValueError(f"repo_path does not exist or is not a directory: {repo_path}")
        files: list[dict[str, Any]] = []
        for path in root.rglob("*"):
            if path.is_file() and should_scan_file(path):
                rel = str(path.relative_to(root))
                files.append({"path": rel, "content": path.read_text(encoding="utf-8", errors="ignore"), "source": "repo"})
        return files


class GitDiffTool(BaseTool):
    name: str = "git_diff_loader"
    description: str = "Load or parse git unified diff text."

    def run(self, repo_path: str | None = None, diff_text: str | None = None, diff_mode: str = "cached") -> tuple[str, list[dict[str, Any]]]:
        text = diff_text or load_git_diff(repo_path or ".", diff_mode)
        return text, parse_unified_diff(text)


class StaticScanTool(BaseTool):
    name: str = "static_scan"
    description: str = "Run deterministic builtin static scan rules."

    def run(self, files: list[dict[str, Any]]) -> list[Finding]:
        return scan_files(files)


class SecretScanTool(StaticScanTool):
    name: str = "secret_scan"


class ContextExtractorTool(BaseTool):
    name: str = "context_extractor"
    description: str = "Extract code evidence around findings."

    def run(self, findings: list[Finding], files: list[dict[str, Any]]):
        return [extract_evidence(finding, files) for finding in findings]


class RiskAnalyzeTool(BaseTool):
    name: str = "risk_analyzer"
    description: str = "Analyze scanner candidates. Uses rule template when no LLM API is configured."

    def run(self, findings: list[Finding]) -> list[RiskAnalysis]:
        return [
            RiskAnalysis(
                finding_id=f.finding_id,
                risk_type=f.category,
                risk_reason=f.message,
                exploit_scenario=_scenario_for(f),
                confidence=0.86 if f.severity == "high" else 0.72,
                severity=f.severity,
            )
            for f in findings
        ]


class FalsePositiveReviewTool(BaseTool):
    name: str = "false_positive_reviewer"
    description: str = "Review likely false positives using scanner evidence."

    def run(self, findings: list[Finding]) -> list[ReviewResult]:
        results: list[ReviewResult] = []
        for finding in findings:
            evidence = finding.evidence_text.lower()
            is_fp = finding.category == "Secrets" and any(marker in evidence for marker in ["example", "dummy", "placeholder"])
            results.append(
                ReviewResult(
                    finding_id=finding.finding_id,
                    is_false_positive=is_fp,
                    reason="Looks like sample placeholder data." if is_fp else "Static evidence matches a risky pattern.",
                    final_severity="low" if is_fp else finding.severity,
                )
            )
        return results


class FixSuggestTool(BaseTool):
    name: str = "fix_advisor"
    description: str = "Generate remediation guidance and patch hints."

    def run(self, findings: list[Finding], reviews: list[ReviewResult]) -> list[FixSuggestion]:
        review_map = {review.finding_id: review for review in reviews}
        suggestions: list[FixSuggestion] = []
        for finding in findings:
            review = review_map.get(finding.finding_id)
            if review and review.is_false_positive:
                continue
            suggestion, safe_code, hint = _fix_for(finding)
            suggestions.append(FixSuggestion(finding_id=finding.finding_id, suggestion=suggestion, safe_code_example=safe_code, patch_hint=hint))
        return suggestions


class ReportWriterTool(BaseTool):
    name: str = "report_writer"
    description: str = "Write Markdown and JSON audit reports."

    def run(self, state: dict[str, Any]) -> AuditReport:
        report_id = str(uuid.uuid4())[:8]
        report_dir = Path(os.getenv("CODEAUDIT_REPORT_DIR", "data/reports"))
        report_dir.mkdir(parents=True, exist_ok=True)
        findings: list[Finding] = state.get("candidate_findings", [])
        stats = Counter(f.severity for f in findings)
        recommendations = [item.suggestion for item in state.get("fix_suggestions", [])]
        summary = f"Scanned {len(state.get('scanned_files', []))} files and found {len(findings)} candidate risks."
        markdown_path = report_dir / f"{report_id}.md"
        json_path = report_dir / f"{report_id}.json"
        report = AuditReport(
            report_id=report_id,
            mode=state.get("mode", "repo_scan"),
            repo_path=state.get("repo_path"),
            summary=summary,
            risk_stats=dict(stats),
            findings=findings,
            recommendations=recommendations,
            traces=state.get("traces", []),
            markdown_path=str(markdown_path),
            json_path=str(json_path),
        )
        markdown_path.write_text(_to_markdown(report, state), encoding="utf-8")
        json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        return report


def _scenario_for(finding: Finding) -> str:
    scenarios = {
        "Secrets": "An attacker reads repository history or logs and reuses exposed credentials.",
        "Dangerous Function": "Untrusted input reaches dynamic execution or unsafe deserialization.",
        "Command Execution": "User-controlled command text is executed by the shell.",
        "SQL Injection": "Input changes query structure and reads or modifies unintended data.",
        "Path Traversal": "Input escapes an intended directory and accesses sensitive files.",
    }
    return scenarios.get(finding.category, "The flagged code may become exploitable depending on input control.")


def _fix_for(finding: Finding) -> tuple[str, str, str]:
    if finding.category == "Secrets":
        return ("Move secrets to environment variables or a secret manager.", "password = os.getenv('APP_PASSWORD')", "Rotate the exposed value and replace literals with env lookups.")
    if finding.rule_id == "PY_DANGEROUS_FUNCTION":
        return ("Avoid eval/exec and unsafe loaders; use typed parsers or safe_load.", "data = yaml.safe_load(raw_text)", "Replace dynamic execution/deserialization with a constrained parser.")
    if finding.category == "Command Execution":
        return ("Avoid shell=True and pass arguments as a list.", "subprocess.run(['ls', target], check=True)", "Validate input and call subprocess without a shell.")
    if finding.category == "SQL Injection":
        return ("Use parameterized queries.", "cursor.execute('SELECT * FROM users WHERE name = ?', (name,))", "Replace string-built SQL with bound parameters.")
    if finding.category == "Path Traversal":
        return ("Normalize paths and enforce an allowed base directory.", "safe = (base / user_path).resolve(); assert safe.is_relative_to(base)", "Resolve and verify paths before reading files.")
    return ("Review the risky pattern and apply least-privilege validation.", "", "Refactor the flagged line.")


def _to_markdown(report: AuditReport, state: dict[str, Any]) -> str:
    fix_map = {item.finding_id: item for item in state.get("fix_suggestions", [])}
    risk_map = {item.finding_id: item for item in state.get("risk_analyses", [])}
    lines = [f"# CodeAudit Report {report.report_id}", "", f"- Mode: {report.mode}", f"- Summary: {report.summary}", "", "## Risk Stats"]
    for key, value in report.risk_stats.items():
        lines.append(f"- {key}: {value}")
    lines.extend(["", "## Findings"])
    for finding in report.findings:
        risk = risk_map.get(finding.finding_id)
        fix = fix_map.get(finding.finding_id)
        lines.extend(
            [
                f"### {finding.rule_id} ({finding.severity})",
                f"- File: `{finding.file_path}:{finding.line_start}`",
                f"- Category: {finding.category}",
                f"- Evidence: `{finding.evidence_text}`",
                f"- Risk: {risk.risk_reason if risk else finding.message}",
                f"- Exploit scenario: {risk.exploit_scenario if risk else 'N/A'}",
                f"- Fix: {fix.suggestion if fix else 'Review manually.'}",
                "",
            ]
        )
    lines.extend(["## Agent Trace"])
    for trace in report.traces:
        lines.append(f"- {trace.node_name} via {trace.tool_name}: {trace.status} in {trace.elapsed_ms}ms")
    return "\n".join(lines)
