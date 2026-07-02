from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
import uuid
from collections import Counter
from pathlib import Path
from typing import Any

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover - dependency fallback
    def load_dotenv() -> bool:
        return False

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
        if _llm_enabled():
            analyses = [_llm_risk_analysis(finding) for finding in findings]
            if all(analyses):
                return [item for item in analyses if item is not None]
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
        if _llm_enabled():
            reviews = [_llm_false_positive_review(finding) for finding in findings]
            if all(reviews):
                return [item for item in reviews if item is not None]
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
            if _llm_enabled():
                llm_suggestion = _llm_fix_suggestion(finding)
                if llm_suggestion:
                    suggestions.append(llm_suggestion)
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


def _llm_enabled() -> bool:
    return bool(os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY"))


def _llm_risk_analysis(finding: Finding) -> RiskAnalysis | None:
    data = _call_llm_json(
        "You are a code security auditor. Return only compact JSON.",
        {
            "task": "Analyze this static-scan finding. Do not invent unrelated issues.",
            "schema": {
                "risk_type": "string",
                "risk_reason": "string",
                "exploit_scenario": "string",
                "confidence": "number from 0 to 1",
                "severity": "low|medium|high|critical",
            },
            "finding": finding.model_dump(),
        },
    )
    if not data:
        return None
    try:
        return RiskAnalysis(
            finding_id=finding.finding_id,
            risk_type=str(data.get("risk_type") or finding.category),
            risk_reason=str(data.get("risk_reason") or finding.message),
            exploit_scenario=str(data.get("exploit_scenario") or _scenario_for(finding)),
            confidence=max(0.0, min(1.0, float(data.get("confidence", 0.75)))),
            severity=str(data.get("severity") or finding.severity),
        )
    except (TypeError, ValueError):
        return None


def _llm_false_positive_review(finding: Finding) -> ReviewResult | None:
    data = _call_llm_json(
        "You are reviewing static-scan findings for likely false positives. Return only compact JSON.",
        {
            "task": "Decide whether this finding is likely a false positive using only the evidence.",
            "schema": {
                "is_false_positive": "boolean",
                "reason": "string",
                "final_severity": "low|medium|high|critical",
            },
            "finding": finding.model_dump(),
        },
    )
    if not data:
        return None
    return ReviewResult(
        finding_id=finding.finding_id,
        is_false_positive=bool(data.get("is_false_positive", False)),
        reason=str(data.get("reason") or "LLM review completed."),
        final_severity=str(data.get("final_severity") or finding.severity),
    )


def _llm_fix_suggestion(finding: Finding) -> FixSuggestion | None:
    data = _call_llm_json(
        "You are a secure coding advisor. Return only compact JSON.",
        {
            "task": "Suggest a remediation. Do not modify code automatically.",
            "schema": {
                "suggestion": "string",
                "safe_code_example": "string",
                "patch_hint": "string",
            },
            "finding": finding.model_dump(),
        },
    )
    if not data:
        return None
    return FixSuggestion(
        finding_id=finding.finding_id,
        suggestion=str(data.get("suggestion") or _fix_for(finding)[0]),
        safe_code_example=str(data.get("safe_code_example") or _fix_for(finding)[1]),
        patch_hint=str(data.get("patch_hint") or _fix_for(finding)[2]),
    )


def _call_llm_json(system_prompt: str, payload: dict[str, Any]) -> dict[str, Any] | None:
    api_key = os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None
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
        return parsed if isinstance(parsed, dict) else None
    except (KeyError, json.JSONDecodeError, urllib.error.URLError, TimeoutError, OSError):
        return None


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
