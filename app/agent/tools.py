from __future__ import annotations

import json
import os
import shutil
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
from app.schemas.enums import ProfileScope
from app.schemas.project import AuditStageResult, ProjectProfile, SecurityTool, ToolExecutionResult, ToolPlan, VulnKnowledge
from app.schemas.report import AuditReport
from app.schemas.runtime import AuditMetrics, FallbackRecord
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


class ProjectReaderTool(BaseTool):
    name: str = "project_reader"
    description: str = "Read project structure and build a security-oriented project profile without executing code."

    def run(self, repo_path: str | None = None, files: list[dict[str, Any]] | None = None) -> tuple[ProjectProfile, list[dict[str, Any]]]:
        source_files = files or []
        all_paths: list[Path] = []
        root: Path | None = None
        if repo_path:
            root = Path(repo_path).resolve()
            if root.exists() and root.is_dir():
                all_paths = [path for path in root.rglob("*") if path.is_file() and not _is_ignored_path(path)]
                if not source_files:
                    source_files = RepoLoaderTool().run(str(root))

        rel_paths = [str(path.relative_to(root)) if root else item["path"] for path in all_paths] if root else [item["path"] for item in source_files]
        dependency_files = [path for path in rel_paths if Path(path).name.lower() in _DEPENDENCY_FILE_NAMES]
        text_by_path = _read_profile_text(root, all_paths, source_files)
        languages = _detect_languages(rel_paths)
        frameworks = _detect_frameworks(rel_paths, text_by_path)
        entrypoints = _match_paths(rel_paths, ["main.py", "app.py", "manage.py", "asgi.py", "wsgi.py", "server.py"])
        route_files = _match_semantic_files(rel_paths, text_by_path, ["route", "router", "urls", "controller", "@app.route", "APIRouter"])
        auth_files = _match_semantic_files(rel_paths, text_by_path, ["auth", "login", "jwt", "oauth", "permission", "token"])
        db_files = _match_semantic_files(rel_paths, text_by_path, ["db", "database", "model", "mapper", "repository", "sqlite", "sqlalchemy", "cursor.execute"])
        upload_files = _match_semantic_files(rel_paths, text_by_path, ["upload", "file", "multipart", "send_file", "UploadFile"])
        risk_surfaces = _infer_risk_surfaces(frameworks, dependency_files, route_files, auth_files, db_files, upload_files, text_by_path)
        is_diff = any(item.get("source") == "diff" for item in source_files)
        if is_diff and root:
            profile_scope = ProfileScope.DIFF_ENRICHED
            profile_confidence = 0.8
            missing_context = ["Only changed files and selected repository context were profiled."]
        elif is_diff:
            profile_scope = ProfileScope.DIFF_ONLY
            profile_confidence = 0.55
            missing_context = ["Repository files and dependency metadata are unavailable."]
        else:
            profile_scope = ProfileScope.FULL_REPO
            profile_confidence = 1.0
            missing_context = []
        return (
            ProjectProfile(
                languages=languages,
                frameworks=frameworks,
                dependency_files=dependency_files,
                entrypoints=entrypoints,
                route_files=route_files,
                auth_files=auth_files,
                db_files=db_files,
                upload_files=upload_files,
                risk_surfaces=risk_surfaces,
                profile_scope=profile_scope,
                profile_confidence=profile_confidence,
                missing_context=missing_context,
            ),
            source_files,
        )


class VulnKBRetrieverTool(BaseTool):
    name: str = "vulnkb_retriever"
    description: str = "Retrieve relevant vulnerability knowledge documents for the project profile and user task."

    def run(self, profile: ProjectProfile, task: str = "") -> list[VulnKnowledge]:
        kb_dir = Path("knowledge_base")
        if not kb_dir.exists():
            return []
        query_terms = {item.lower() for item in [*profile.risk_surfaces, *profile.frameworks, *profile.languages, task] if item}
        knowledge: list[VulnKnowledge] = []
        for path in sorted(kb_dir.glob("*.md")):
            content = path.read_text(encoding="utf-8", errors="ignore")
            content_lower = content.lower()
            matched = sorted({term for term in query_terms if term and term in content_lower})
            if matched or _kb_default_match(path.name, profile):
                knowledge.append(
                    VulnKnowledge(
                        knowledge_id=path.stem,
                        title=_first_heading(content) or path.stem.replace("_", " ").title(),
                        file_path=str(path),
                        matched_risk_types=_risk_types_for_kb(path.stem),
                        content=content,
                    )
                )
        return knowledge


class ToolSelectorTool(BaseTool):
    name: str = "tool_selector"
    description: str = "Select security tools based on project profile, retrieved vulnerability knowledge and scan mode."

    def run(self, profile: ProjectProfile, knowledge: list[VulnKnowledge], scan_mode: str, files: list[dict[str, Any]]) -> ToolPlan:
        tools = _load_security_tools()
        risk_types = sorted({risk for item in knowledge for risk in item.matched_risk_types} | set(profile.risk_surfaces))
        target_files = _select_target_files(profile, files)
        selected: list[str] = []
        reasons: list[str] = []
        for tool in tools:
            if scan_mode not in tool.supported_modes:
                continue
            if not _intersects(profile.languages, tool.supported_languages):
                continue
            if not _intersects(risk_types, tool.risk_types):
                continue
            selected.append(tool.name)
            reasons.append(f"{tool.name} matches languages={tool.supported_languages} risk_types={tool.risk_types}")
        if "custom_rule_scanner" not in selected:
            selected.append("custom_rule_scanner")
            reasons.append("custom_rule_scanner is the builtin fallback scanner.")
        return ToolPlan(
            selected_tools=selected,
            selected_risk_types=risk_types,
            target_files=target_files,
            selection_reason="; ".join(reasons),
        )


class ToolExecutorTool(BaseTool):
    name: str = "tool_executor"
    description: str = "Execute selected security tools safely. External tools are skipped when unavailable."

    def run(self, plan: ToolPlan, files: list[dict[str, Any]], mode: str) -> tuple[list[ToolExecutionResult], list[AuditStageResult]]:
        target_files = set(plan.target_files)
        selected_files = [item for item in files if not target_files or item["path"] in target_files]
        results: list[ToolExecutionResult] = []
        for tool_name in plan.selected_tools:
            if tool_name == "secret_scanner":
                findings = [finding for finding in scan_files(selected_files) if finding.category == "Secrets"]
                results.append(ToolExecutionResult(tool_name=tool_name, status="success", findings=findings, output_summary=f"{len(findings)} secret findings"))
            elif tool_name == "custom_rule_scanner":
                findings = scan_files(selected_files)
                results.append(ToolExecutionResult(tool_name=tool_name, status="success", findings=findings, output_summary=f"{len(findings)} builtin rule findings"))
            elif tool_name in {"bandit", "semgrep"}:
                executable = shutil.which(tool_name)
                if not executable:
                    results.append(
                        ToolExecutionResult(
                            tool_name=tool_name,
                            status="skipped",
                            skipped_reason=f"{tool_name} is not installed; builtin scanners were used instead.",
                            output_summary="external tool unavailable",
                        )
                    )
                else:
                    results.append(
                        ToolExecutionResult(
                            tool_name=tool_name,
                            status="skipped",
                            skipped_reason=f"{tool_name} integration is registered but not executed in MVP safe mode.",
                            output_summary="registered external tool skipped",
                        )
                    )
            elif tool_name == "context_extractor":
                results.append(ToolExecutionResult(tool_name=tool_name, status="success", findings=[], output_summary="context extraction runs after finding merge"))
        return results, _build_stage_results(results)


class FindingMergerTool(BaseTool):
    name: str = "finding_merger"
    description: str = "Merge and deduplicate findings emitted by selected tools."

    def run(self, tool_results: list[ToolExecutionResult]) -> list[Finding]:
        merged: dict[tuple[str, str, int, str], Finding] = {}
        for result in tool_results:
            for finding in result.findings:
                key = (finding.rule_id, finding.file_path, finding.line_start, finding.evidence_text)
                if key not in merged:
                    merged[key] = finding
        return list(merged.values())


_DEPENDENCY_FILE_NAMES = {
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "pipfile",
    "package.json",
    "pom.xml",
    "build.gradle",
    "go.mod",
}


def _is_ignored_path(path: Path) -> bool:
    ignored = {".git", ".venv", "venv", "node_modules", "target", "dist", "__pycache__", ".mypy_cache"}
    return bool(set(path.parts) & ignored)


def _read_profile_text(root: Path | None, all_paths: list[Path], files: list[dict[str, Any]]) -> dict[str, str]:
    if root:
        text_by_path: dict[str, str] = {}
        for path in all_paths:
            if path.suffix.lower() in {".py", ".txt", ".toml", ".json", ".xml", ".yml", ".yaml", ".md"}:
                rel = str(path.relative_to(root))
                text_by_path[rel] = path.read_text(encoding="utf-8", errors="ignore")[:20000]
        return text_by_path
    return {item["path"]: item.get("content", "")[:20000] for item in files}


def _detect_languages(paths: list[str]) -> list[str]:
    mapping = {".py": "Python", ".js": "JavaScript", ".ts": "TypeScript", ".java": "Java", ".go": "Go", ".rb": "Ruby"}
    return sorted({mapping[Path(path).suffix.lower()] for path in paths if Path(path).suffix.lower() in mapping})


def _detect_frameworks(paths: list[str], text_by_path: dict[str, str]) -> list[str]:
    joined = "\n".join(text_by_path.values()).lower()
    frameworks = []
    checks = {
        "FastAPI": ["fastapi", "apirouter"],
        "Flask": ["flask", "@app.route"],
        "Django": ["django", "manage.py"],
        "Spring": ["springframework", "@restcontroller"],
        "Express": ["express"],
        "SQLAlchemy": ["sqlalchemy"],
    }
    for name, needles in checks.items():
        if any(needle in joined for needle in needles) or any("manage.py" in path for path in paths if name == "Django"):
            frameworks.append(name)
    return sorted(set(frameworks))


def _match_paths(paths: list[str], names: list[str]) -> list[str]:
    names_lower = {name.lower() for name in names}
    return sorted([path for path in paths if Path(path).name.lower() in names_lower])


def _match_semantic_files(paths: list[str], text_by_path: dict[str, str], keywords: list[str]) -> list[str]:
    matches: set[str] = set()
    lowered_keywords = [keyword.lower() for keyword in keywords]
    for path in paths:
        normalized = path.lower().replace("\\", "/")
        content = text_by_path.get(path, "").lower()
        if any(keyword in normalized or keyword in content for keyword in lowered_keywords):
            matches.add(path)
    return sorted(matches)


def _infer_risk_surfaces(
    frameworks: list[str],
    dependency_files: list[str],
    route_files: list[str],
    auth_files: list[str],
    db_files: list[str],
    upload_files: list[str],
    text_by_path: dict[str, str],
) -> list[str]:
    joined = "\n".join(text_by_path.values()).lower()
    surfaces = {"Secrets"}
    if db_files or any(token in joined for token in ["select ", "cursor.execute", "sqlalchemy"]):
        surfaces.add("SQL Injection")
    if any(token in joined for token in ["subprocess", "os.system", "shell=true"]):
        surfaces.add("Command Execution")
    if upload_files or any(token in joined for token in ["../", "uploadfile", "send_file", "open("]):
        surfaces.add("Path Traversal")
    if any(token in joined for token in ["pickle.load", "yaml.load"]):
        surfaces.add("Unsafe Deserialization")
    if auth_files or route_files or frameworks:
        surfaces.add("Broken Access Control")
    if dependency_files:
        surfaces.add("Dependency Risk")
    return sorted(surfaces)


def _first_heading(content: str) -> str | None:
    for line in content.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return None


def _risk_types_for_kb(stem: str) -> list[str]:
    mapping = {
        "sql_injection": ["SQL Injection"],
        "command_injection": ["Command Execution"],
        "secret_leak": ["Secrets"],
        "path_traversal": ["Path Traversal"],
        "unsafe_deserialization": ["Unsafe Deserialization"],
        "broken_access_control": ["Broken Access Control"],
    }
    return mapping.get(stem, [])


def _kb_default_match(file_name: str, profile: ProjectProfile) -> bool:
    risk_text = " ".join(profile.risk_surfaces).lower()
    stem = Path(file_name).stem
    aliases = {
        "sql_injection": "sql injection",
        "command_injection": "command execution",
        "secret_leak": "secrets",
        "path_traversal": "path traversal",
        "unsafe_deserialization": "unsafe deserialization",
        "broken_access_control": "broken access control",
    }
    return aliases.get(stem, stem) in risk_text


def _load_security_tools() -> list[SecurityTool]:
    path = Path("config/security_tools.yaml")
    if not path.exists():
        return [
            SecurityTool(name="custom_rule_scanner", supported_languages=["Python"], risk_types=["Secrets", "SQL Injection", "Command Execution"], supported_modes=["repo_scan", "diff_scan"])
        ]
    return _parse_security_tools_yaml(path.read_text(encoding="utf-8"))


def _parse_security_tools_yaml(text: str) -> list[SecurityTool]:
    tools: list[SecurityTool] = []
    current: dict[str, Any] | None = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped == "tools:":
            continue
        if line.startswith("  ") and stripped.endswith(":") and not line.startswith("    "):
            if current:
                tools.append(SecurityTool(**current))
            current = {"name": stripped[:-1]}
            continue
        if current is not None and ":" in stripped:
            key, value = stripped.split(":", 1)
            value = value.strip()
            if value.startswith("[") and value.endswith("]"):
                current[key] = [item.strip().strip("\"'") for item in value[1:-1].split(",") if item.strip()]
            elif value.lower() in {"true", "false"}:
                current[key] = value.lower() == "true"
            else:
                current[key] = value.strip("\"'")
    if current:
        tools.append(SecurityTool(**current))
    return tools


def _intersects(left: list[str], right: list[str]) -> bool:
    if not left or not right:
        return True
    return bool({item.lower() for item in left} & {item.lower() for item in right})


def _select_target_files(profile: ProjectProfile, files: list[dict[str, Any]]) -> list[str]:
    priority = set(profile.route_files + profile.auth_files + profile.db_files + profile.upload_files + profile.entrypoints)
    if priority:
        return sorted(priority)
    return sorted([item["path"] for item in files])


def _build_stage_results(results: list[ToolExecutionResult]) -> list[AuditStageResult]:
    stage_risks = {
        "init": [],
        "secret": ["Secrets"],
        "injection": ["SQL Injection"],
        "command": ["Command Execution"],
        "file": ["Path Traversal", "Unsafe Deserialization"],
        "auth": ["Broken Access Control"],
        "review": [],
        "report": [],
    }
    all_findings = [finding for result in results for finding in result.findings]
    stage_results: list[AuditStageResult] = []
    for stage, categories in stage_risks.items():
        count = len([finding for finding in all_findings if finding.category in categories]) if categories else 0
        status = "success" if stage in {"init", "secret", "injection", "command", "review", "report"} else "planned"
        stage_results.append(AuditStageResult(stage_name=stage, status=status, findings_count=count, summary=f"{stage} stage findings: {count}"))
    return stage_results


class RiskAnalyzeTool(BaseTool):
    name: str = "risk_analyzer"
    description: str = "Analyze scanner candidates. Uses rule template when no LLM API is configured."

    def run(self, findings: list[Finding], evidences: list[Any] | None = None) -> list[RiskAnalysis]:
        fallback_reason = None
        if _llm_enabled():
            analyses, fallback_reason = _llm_batch_risk_analysis(findings, evidences or [])
            if analyses is not None:
                return analyses
        elif findings:
            fallback_reason = "LLM API key is not configured."
        return [
            RiskAnalysis(
                finding_id=f.finding_id,
                risk_type=f.category,
                risk_reason=f.message,
                exploit_scenario=_scenario_for(f),
                confidence=0.86 if f.severity == "high" else 0.72,
                severity=f.severity,
                analysis_source="template",
                fallback_reason=fallback_reason,
            )
            for f in findings
        ]


class FalsePositiveReviewTool(BaseTool):
    name: str = "false_positive_reviewer"
    description: str = "Review likely false positives using scanner evidence."

    def run(self, findings: list[Finding], evidences: list[Any] | None = None) -> list[ReviewResult]:
        fallback_reason = None
        if _llm_enabled():
            reviews, fallback_reason = _llm_batch_false_positive_review(findings, evidences or [])
            if reviews is not None:
                return reviews
        elif findings:
            fallback_reason = "LLM API key is not configured."
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
                    analysis_source="template",
                    fallback_reason=fallback_reason,
                )
            )
        return results


class FixSuggestTool(BaseTool):
    name: str = "fix_advisor"
    description: str = "Generate remediation guidance and patch hints."

    def run(self, findings: list[Finding], reviews: list[ReviewResult], evidences: list[Any] | None = None) -> list[FixSuggestion]:
        review_map = {review.finding_id: review for review in reviews}
        active_findings = [finding for finding in findings if not (review_map.get(finding.finding_id) and review_map[finding.finding_id].is_false_positive)]
        fallback_reason = None
        if _llm_enabled():
            llm_suggestions, fallback_reason = _llm_batch_fix_suggestions(active_findings, evidences or [])
            if llm_suggestions is not None:
                return llm_suggestions
        elif active_findings:
            fallback_reason = "LLM API key is not configured."
        suggestions: list[FixSuggestion] = []
        for finding in active_findings:
            suggestion, safe_code, hint = _fix_for(finding)
            suggestions.append(
                FixSuggestion(
                    finding_id=finding.finding_id,
                    suggestion=suggestion,
                    safe_code_example=safe_code,
                    patch_hint=hint,
                    analysis_source="template",
                    fallback_reason=fallback_reason,
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
        findings: list[Finding] = state.get("candidate_findings", [])
        risk_analyses: list[RiskAnalysis] = state.get("risk_analyses", [])
        review_results: list[ReviewResult] = state.get("review_results", [])
        fix_suggestions: list[FixSuggestion] = state.get("fix_suggestions", [])
        stats = Counter(f.severity for f in findings)
        recommendations = [item.suggestion for item in fix_suggestions]
        analysis_items = [*risk_analyses, *review_results, *fix_suggestions]
        analysis_summary = Counter(item.analysis_source for item in analysis_items if getattr(item, "analysis_source", None))
        fallback_reasons = sorted({item.fallback_reason for item in analysis_items if getattr(item, "fallback_reason", None)})
        fallback_records: list[FallbackRecord] = state.get("fallbacks", [])
        if not fallback_records:
            fallback_records = [FallbackRecord(component="llm_analysis", reason=reason, strategy="template") for reason in fallback_reasons]
        confirmed_findings = [
            finding
            for finding in findings
            if not any(review.finding_id == finding.finding_id and review.is_false_positive for review in review_results)
        ]
        metrics = state.get("metrics") or AuditMetrics()
        metrics.detected_findings = len(findings)
        metrics.confirmed_findings = len(confirmed_findings)
        metrics.dismissed_findings = len(findings) - len(confirmed_findings)
        metrics.tool_call_count = len(state.get("tool_results", []))
        metrics.llm_call_count = sum(
            [
                any(item.analysis_source == "llm" for item in risk_analyses),
                any(item.analysis_source == "llm" for item in review_results),
                any(item.analysis_source == "llm" for item in fix_suggestions),
            ]
        )
        metrics.fallback_count = len(fallback_records)
        metrics.total_latency_ms = sum(getattr(trace, "elapsed_ms", 0) for trace in state.get("traces", []))
        metrics.stage_coverage = {item.stage_name: str(item.status) for item in state.get("audit_stage_results", [])}
        state["confirmed_findings"] = confirmed_findings
        state["fallbacks"] = fallback_records
        state["metrics"] = metrics
        from app.agent.state import serialize_audit_state, sync_audit_state

        sync_audit_state(state)
        summary = f"Scanned {len(state.get('scanned_files', []))} files and found {len(findings)} candidate risks."
        markdown_path = report_dir / f"{report_id}.md"
        json_path = report_dir / f"{report_id}.json"
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
            findings=findings,
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
            state_snapshot=serialize_audit_state(state),
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


def _findings_with_evidence(findings: list[Finding], evidences: list[Any]) -> list[dict[str, Any]]:
    evidence_map = {item.finding_id: item for item in evidences if hasattr(item, "finding_id")}
    payload: list[dict[str, Any]] = []
    for finding in findings:
        item = finding.model_dump()
        evidence = evidence_map.get(finding.finding_id)
        if evidence:
            item["evidence"] = evidence.model_dump() if hasattr(evidence, "model_dump") else dict(evidence)
        payload.append(item)
    return payload


def _llm_batch_risk_analysis(findings: list[Finding], evidences: list[Any]) -> tuple[list[RiskAnalysis] | None, str | None]:
    if not findings:
        return [], None
    data, fallback_reason = _call_llm_json(
        "You are a code security auditor. Return only compact JSON.",
        {
            "task": "Analyze these static-scan findings. Do not invent unrelated issues. Return one result per finding_id.",
            "schema": {
                "risk_analyses": [
                    {
                        "finding_id": "string",
                        "risk_type": "string",
                        "risk_reason": "string",
                        "exploit_scenario": "string",
                        "confidence": "number from 0 to 1",
                        "severity": "low|medium|high|critical",
                    }
                ]
            },
            "findings": _findings_with_evidence(findings, evidences),
        },
    )
    if not data:
        return None, fallback_reason
    items = data.get("risk_analyses")
    if not isinstance(items, list):
        return None, "LLM response missing risk_analyses list."
    finding_map = {finding.finding_id: finding for finding in findings}
    seen: set[str] = set()
    analyses: list[RiskAnalysis] = []
    try:
        for item in items:
            if not isinstance(item, dict):
                return None, "LLM risk analysis item is not an object."
            finding_id = str(item.get("finding_id") or "")
            finding = finding_map.get(finding_id)
            if not finding:
                continue
            seen.add(finding_id)
            analyses.append(
                RiskAnalysis(
                    finding_id=finding_id,
                    risk_type=str(item.get("risk_type") or finding.category),
                    risk_reason=str(item.get("risk_reason") or finding.message),
                    exploit_scenario=str(item.get("exploit_scenario") or _scenario_for(finding)),
                    confidence=max(0.0, min(1.0, float(item.get("confidence", 0.75)))),
                    severity=str(item.get("severity") or finding.severity),
                    analysis_source="llm",
                )
            )
    except (TypeError, ValueError):
        return None, "LLM risk analysis failed schema coercion."
    missing = set(finding_map) - seen
    if missing:
        return None, f"LLM risk analysis missing finding_ids: {', '.join(sorted(missing))}."
    return analyses, None


def _llm_batch_false_positive_review(findings: list[Finding], evidences: list[Any]) -> tuple[list[ReviewResult] | None, str | None]:
    if not findings:
        return [], None
    data, fallback_reason = _call_llm_json(
        "You are reviewing static-scan findings for likely false positives. Return only compact JSON.",
        {
            "task": "Decide whether these findings are likely false positives using only the evidence. Return one result per finding_id.",
            "schema": {
                "review_results": [
                    {
                        "finding_id": "string",
                        "is_false_positive": "boolean",
                        "reason": "string",
                        "final_severity": "low|medium|high|critical",
                    }
                ]
            },
            "findings": _findings_with_evidence(findings, evidences),
        },
    )
    if not data:
        return None, fallback_reason
    items = data.get("review_results")
    if not isinstance(items, list):
        return None, "LLM response missing review_results list."
    finding_map = {finding.finding_id: finding for finding in findings}
    seen: set[str] = set()
    reviews: list[ReviewResult] = []
    for item in items:
        if not isinstance(item, dict):
            return None, "LLM review item is not an object."
        finding_id = str(item.get("finding_id") or "")
        finding = finding_map.get(finding_id)
        if not finding:
            continue
        seen.add(finding_id)
        reviews.append(
            ReviewResult(
                finding_id=finding_id,
                is_false_positive=bool(item.get("is_false_positive", False)),
                reason=str(item.get("reason") or "LLM review completed."),
                final_severity=str(item.get("final_severity") or finding.severity),
                analysis_source="llm",
            )
        )
    missing = set(finding_map) - seen
    if missing:
        return None, f"LLM false-positive review missing finding_ids: {', '.join(sorted(missing))}."
    return reviews, None


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
                suggestion=str(item.get("suggestion") or template_suggestion),
                safe_code_example=str(item.get("safe_code_example") or template_code),
                patch_hint=str(item.get("patch_hint") or template_hint),
                analysis_source="llm",
            )
        )
    missing = set(finding_map) - seen
    if missing:
        return None, f"LLM fix suggestions missing finding_ids: {', '.join(sorted(missing))}."
    return suggestions, None


def _call_llm_json(system_prompt: str, payload: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    api_key = os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None, "LLM API key is not configured."
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
            return None, "LLM response JSON is not an object."
        return parsed, None
    except KeyError:
        return None, "LLM response missing expected chat completion fields."
    except json.JSONDecodeError:
        return None, "LLM response is not valid JSON."
    except TimeoutError:
        return None, "LLM request timed out."
    except urllib.error.URLError as exc:
        return None, f"LLM request failed: {exc.reason}."
    except OSError as exc:
        return None, f"LLM request failed: {exc}."


def _to_markdown(report: AuditReport, state: dict[str, Any]) -> str:
    fix_map = {item.finding_id: item for item in state.get("fix_suggestions", [])}
    risk_map = {item.finding_id: item for item in state.get("risk_analyses", [])}
    review_map = {item.finding_id: item for item in state.get("review_results", [])}
    lines = [f"# CodeAudit Report {report.report_id}", "", f"- Mode: {report.mode}", f"- Summary: {report.summary}", "", "## Risk Stats"]
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
    if report.tool_plan:
        lines.extend(
            [
                "",
                "## Tool Plan",
                f"- Selected tools: {', '.join(report.tool_plan.selected_tools) or 'N/A'}",
                f"- Selected risk types: {', '.join(report.tool_plan.selected_risk_types) or 'N/A'}",
                f"- Target files: {', '.join(report.tool_plan.target_files) or 'N/A'}",
                f"- Reason: {report.tool_plan.selection_reason}",
            ]
        )
    if report.tool_results:
        lines.extend(["", "## Tool Execution"])
        for result in report.tool_results:
            suffix = f" skipped: {result.skipped_reason}" if result.skipped_reason else ""
            lines.append(f"- {result.tool_name}: {result.status}, {len(result.findings)} findings.{suffix}")
    if report.audit_stage_results:
        lines.extend(["", "## Audit Stages"])
        for stage in report.audit_stage_results:
            lines.append(f"- {stage.stage_name}: {stage.status}, findings={stage.findings_count}")
    lines.extend(["", "## Analysis Source"])
    if report.analysis_summary:
        for key, value in report.analysis_summary.items():
            lines.append(f"- {key}: {value}")
    else:
        lines.append("- No analysis results.")
    if report.fallback_reasons:
        lines.extend(["", "## Fallback Reasons"])
        for reason in report.fallback_reasons:
            lines.append(f"- {reason}")
    lines.extend(["", "## Findings"])
    for finding in report.findings:
        risk = risk_map.get(finding.finding_id)
        review = review_map.get(finding.finding_id)
        fix = fix_map.get(finding.finding_id)
        lines.extend(
            [
                f"### {finding.rule_id} ({finding.severity})",
                f"- File: `{finding.file_path}:{finding.line_start}`",
                f"- Category: {finding.category}",
                f"- Evidence: `{finding.evidence_text}`",
                f"- Analysis source: {risk.analysis_source if risk else 'scanner'}",
                f"- False positive: {review.is_false_positive if review else 'N/A'}",
                f"- Review reason: {review.reason if review else 'N/A'}",
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
