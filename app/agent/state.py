from typing import Any, TypedDict


class AuditState(TypedDict, total=False):
    mode: str
    repo_path: str | None
    diff_text: str | None
    diff_mode: str | None
    changed_files: list[dict[str, Any]]
    scanned_files: list[dict[str, Any]]
    project_profile: Any
    vuln_knowledge: list[Any]
    tool_plan: Any
    tool_results: list[Any]
    audit_stage_results: list[Any]
    candidate_findings: list[Any]
    evidences: list[Any]
    risk_analyses: list[Any]
    review_results: list[Any]
    fix_suggestions: list[Any]
    final_report: Any
    traces: list[Any]
    errors: list[str]
