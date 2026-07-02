from typing import Any, TypedDict


class AuditState(TypedDict, total=False):
    mode: str
    repo_path: str | None
    diff_text: str | None
    diff_mode: str | None
    changed_files: list[dict[str, Any]]
    scanned_files: list[dict[str, Any]]
    candidate_findings: list[Any]
    evidences: list[Any]
    risk_analyses: list[Any]
    review_results: list[Any]
    fix_suggestions: list[Any]
    final_report: Any
    traces: list[Any]
    errors: list[str]
