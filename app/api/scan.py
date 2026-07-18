from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from app.agent.graph import run_audit

router = APIRouter(prefix="/scan", tags=["scan"])


class RepoScanRequest(BaseModel):
    repo_path: str
    user_task: str | None = None


class DiffScanRequest(BaseModel):
    repo_path: str | None = None
    diff_text: str | None = None
    diff_mode: str = "cached"
    user_task: str | None = None


def _response(state: dict):
    report = state["final_report"]
    return {
        "report_id": report.report_id,
        "summary": report.summary,
        "project_profile": report.project_profile.model_dump() if report.project_profile else None,
        "vuln_knowledge": [item.model_dump() for item in report.vuln_knowledge],
        "audit_plan": report.audit_plan.model_dump() if report.audit_plan else None,
        "stage_queue": [item.model_dump() for item in report.stage_queue],
        "tool_plan": report.tool_plan.model_dump() if report.tool_plan else None,
        "tool_results": [item.model_dump() for item in report.tool_results],
        "audit_stage_results": [item.model_dump() for item in report.audit_stage_results],
        "evidences": [item.model_dump() for item in report.evidences],
        "findings": [finding.model_dump() for finding in report.findings],
        "dismissed_findings": [finding.model_dump() for finding in report.dismissed_findings],
        "needs_review_findings": [finding.model_dump() for finding in report.needs_review_findings],
        "risk_analyses": [item.model_dump() for item in report.risk_analyses],
        "review_results": [item.model_dump() for item in report.review_results],
        "fix_suggestions": [item.model_dump() for item in report.fix_suggestions],
        "analysis_summary": report.analysis_summary,
        "fallback_reasons": report.fallback_reasons,
        "fallback_records": [item.model_dump() for item in report.fallback_records],
        "budget": report.budget.model_dump(),
        "metrics": report.metrics.model_dump(),
        "traces": [trace.model_dump() for trace in report.traces],
        "markdown_path": report.markdown_path,
        "json_path": report.json_path,
        "sarif_path": report.sarif_path,
    }


@router.post("/repo")
def scan_repo(request: RepoScanRequest):
    state = run_audit({"mode": "repo_scan", "repo_path": request.repo_path, "user_task": request.user_task, "traces": [], "errors": []})
    return _response(state)


@router.post("/diff")
def scan_diff(request: DiffScanRequest):
    state = run_audit(
        {
            "mode": "diff_scan",
            "repo_path": request.repo_path,
            "diff_text": request.diff_text,
            "diff_mode": request.diff_mode,
            "user_task": request.user_task,
            "traces": [],
            "errors": [],
        }
    )
    return _response(state)
