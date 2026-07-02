from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from app.agent.graph import run_audit

router = APIRouter(prefix="/scan", tags=["scan"])


class RepoScanRequest(BaseModel):
    repo_path: str


class DiffScanRequest(BaseModel):
    repo_path: str | None = None
    diff_text: str | None = None
    diff_mode: str = "cached"


def _response(state: dict):
    report = state["final_report"]
    return {
        "report_id": report.report_id,
        "summary": report.summary,
        "findings": [finding.model_dump() for finding in report.findings],
        "risk_analyses": [item.model_dump() for item in report.risk_analyses],
        "review_results": [item.model_dump() for item in report.review_results],
        "fix_suggestions": [item.model_dump() for item in report.fix_suggestions],
        "analysis_summary": report.analysis_summary,
        "fallback_reasons": report.fallback_reasons,
        "traces": [trace.model_dump() for trace in report.traces],
        "markdown_path": report.markdown_path,
        "json_path": report.json_path,
    }


@router.post("/repo")
def scan_repo(request: RepoScanRequest):
    state = run_audit({"mode": "repo_scan", "repo_path": request.repo_path, "traces": [], "errors": []})
    return _response(state)


@router.post("/diff")
def scan_diff(request: DiffScanRequest):
    state = run_audit(
        {
            "mode": "diff_scan",
            "repo_path": request.repo_path,
            "diff_text": request.diff_text,
            "diff_mode": request.diff_mode,
            "traces": [],
            "errors": [],
        }
    )
    return _response(state)
