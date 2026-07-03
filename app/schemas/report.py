from app.schemas.base import BaseModel

from app.schemas.finding import Finding, FixSuggestion, ReviewResult, RiskAnalysis
from app.schemas.project import AuditStageResult, ProjectProfile, ToolExecutionResult, ToolPlan, VulnKnowledge


class AgentTrace(BaseModel):
    node_name: str
    tool_name: str
    input_summary: str
    output_summary: str
    elapsed_ms: int
    status: str


class AuditReport(BaseModel):
    report_id: str
    mode: str
    repo_path: str | None = None
    summary: str
    risk_stats: dict[str, int]
    project_profile: ProjectProfile | None = None
    vuln_knowledge: list[VulnKnowledge] = []
    tool_plan: ToolPlan | None = None
    tool_results: list[ToolExecutionResult] = []
    audit_stage_results: list[AuditStageResult] = []
    findings: list[Finding]
    risk_analyses: list[RiskAnalysis] = []
    review_results: list[ReviewResult] = []
    fix_suggestions: list[FixSuggestion] = []
    analysis_summary: dict[str, int] = {}
    fallback_reasons: list[str] = []
    recommendations: list[str]
    traces: list[AgentTrace]
    markdown_path: str
    json_path: str
