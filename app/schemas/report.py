from typing import Any

from app.schemas.base import BaseModel, Field
from app.schemas.evidence import Evidence

from app.schemas.finding import Finding, FixSuggestion, ReviewResult, RiskAnalysis
from app.schemas.planning import AuditPlan, AuditStagePlan
from app.schemas.project import AuditStageResult, ProjectProfile, ToolExecutionResult, ToolPlan, VulnKnowledge
from app.schemas.runtime import AuditBudget, AuditMetrics, FallbackRecord


class AgentTrace(BaseModel):
    node_name: str
    tool_name: str = ""
    stage: str | None = None
    input_summary: str = ""
    output_summary: str = ""
    decision: str | None = None
    tool_calls: list[str] = Field(default_factory=list)
    llm_used: bool = False
    token_usage: int = 0
    elapsed_ms: int = Field(default=0, ge=0)
    status: str = "success"
    fallback_used: bool = False
    fallback_reason: str | None = None
    error: str | None = None


class AuditReport(BaseModel):
    report_id: str
    mode: str
    repo_path: str | None = None
    summary: str
    risk_stats: dict[str, int] = Field(default_factory=dict)
    project_profile: ProjectProfile | None = None
    vuln_knowledge: list[VulnKnowledge] = Field(default_factory=list)
    audit_plan: AuditPlan | None = None
    stage_queue: list[AuditStagePlan] = Field(default_factory=list)
    tool_plan: ToolPlan | None = None
    tool_results: list[ToolExecutionResult] = Field(default_factory=list)
    audit_stage_results: list[AuditStageResult] = Field(default_factory=list)
    evidences: list[Evidence] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    dismissed_findings: list[Finding] = Field(default_factory=list)
    needs_review_findings: list[Finding] = Field(default_factory=list)
    risk_analyses: list[RiskAnalysis] = Field(default_factory=list)
    review_results: list[ReviewResult] = Field(default_factory=list)
    fix_suggestions: list[FixSuggestion] = Field(default_factory=list)
    analysis_summary: dict[str, int] = Field(default_factory=dict)
    fallback_reasons: list[str] = Field(default_factory=list)
    fallback_records: list[FallbackRecord] = Field(default_factory=list)
    budget: AuditBudget = Field(default_factory=AuditBudget)
    metrics: AuditMetrics = Field(default_factory=AuditMetrics)
    recommendations: list[str] = Field(default_factory=list)
    traces: list[AgentTrace] = Field(default_factory=list)
    state_snapshot: dict[str, Any] = Field(default_factory=dict)
    markdown_path: str = ""
    json_path: str = ""
    sarif_path: str = ""
