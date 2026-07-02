from app.schemas.base import BaseModel

from app.schemas.finding import Finding


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
    findings: list[Finding]
    recommendations: list[str]
    traces: list[AgentTrace]
    markdown_path: str
    json_path: str
