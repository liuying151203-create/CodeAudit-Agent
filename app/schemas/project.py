from typing import Any

from app.schemas.base import BaseModel
from app.schemas.finding import Finding


class ProjectProfile(BaseModel):
    languages: list[str] = []
    frameworks: list[str] = []
    dependency_files: list[str] = []
    entrypoints: list[str] = []
    route_files: list[str] = []
    auth_files: list[str] = []
    db_files: list[str] = []
    upload_files: list[str] = []
    risk_surfaces: list[str] = []


class VulnKnowledge(BaseModel):
    knowledge_id: str
    title: str
    file_path: str
    matched_risk_types: list[str] = []
    content: str


class SecurityTool(BaseModel):
    name: str
    supported_languages: list[str] = []
    risk_types: list[str] = []
    supported_modes: list[str] = []
    cost_level: str = "low"
    requires_install: bool = False
    description: str = ""


class ToolPlan(BaseModel):
    selected_tools: list[str] = []
    selected_risk_types: list[str] = []
    target_files: list[str] = []
    selection_reason: str = ""


class ToolExecutionResult(BaseModel):
    tool_name: str
    status: str
    findings: list[Finding] = []
    output_summary: str = ""
    skipped_reason: str | None = None
    metadata: dict[str, Any] = {}


class AuditStageResult(BaseModel):
    stage_name: str
    status: str
    findings_count: int = 0
    summary: str = ""
