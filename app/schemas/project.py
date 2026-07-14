from typing import Any

from app.schemas.base import BaseModel, Field
from app.schemas.enums import ProfileScope
from app.schemas.execution import ToolRunResult, ValidatedToolCall
from app.schemas.runtime import AuditStageResult


class ProjectProfile(BaseModel):
    languages: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    dependency_files: list[str] = Field(default_factory=list)
    entrypoints: list[str] = Field(default_factory=list)
    route_files: list[str] = Field(default_factory=list)
    auth_files: list[str] = Field(default_factory=list)
    db_files: list[str] = Field(default_factory=list)
    upload_files: list[str] = Field(default_factory=list)
    risk_surfaces: list[str] = Field(default_factory=list)
    security_signals: list[str] = Field(default_factory=list)
    profile_scope: ProfileScope = ProfileScope.FULL_REPO
    profile_confidence: float = Field(default=1.0, ge=0, le=1)
    missing_context: list[str] = Field(default_factory=list)


class VulnKnowledge(BaseModel):
    knowledge_id: str
    title: str
    file_path: str
    risk_type: str | None = None
    languages: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    dangerous_patterns: list[str] = Field(default_factory=list)
    recommended_capabilities: list[str] = Field(default_factory=list)
    audit_focus: list[str] = Field(default_factory=list)
    fix_guidance: list[str] = Field(default_factory=list)
    relevance_score: float = Field(default=0.0, ge=0, le=1)
    match_reasons: list[str] = Field(default_factory=list)
    matched_risk_types: list[str] = Field(default_factory=list)
    content: str


class SecurityTool(BaseModel):
    name: str
    adapter: str | None = None
    executable: str | None = None
    supported_languages: list[str] = Field(default_factory=list)
    risk_types: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    supported_modes: list[str] = Field(default_factory=list)
    cost_level: str = "low"
    requires_install: bool = False
    read_only: bool = True
    timeout_seconds: int = Field(default=30, ge=1, le=600)
    description: str = ""


class ToolPlan(BaseModel):
    selected_tools: list[str] = Field(default_factory=list)
    selected_risk_types: list[str] = Field(default_factory=list)
    target_files: list[str] = Field(default_factory=list)
    selection_reason: str = ""
    tool_calls: list[ValidatedToolCall] = Field(default_factory=list)
    unavailable_tools: list[str] = Field(default_factory=list)
    rejected_targets: list[str] = Field(default_factory=list)
    fallback_reasons: list[str] = Field(default_factory=list)


ToolExecutionResult = ToolRunResult


__all__ = [
    "AuditStageResult",
    "ProjectProfile",
    "SecurityTool",
    "ToolExecutionResult",
    "ToolPlan",
    "VulnKnowledge",
]
