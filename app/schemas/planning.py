from __future__ import annotations

from app.schemas.base import BaseModel, Field
from app.schemas.enums import AuditStageName, Severity


class AuditStagePlan(BaseModel):
    stage: AuditStageName
    priority: Severity = Severity.MEDIUM
    risk_types: list[str] = Field(default_factory=list)
    target_files: list[str] = Field(default_factory=list)
    required_capabilities: list[str] = Field(default_factory=list)
    evidence_goals: list[str] = Field(default_factory=list)
    reason: str = ""


class AuditPlan(BaseModel):
    summary: str = ""
    stages: list[AuditStagePlan] = Field(default_factory=list)
    planner_source: str = "template"
    fallback_reason: str | None = None
