from __future__ import annotations

from typing import Any

from app.schemas.base import BaseModel, Field
from app.schemas.enums import AuditStageName, ToolCallStatus
from app.schemas.finding import Finding


class ToolRequest(BaseModel):
    stage: AuditStageName | None = None
    required_capability: str
    target_files: list[str] = Field(default_factory=list)
    risk_types: list[str] = Field(default_factory=list)
    reason: str
    requested_context: dict[str, Any] = Field(default_factory=dict)


class ValidatedToolCall(BaseModel):
    call_id: str
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = Field(default=30, ge=1, le=600)
    target_files: list[str] = Field(default_factory=list)
    validation_status: ToolCallStatus = ToolCallStatus.VALIDATED
    selection_reason: str = ""
    fallback_tool: str | None = None
    stage: AuditStageName | None = None


class ToolObservation(BaseModel):
    observation_type: str
    content: str
    file_path: str | None = None
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolRunResult(BaseModel):
    call_id: str | None = None
    tool_name: str
    stage: AuditStageName | None = None
    status: str | ToolCallStatus
    findings: list[Finding] = Field(default_factory=list)
    observations: list[ToolObservation] = Field(default_factory=list)
    artifacts: list[str] = Field(default_factory=list)
    output_summary: str = ""
    skipped_reason: str | None = None
    duration_ms: int = Field(default=0, ge=0)
    fallback_used: bool = False
    fallback_tool: str | None = None
    error_message: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
