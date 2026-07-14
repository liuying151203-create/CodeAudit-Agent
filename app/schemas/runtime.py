from __future__ import annotations

from typing import Any

try:
    from pydantic import model_validator
except Exception:  # pragma: no cover - lightweight runtime fallback
    def model_validator(*_: object, **__: object):
        return lambda function: function

from app.schemas.base import BaseModel, Field
from app.schemas.enums import AuditDecisionType, AuditStageName, StageStatus
from app.schemas.execution import ToolRequest
from app.schemas.finding import FindingDraft


class AuditBudget(BaseModel):
    max_tool_rounds_per_stage: int = Field(default=2, ge=0, le=20)
    max_tool_calls_per_round: int = Field(default=2, ge=1, le=20)
    max_files_per_call: int = Field(default=5, ge=1, le=100)
    max_context_lines_per_file: int = Field(default=80, ge=1, le=2000)
    max_stage_tokens: int = Field(default=12000, ge=0)
    max_stage_seconds: int = Field(default=120, ge=1)
    max_total_seconds: int = Field(default=600, ge=1)
    used_tool_rounds: dict[str, int] = Field(default_factory=dict)
    used_tool_calls: int = 0
    used_tokens: int = 0


class AuditMetrics(BaseModel):
    detected_findings: int = 0
    confirmed_findings: int = 0
    dismissed_findings: int = 0
    tool_call_count: int = 0
    llm_call_count: int = 0
    fallback_count: int = 0
    total_tokens: int = 0
    total_latency_ms: int = 0
    stage_coverage: dict[str, str] = Field(default_factory=dict)


class FallbackRecord(BaseModel):
    component: str
    reason: str
    strategy: str
    stage: AuditStageName | None = None


class AuditError(BaseModel):
    component: str
    message: str
    blocking: bool = False
    stage: AuditStageName | None = None


class AuditHypothesis(BaseModel):
    hypothesis_id: str
    stage: AuditStageName
    risk_type: str
    description: str
    target_files: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    status: str = "open"


class AuditDecision(BaseModel):
    decision: AuditDecisionType
    reason: str
    tool_request: ToolRequest | None = None
    finding: FindingDraft | None = None

    @model_validator(mode="after")
    def validate_payload(self) -> "AuditDecision":
        if self.decision == AuditDecisionType.CALL_TOOL and self.tool_request is None:
            raise ValueError("CALL_TOOL requires tool_request")
        if self.decision == AuditDecisionType.CALL_TOOL and self.finding is not None:
            raise ValueError("CALL_TOOL cannot include finding")
        if self.decision == AuditDecisionType.EMIT_FINDING and self.finding is None:
            raise ValueError("EMIT_FINDING requires finding")
        if self.decision == AuditDecisionType.EMIT_FINDING and self.tool_request is not None:
            raise ValueError("EMIT_FINDING cannot include tool_request")
        if self.decision == AuditDecisionType.FINISH_STAGE and (self.tool_request or self.finding):
            raise ValueError("FINISH_STAGE cannot include tool_request or finding")
        return self


class AuditStageResult(BaseModel):
    stage_name: str
    status: StageStatus | str
    findings_count: int = Field(default=0, ge=0)
    summary: str = ""
    tool_call_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    hypothesis_ids: list[str] = Field(default_factory=list)
    fallback_reasons: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)
