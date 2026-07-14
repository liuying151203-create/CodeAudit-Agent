from app.schemas.base import BaseModel, Field
from app.schemas.enums import AuditStageName, FindingStatus, Severity

try:
    from pydantic import model_validator
except Exception:  # pragma: no cover - lightweight runtime fallback
    def model_validator(*_: object, **__: object):
        return lambda function: function


class FindingDraft(BaseModel):
    rule_id: str
    risk_type: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    file_path: str
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    message: str
    evidence_ids: list[str] = Field(min_length=1)
    stage: AuditStageName | None = None
    source: str = "llm"

    @model_validator(mode="after")
    def validate_line_range(self) -> "FindingDraft":
        if self.line_end < self.line_start:
            raise ValueError("line_end must be greater than or equal to line_start")
        return self


class Finding(BaseModel):
    finding_id: str
    rule_id: str
    file_path: str
    line_start: int
    line_end: int
    severity: str = Field(pattern="^(info|low|medium|high|critical)$")
    category: str
    message: str
    evidence_text: str
    source: str = "builtin"
    risk_type: str | None = None
    confidence: float = Field(default=0.5, ge=0, le=1)
    evidence_ids: list[str] = Field(default_factory=list)
    stage: AuditStageName | None = None
    status: FindingStatus = FindingStatus.CANDIDATE
    analysis_source: str = "scanner"
    fallback_reason: str | None = None

    @model_validator(mode="after")
    def populate_compatibility_fields(self) -> "Finding":
        if self.line_start < 1 or self.line_end < self.line_start:
            raise ValueError("finding line range is invalid")
        if self.risk_type is None:
            object.__setattr__(self, "risk_type", self.category)
        return self


class RiskAnalysis(BaseModel):
    finding_id: str
    risk_type: str
    risk_reason: str
    exploit_scenario: str
    confidence: float = Field(ge=0, le=1)
    severity: str = Field(pattern="^(info|low|medium|high|critical)$")
    analysis_source: str = "template"
    fallback_reason: str | None = None


class ReviewResult(BaseModel):
    finding_id: str
    is_false_positive: bool
    reason: str
    final_severity: str = Field(pattern="^(info|low|medium|high|critical)$")
    status: FindingStatus | None = None
    analysis_source: str = "template"
    fallback_reason: str | None = None


class FixSuggestion(BaseModel):
    finding_id: str
    suggestion: str
    safe_code_example: str
    patch_hint: str
    analysis_source: str = "template"
    fallback_reason: str | None = None
