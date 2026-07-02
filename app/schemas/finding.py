from app.schemas.base import BaseModel, Field


class Finding(BaseModel):
    finding_id: str
    rule_id: str
    file_path: str
    line_start: int
    line_end: int
    severity: str
    category: str
    message: str
    evidence_text: str
    source: str = "builtin"


class RiskAnalysis(BaseModel):
    finding_id: str
    risk_type: str
    risk_reason: str
    exploit_scenario: str
    confidence: float = Field(ge=0, le=1)
    severity: str


class ReviewResult(BaseModel):
    finding_id: str
    is_false_positive: bool
    reason: str
    final_severity: str


class FixSuggestion(BaseModel):
    finding_id: str
    suggestion: str
    safe_code_example: str
    patch_hint: str
