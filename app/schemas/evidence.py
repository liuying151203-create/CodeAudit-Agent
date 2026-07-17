from app.schemas.base import BaseModel, Field
from app.schemas.enums import AuditStageName


class Evidence(BaseModel):
    evidence_id: str = ""
    finding_id: str
    file_path: str = ""
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    local_start_line: int | None = Field(default=None, ge=1)
    local_end_line: int | None = Field(default=None, ge=1)
    code_snippet: str = ""
    code_context: str
    symbol_name: str | None = None
    function_name: str | None = None
    class_name: str | None = None
    imports: list[str] = Field(default_factory=list)
    dataflow_steps: list[str] = Field(default_factory=list)
    is_changed_line: bool = False
    changed_line: bool = False
    source_tool: str = "context_extractor"
    source_call_id: str | None = None
    stage: AuditStageName | None = None
    surrounding_lines: list[str] = Field(default_factory=list)
