from app.schemas.base import BaseModel, Field


class Evidence(BaseModel):
    evidence_id: str = ""
    finding_id: str
    file_path: str = ""
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
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
    surrounding_lines: list[str] = Field(default_factory=list)
