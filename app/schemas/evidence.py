from app.schemas.base import BaseModel


class Evidence(BaseModel):
    finding_id: str
    code_context: str
    function_name: str | None = None
    imports: list[str] = []
    changed_line: bool = False
    surrounding_lines: list[str] = []
