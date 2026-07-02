from __future__ import annotations

import ast
from typing import Any

from app.schemas.evidence import Evidence
from app.schemas.finding import Finding


def extract_evidence(finding: Finding, files: list[dict[str, Any]]) -> Evidence:
    file_item = next((item for item in files if item["path"] == finding.file_path), None)
    lines = (file_item or {}).get("content", "").splitlines()
    start = max(finding.line_start - 4, 1)
    end = min(finding.line_end + 4, len(lines))
    surrounding = [f"{idx}: {lines[idx - 1]}" for idx in range(start, end + 1)]
    return Evidence(
        finding_id=finding.finding_id,
        code_context="\n".join(surrounding),
        function_name=_find_function(lines, finding.line_start),
        imports=_find_imports(lines),
        changed_line=finding.line_start in set((file_item or {}).get("changed_lines") or []),
        surrounding_lines=surrounding,
    )


def _find_imports(lines: list[str]) -> list[str]:
    return [line.strip() for line in lines if line.strip().startswith(("import ", "from "))]


def _find_function(lines: list[str], line_no: int) -> str | None:
    try:
        tree = ast.parse("\n".join(lines))
    except SyntaxError:
        return None
    found: str | None = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.lineno <= line_no <= getattr(node, "end_lineno", node.lineno):
                found = node.name
    return found
