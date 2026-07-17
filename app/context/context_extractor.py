from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

from app.schemas.evidence import Evidence
from app.schemas.finding import Finding


def extract_evidence(finding: Finding, files: list[dict[str, Any]]) -> Evidence:
    file_item = next((item for item in files if item["path"] == finding.file_path), None) or {}
    lines = str(file_item.get("content") or "").splitlines()
    local_line = _local_line(file_item, finding.line_start)
    local_start = max(local_line - 4, 1)
    local_end = min(local_line + max(4, finding.line_end - finding.line_start + 3), len(lines))
    language = _language_for(finding.file_path)
    scope = _python_scope(lines, local_line) if language == "python" else _java_scope(lines, local_line)
    imports = _imports(lines, language)
    relationships = _local_call_relationships(lines, local_line, scope.get("function_name"), language)
    surrounding = [f"{_original_line(file_item, idx)}: {lines[idx - 1]}" for idx in range(local_start, local_end + 1)]
    changed_original = set(file_item.get("changed_original_lines") or file_item.get("changed_lines") or [])
    changed = finding.line_start in changed_original
    return Evidence(
        evidence_id=f"evidence:{finding.finding_id}",
        finding_id=finding.finding_id,
        file_path=finding.file_path,
        start_line=_original_line(file_item, local_start) if lines else finding.line_start,
        end_line=_original_line(file_item, local_end) if lines else finding.line_end,
        local_start_line=local_start if lines else None,
        local_end_line=local_end if lines else None,
        code_snippet="\n".join(lines[local_start - 1 : local_end]),
        code_context="\n".join(surrounding),
        symbol_name=scope.get("function_name") or scope.get("class_name"),
        function_name=scope.get("function_name"),
        class_name=scope.get("class_name"),
        imports=imports,
        dataflow_steps=relationships,
        is_changed_line=changed,
        changed_line=changed,
        surrounding_lines=surrounding,
    )


def _language_for(file_path: str) -> str:
    return "python" if Path(file_path).suffix.lower() == ".py" else "java"


def _imports(lines: list[str], language: str) -> list[str]:
    if language == "python":
        return [line.strip() for line in lines if line.strip().startswith(("import ", "from "))][:40]
    return [line.strip().rstrip(";") for line in lines if line.strip().startswith(("import ", "package "))][:40]


def _python_scope(lines: list[str], line_no: int) -> dict[str, str | None]:
    try:
        tree = ast.parse("\n".join(lines))
    except SyntaxError:
        return {"function_name": None, "class_name": None}
    functions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.lineno <= line_no <= getattr(node, "end_lineno", node.lineno)
    ]
    classes = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef) and node.lineno <= line_no <= getattr(node, "end_lineno", node.lineno)
    ]
    function = min(functions, key=lambda item: getattr(item, "end_lineno", item.lineno) - item.lineno, default=None)
    class_node = min(classes, key=lambda item: getattr(item, "end_lineno", item.lineno) - item.lineno, default=None)
    return {"function_name": function.name if function else None, "class_name": class_node.name if class_node else None}


def _java_scope(lines: list[str], line_no: int) -> dict[str, str | None]:
    class_name = None
    function_name = None
    class_pattern = re.compile(r"\b(?:class|interface|record|enum)\s+([A-Za-z_$][\w$]*)")
    method_pattern = re.compile(
        r"(?:public|protected|private|static|final|synchronized|abstract|native|\s)+[\w<>,.?\[\]]+\s+([A-Za-z_$][\w$]*)\s*\([^;]*\)\s*(?:throws\s+[^\{]+)?\{"
    )
    for line in lines[:line_no]:
        class_match = class_pattern.search(line)
        method_match = method_pattern.search(line)
        if class_match:
            class_name = class_match.group(1)
        if method_match and method_match.group(1) not in {"if", "for", "while", "switch", "catch"}:
            function_name = method_match.group(1)
    return {"function_name": function_name, "class_name": class_name}


def _local_call_relationships(lines: list[str], line_no: int, function_name: str | None, language: str) -> list[str]:
    if language == "python":
        try:
            tree = ast.parse("\n".join(lines))
        except SyntaxError:
            return []
        scope: ast.AST = tree
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.lineno <= line_no <= getattr(node, "end_lineno", node.lineno):
                scope = node
                break
        calls = list(dict.fromkeys(_python_call_name(node.func) for node in ast.walk(scope) if isinstance(node, ast.Call)))
    else:
        context = "\n".join(lines[max(0, line_no - 15) : min(len(lines), line_no + 15)])
        calls = list(dict.fromkeys(match.group(1) for match in re.finditer(r"\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(", context)))
        calls = [call for call in calls if call not in {"if", "for", "while", "switch", "catch", function_name}]
    prefix = function_name or "module"
    return [f"{prefix} -> {call}" for call in calls[:20] if call]


def _python_call_name(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        base = _python_call_name(func.value)
        return f"{base}.{func.attr}" if base else func.attr
    return ""


def _local_line(file_item: dict[str, Any], original_line: int) -> int:
    line_map = {int(local): int(actual) for local, actual in (file_item.get("line_map") or {}).items()}
    return next((local for local, actual in line_map.items() if actual == original_line), original_line)


def _original_line(file_item: dict[str, Any], local_line: int) -> int:
    return int((file_item.get("line_map") or {}).get(str(local_line), local_line))
