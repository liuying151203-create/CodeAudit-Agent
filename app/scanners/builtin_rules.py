from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

from app.schemas.finding import Finding


SECRET_PATTERN = re.compile(
    r"(?i)\b(api[_-]?key|token|password|passwd|private[_-]?key|secret)\b\s*[:=]\s*['\"][^'\"]{4,}['\"]"
)
SQL_CONCAT_PATTERN = re.compile(r"(?i)(select|insert|update|delete).*(\+|%|\.format\(|f['\"])")
PATH_TRAVERSAL_PATTERN = re.compile(r"(\.\./|\.\.\\|request\.(args|form|json)|input\()")


def scan_text(file_path: str, text: str, changed_lines: set[int] | None = None, source: str = "builtin") -> list[Finding]:
    findings: list[Finding] = []
    changed_lines = changed_lines or set()
    lines = text.splitlines()

    def add(rule_id: str, line_no: int, severity: str, category: str, message: str, evidence: str) -> None:
        if changed_lines and line_no not in changed_lines:
            return
        findings.append(
            Finding(
                finding_id=f"{rule_id}:{file_path}:{line_no}:{len(findings) + 1}",
                rule_id=rule_id,
                file_path=file_path,
                line_start=line_no,
                line_end=line_no,
                severity=severity,
                category=category,
                message=message,
                evidence_text=evidence.strip(),
                source=source,
            )
        )

    suffix = Path(file_path).suffix.lower()
    rule_prefix = "JAVA" if suffix in {".java", ".xml"} else "PY"
    lowered_text = text.lower()
    for idx, line in enumerate(lines, start=1):
        if SECRET_PATTERN.search(line):
            add(f"{rule_prefix}_SECRET_HARDCODED", idx, "high", "Secrets", "Possible hardcoded secret.", line)
        if "shell=True" in line and "subprocess" in text:
            add("PY_SUBPROCESS_SHELL_TRUE", idx, "high", "Command Execution", "subprocess with shell=True can execute injected commands.", line)
        if SQL_CONCAT_PATTERN.search(line):
            add(f"{rule_prefix}_SQL_STRING_BUILD", idx, "medium", "SQL Injection", "SQL query appears to be built with string interpolation or concatenation.", line)
        if suffix == ".xml" and "${" in line and any(keyword in lowered_text for keyword in ("select", "insert", "update", "delete")):
            add("JAVA_MYBATIS_RAW_SUBSTITUTION", idx, "high", "SQL Injection", "MyBatis raw substitution can place untrusted text into SQL.", line)
        if suffix == ".java" and ("Runtime.getRuntime().exec" in line or "new ProcessBuilder" in line):
            add("JAVA_COMMAND_EXECUTION", idx, "high", "Command Execution", "Java process execution requires strict argument validation.", line)
        if suffix == ".java" and ("ObjectInputStream" in line or ".readObject(" in line):
            add("JAVA_UNSAFE_DESERIALIZATION", idx, "high", "Unsafe Deserialization", "Native Java deserialization can instantiate unsafe object graphs.", line)
        if "../" in line or "..\\" in line:
            add(f"{rule_prefix}_PATH_TRAVERSAL", idx, "medium", "Path Traversal", "Path construction includes parent directory traversal.", line)

    if suffix != ".py":
        return findings
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            line = getattr(node, "lineno", 1)
            evidence = lines[line - 1] if 0 < line <= len(lines) else name
            if name in {"eval", "exec", "pickle.load", "yaml.load"}:
                add("PY_DANGEROUS_FUNCTION", line, "high", "Dangerous Function", f"Dangerous call: {name}.", evidence)
            if name == "os.system":
                add("PY_OS_SYSTEM", line, "high", "Command Execution", "os.system can execute injected commands.", evidence)
    return findings


def scan_files(files: list[dict[str, Any]]) -> list[Finding]:
    all_findings: list[Finding] = []
    for item in files:
        all_findings.extend(
            scan_text(
                file_path=item["path"],
                text=item["content"],
                changed_lines=set(item.get("changed_lines") or []),
                source=item.get("source", "builtin"),
            )
        )
    return all_findings


def scan_path(path: Path) -> list[Finding]:
    return scan_text(str(path), path.read_text(encoding="utf-8", errors="ignore"))


def _call_name(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        base = _call_name(func.value)
        return f"{base}.{func.attr}" if base else func.attr
    return ""
