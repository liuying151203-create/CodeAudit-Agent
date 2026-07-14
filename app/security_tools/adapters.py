from __future__ import annotations

import json
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.scanners.builtin_rules import scan_files
from app.schemas.execution import ToolRunResult, ValidatedToolCall
from app.schemas.finding import Finding
from app.schemas.project import SecurityTool

MAX_OUTPUT_BYTES = 2_000_000
SEMGREP_CONFIG = Path(__file__).resolve().parents[2] / "config" / "semgrep_rules.yml"


@dataclass
class CommandOutput:
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    truncated: bool = False


def execute_adapter(
    tool: SecurityTool,
    call: ValidatedToolCall,
    files: list[dict[str, Any]],
    repo_root: Path | None,
    mode: str,
) -> ToolRunResult:
    started = time.monotonic()
    selected_files = _select_files(files, call.target_files)
    try:
        if tool.adapter == "builtin_secret":
            findings = [item for item in _builtin_findings(selected_files, tool.name) if item.category == "Secrets"]
            return _success(call, findings, started, f"{len(findings)} secret findings")
        if tool.adapter == "builtin_rules":
            findings = [item for item in _builtin_findings(selected_files, tool.name) if item.category != "Secrets"]
            return _success(call, findings, started, f"{len(findings)} builtin rule findings")
        if tool.adapter == "context_extractor":
            return _success(call, [], started, "Context extraction is deferred until findings are merged.")
        if repo_root is None:
            return _skipped(call, started, "External tools require a validated repository path.")
        if tool.adapter == "bandit_json":
            return _run_bandit(tool, call, repo_root, files, mode)
        if tool.adapter == "semgrep_json":
            return _run_semgrep(tool, call, repo_root, files, mode)
        if tool.adapter == "gitleaks_json":
            return _run_gitleaks(tool, call, repo_root, files, mode)
        return _skipped(call, started, f"Adapter is not enabled: {tool.adapter}")
    except Exception as exc:
        return ToolRunResult(
            call_id=call.call_id,
            tool_name=tool.name,
            stage=call.stage,
            status="error",
            duration_ms=_elapsed_ms(started),
            error_message=f"{type(exc).__name__}: {exc}",
            output_summary="Tool adapter failed.",
        )


def run_fixed_command(argv: list[str], cwd: Path, timeout_seconds: int) -> CommandOutput:
    """Run a predefined argv without a shell and retain only bounded output."""
    started = time.monotonic()
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        process = subprocess.Popen(
            argv,
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            shell=False,
        )
        timed_out = False
        try:
            process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            process.wait()
        stdout, stdout_truncated = _read_bounded(stdout_file)
        stderr, stderr_truncated = _read_bounded(stderr_file)
    return CommandOutput(
        returncode=process.returncode,
        stdout=stdout,
        stderr=stderr,
        duration_ms=_elapsed_ms(started),
        timed_out=timed_out,
        truncated=stdout_truncated or stderr_truncated,
    )


def parse_bandit_json(payload: str, repo_root: Path) -> list[Finding]:
    data = json.loads(payload or "{}")
    findings: list[Finding] = []
    for index, item in enumerate(data.get("results") or [], start=1):
        line = max(1, int(item.get("line_number") or 1))
        severity = _normalize_severity(item.get("issue_severity"))
        rule_id = str(item.get("test_id") or "BANDIT")
        message = str(item.get("issue_text") or "Bandit security finding.")
        findings.append(
            _finding(
                source="bandit",
                rule_id=rule_id,
                file_path=_relative_path(item.get("filename"), repo_root),
                line_start=line,
                line_end=max([line, *[int(value) for value in item.get("line_range") or []]]),
                severity=severity,
                category=_risk_type(f"{rule_id} {message}"),
                message=message,
                evidence=str(item.get("code") or "Bandit matched this source location.").strip(),
                confidence=_confidence(item.get("issue_confidence")),
                index=index,
            )
        )
    return findings


def parse_semgrep_json(payload: str, repo_root: Path) -> list[Finding]:
    data = json.loads(payload or "{}")
    findings: list[Finding] = []
    for index, item in enumerate(data.get("results") or [], start=1):
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        line_start = max(1, int((item.get("start") or {}).get("line") or 1))
        line_end = max(line_start, int((item.get("end") or {}).get("line") or line_start))
        rule_id = str(item.get("check_id") or "SEMGREP")
        message = str(extra.get("message") or "Semgrep security finding.")
        category = str(metadata.get("risk_type") or _risk_type(f"{rule_id} {message} {metadata}"))
        findings.append(
            _finding(
                source="semgrep",
                rule_id=rule_id,
                file_path=_relative_path(item.get("path"), repo_root),
                line_start=line_start,
                line_end=line_end,
                severity=_normalize_severity(extra.get("severity")),
                category=category,
                message=message,
                evidence=str(extra.get("lines") or "Semgrep matched this source location.").strip(),
                confidence=0.8,
                index=index,
            )
        )
    return findings


def parse_gitleaks_json(payload: str, repo_root: Path) -> list[Finding]:
    data = json.loads(payload or "[]")
    findings: list[Finding] = []
    for index, item in enumerate(data if isinstance(data, list) else [], start=1):
        line_start = max(1, int(item.get("StartLine") or 1))
        line_end = max(line_start, int(item.get("EndLine") or line_start))
        findings.append(
            _finding(
                source="gitleaks",
                rule_id=str(item.get("RuleID") or "GITLEAKS_SECRET"),
                file_path=_relative_path(item.get("File"), repo_root),
                line_start=line_start,
                line_end=line_end,
                severity="high",
                category="Secrets",
                message=str(item.get("Description") or "Gitleaks detected a possible secret."),
                evidence="<redacted secret evidence>",
                confidence=0.9,
                index=index,
            )
        )
    return findings


def _run_bandit(tool: SecurityTool, call: ValidatedToolCall, root: Path, files: list[dict[str, Any]], mode: str) -> ToolRunResult:
    targets = _absolute_targets(root, call.target_files)
    output = run_fixed_command([tool.executable or "bandit", "-f", "json", "-q", *targets], root, call.timeout_seconds)
    return _external_result(tool, call, output, parse_bandit_json, root, files, mode, {0, 1})


def _run_semgrep(tool: SecurityTool, call: ValidatedToolCall, root: Path, files: list[dict[str, Any]], mode: str) -> ToolRunResult:
    targets = _absolute_targets(root, call.target_files)
    argv = [tool.executable or "semgrep", "scan", "--json", "--quiet", "--config", str(SEMGREP_CONFIG), *targets]
    output = run_fixed_command(argv, root, call.timeout_seconds)
    return _external_result(tool, call, output, parse_semgrep_json, root, files, mode, {0})


def _run_gitleaks(tool: SecurityTool, call: ValidatedToolCall, root: Path, files: list[dict[str, Any]], mode: str) -> ToolRunResult:
    with tempfile.TemporaryDirectory() as temp_dir:
        report_path = Path(temp_dir) / "gitleaks.json"
        argv = [
            tool.executable or "gitleaks",
            "detect",
            "--no-git",
            "--no-banner",
            "--source",
            str(root),
            "--report-format",
            "json",
            "--report-path",
            str(report_path),
        ]
        output = run_fixed_command(argv, root, call.timeout_seconds)
        payload = report_path.read_text(encoding="utf-8", errors="ignore")[:MAX_OUTPUT_BYTES] if report_path.exists() else "[]"
    if output.timed_out:
        return _timeout(tool, call, output)
    if output.returncode not in {0, 1}:
        return _command_error(tool, call, output)
    findings = _filter_diff_findings(parse_gitleaks_json(payload, root), files, mode)
    return ToolRunResult(
        call_id=call.call_id,
        tool_name=tool.name,
        stage=call.stage,
        status="success",
        findings=findings,
        duration_ms=output.duration_ms,
        output_summary=f"{len(findings)} normalized findings",
        metadata={"returncode": output.returncode, "output_truncated": output.truncated},
    )


def _external_result(tool: SecurityTool, call: ValidatedToolCall, output: CommandOutput, parser: Any, root: Path, files: list[dict[str, Any]], mode: str, valid_codes: set[int]) -> ToolRunResult:
    if output.timed_out:
        return _timeout(tool, call, output)
    if output.returncode not in valid_codes:
        return _command_error(tool, call, output)
    try:
        findings = _filter_diff_findings(parser(output.stdout, root), files, mode)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        return ToolRunResult(
            call_id=call.call_id,
            tool_name=tool.name,
            stage=call.stage,
            status="error",
            duration_ms=output.duration_ms,
            error_message=f"Invalid JSON output: {exc}",
            output_summary="External tool output could not be parsed.",
        )
    return ToolRunResult(
        call_id=call.call_id,
        tool_name=tool.name,
        stage=call.stage,
        status="success",
        findings=findings,
        duration_ms=output.duration_ms,
        output_summary=f"{len(findings)} normalized findings",
        metadata={"returncode": output.returncode, "output_truncated": output.truncated},
    )


def _builtin_findings(files: list[dict[str, Any]], source: str) -> list[Finding]:
    prepared = [{**item, "source": source} for item in files]
    return scan_files(prepared)


def _success(call: ValidatedToolCall, findings: list[Finding], started: float, summary: str) -> ToolRunResult:
    return ToolRunResult(call_id=call.call_id, tool_name=call.tool_name, stage=call.stage, status="success", findings=findings, duration_ms=_elapsed_ms(started), output_summary=summary)


def _skipped(call: ValidatedToolCall, started: float, reason: str) -> ToolRunResult:
    return ToolRunResult(call_id=call.call_id, tool_name=call.tool_name, stage=call.stage, status="skipped", skipped_reason=reason, duration_ms=_elapsed_ms(started), output_summary="Tool was skipped.")


def _timeout(tool: SecurityTool, call: ValidatedToolCall, output: CommandOutput) -> ToolRunResult:
    return ToolRunResult(call_id=call.call_id, tool_name=tool.name, stage=call.stage, status="timeout", duration_ms=output.duration_ms, error_message="Tool execution timed out.", output_summary="External tool timed out.")


def _command_error(tool: SecurityTool, call: ValidatedToolCall, output: CommandOutput) -> ToolRunResult:
    return ToolRunResult(call_id=call.call_id, tool_name=tool.name, stage=call.stage, status="error", duration_ms=output.duration_ms, error_message=_safe_error(output.stderr), output_summary=f"External tool exited with code {output.returncode}.", metadata={"returncode": output.returncode, "output_truncated": output.truncated})


def _finding(source: str, rule_id: str, file_path: str, line_start: int, line_end: int, severity: str, category: str, message: str, evidence: str, confidence: float, index: int) -> Finding:
    return Finding(
        finding_id=f"{source}:{rule_id}:{file_path}:{line_start}:{index}",
        rule_id=rule_id,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        severity=severity,
        category=category,
        message=message,
        evidence_text=evidence[:2000],
        source=source,
        sources=[source],
        source_rule_ids=[rule_id],
        confidence=confidence,
    )


def _select_files(files: list[dict[str, Any]], targets: list[str]) -> list[dict[str, Any]]:
    target_set = set(targets)
    return [item for item in files if not target_set or str(item.get("path")) in target_set]


def _absolute_targets(root: Path, targets: list[str]) -> list[str]:
    return [str((root / target).resolve()) for target in targets] or [str(root)]


def _relative_path(value: Any, root: Path) -> str:
    path = Path(str(value or "unknown"))
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _filter_diff_findings(findings: list[Finding], files: list[dict[str, Any]], mode: str) -> list[Finding]:
    if mode != "diff_scan":
        return findings
    changed = {str(item.get("path")): set(item.get("changed_lines") or []) for item in files}
    return [item for item in findings if not changed.get(item.file_path) or item.line_start in changed[item.file_path]]


def _risk_type(text: str) -> str:
    value = text.lower()
    if any(marker in value for marker in ("sql", "query", "injection")):
        return "SQL Injection"
    if any(marker in value for marker in ("command", "shell", "subprocess", "runtime.exec", "processbuilder")):
        return "Command Execution"
    if any(marker in value for marker in ("deserialize", "pickle", "yaml.load", "objectinput")):
        return "Unsafe Deserialization"
    if any(marker in value for marker in ("path", "file", "directory", "traversal")):
        return "Path Traversal"
    if any(marker in value for marker in ("auth", "permission", "access control")):
        return "Broken Access Control"
    return "Dangerous Function"


def _normalize_severity(value: Any) -> str:
    mapping = {"INFO": "info", "WARNING": "medium", "ERROR": "high", "LOW": "low", "MEDIUM": "medium", "HIGH": "high", "CRITICAL": "critical"}
    return mapping.get(str(value or "MEDIUM").upper(), "medium")


def _confidence(value: Any) -> float:
    return {"LOW": 0.55, "MEDIUM": 0.75, "HIGH": 0.9}.get(str(value or "MEDIUM").upper(), 0.75)


def _read_bounded(file_obj: Any) -> tuple[str, bool]:
    file_obj.seek(0)
    data = file_obj.read(MAX_OUTPUT_BYTES + 1)
    return data[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace"), len(data) > MAX_OUTPUT_BYTES


def _safe_error(stderr: str) -> str:
    return (stderr.strip() or "External tool failed without an error message.")[:2000]


def _elapsed_ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1000))
