from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import replace
from pathlib import Path, PurePosixPath
from typing import Any

from app.agent.prompt_context import DEFAULT_SANITIZER
from app.schemas.execution import ToolObservation, ToolRunResult, ValidatedToolCall
from app.schemas.finding import Finding
from app.schemas.project import SecurityTool
from app.security_tools.mcp_client import MCPClientError, MCPServerConfig, StdioMCPClient

DEFAULT_MCP_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "mcp_servers.json"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
MAX_MCP_INPUT_CHARS = 500_000
MAX_MCP_OUTPUT_ITEMS = 500


def load_mcp_server_configs(path: Path | None = None) -> list[MCPServerConfig]:
    config_path = resolve_mcp_config_path(path)
    if not config_path.exists():
        return []
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("MCP config root must be an object")
    configs: list[MCPServerConfig] = []
    for item in payload.get("servers") or []:
        if not isinstance(item, dict) or not item.get("name") or not item.get("command"):
            continue
        configs.append(
            MCPServerConfig(
                name=str(item["name"]),
                command=str(item["command"]),
                args=tuple(str(value) for value in item.get("args") or []),
                enabled=bool(item.get("enabled", True)),
                timeout_seconds=max(1, min(600, int(item.get("timeout_seconds") or 30))),
                env_passthrough=tuple(str(value) for value in item.get("env_passthrough") or []),
                allowed_tools=tuple(str(value) for value in item.get("allowed_tools") or []),
                defaults=dict(item.get("defaults") or {}),
            )
        )
    return configs


def resolve_mcp_config_path(path: Path | None = None) -> Path:
    return (path or Path(os.getenv("CODEAUDIT_MCP_CONFIG", str(DEFAULT_MCP_CONFIG_PATH)))).resolve()


def discover_mcp_security_tools(path: Path | None = None) -> tuple[list[SecurityTool], list[str]]:
    tools: list[SecurityTool] = []
    errors: list[str] = []
    try:
        configs = load_mcp_server_configs(path)
    except (json.JSONDecodeError, OSError, TypeError, ValueError) as exc:
        return [], [f"config: {type(exc).__name__}: {exc}"]
    for server in configs:
        if not server.enabled:
            continue
        try:
            with StdioMCPClient(server, PROJECT_ROOT) as client:
                descriptors = client.list_tools()
        except (MCPClientError, OSError, ValueError) as exc:
            errors.append(f"{server.name}: {type(exc).__name__}: {exc}")
            continue
        for descriptor in descriptors:
            remote_name = str(descriptor.get("name") or "")
            if not remote_name or not _tool_is_allowed(remote_name, server.allowed_tools):
                continue
            annotations = descriptor.get("annotations") or {}
            if not isinstance(annotations, dict):
                continue
            if annotations.get("readOnlyHint") is not True or annotations.get("destructiveHint") is True:
                continue
            try:
                tool = _descriptor_to_tool(descriptor, server)
            except (TypeError, ValueError) as exc:
                errors.append(f"{server.name}/{remote_name}: invalid tool descriptor: {exc}")
                continue
            if tool.capabilities and tool.supported_languages and tool.supported_modes:
                tools.append(tool)
    return tools, errors


def execute_mcp_tool(
    tool: SecurityTool,
    call: ValidatedToolCall,
    files: list[dict[str, Any]],
    repo_root: Path | None,
    mode: str,
    config_path: Path | None = None,
) -> ToolRunResult:
    server = next((item for item in load_mcp_server_configs(config_path) if item.name == tool.mcp_server), None)
    if server is None or not server.enabled:
        raise MCPClientError(f"MCP server is unavailable: {tool.mcp_server}")
    selected = _select_files(files, call.target_files)
    arguments = _build_arguments(tool, call, selected, repo_root, mode)
    call_server = replace(server, timeout_seconds=min(server.timeout_seconds, call.timeout_seconds))
    with StdioMCPClient(call_server, PROJECT_ROOT) as client:
        result = client.call_tool(tool.mcp_tool_name or tool.name, arguments)
    if result.get("isError"):
        raise MCPClientError(_result_text(result) or "MCP tool returned an execution error")
    findings, observations = _normalize_result(tool, call, result, selected)
    return ToolRunResult(
        call_id=call.call_id,
        tool_name=tool.name,
        stage=call.stage,
        status="success",
        findings=findings,
        observations=observations,
        output_summary=f"{len(findings)} normalized MCP findings and {len(observations)} observations",
        metadata={"mcp_server": server.name, "mcp_tool": tool.mcp_tool_name, "arguments": sorted(arguments)},
    )


def _descriptor_to_tool(descriptor: dict[str, Any], server: MCPServerConfig) -> SecurityTool:
    metadata = dict(server.defaults)
    descriptor_metadata = descriptor.get("metadata") or {}
    if not isinstance(descriptor_metadata, dict):
        raise ValueError("metadata must be an object")
    metadata.update(descriptor_metadata)
    meta = descriptor.get("_meta") or {}
    if not isinstance(meta, dict) or not isinstance(meta.get("io.codeaudit/tool") or {}, dict):
        raise ValueError("_meta.io.codeaudit/tool must be an object")
    metadata.update(meta.get("io.codeaudit/tool") or {})
    remote_name = str(descriptor["name"])
    internal_name = _safe_tool_name(f"mcp.{server.name}.{remote_name}")
    return SecurityTool(
        name=internal_name,
        adapter="mcp",
        supported_languages=list(metadata.get("supported_languages") or []),
        risk_types=list(metadata.get("risk_types") or []),
        capabilities=list(metadata.get("capabilities") or []),
        supported_modes=list(metadata.get("supported_modes") or ["repo_scan", "diff_scan"]),
        cost_level=str(metadata.get("cost_level") or "medium"),
        read_only=True,
        timeout_seconds=max(1, min(600, int(metadata.get("timeout_seconds") or server.timeout_seconds))),
        description=str(descriptor.get("description") or "Read-only MCP security tool"),
        mcp_server=server.name,
        mcp_tool_name=remote_name,
        input_schema=_input_schema(descriptor.get("inputSchema")),
    )


def _build_arguments(
    tool: SecurityTool,
    call: ValidatedToolCall,
    files: list[dict[str, Any]],
    root: Path | None,
    mode: str,
) -> dict[str, Any]:
    schema = tool.input_schema or {"type": "object"}
    properties = schema.get("properties") or {}
    available: dict[str, Any] = {
        "mode": mode,
        "scan_mode": mode,
        "repo_path": str(root) if root else None,
        "target_files": [str(item.get("path") or "") for item in files],
        "risk_types": tool.risk_types,
        "files": _bounded_files(files),
    }
    arguments = {key: available[key] for key in properties if key in available and available[key] is not None}
    missing = [key for key in schema.get("required") or [] if key not in arguments]
    if missing:
        raise MCPClientError(f"Unsupported required MCP arguments: {', '.join(missing)}")
    return arguments


def _input_schema(value: Any) -> dict[str, Any]:
    schema = value or {"type": "object"}
    if not isinstance(schema, dict) or schema.get("type", "object") != "object":
        raise ValueError("inputSchema must describe an object")
    return dict(schema)


def _bounded_files(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    remaining = MAX_MCP_INPUT_CHARS
    payload: list[dict[str, Any]] = []
    for item in files:
        if remaining <= 0:
            break
        content = DEFAULT_SANITIZER.sanitize_code(str(item.get("content") or ""))[:remaining]
        remaining -= len(content)
        payload.append(
            {
                "path": str(item.get("path") or ""),
                "content": content,
                "changed_lines": list(item.get("changed_original_lines") or item.get("changed_lines") or []),
            }
        )
    return payload


def _normalize_result(
    tool: SecurityTool,
    call: ValidatedToolCall,
    result: dict[str, Any],
    files: list[dict[str, Any]],
) -> tuple[list[Finding], list[ToolObservation]]:
    payload = result.get("structuredContent")
    if not isinstance(payload, dict):
        text = _result_text(result)
        try:
            candidate = json.loads(text) if text else {}
            payload = candidate if isinstance(candidate, dict) else {}
        except json.JSONDecodeError:
            payload = {}
    file_map = {str(item.get("path") or "").replace("\\", "/"): item for item in files}
    findings: list[Finding] = []
    for index, item in enumerate((payload.get("findings") or [])[:MAX_MCP_OUTPUT_ITEMS], start=1):
        if not isinstance(item, dict):
            continue
        path = str(item.get("file_path") or item.get("path") or "").replace("\\", "/")
        if path not in file_map or not _safe_relative(path):
            continue
        category = str(item.get("risk_type") or item.get("category") or "Dangerous Function")
        if tool.risk_types and category.lower() not in {value.lower() for value in tool.risk_types}:
            continue
        line_start = _positive_int(item.get("line_start") or item.get("line"), 1)
        line_end = max(line_start, _positive_int(item.get("line_end"), line_start))
        line_count = max(1, len(str(file_map[path].get("content") or "").splitlines()))
        if line_start > line_count:
            continue
        rule_id = str(item.get("rule_id") or "MCP_FINDING")[:128]
        message = DEFAULT_SANITIZER.redact_text(str(item.get("message") or "MCP security finding."))[:2000]
        evidence = DEFAULT_SANITIZER.sanitize_code(str(item.get("evidence") or item.get("evidence_text") or message))[:2000]
        fingerprint = hashlib.sha256(f"{tool.name}:{rule_id}:{path}:{line_start}:{index}".encode()).hexdigest()[:16]
        findings.append(
            Finding(
                finding_id=f"mcp:{fingerprint}",
                rule_id=rule_id,
                file_path=path,
                line_start=line_start,
                line_end=min(line_end, line_count),
                severity=_severity(item.get("severity")),
                category=category,
                message=message,
                evidence_text=evidence,
                source=tool.name,
                confidence=_confidence(item.get("confidence")),
                stage=call.stage,
                analysis_source="mcp",
            )
        )
    observations: list[ToolObservation] = []
    for item in (payload.get("observations") or [])[:MAX_MCP_OUTPUT_ITEMS]:
        if not isinstance(item, dict):
            continue
        path = str(item.get("file_path") or "").replace("\\", "/") or None
        if path is not None and path not in file_map:
            continue
        observations.append(
            ToolObservation(
                observation_type=str(item.get("observation_type") or "mcp_context")[:128],
                content=DEFAULT_SANITIZER.sanitize_code(str(item.get("content") or ""))[:4000],
                file_path=path,
                start_line=_optional_positive_int(item.get("start_line")),
                end_line=_optional_positive_int(item.get("end_line")),
                metadata={"source": tool.name},
            )
        )
    if not findings and not observations:
        text = _result_text(result)
        if text:
            observations.append(
                ToolObservation(
                    observation_type="mcp_text",
                    content=DEFAULT_SANITIZER.sanitize_code(text)[:4000],
                    metadata={"source": tool.name},
                )
            )
    return findings, observations


def _result_text(result: dict[str, Any]) -> str:
    return "\n".join(
        str(item.get("text") or "")
        for item in result.get("content") or []
        if isinstance(item, dict) and item.get("type") == "text"
    )


def _select_files(files: list[dict[str, Any]], targets: list[str]) -> list[dict[str, Any]]:
    target_set = set(targets)
    return [item for item in files if not target_set or str(item.get("path") or "") in target_set]


def _tool_is_allowed(name: str, allowed: tuple[str, ...]) -> bool:
    return name in allowed or "*" in allowed


def _safe_tool_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:128]


def _safe_relative(value: str) -> bool:
    path = PurePosixPath(value)
    return bool(value) and not path.is_absolute() and ".." not in path.parts and not path.drive


def _positive_int(value: Any, default: int) -> int:
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return default


def _optional_positive_int(value: Any) -> int | None:
    return _positive_int(value, 1) if value is not None else None


def _severity(value: Any) -> str:
    normalized = str(value or "medium").lower()
    return normalized if normalized in {"info", "low", "medium", "high", "critical"} else "medium"


def _confidence(value: Any) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.7
