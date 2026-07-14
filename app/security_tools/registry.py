from __future__ import annotations

from pathlib import Path
from typing import Any

from app.schemas.project import SecurityTool

DEFAULT_REGISTRY_PATH = Path(__file__).resolve().parents[2] / "config" / "security_tools.yaml"


def load_security_tools(path: Path | None = None) -> list[SecurityTool]:
    registry_path = path or DEFAULT_REGISTRY_PATH
    if not registry_path.exists():
        return [
            SecurityTool(
                name="custom_rule_scanner",
                adapter="builtin_rules",
                supported_languages=["Python", "Java"],
                risk_types=["Secrets", "SQL Injection", "Command Execution"],
                capabilities=["scan_sql_patterns", "scan_command_execution"],
                supported_modes=["repo_scan", "diff_scan"],
            )
        ]
    return parse_security_tools_yaml(registry_path.read_text(encoding="utf-8"))


def parse_security_tools_yaml(text: str) -> list[SecurityTool]:
    tools: list[SecurityTool] = []
    current: dict[str, Any] | None = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped == "tools:":
            continue
        if line.startswith("  ") and stripped.endswith(":") and not line.startswith("    "):
            if current:
                tools.append(SecurityTool(**current))
            current = {"name": stripped[:-1]}
            continue
        if current is None or ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        current[key] = _parse_scalar(value.strip())
    if current:
        tools.append(SecurityTool(**current))
    return tools


def mcp_tool_to_security_tool(descriptor: dict[str, Any]) -> SecurityTool:
    """Convert a discovered MCP tool descriptor into the internal registry shape."""
    metadata = descriptor.get("metadata") or {}
    annotations = descriptor.get("annotations") or {}
    return SecurityTool(
        name=str(descriptor.get("name") or "mcp_tool"),
        adapter="mcp",
        supported_languages=list(metadata.get("supported_languages") or []),
        risk_types=list(metadata.get("risk_types") or []),
        capabilities=list(metadata.get("capabilities") or []),
        supported_modes=list(metadata.get("supported_modes") or ["repo_scan", "diff_scan"]),
        cost_level=str(metadata.get("cost_level") or "medium"),
        requires_install=False,
        read_only=bool(annotations.get("readOnlyHint", False)),
        timeout_seconds=int(metadata.get("timeout_seconds") or 30),
        description=str(descriptor.get("description") or "MCP security tool"),
    )


def _parse_scalar(value: str) -> Any:
    if value.startswith("[") and value.endswith("]"):
        return [item.strip().strip("\"'") for item in value[1:-1].split(",") if item.strip()]
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    if value.isdigit():
        return int(value)
    return value.strip("\"'")
