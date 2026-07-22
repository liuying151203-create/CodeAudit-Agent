from __future__ import annotations

import shutil
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath
from typing import Any

from app.schemas.enums import AuditStageName
from app.schemas.execution import ToolRunResult, ValidatedToolCall
from app.schemas.planning import AuditPlan
from app.schemas.project import ProjectProfile, SecurityTool, ToolPlan, VulnKnowledge
from app.schemas.runtime import AuditBudget
from app.security_tools.adapters import execute_adapter
from app.security_tools.registry import get_mcp_discovery_errors, load_security_tools

ENABLED_ADAPTERS = {
    "bandit_json",
    "builtin_rules",
    "builtin_secret",
    "context_extractor",
    "gitleaks_json",
    "mcp",
    "semgrep_json",
}
EXTERNAL_ADAPTERS = {"bandit_json", "gitleaks_json", "mcp", "semgrep_json"}
FALLBACK_TOOLS = {
    "bandit": "custom_rule_scanner",
    "gitleaks": "secret_scanner",
    "semgrep": "custom_rule_scanner",
}


def select_tool_plan(
    profile: ProjectProfile,
    knowledge: list[VulnKnowledge],
    scan_mode: str,
    files: list[dict[str, Any]],
    audit_plan: AuditPlan | None = None,
    repo_path: str | None = None,
    budget: AuditBudget | None = None,
    registry: list[SecurityTool] | None = None,
    strict_capabilities: bool = False,
) -> ToolPlan:
    registry_provided = registry is not None
    tools = registry if registry is not None else load_security_tools()
    budget = budget or AuditBudget()
    available_paths = sorted({_normalize_path(item.get("path")) for item in files if _normalize_path(item.get("path"))})
    planned_targets = sorted({path for stage in (audit_plan.stages if audit_plan else []) for path in stage.target_files})
    target_files, rejected_targets = _validate_targets(planned_targets or available_paths, available_paths, repo_path)
    risk_types = _planned_risks(profile, knowledge, audit_plan)
    capabilities = {capability for stage in (audit_plan.stages if audit_plan else []) for capability in stage.required_capabilities}
    root = _valid_root(repo_path)

    selected: list[SecurityTool] = []
    unavailable: list[str] = []
    reasons: list[str] = []
    fallback_reasons: list[str] = []
    if not registry_provided:
        for error in get_mcp_discovery_errors():
            fallback_reasons.append(f"MCP discovery failed; registered builtin tools remain available. {error}")
    for tool in tools:
        if scan_mode not in tool.supported_modes or not tool.read_only:
            continue
        if tool.adapter not in ENABLED_ADAPTERS:
            reasons.append(f"{tool.name} was rejected because adapter {tool.adapter!r} is not enabled.")
            continue
        if not _intersects(profile.languages, tool.supported_languages):
            continue
        capability_match = bool(capabilities & set(tool.capabilities))
        risk_match = _intersects(risk_types, tool.risk_types)
        if strict_capabilities and capabilities and not capability_match:
            continue
        if not strict_capabilities and not (capability_match or risk_match):
            continue
        if strict_capabilities and not capabilities and not risk_match:
            continue
        if tool.adapter in EXTERNAL_ADAPTERS and root is None:
            unavailable.append(tool.name)
            reason = f"{tool.name} requires a repository path; builtin fallback selected."
            fallback_reasons.append(reason)
            continue
        if tool.adapter == "gitleaks_json" and root is not None and _contains_symlink(root):
            unavailable.append(tool.name)
            reason = f"{tool.name} was skipped because repository symlinks require builtin path-safe scanning."
            fallback_reasons.append(reason)
            continue
        if tool.requires_install and not shutil.which(tool.executable or tool.name):
            unavailable.append(tool.name)
            reason = f"{tool.name} is not installed; builtin fallback selected."
            fallback_reasons.append(reason)
            continue
        selected.append(tool)
        reasons.append(f"{tool.name} provides {', '.join(sorted(set(tool.capabilities) & capabilities)) or 'matching risk coverage'}.")

    selected = _ensure_builtin_fallbacks(selected, tools, profile, risk_types, capabilities, strict_capabilities)
    adapter_priority = {
        "bandit_json": 0,
        "gitleaks_json": 0,
        "mcp": 0,
        "semgrep_json": 0,
        "builtin_rules": 1,
        "builtin_secret": 1,
        "context_extractor": 2,
    }
    selected.sort(
        key=lambda tool: (
            adapter_priority.get(tool.adapter or "", 1),
            -len(capabilities & set(tool.capabilities)),
            tool.name,
        )
    )
    calls: list[ValidatedToolCall] = []
    for tool in selected:
        tool_targets = available_paths if tool.adapter == "builtin_secret" else target_files
        batches = _target_batches(tool, tool_targets, budget.max_files_per_call)
        for batch in batches:
            calls.append(
                ValidatedToolCall(
                    call_id=f"call-{uuid.uuid4().hex[:12]}",
                    tool_name=tool.name,
                    arguments={"mode": scan_mode},
                    timeout_seconds=tool.timeout_seconds,
                    target_files=batch,
                    selection_reason=f"Validated read-only adapter {tool.adapter} for {scan_mode}.",
                    fallback_tool=_fallback_tool(tool),
                    stage=_stage_for_tool(tool, audit_plan),
                )
            )

    selected_names = list(dict.fromkeys(tool.name for tool in selected))
    return ToolPlan(
        selected_tools=selected_names,
        selected_risk_types=risk_types,
        target_files=target_files,
        selection_reason="; ".join(reasons + fallback_reasons),
        tool_calls=calls,
        unavailable_tools=sorted(set(unavailable)),
        rejected_targets=rejected_targets,
        fallback_reasons=fallback_reasons,
    )


def execute_tool_plan(
    plan: ToolPlan,
    files: list[dict[str, Any]],
    repo_path: str | None,
    mode: str,
    registry: list[SecurityTool] | None = None,
) -> list[ToolRunResult]:
    tools = {tool.name: tool for tool in (registry or load_security_tools())}
    root = _valid_root(repo_path)
    executable_calls = [call for call in plan.tool_calls if call.tool_name in tools]
    max_workers = max(1, min(4, len(executable_calls)))
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="security-tool") as pool:
        futures = [(call, pool.submit(execute_adapter, tools[call.tool_name], call, files, root, mode)) for call in executable_calls]
        results = []
        for call, future in futures:
            result = future.result()
            tool = tools[call.tool_name]
            metadata = {**result.metadata, "capabilities": tool.capabilities, "target_files": call.target_files}
            results.append(result.model_copy(update={"metadata": metadata}))

    for tool_name in plan.unavailable_tools:
        reason = next((item for item in plan.fallback_reasons if item.startswith(tool_name)), f"{tool_name} is unavailable.")
        results.append(ToolRunResult(tool_name=tool_name, status="skipped", skipped_reason=reason, output_summary="External tool unavailable."))

    successful_tools = {result.tool_name for result in results if _status_value(result.status) == "success"}
    failed_by_call = {result.call_id: index for index, result in enumerate(results) if _status_value(result.status) in {"error", "timeout"}}
    calls_by_id = {call.call_id: call for call in executable_calls}
    for call_id, result_index in failed_by_call.items():
        call = calls_by_id.get(call_id)
        if not call or not call.fallback_tool:
            continue
        failed = results[result_index]
        if call.fallback_tool in successful_tools:
            results[result_index] = failed.model_copy(update={"fallback_used": True, "fallback_tool": call.fallback_tool})
            continue
        fallback = tools.get(call.fallback_tool)
        if fallback:
            fallback_call = call.model_copy(update={"call_id": f"call-{uuid.uuid4().hex[:12]}", "tool_name": fallback.name, "fallback_tool": None})
            fallback_result = execute_adapter(fallback, fallback_call, files, root, mode)
            fallback_result = fallback_result.model_copy(update={"fallback_used": True, "fallback_tool": fallback.name})
            results.append(fallback_result)
            successful_tools.add(fallback.name)
            results[result_index] = failed.model_copy(update={"fallback_used": True, "fallback_tool": fallback.name})
    return results


def _ensure_builtin_fallbacks(
    selected: list[SecurityTool],
    tools: list[SecurityTool],
    profile: ProjectProfile,
    risk_types: list[str],
    capabilities: set[str],
    strict_capabilities: bool,
) -> list[SecurityTool]:
    selected_names = {tool.name for tool in selected}
    required: set[str] = set()
    if not strict_capabilities or "scan_secrets" in capabilities or (not capabilities and "Secrets" in risk_types):
        required.add("secret_scanner")
    non_secret_scan = capabilities & {"scan_sql_patterns", "scan_command_execution", "scan_file_paths", "scan_deserialization"}
    if (non_secret_scan or (not capabilities and {risk.lower() for risk in risk_types} - {"secrets"})) and set(profile.languages) & {"Python", "Java"}:
        required.add("custom_rule_scanner")
    for name in ("secret_scanner", "custom_rule_scanner"):
        if name not in required or name in selected_names:
            continue
        tool = next((item for item in tools if item.name == name and item.read_only), None)
        if tool:
            selected.append(tool)
            selected_names.add(name)
    return selected


def _validate_targets(candidates: list[str], available_paths: list[str], repo_path: str | None) -> tuple[list[str], list[str]]:
    available = set(available_paths)
    root = _valid_root(repo_path)
    accepted: list[str] = []
    rejected: list[str] = []
    for candidate in candidates:
        normalized = _normalize_path(candidate)
        if not normalized or normalized not in available or not _is_safe_relative(normalized):
            rejected.append(str(candidate))
            continue
        if root is not None:
            resolved = (root / normalized).resolve()
            try:
                resolved.relative_to(root)
            except ValueError:
                rejected.append(str(candidate))
                continue
        accepted.append(normalized)
    return sorted(set(accepted)), sorted(set(rejected))


def _target_batches(tool: SecurityTool, targets: list[str], batch_size: int) -> list[list[str]]:
    if tool.adapter == "gitleaks_json":
        return [[]]
    if not targets:
        return [[]]
    return [targets[index : index + batch_size] for index in range(0, len(targets), batch_size)]


def _stage_for_tool(tool: SecurityTool, audit_plan: AuditPlan | None) -> AuditStageName | None:
    for stage in audit_plan.stages if audit_plan else []:
        if set(stage.required_capabilities) & set(tool.capabilities) or _intersects(stage.risk_types, tool.risk_types):
            return stage.stage
    return None


def _fallback_tool(tool: SecurityTool) -> str | None:
    if tool.name in FALLBACK_TOOLS:
        return FALLBACK_TOOLS[tool.name]
    if tool.adapter == "mcp":
        if "scan_secrets" in tool.capabilities:
            return "secret_scanner"
        if any(capability.startswith("extract_") for capability in tool.capabilities):
            return "context_extractor"
        return "custom_rule_scanner"
    return None


def _planned_risks(profile: ProjectProfile, knowledge: list[VulnKnowledge], audit_plan: AuditPlan | None) -> list[str]:
    planned = {risk for stage in (audit_plan.stages if audit_plan else []) for risk in stage.risk_types}
    inferred = {risk for item in knowledge for risk in item.matched_risk_types} | set(profile.risk_surfaces)
    return sorted(planned or inferred or {"Secrets"})


def _valid_root(repo_path: str | None) -> Path | None:
    if not repo_path:
        return None
    root = Path(repo_path).resolve()
    return root if root.exists() and root.is_dir() else None


def _contains_symlink(root: Path) -> bool:
    try:
        return any(path.is_symlink() for path in root.rglob("*"))
    except OSError:
        return True


def _normalize_path(value: Any) -> str:
    return str(value or "").replace("\\", "/").strip()


def _is_safe_relative(value: str) -> bool:
    path = PurePosixPath(value)
    return bool(value) and not path.is_absolute() and ".." not in path.parts and not path.drive


def _intersects(left: list[str] | set[str], right: list[str] | set[str]) -> bool:
    if not left or not right:
        return False
    return bool({item.lower() for item in left} & {item.lower() for item in right})


def _status_value(status: Any) -> str:
    return str(getattr(status, "value", status))
