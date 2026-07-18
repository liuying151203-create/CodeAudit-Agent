from __future__ import annotations

import importlib.util
import os
import shutil
from pathlib import Path
from typing import Any

from app.schemas.finding import Finding
from app.schemas.report import AgentTrace
from app.security_tools.registry import load_security_tools

NODE_LABELS = {
    "router": "校验审计请求",
    "repo_loader": "读取项目源码",
    "diff_loader": "解析 Git Diff",
    "project_reader": "生成项目画像",
    "vulnkb_retriever": "检索漏洞知识",
    "audit_planner": "规划审计阶段",
    "stage_scheduler": "启动风险阶段",
    "tool_selector": "选择安全工具",
    "tool_executor": "执行安全工具",
    "evidence_builder": "构建代码证据",
    "audit_reasoner": "Agent 审计决策",
    "finding_builder": "校验候选风险",
    "stage_finalize": "收敛风险阶段",
    "finding_merger": "合并风险来源",
    "finding_assessor": "风险分析与误报复核",
    "fix_suggest": "生成修复建议",
    "report": "生成审计报告",
}

STATUS_LABELS = {
    "success": "成功",
    "completed": "完成",
    "running": "运行中",
    "warning": "需关注",
    "error": "失败",
    "timeout": "超时",
    "skipped": "已跳过",
    "fallback": "已降级",
    "confirmed": "已确认",
    "dismissed": "已排除",
    "needs_review": "待复核",
    "budget_exhausted": "预算耗尽",
    "partial": "部分完成",
}


def runtime_status() -> dict[str, Any]:
    external_tools = []
    for tool in load_security_tools():
        if not tool.requires_install:
            continue
        executable = tool.executable or tool.name
        path = shutil.which(executable)
        external_tools.append(
            {
                "name": tool.name,
                "available": bool(path),
                "detail": path or "未发现，将使用内置 fallback",
            }
        )
    api_key = os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY")
    return {
        "langgraph": {
            "available": importlib.util.find_spec("langgraph") is not None,
            "detail": "事件流编排可用" if importlib.util.find_spec("langgraph") is not None else "使用顺序执行 fallback",
        },
        "llm": {
            "available": bool(api_key),
            "detail": os.getenv("LLM_MODEL", "gpt-4o-mini") if api_key else "未配置，将使用确定性分析",
        },
        "external_tools": external_tools,
        "fallback": {"available": True, "detail": "内置 Secret 与 Python/Java 规则可用"},
    }


def tool_result_rows(results: list[Any]) -> list[dict[str, Any]]:
    rows = []
    for result in results:
        status = _value(result.status)
        rows.append(
            {
                "工具": result.tool_name,
                "阶段": _value(result.stage) if result.stage else "-",
                "状态": STATUS_LABELS.get(status, status),
                "Finding": len(result.findings),
                "耗时(ms)": result.duration_ms,
                "Fallback": result.fallback_tool or "-",
                "结果摘要": result.output_summary or result.skipped_reason or result.error_message or "-",
            }
        )
    return rows


def stage_result_rows(results: list[Any]) -> list[dict[str, Any]]:
    rows = []
    for result in results:
        status = _value(result.status)
        rows.append(
            {
                "阶段": result.stage_name,
                "状态": STATUS_LABELS.get(status, status),
                "Finding": result.findings_count,
                "工具轮次": result.metrics.get("tool_rounds", 0),
                "决策次数": result.metrics.get("decisions", 0),
                "证据": len(result.evidence_ids),
                "耗时(ms)": result.metrics.get("elapsed_ms", 0),
                "说明": result.summary,
            }
        )
    return rows


def trace_rows(traces: list[AgentTrace]) -> list[dict[str, Any]]:
    return [
        {
            "节点": NODE_LABELS.get(trace.node_name, trace.node_name),
            "阶段": trace.stage or "-",
            "决策": trace.decision or "-",
            "工具": ", ".join(trace.tool_calls) or trace.tool_name or "-",
            "LLM": "是" if trace.llm_used else "否",
            "Token": trace.token_usage,
            "耗时(ms)": trace.elapsed_ms,
            "状态": STATUS_LABELS.get(trace.status, trace.status),
            "Fallback": trace.fallback_reason or "-",
        }
        for trace in traces
    ]


def event_rows(events: list[Any]) -> list[dict[str, Any]]:
    return [
        {
            "#": event.sequence,
            "节点": NODE_LABELS.get(event.node_name, event.node_name),
            "阶段": _value(event.stage) if event.stage else "-",
            "决策": event.decision or "-",
            "工具": ", ".join(event.tool_names) or "-",
            "进度": f"{event.progress:.0%}",
            "状态": STATUS_LABELS.get(event.status, event.status),
        }
        for event in events
    ]


def finding_origin(finding: Finding) -> str:
    types = {item.source_type for item in finding.provenance}
    if "mcp" in types:
        return "MCP 工具"
    if "llm" in types or finding.source == "llm":
        return "LLM 补充"
    if "external_tool" in types:
        return "外部扫描器"
    return "内置扫描器"


def code_language(file_path: str) -> str:
    suffix = Path(file_path).suffix.lower()
    return {".py": "python", ".java": "java", ".xml": "xml", ".yaml": "yaml", ".yml": "yaml", ".json": "json"}.get(suffix, "text")


def unique_findings(findings: list[Finding]) -> list[Finding]:
    return list({item.finding_id: item for item in findings}.values())


def _value(value: Any) -> str:
    return str(getattr(value, "value", value))
