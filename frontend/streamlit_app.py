from __future__ import annotations

import html
import json
import sys
from pathlib import Path
from typing import Any

import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.agent.graph import stream_audit
from app.schemas.enums import FindingStatus
from app.schemas.runtime import AuditBudget
from frontend.ui_data import (
    NODE_LABELS,
    STATUS_LABELS,
    code_language,
    event_rows,
    finding_origin,
    runtime_status,
    stage_result_rows,
    tool_result_rows,
    trace_rows,
    unique_findings,
)

st.set_page_config(page_title="CodeAudit-Agent", layout="wide", initial_sidebar_state="expanded")

DEFAULT_REPO = str((PROJECT_ROOT / "data/sample_repos/small_python_app").resolve())
DEFAULT_DIFF_PATH = PROJECT_ROOT / "data/sample_repos/sample.diff"
DEFAULT_DIFF = DEFAULT_DIFF_PATH.read_text(encoding="utf-8") if DEFAULT_DIFF_PATH.exists() else ""


def _inject_styles() -> None:
    st.markdown(
        """
        <style>
        :root {
            --ca-ink: #17212b;
            --ca-muted: #607080;
            --ca-border: #d9e1e8;
            --ca-surface: #ffffff;
            --ca-canvas: #f5f8fa;
            --ca-accent: #087f8c;
            --ca-blue: #2563eb;
            --ca-danger: #b42318;
            --ca-warn: #b54708;
            --ca-ok: #18794e;
        }
        .stApp { background: var(--ca-canvas); color: var(--ca-ink); }
        [data-testid="stHeader"] { background: rgba(245, 248, 250, 0.94); }
        [data-testid="stSidebar"] { border-right: 1px solid var(--ca-border); background: #edf3f6; }
        [data-testid="stSidebar"] .block-container { padding-top: 1.4rem; }
        .block-container { padding-top: 1.4rem; padding-bottom: 3rem; max-width: 1500px; }
        .ca-header { display: flex; align-items: center; justify-content: space-between; gap: 1rem; padding: 0 0 1rem; border-bottom: 1px solid var(--ca-border); margin-bottom: 1rem; }
        .ca-title { font-size: 1.55rem; font-weight: 720; line-height: 1.2; color: var(--ca-ink); }
        .ca-subtitle { color: var(--ca-muted); font-size: 0.9rem; margin-top: 0.25rem; }
        .ca-kicker { color: var(--ca-accent); font-size: 0.76rem; font-weight: 700; text-transform: uppercase; }
        .ca-badges, .ca-chips { display: flex; flex-wrap: wrap; gap: 0.4rem; align-items: center; }
        .ca-badge, .ca-chip { display: inline-flex; align-items: center; min-height: 1.65rem; padding: 0.18rem 0.55rem; border: 1px solid var(--ca-border); border-radius: 6px; background: var(--ca-surface); color: #344454; font-size: 0.76rem; line-height: 1.2; }
        .ca-badge.ok { border-color: #9ac7b4; color: var(--ca-ok); background: #f0faf5; }
        .ca-badge.warn { border-color: #e8b98b; color: var(--ca-warn); background: #fff8f0; }
        .ca-badge.error { border-color: #efaaa4; color: var(--ca-danger); background: #fff5f4; }
        .ca-severity { display: inline-flex; padding: 0.16rem 0.48rem; border-radius: 5px; font-size: 0.72rem; font-weight: 750; text-transform: uppercase; }
        .ca-severity.critical, .ca-severity.high { color: #9f1c13; background: #feeceb; }
        .ca-severity.medium { color: #9a4d00; background: #fff1dc; }
        .ca-severity.low, .ca-severity.info { color: #1559a5; background: #eaf3ff; }
        .ca-status-row { display: flex; justify-content: space-between; gap: 0.75rem; padding: 0.38rem 0; border-bottom: 1px solid #dce5ea; font-size: 0.8rem; }
        .ca-status-row:last-child { border-bottom: 0; }
        .ca-status-value { color: var(--ca-muted); text-align: right; overflow-wrap: anywhere; }
        div[data-testid="stMetric"] { background: var(--ca-surface); border: 1px solid var(--ca-border); border-radius: 7px; padding: 0.7rem 0.85rem; }
        div[data-testid="stMetric"] label { color: var(--ca-muted); }
        div[data-testid="stExpander"] { border-color: var(--ca-border); border-radius: 7px; background: var(--ca-surface); }
        div[data-testid="stForm"], div[data-testid="stVerticalBlockBorderWrapper"] { border-radius: 7px; }
        .stButton button, .stDownloadButton button { border-radius: 6px; font-weight: 650; }
        .stTabs [data-baseweb="tab-list"] { gap: 0.25rem; border-bottom: 1px solid var(--ca-border); }
        .stTabs [data-baseweb="tab"] { border-radius: 5px 5px 0 0; }
        code { overflow-wrap: anywhere; }
        @media (max-width: 760px) {
            .block-container { padding-left: 0.75rem; padding-right: 0.75rem; padding-top: 0.8rem; }
            .ca-header { align-items: flex-start; flex-direction: column; }
            .ca-title { font-size: 1.3rem; }
            div[data-testid="stMetric"] { padding: 0.55rem 0.65rem; }
            [data-testid="stHorizontalBlock"] { flex-wrap: wrap; }
            [data-testid="stColumn"] { min-width: min(100%, 220px); flex: 1 1 220px; }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _initialize_state() -> None:
    defaults = {
        "scan_mode": "仓库扫描",
        "repo_path": DEFAULT_REPO,
        "diff_source": "粘贴 Diff",
        "diff_text": DEFAULT_DIFF,
        "user_task": "",
        "audit_state": None,
        "audit_events": [],
        "audit_error": None,
    }
    for key, value in defaults.items():
        st.session_state.setdefault(key, value)


def _header(status: dict[str, Any]) -> None:
    llm_class = "ok" if status["llm"]["available"] else "warn"
    graph_class = "ok" if status["langgraph"]["available"] else "warn"
    st.markdown(
        f"""
        <div class="ca-header">
          <div>
            <div class="ca-kicker">Security audit workspace</div>
            <div class="ca-title">CodeAudit-Agent</div>
            <div class="ca-subtitle">项目理解、工具编排、证据审计与风险复核</div>
          </div>
          <div class="ca-badges">
            <span class="ca-badge {graph_class}">LangGraph {'在线' if status['langgraph']['available'] else 'Fallback'}</span>
            <span class="ca-badge {llm_class}">LLM {'已配置' if status['llm']['available'] else '确定性模式'}</span>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _sidebar(status: dict[str, Any]) -> bool:
    st.sidebar.markdown("## 审计请求")
    mode = st.sidebar.segmented_control(
        "扫描模式",
        options=["仓库扫描", "Git Diff"],
        key="scan_mode",
        selection_mode="single",
    )
    st.sidebar.text_input(
        "仓库路径",
        key="repo_path",
        help="仓库扫描时必填；粘贴 Diff 时可留空，提供后可补充项目上下文。",
    )
    if mode == "Git Diff":
        diff_source = st.sidebar.segmented_control(
            "Diff 来源",
            options=["粘贴 Diff", "暂存区", "HEAD"],
            key="diff_source",
            selection_mode="single",
        )
        if diff_source == "粘贴 Diff":
            st.sidebar.text_area("Unified diff", key="diff_text", height=230)
    st.sidebar.text_area(
        "审计关注点",
        key="user_task",
        height=82,
        placeholder="例如：重点检查鉴权绕过和 SQL 注入",
    )
    with st.sidebar.expander("审计预算"):
        rounds = st.slider("每阶段最大工具轮次", 1, 5, 2)
        files = st.slider("单次调用最大文件数", 1, 20, 5)
        seconds = st.slider("总耗时上限（秒）", 60, 900, 600, step=30)
    st.session_state["audit_budget"] = AuditBudget(
        max_tool_rounds_per_stage=rounds,
        max_files_per_call=files,
        max_total_seconds=seconds,
    )
    run_clicked = st.sidebar.button(
        "开始审计",
        type="primary",
        icon=":material/play_arrow:",
        width="stretch",
    )
    st.sidebar.markdown("---")
    _sidebar_runtime(status)
    return run_clicked


def _sidebar_runtime(status: dict[str, Any]) -> None:
    st.sidebar.markdown("### 运行环境")
    items = [
        ("LangGraph", status["langgraph"]["available"], status["langgraph"]["detail"]),
        ("LLM", status["llm"]["available"], status["llm"]["detail"]),
        *[(item["name"], item["available"], item["detail"]) for item in status["external_tools"]],
        ("Builtin fallback", True, status["fallback"]["detail"]),
    ]
    rows = []
    for name, available, detail in items:
        css_class = "ok" if available else "warn"
        label = "可用" if available else "降级"
        rows.append(
            f'<div class="ca-status-row"><span>{html.escape(name)}</span><span class="ca-status-value"><span class="ca-badge {css_class}">{label}</span><br>{html.escape(detail)}</span></div>'
        )
    st.sidebar.markdown("".join(rows), unsafe_allow_html=True)


def _audit_input() -> dict[str, Any]:
    mode = "diff_scan" if st.session_state.scan_mode == "Git Diff" else "repo_scan"
    diff_source = st.session_state.diff_source
    diff_text = st.session_state.diff_text if mode == "diff_scan" and diff_source == "粘贴 Diff" else None
    diff_mode = "head" if diff_source == "HEAD" else "cached"
    repo_path = st.session_state.repo_path.strip() or None
    return {
        "mode": mode,
        "repo_path": repo_path,
        "diff_text": diff_text or None,
        "diff_mode": diff_mode,
        "user_task": st.session_state.user_task.strip() or None,
        "budget": st.session_state.audit_budget,
        "traces": [],
        "errors": [],
    }


def _run_audit() -> None:
    st.session_state.audit_state = None
    st.session_state.audit_events = []
    st.session_state.audit_error = None
    final_state = None
    with st.status("正在初始化审计任务", expanded=True) as live_status:
        progress = st.progress(0, text="校验输入")
        recent = st.empty()
        try:
            for event, state in stream_audit(_audit_input()):
                final_state = state
                st.session_state.audit_events.append(event)
                stage_text = f" · {event.stage.value}" if event.stage else ""
                label = NODE_LABELS.get(event.node_name, event.node_name)
                progress.progress(event.progress, text=f"{label}{stage_text}")
                recent.dataframe(event_rows(st.session_state.audit_events[-6:]), hide_index=True, width="stretch")
            if final_state is None or "final_report" not in final_state:
                raise RuntimeError("审计流程没有生成最终报告。")
            st.session_state.audit_state = final_state
            report = final_state["final_report"]
            live_status.update(label=report.summary, state="complete", expanded=False)
        except Exception as exc:
            st.session_state.audit_error = f"{type(exc).__name__}: {exc}"
            live_status.update(label="审计任务执行失败", state="error", expanded=True)
            st.error(st.session_state.audit_error)


def _empty_state(status: dict[str, Any]) -> None:
    st.subheader("等待审计任务")
    st.info("在左侧选择仓库扫描或 Git Diff，开始后这里会实时显示 Agent 的阶段、工具与决策。")
    cols = st.columns(4)
    cols[0].metric("Agent 编排", "LangGraph" if status["langgraph"]["available"] else "Fallback")
    cols[1].metric("LLM", "已配置" if status["llm"]["available"] else "确定性模式")
    available = sum(1 for item in status["external_tools"] if item["available"])
    cols[2].metric("外部工具", f"{available}/{len(status['external_tools'])}")
    cols[3].metric("内置扫描", "可用")


def _summary(state: dict[str, Any]) -> None:
    report = state["final_report"]
    errors = state.get("errors", [])
    stage_statuses = {str(getattr(item.status, "value", item.status)) for item in report.audit_stage_results}
    if "budget_exhausted" in stage_statuses:
        st.warning(f"{report.summary} 部分阶段已达到审计预算上限，请结合 Agent Trace 查看终止位置。")
    elif errors or stage_statuses & {"partial", "failed"}:
        st.warning(report.summary)
    else:
        st.success(report.summary)
    cols = st.columns(5)
    cols[0].metric("扫描文件", len(state.get("scanned_files", [])))
    cols[1].metric("已确认", report.metrics.confirmed_findings)
    cols[2].metric("待复核", len(report.needs_review_findings))
    cols[3].metric("已排除", report.metrics.dismissed_findings)
    cols[4].metric("工具调用", report.metrics.tool_call_count)


def _render_results(state: dict[str, Any]) -> None:
    report = state["final_report"]
    _summary(state)
    overview_tab, tools_tab, findings_tab, trace_tab, reports_tab = st.tabs(
        ["项目概览", "工具执行", "风险与证据", "Agent Trace", "审计报告"]
    )
    with overview_tab:
        _render_overview(report)
    with tools_tab:
        _render_tools(report, state)
    with findings_tab:
        _render_findings_workspace(report, state)
    with trace_tab:
        _render_trace(report, state)
    with reports_tab:
        _render_reports(report)


def _render_overview(report: Any) -> None:
    profile_col, plan_col = st.columns([0.9, 1.1])
    with profile_col:
        st.subheader("ProjectProfile")
        profile = report.project_profile
        if not profile:
            st.info("未生成项目画像。")
        else:
            st.caption(f"画像范围：{profile.profile_scope.value} · 置信度：{profile.profile_confidence:.0%}")
            st.markdown("**语言与框架**")
            _chips([*profile.languages, *profile.frameworks])
            st.markdown("**风险面**")
            _chips(profile.risk_surfaces)
            key_files = [
                ("依赖", profile.dependency_files),
                ("入口", profile.entrypoints),
                ("路由", profile.route_files),
                ("认证", profile.auth_files),
                ("数据库", profile.db_files),
                ("上传", profile.upload_files),
            ]
            rows = [{"类型": label, "文件": path} for label, paths in key_files for path in paths]
            if rows:
                st.dataframe(rows, hide_index=True, width="stretch")
            if profile.missing_context:
                st.warning("；".join(profile.missing_context))
    with plan_col:
        st.subheader("AuditPlan")
        if report.audit_plan:
            st.caption(f"规划来源：{report.audit_plan.planner_source} · {report.audit_plan.summary}")
            rows = [
                {
                    "阶段": stage.stage.value,
                    "优先级": stage.priority.value,
                    "风险类型": ", ".join(stage.risk_types),
                    "能力": ", ".join(stage.required_capabilities),
                    "目标文件": len(stage.target_files),
                    "证据目标": ", ".join(stage.evidence_goals),
                }
                for stage in report.audit_plan.stages
            ]
            st.dataframe(rows, hide_index=True, width="stretch")
        else:
            st.info("未生成审计计划。")
    st.subheader("漏洞知识命中")
    if not report.vuln_knowledge:
        st.info("当前项目画像未命中漏洞知识条目。")
        return
    for item in report.vuln_knowledge:
        with st.expander(f"{item.title} · 相关度 {item.relevance_score:.0%}"):
            left, right = st.columns(2)
            left.markdown("**命中原因**")
            left.write("；".join(item.match_reasons) or "规则召回")
            left.markdown("**审计关注点**")
            left.write("；".join(item.audit_focus) or "-")
            right.markdown("**推荐能力**")
            _chips(item.recommended_capabilities, container=right)
            right.markdown("**修复原则**")
            right.write("；".join(item.fix_guidance) or "-")


def _render_tools(report: Any, state: dict[str, Any]) -> None:
    st.subheader("工具选择")
    if report.tool_plan:
        _chips(report.tool_plan.selected_tools)
        st.caption(report.tool_plan.selection_reason or "根据审计阶段和工具能力完成选择。")
        if report.tool_plan.unavailable_tools:
            st.warning(f"不可用工具：{', '.join(report.tool_plan.unavailable_tools)}；已选择内置 fallback。")
        if report.tool_plan.rejected_targets:
            st.error(f"被拒绝的目标路径：{', '.join(report.tool_plan.rejected_targets)}")
    st.subheader("执行结果")
    rows = tool_result_rows(report.tool_results)
    if rows:
        st.dataframe(rows, hide_index=True, width="stretch")
    else:
        st.info("没有工具执行记录。")
    st.subheader("风险阶段")
    stage_rows = stage_result_rows(report.audit_stage_results)
    if stage_rows:
        st.dataframe(stage_rows, hide_index=True, width="stretch")
    if report.fallback_records:
        st.subheader("Fallback 记录")
        st.dataframe(
            [
                {
                    "组件": item.component,
                    "阶段": item.stage.value if item.stage else "-",
                    "原因": item.reason,
                    "替代策略": item.strategy,
                }
                for item in report.fallback_records
            ],
            hide_index=True,
            width="stretch",
        )
    _render_errors(state)


def _render_findings_workspace(report: Any, state: dict[str, Any]) -> None:
    all_findings = unique_findings([*report.findings, *report.dismissed_findings, *report.needs_review_findings])
    filter_col, source_col = st.columns(2)
    severities = [value for value in ("critical", "high", "medium", "low", "info") if any(item.severity == value for item in all_findings)]
    selected_severities = filter_col.multiselect("严重等级", severities, default=severities)
    origins = sorted({finding_origin(item) for item in all_findings})
    selected_origins = source_col.multiselect("Finding 来源", origins, default=origins)

    def selected(items: list[Any]) -> list[Any]:
        return [item for item in unique_findings(items) if item.severity in selected_severities and finding_origin(item) in selected_origins]

    active = selected([item for item in report.findings if item.status == FindingStatus.CONFIRMED])
    needs_review = selected(report.needs_review_findings)
    dismissed = selected(report.dismissed_findings)
    risk_tab, review_tab, dismissed_tab, hypothesis_tab = st.tabs(
        [f"已确认 ({len(active)})", f"待复核 ({len(needs_review)})", f"已排除 ({len(dismissed)})", "审计假设"]
    )
    with risk_tab:
        _render_finding_list(active, report)
    with review_tab:
        _render_finding_list(needs_review, report)
    with dismissed_tab:
        _render_finding_list(dismissed, report)
    with hypothesis_tab:
        hypotheses = state.get("audit_hypotheses", [])
        if not hypotheses:
            st.info("没有未验证的审计假设。")
        else:
            st.dataframe(
                [
                    {
                        "阶段": item.stage.value,
                        "风险类型": item.risk_type,
                        "描述": item.description,
                        "目标文件": ", ".join(item.target_files),
                        "证据": ", ".join(item.evidence_ids),
                        "状态": item.status,
                    }
                    for item in hypotheses
                ],
                hide_index=True,
                width="stretch",
            )


def _render_finding_list(findings: list[Any], report: Any) -> None:
    if not findings:
        st.info("当前筛选条件下没有 Finding。")
        return
    risk_map = {item.finding_id: item for item in report.risk_analyses}
    review_map = {item.finding_id: item for item in report.review_results}
    fix_map = {item.finding_id: item for item in report.fix_suggestions}
    evidence_map = {item.evidence_id: item for item in report.evidences}
    for finding in findings:
        status = STATUS_LABELS.get(finding.status.value, finding.status.value)
        title = f"{finding.severity.upper()} · {finding.category} · {finding.file_path}:{finding.line_start} · {status}"
        with st.expander(title, expanded=finding.severity in {"critical", "high"}):
            st.markdown(
                f'<span class="ca-severity {finding.severity}">{finding.severity}</span> '
                f'<span class="ca-badge">{html.escape(finding_origin(finding))}</span> '
                f'<span class="ca-badge">置信度 {finding.confidence:.0%}</span>',
                unsafe_allow_html=True,
            )
            st.write(finding.message)
            evidence_tab, analysis_tab, fix_tab = st.tabs(["代码证据", "分析与复核", "修复建议"])
            with evidence_tab:
                st.code(finding.evidence_text, language=code_language(finding.file_path))
                matched_evidence = [evidence_map[value] for value in finding.evidence_ids if value in evidence_map]
                for evidence in matched_evidence:
                    details = [
                        f"Evidence: {evidence.evidence_id}",
                        f"函数: {evidence.function_name or '-'}",
                        f"类: {evidence.class_name or '-'}",
                        f"变更行: {'是' if evidence.is_changed_line else '否'}",
                    ]
                    st.caption(" · ".join(details))
                    if evidence.dataflow_steps:
                        st.write("局部调用关系：" + "；".join(evidence.dataflow_steps))
                    if evidence.imports:
                        st.write("相关 imports：" + "；".join(evidence.imports))
                if finding.provenance:
                    st.dataframe(
                        [
                            {
                                "来源类型": item.source_type,
                                "来源": item.source_name,
                                "规则": item.source_rule_id or "-",
                                "Call ID": item.tool_call_id or "-",
                            }
                            for item in finding.provenance
                        ],
                        hide_index=True,
                        width="stretch",
                    )
            with analysis_tab:
                risk = risk_map.get(finding.finding_id)
                review = review_map.get(finding.finding_id)
                if risk:
                    st.markdown("**风险分析**")
                    st.write(risk.risk_reason)
                    st.markdown("**攻击场景**")
                    st.write(risk.exploit_scenario)
                    st.caption(f"分析来源：{risk.analysis_source} · 严重等级：{risk.severity} · 置信度：{risk.confidence:.0%}")
                if review:
                    st.markdown("**误报复核**")
                    st.write(review.reason)
                    review_status = review.status.value if review.status else "-"
                    st.caption(f"结论：{STATUS_LABELS.get(review_status, review_status)} · 来源：{review.analysis_source}")
            with fix_tab:
                fix = fix_map.get(finding.finding_id)
                if not fix:
                    st.info("该 Finding 未确认或需要人工复核，暂不生成自动修复建议。")
                else:
                    st.write(fix.suggestion)
                    if fix.safe_code_example:
                        st.code(fix.safe_code_example, language=code_language(finding.file_path))
                    st.caption(f"Patch hint：{fix.patch_hint} · 建议来源：{fix.analysis_source}")


def _render_trace(report: Any, state: dict[str, Any]) -> None:
    st.subheader("实时事件")
    events = st.session_state.get("audit_events", [])
    if events:
        st.dataframe(event_rows(events), hide_index=True, width="stretch")
    else:
        st.info("当前会话没有事件流记录。")
    st.subheader("节点 Trace")
    rows = trace_rows(report.traces)
    if rows:
        st.dataframe(rows, hide_index=True, width="stretch")
    budget_col, coverage_col = st.columns(2)
    with budget_col:
        st.markdown("**预算使用**")
        st.json(report.budget.model_dump(mode="json"), expanded=False)
    with coverage_col:
        st.markdown("**阶段覆盖**")
        st.json(report.metrics.stage_coverage, expanded=False)
    _render_errors(state)


def _render_reports(report: Any) -> None:
    markdown = _read_text(report.markdown_path)
    json_text = _read_text(report.json_path) or report.model_dump_json(indent=2)
    sarif = _read_text(report.sarif_path)
    markdown_tab, json_tab, sarif_tab = st.tabs(["Markdown", "JSON", "SARIF"])
    with markdown_tab:
        st.download_button(
            "下载 Markdown",
            data=markdown,
            file_name=Path(report.markdown_path).name,
            mime="text/markdown",
            icon=":material/download:",
        )
        st.markdown(markdown)
        st.caption(report.markdown_path)
    with json_tab:
        st.download_button(
            "下载 JSON",
            data=json_text,
            file_name=Path(report.json_path).name,
            mime="application/json",
            icon=":material/download:",
        )
        st.code(json_text, language="json")
        st.caption(report.json_path)
    with sarif_tab:
        st.download_button(
            "下载 SARIF",
            data=sarif,
            file_name=Path(report.sarif_path).name,
            mime="application/sarif+json",
            icon=":material/download:",
        )
        st.code(sarif, language="json")
        st.caption(report.sarif_path)


def _render_errors(state: dict[str, Any]) -> None:
    errors = state.get("errors", [])
    if not errors:
        return
    st.subheader("错误与部分成功")
    for error in errors:
        if hasattr(error, "message"):
            st.error(f"{error.component}: {error.message}")
        else:
            st.error(str(error))


def _chips(values: list[str], container: Any = st) -> None:
    unique = list(dict.fromkeys(value for value in values if value))
    if not unique:
        container.caption("无")
        return
    markup = '<div class="ca-chips">' + "".join(f'<span class="ca-chip">{html.escape(value)}</span>' for value in unique) + "</div>"
    container.markdown(markup, unsafe_allow_html=True)


def _read_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError:
        return ""


_inject_styles()
_initialize_state()
environment = runtime_status()
_header(environment)
run = _sidebar(environment)
if run:
    _run_audit()
if st.session_state.audit_error and not run:
    st.error(st.session_state.audit_error)
if st.session_state.audit_state:
    _render_results(st.session_state.audit_state)
else:
    _empty_state(environment)
