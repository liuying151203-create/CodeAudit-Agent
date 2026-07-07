# 工作流说明

本文档说明 CodeAudit-Agent 当前版本从接收请求到生成报告的完整运行流程。

## 入口

CodeAudit-Agent 有两个主要入口：

- FastAPI：`app/api/scan.py`
  - `POST /scan/repo`
  - `POST /scan/diff`
- Streamlit：`frontend/streamlit_app.py`

两个入口最终都会调用：

```python
from app.agent.graph import run_audit
```

`run_audit` 接收一个 `AuditState` 字典，并返回填充完整的审计状态。

## API 调用链总览

### 调用 `/scan/repo` 时怎么走

入口代码：

```text
app/api/scan.py::scan_repo
```

请求：

```http
POST /scan/repo
```

请求体：

```json
{
  "repo_path": "data/sample_repos/small_python_app"
}
```

FastAPI 收到请求后执行：

```python
state = run_audit({
    "mode": "repo_scan",
    "repo_path": request.repo_path,
    "traces": [],
    "errors": [],
})
```

之后进入：

```text
app/agent/graph.py::run_audit
```

如果当前环境安装了 LangGraph，`run_audit` 会执行 `build_graph().invoke(initial_state)`。  
如果没有 LangGraph，会走文件中定义的顺序 fallback。两条路径执行的节点顺序保持一致。

`/scan/repo` 的实际节点链路：

```text
scan_repo
  -> run_audit
  -> router_node
  -> project_reader_node
  -> vulnkb_retriever_node
  -> tool_selector_node
  -> tool_executor_node
  -> finding_merger_node
  -> context_extract_node
  -> risk_analyze_node
  -> false_positive_review_node
  -> fix_suggest_node
  -> report_node
  -> _response
```

关键状态变化：

```text
repo_path
  -> project_profile
  -> vuln_knowledge
  -> tool_plan
  -> tool_results
  -> candidate_findings
  -> evidences
  -> risk_analyses
  -> review_results
  -> fix_suggestions
  -> final_report
```

最后 `_response` 把 `final_report` 转成 API 响应：

```python
{
    "report_id": report.report_id,
    "summary": report.summary,
    "project_profile": ...,
    "vuln_knowledge": ...,
    "tool_plan": ...,
    "tool_results": ...,
    "audit_stage_results": ...,
    "findings": ...,
    "risk_analyses": ...,
    "review_results": ...,
    "fix_suggestions": ...,
    "traces": ...,
    "markdown_path": ...,
    "json_path": ...,
}
```

### 调用 `/scan/diff` 时怎么走

入口代码：

```text
app/api/scan.py::scan_diff
```

请求：

```http
POST /scan/diff
```

请求体可以直接传 diff：

```json
{
  "diff_text": "diff --git a/app.py b/app.py\n..."
}
```

也可以让系统根据仓库读取 Git diff：

```json
{
  "repo_path": "D:/your/repo",
  "diff_mode": "cached"
}
```

FastAPI 收到请求后执行：

```python
state = run_audit({
    "mode": "diff_scan",
    "repo_path": request.repo_path,
    "diff_text": request.diff_text,
    "diff_mode": request.diff_mode,
    "traces": [],
    "errors": [],
})
```

`/scan/diff` 的实际节点链路：

```text
scan_diff
  -> run_audit
  -> router_node
  -> diff_loader_node
  -> project_reader_node
  -> vulnkb_retriever_node
  -> tool_selector_node
  -> tool_executor_node
  -> finding_merger_node
  -> context_extract_node
  -> risk_analyze_node
  -> false_positive_review_node
  -> fix_suggest_node
  -> report_node
  -> _response
```

和 `/scan/repo` 相比，`/scan/diff` 多了 `diff_loader_node`。

`diff_loader_node` 会把 diff 文本解析成：

```text
diff_text
changed_files
scanned_files
```

后续 `ProjectReaderTool`、`ToolSelectorTool`、`ToolExecutorTool` 都基于这些 diff 文件继续工作。也就是说 diff_scan 不会默认扫描整个仓库，而是围绕变更内容做审计。

典型 repo_scan 输入：

```python
{
    "mode": "repo_scan",
    "repo_path": "data/sample_repos/small_python_app",
    "traces": [],
    "errors": [],
}
```

典型 diff_scan 输入：

```python
{
    "mode": "diff_scan",
    "repo_path": None,
    "diff_text": "...unified diff...",
    "diff_mode": "cached",
    "traces": [],
    "errors": [],
}
```

## 状态结构

工作流中的中间数据都放在 `AuditState` 中，定义位置：

```text
app/agent/state.py
```

核心字段包括：

- `mode`：扫描模式，取值为 `repo_scan` 或 `diff_scan`。
- `repo_path`：本地仓库路径。
- `diff_text`：用户传入或 Git 读取到的 diff 文本。
- `changed_files`：diff_scan 解析出的变更文件。
- `scanned_files`：后续扫描会读取的文件内容。
- `project_profile`：项目画像，由 `ProjectReaderTool` 生成。
- `vuln_knowledge`：命中的漏洞知识库条目。
- `tool_plan`：工具选择计划。
- `tool_results`：工具执行结果。
- `audit_stage_results`：多阶段审计结果。
- `candidate_findings`：合并后的候选风险。
- `evidences`：每个 finding 对应的代码上下文。
- `risk_analyses`：风险分析结果。
- `review_results`：误报复核结果。
- `fix_suggestions`：修复建议。
- `final_report`：最终报告对象。
- `traces`：每个节点的执行 trace。
- `errors`：执行过程中的错误信息。

## 当前 LangGraph 拓扑

图编排代码位于：

```text
app/agent/graph.py
```

当前工作流是：

```text
router
  ├─ repo_scan -> project_reader
  └─ diff_scan -> diff_loader -> project_reader

project_reader
  -> vulnkb_retriever
  -> tool_selector
  -> tool_executor
  -> finding_merger
  -> context_extract
  -> risk_analyze
  -> false_positive_review
  -> fix_suggest
  -> report
```

如果环境中没有安装 LangGraph，`run_audit` 会走同样顺序的 fallback 执行链。fallback 逻辑也在 `app/agent/graph.py`。

## 哪里体现 Agent

本项目的 Agent 不等于“调用一次 LLM”。Agent 体现在以下几个具体机制上：

### 1. 有共享状态

状态定义在：

```text
app/agent/state.py::AuditState
```

每个节点都读取和写入同一个 `AuditState`。例如：

- `project_reader_node` 写入 `project_profile`
- `vulnkb_retriever_node` 写入 `vuln_knowledge`
- `tool_selector_node` 写入 `tool_plan`
- `tool_executor_node` 写入 `tool_results`
- `finding_merger_node` 写入 `candidate_findings`
- `context_extract_node` 写入 `evidences`
- `risk_analyze_node` 写入 `risk_analyses`
- `report_node` 写入 `final_report`

这使流程不是一段线性脚本，而是围绕状态逐步决策和累积上下文。

### 2. 有图编排

图定义在：

```text
app/agent/graph.py::build_graph
```

核心代码：

```python
graph.add_conditional_edges(
    "router",
    _route,
    {"repo_loader": "project_reader", "diff_loader": "diff_loader"},
)
```

这里体现了 Agent 的路径选择能力：

- `repo_scan` 直接进入 `project_reader`
- `diff_scan` 先进入 `diff_loader`，再进入 `project_reader`

后续节点按图连接继续执行。

### 3. 有工具选择

工具选择节点是：

```text
app/agent/nodes.py::tool_selector_node
app/agent/tools.py::ToolSelectorTool
```

它不是固定写死只跑一个扫描器，而是读取：

- `ProjectProfile`
- `VulnKnowledge`
- `scan_mode`
- `config/security_tools.yaml`

然后生成：

```python
ToolPlan(
    selected_tools=[...],
    selected_risk_types=[...],
    target_files=[...],
    selection_reason="..."
)
```

这是当前版本最关键的 Agent 决策点。

### 4. 有工具执行和降级

工具执行节点是：

```text
app/agent/nodes.py::tool_executor_node
app/agent/tools.py::ToolExecutorTool
```

它根据 `ToolPlan` 执行工具：

- `secret_scanner`
- `custom_rule_scanner`
- `bandit`
- `semgrep`
- `context_extractor`

外部工具不可用时，不会让流程失败，而是生成 skipped 结果并降级到内置规则扫描。

### 5. 有可解释 trace

所有节点调用都通过：

```text
app/utils/trace.py::trace_tool
```

trace 会记录：

- 节点名
- 工具名
- 输入摘要
- 输出摘要
- 耗时
- 状态

因此报告里可以看到 Agent 具体走了哪些节点、调用了哪些工具、每一步是否成功。

## 哪里用了 LLM

LLM 只在三个工具中使用：

```text
app/agent/tools.py::RiskAnalyzeTool
app/agent/tools.py::FalsePositiveReviewTool
app/agent/tools.py::FixSuggestTool
```

底层调用函数是：

```text
app/agent/tools.py::_call_llm_json
```

### 1. RiskAnalyzeTool

节点：

```text
app/agent/nodes.py::risk_analyze_node
```

调用：

```python
RiskAnalyzeTool().run(
    state.get("candidate_findings", []),
    state.get("evidences", []),
)
```

作用：

- 解释风险原因
- 给出攻击场景
- 给出置信度
- 给出严重等级

如果配置了 LLM API，会调用：

```text
_llm_batch_risk_analysis
```

如果未配置 LLM API 或 LLM 返回异常，会回退到模板分析。

### 2. FalsePositiveReviewTool

节点：

```text
app/agent/nodes.py::false_positive_review_node
```

调用：

```python
FalsePositiveReviewTool().run(
    state.get("candidate_findings", []),
    state.get("evidences", []),
)
```

作用：

- 判断 finding 是否可能是误报
- 给出复核理由
- 给出最终严重等级

如果配置了 LLM API，会调用：

```text
_llm_batch_false_positive_review
```

否则使用本地规则复核。

### 3. FixSuggestTool

节点：

```text
app/agent/nodes.py::fix_suggest_node
```

调用：

```python
FixSuggestTool().run(
    state.get("candidate_findings", []),
    state.get("review_results", []),
    state.get("evidences", []),
)
```

作用：

- 对非误报 finding 给出修复建议
- 给出安全代码示例
- 给出 patch hint

如果配置了 LLM API，会调用：

```text
_llm_batch_fix_suggestions
```

否则使用本地修复模板。

### LLM 实际看到了什么

LLM 不是只看一行 finding。当前会把 finding 和 evidence 合并后发给 LLM：

```text
app/agent/tools.py::_findings_with_evidence
```

payload 中包含：

- `finding_id`
- `rule_id`
- `file_path`
- `line_start`
- `severity`
- `category`
- `message`
- `evidence_text`
- `code_context`
- `function_name`
- `imports`
- `changed_line`
- `surrounding_lines`

也就是说，LLM 是在静态工具发现候选问题之后，结合源码上下文进行分析、复核和修复建议。

### LLM 是否真的被调用如何判断

看报告里的：

```text
analysis_summary
fallback_reasons
risk_analyses[].analysis_source
review_results[].analysis_source
fix_suggestions[].analysis_source
```

如果 `analysis_source` 是 `llm`，说明该结果来自 LLM。  
如果是 `template`，说明走了本地模板。  
如果存在 `fallback_reasons`，说明 LLM 未配置、超时、返回 JSON 不合法或结构校验失败。

## 工具是怎么被利用的

工具注册表：

```text
config/security_tools.yaml
```

工具实现：

```text
app/agent/tools.py
```

工具调用发生在 `nodes.py` 中。每个节点只负责调用一个工具，并把工具输出写回 `AuditState`。

### 工具调用关系

```text
project_reader_node
  -> ProjectReaderTool.run

vulnkb_retriever_node
  -> VulnKBRetrieverTool.run

tool_selector_node
  -> ToolSelectorTool.run

tool_executor_node
  -> ToolExecutorTool.run

finding_merger_node
  -> FindingMergerTool.run

context_extract_node
  -> ContextExtractorTool.run

risk_analyze_node
  -> RiskAnalyzeTool.run

false_positive_review_node
  -> FalsePositiveReviewTool.run

fix_suggest_node
  -> FixSuggestTool.run

report_node
  -> ReportWriterTool.run
```

### ToolSelectorTool 如何选工具

输入：

- `ProjectProfile`
- `VulnKnowledge`
- `scan_mode`
- `scanned_files`

工具注册表中的每个工具都有：

- `supported_languages`
- `risk_types`
- `supported_modes`
- `cost_level`
- `requires_install`
- `description`

选择逻辑：

1. 工具必须支持当前 scan mode。
2. 工具语言要匹配项目语言。
3. 工具风险类型要匹配项目风险面或知识库命中风险。
4. 如果没有合适工具，补上 `custom_rule_scanner` 作为 fallback。

输出是 `ToolPlan`。

### ToolExecutorTool 如何执行工具

输入：

```python
ToolExecutorTool().run(
    plan=state["tool_plan"],
    files=state["scanned_files"],
    mode=state["mode"],
)
```

当前执行策略：

- `secret_scanner`：运行内置规则，只保留 `Secrets`。
- `custom_rule_scanner`：运行完整内置规则。
- `bandit`：检查是否安装；未安装则 skipped。
- `semgrep`：检查是否安装；未安装则 skipped。
- `context_extractor`：记录为已选择，实际上下文提取在 `context_extract_node`。

这保证了外部工具没装时 repo_scan / diff_scan 仍能跑通。

## 1. router

节点函数：

```text
app/agent/nodes.py::router_node
```

职责：

- 初始化 `traces` 和 `errors`。
- 根据输入确定扫描模式。
- 如果传入 `diff_text`，强制进入 `diff_scan`。
- 如果没有 `diff_text`，使用传入的 `mode`，默认是 `repo_scan`。
- 检查必要输入是否存在。

关键行为：

- `diff_scan` 至少需要 `diff_text` 或 `repo_path`。
- `repo_scan` 必须有 `repo_path`。
- 输入不完整时直接抛错，避免后续节点在错误状态下继续运行。

## 2. diff_loader

节点函数：

```text
app/agent/nodes.py::diff_loader_node
```

工具：

```text
app/agent/tools.py::GitDiffTool
app/diff/git_diff_loader.py
app/diff/diff_parser.py
```

只在 `diff_scan` 模式下执行。

职责：

- 如果用户传入 `diff_text`，直接使用该 diff。
- 如果没有传入 `diff_text`，根据 `repo_path` 和 `diff_mode` 读取 Git diff。
- 解析 unified diff，生成变更文件和新增行信息。

输出：

- `diff_text`
- `changed_files`
- `scanned_files`

`scanned_files` 在 diff_scan 中只包含 diff 重建出的 Python 变更内容。后续工具只扫描这些变更内容，而不是整个仓库。

## 3. project_reader

节点函数：

```text
app/agent/nodes.py::project_reader_node
```

工具：

```text
app/agent/tools.py::ProjectReaderTool
```

职责：

- 读取项目结构。
- 识别项目语言。
- 识别框架。
- 找出依赖文件。
- 找出入口文件、路由文件、认证文件、数据库文件、上传相关文件。
- 推断项目风险面。

输出：

```python
ProjectProfile(
    languages=[...],
    frameworks=[...],
    dependency_files=[...],
    entrypoints=[...],
    route_files=[...],
    auth_files=[...],
    db_files=[...],
    upload_files=[...],
    risk_surfaces=[...],
)
```

repo_scan 下，`ProjectReaderTool` 会从 `repo_path` 读取项目文件。  
diff_scan 下，如果没有完整 `repo_path`，它会基于 `diff_loader` 已经解析出的 `scanned_files` 构建一个局部项目画像。

注意：该节点只读取文件文本，不执行被审计项目代码。

## 4. vulnkb_retriever

节点函数：

```text
app/agent/nodes.py::vulnkb_retriever_node
```

工具：

```text
app/agent/tools.py::VulnKBRetrieverTool
knowledge_base/
```

职责：

- 根据 `ProjectProfile` 中的语言、框架和风险面检索漏洞知识库。
- 返回与当前项目最相关的漏洞知识条目。

当前知识库包括：

- `knowledge_base/sql_injection.md`
- `knowledge_base/command_injection.md`
- `knowledge_base/secret_leak.md`
- `knowledge_base/path_traversal.md`
- `knowledge_base/unsafe_deserialization.md`
- `knowledge_base/broken_access_control.md`

每个知识条目会被包装成：

```python
VulnKnowledge(
    knowledge_id="sql_injection",
    title="SQL 注入",
    file_path="knowledge_base/sql_injection.md",
    matched_risk_types=["SQL Injection"],
    content="..."
)
```

这些知识不会直接变成 finding，而是参与后续工具选择和报告解释。

## 5. tool_selector

节点函数：

```text
app/agent/nodes.py::tool_selector_node
```

工具：

```text
app/agent/tools.py::ToolSelectorTool
config/security_tools.yaml
```

职责：

- 读取工具注册表。
- 根据项目画像、知识库命中内容、扫描模式选择安全工具。
- 选择目标风险类型。
- 选择重点扫描文件。
- 给出选择理由。

输出：

```python
ToolPlan(
    selected_tools=[...],
    selected_risk_types=[...],
    target_files=[...],
    selection_reason="..."
)
```

工具注册表位于：

```text
config/security_tools.yaml
```

当前注册工具包括：

- `secret_scanner`
- `custom_rule_scanner`
- `bandit`
- `semgrep`
- `context_extractor`

选择逻辑基于：

- `supported_languages`
- `risk_types`
- `supported_modes`
- 项目 `risk_surfaces`
- 漏洞知识库命中的风险类型

示例：

```text
Python + DB 文件 + SQL Injection 风险面
  -> 选择 custom_rule_scanner、bandit、semgrep
```

如果没有其它合适工具，系统会保证选择 `custom_rule_scanner` 作为内置 fallback。

## 6. tool_executor

节点函数：

```text
app/agent/nodes.py::tool_executor_node
```

工具：

```text
app/agent/tools.py::ToolExecutorTool
```

职责：

- 执行 `ToolPlan.selected_tools` 中选择的工具。
- 对外部工具做可用性检查。
- 外部工具不可用时记录 skipped，而不是让流程失败。
- 生成多阶段审计结果。

当前执行策略：

- `secret_scanner`：调用内置规则，只保留 `Secrets` 类型 finding。
- `custom_rule_scanner`：调用内置 Python 规则扫描。
- `bandit`：如果未安装，记录 skipped；MVP 不直接执行外部命令。
- `semgrep`：如果未安装，记录 skipped；MVP 不直接执行外部命令。
- `context_extractor`：记录为成功，实际上下文提取在后续 `context_extract` 节点执行。

输出：

```python
tool_results: list[ToolExecutionResult]
audit_stage_results: list[AuditStageResult]
```

`ToolExecutionResult` 包含：

- `tool_name`
- `status`
- `findings`
- `output_summary`
- `skipped_reason`
- `metadata`

`AuditStageResult` 当前覆盖：

- `init`
- `secret`
- `injection`
- `command`
- `file`
- `auth`
- `review`
- `report`

MVP 中 secret、injection、command 有实际统计，其它阶段保留为 planned 或聚合阶段。

## 7. finding_merger

节点函数：

```text
app/agent/nodes.py::finding_merger_node
```

工具：

```text
app/agent/tools.py::FindingMergerTool
```

职责：

- 汇总多个工具输出的 findings。
- 按 `rule_id + file_path + line_start + evidence_text` 去重。
- 写入 `candidate_findings`。

为什么需要这个节点：

- `secret_scanner` 和 `custom_rule_scanner` 可能同时发现同一条 secret。
- 后续接入 Semgrep、Bandit、Gitleaks 后，不同工具也可能报告同一位置的问题。
- 统一合并后，后续 LLM 分析和报告不会重复计算同一风险。

## 8. context_extract

节点函数：

```text
app/agent/nodes.py::context_extract_node
```

工具：

```text
app/agent/tools.py::ContextExtractorTool
app/context/context_extractor.py
```

职责：

- 为每个 `candidate_findings` 提取源码上下文。
- 提取前后若干行代码。
- 提取所在函数名。
- 提取 import 信息。
- 标记是否来自 diff 新增行。

输出：

```python
evidences: list[Evidence]
```

`Evidence` 后续会传给 LLM 分析、误报复核和修复建议节点。这样 LLM 不再只看单行 evidence，而是能看到局部源码上下文。

## 9. risk_analyze

节点函数：

```text
app/agent/nodes.py::risk_analyze_node
```

工具：

```text
app/agent/tools.py::RiskAnalyzeTool
```

职责：

- 对候选 finding 生成结构化风险分析。
- 配置 LLM API 时，批量调用 LLM。
- 未配置 LLM 或调用失败时，回退到本地模板。

输入：

- `candidate_findings`
- `evidences`

输出：

```python
risk_analyses: list[RiskAnalysis]
```

每条 `RiskAnalysis` 包含：

- `finding_id`
- `risk_type`
- `risk_reason`
- `exploit_scenario`
- `confidence`
- `severity`
- `analysis_source`
- `fallback_reason`

`analysis_source` 用于区分结果来自：

- `llm`
- `template`

## 10. false_positive_review

节点函数：

```text
app/agent/nodes.py::false_positive_review_node
```

工具：

```text
app/agent/tools.py::FalsePositiveReviewTool
```

职责：

- 对每个 finding 做误报复核。
- 配置 LLM API 时，批量调用 LLM。
- 未配置 LLM 或调用失败时，使用本地规则复核。

输入：

- `candidate_findings`
- `evidences`

输出：

```python
review_results: list[ReviewResult]
```

每条 `ReviewResult` 包含：

- `finding_id`
- `is_false_positive`
- `reason`
- `final_severity`
- `analysis_source`
- `fallback_reason`

## 11. fix_suggest

节点函数：

```text
app/agent/nodes.py::fix_suggest_node
```

工具：

```text
app/agent/tools.py::FixSuggestTool
```

职责：

- 对非误报 finding 生成修复建议。
- 配置 LLM API 时，批量调用 LLM。
- 未配置 LLM 或调用失败时，使用本地模板。
- 不自动修改用户代码。

输入：

- `candidate_findings`
- `review_results`
- `evidences`

输出：

```python
fix_suggestions: list[FixSuggestion]
```

每条 `FixSuggestion` 包含：

- `finding_id`
- `suggestion`
- `safe_code_example`
- `patch_hint`
- `analysis_source`
- `fallback_reason`

## 12. report

节点函数：

```text
app/agent/nodes.py::report_node
```

工具：

```text
app/agent/tools.py::ReportWriterTool
```

职责：

- 汇总完整审计状态。
- 生成 `AuditReport`。
- 写入 Markdown 报告。
- 写入 JSON 报告。

报告输出目录由环境变量控制：

```env
CODEAUDIT_REPORT_DIR=data/reports
```

报告包含：

- 扫描模式和摘要
- 风险等级统计
- ProjectProfile 项目画像
- VulnKnowledge 知识库命中
- ToolPlan 工具计划
- ToolExecutionResult 工具执行结果
- AuditStageResult 审计阶段
- Findings 风险列表
- Evidence 相关分析结果
- RiskAnalysis 风险分析
- ReviewResult 误报复核
- FixSuggestion 修复建议
- Agent Trace

## Trace 机制

所有节点都通过：

```text
app/utils/trace.py::trace_tool
```

记录执行 trace。

每条 trace 包含：

- `node_name`
- `tool_name`
- `input_summary`
- `output_summary`
- `elapsed_ms`
- `status`

Trace 会写入最终报告，用于解释 Agent 的执行路径和每个节点耗时。

## repo_scan 示例路径

repo_scan 的实际执行顺序：

```text
router
  -> project_reader
  -> vulnkb_retriever
  -> tool_selector
  -> tool_executor
  -> finding_merger
  -> context_extract
  -> risk_analyze
  -> false_positive_review
  -> fix_suggest
  -> report
```

repo_scan 中，`ProjectReaderTool` 会直接读取 `repo_path`。

## diff_scan 示例路径

diff_scan 的实际执行顺序：

```text
router
  -> diff_loader
  -> project_reader
  -> vulnkb_retriever
  -> tool_selector
  -> tool_executor
  -> finding_merger
  -> context_extract
  -> risk_analyze
  -> false_positive_review
  -> fix_suggest
  -> report
```

diff_scan 中，`diff_loader` 先解析 diff，后续节点只围绕变更文件和新增代码行工作。

## 安全约束

当前工作流遵守以下约束：

- 不执行被审计项目代码。
- 不自动利用漏洞。
- 不自动修改用户代码。
- 外部安全工具不可用时降级为内置规则扫描。
- LLM 只基于 finding、上下文证据和结构化输入做分析，不直接无约束扫描整仓。
