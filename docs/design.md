# CodeAudit-Agent 设计说明书

CodeAudit-Agent 是一个面向源码安全审计和 Git diff 风险分析的多阶段 Agent 系统。系统读取本地项目源码或 Git diff，形成项目画像，检索漏洞知识，规划审计阶段，选择并执行安全工具，再由 LLM 围绕工具结果和源码证据进行主动补充审计，最终完成风险复核、修复建议和报告生成。

系统支持 Python 后端项目，以及 Java Spring Boot / MyBatis 后端项目。语言识别、框架规则、漏洞知识和安全工具均通过注册机制扩展，不需要修改 Agent 主流程。

## 1. 设计目标

CodeAudit-Agent 解决两个核心问题：

- `repo_scan`：理解并审计一个本地后端项目。
- `diff_scan`：围绕 Git diff 及其必要上下文审计代码变更。

系统不是把整个仓库直接交给 LLM 自由审查，也不是仅让 LLM 解释静态扫描结果，而是采用以下协作方式：

```text
确定性能力
  -> 读取项目、识别技术栈、检索知识、运行扫描工具、提取代码证据

LLM 推理能力
  -> 规划审计重点、判断是否需要更多证据、提出工具调用、形成风险结论

LangGraph 编排能力
  -> 管理状态、条件分支、工具调用循环、审计阶段循环、fallback 和 trace
```

设计遵循以下原则：

- 证据优先：进入报告的风险必须关联文件、行号和代码证据。
- 工具受控：LLM 只能请求已注册的只读工具，不能直接执行任意命令。
- 分阶段审计：不同风险面分别规划、执行和收敛，避免一次提示词处理所有问题。
- 有限自主：Agent 可以继续取证和调用工具，但必须受轮次、文件数、Token 和耗时预算约束。
- 运行安全：不执行被审计项目代码，不利用漏洞，不自动修改用户代码。
- 可降级：LLM 或外部工具不可用时，仍可通过内置规则完成基础审计。
- 可解释：报告保留审计计划、工具选择原因、调用结果、证据来源和 fallback 原因。

## 2. 系统能力与技术栈

### 2.1 核心技术栈

- Python：实现 Agent、项目读取、扫描器适配和报告生成。
- LangGraph：编排状态化工作流、条件边和循环。
- LangChain：封装 LLM 调用、结构化输出和可调用工具。
- FastAPI：提供仓库扫描和 diff 扫描 API。
- Streamlit：展示项目画像、Agent 执行过程和审计报告。
- Pydantic：定义节点之间传递的结构化数据。
- LLM API：用于审计规划、主动取证、风险分析、误报复核和修复建议。

### 2.2 安全工具

系统内置以下工具：

- `secret_scanner`：检测硬编码密钥、Token、密码和可疑凭据。
- `custom_rule_scanner`：执行项目内置的 Python、Java 和 diff 安全规则。
- `context_extractor`：提取目标代码、函数、类、imports 和局部调用关系。
- `project_reader`：读取文件树并生成项目画像。
- `vulnkb_retriever`：检索本地漏洞知识库。

系统注册以下外部只读扫描工具：

- Semgrep：执行跨语言静态规则和官方安全规则集。
- Bandit：补充 Python 安全规则检测。
- Gitleaks：补充密钥与凭据检测。

外部工具未安装、执行超时或结果解析失败时，系统记录 `skipped`、`error` 或 `fallback`，并使用内置扫描器覆盖基础能力。

### 2.3 工程集成

- Markdown：生成人类可读的完整审计报告。
- JSON：输出完整结构化审计状态和结果。
- SARIF：向 GitHub Code Scanning 和其他静态分析平台输出标准结果。
- GitHub Action：在 push、pull request 或手动触发时运行 `diff_scan` 或 `repo_scan`。
- GitHub PR Comment：将风险摘要、关键 finding 和报告链接回写到 PR。
- MCP Adapter：把外部 MCP Tool Server 的工具映射为内部 `SecurityTool`，继续通过统一工具网关调用。

## 3. 分层架构

系统按职责划分为七层：

```text
API / UI Layer
  -> Agent Orchestration Layer
  -> Project Understanding Layer
  -> Knowledge & Planning Layer
  -> Tool Gateway Layer
  -> LLM Reasoning Layer
  -> Report & Integration Layer
```

### 3.1 API / UI Layer

FastAPI 接收 `repo_scan` 和 `diff_scan` 请求，Streamlit 提供本地交互界面。两个入口只负责组织输入和展示输出，最终都调用同一个 LangGraph 审计图。

### 3.2 Agent Orchestration Layer

LangGraph 管理 `AuditState`，控制节点执行、条件路由、审计阶段切换、工具调用循环、错误恢复和 trace 记录。

该层不实现具体扫描规则，也不直接承担 LLM 推理。

### 3.3 Project Understanding Layer

该层读取文件树、依赖文件和有限源码内容，识别语言、框架、入口、路由、认证、数据库访问、文件上传和其他安全相关模块，输出 `ProjectProfile`。

### 3.4 Knowledge & Planning Layer

该层根据项目画像和用户任务检索漏洞知识，生成按风险阶段组织的 `AuditPlan`。

### 3.5 Tool Gateway Layer

该层由 Tool Registry、Tool Selector 和 Tool Executor 组成，负责工具发现、参数校验、权限限制、统一执行、结果解析和 fallback。

### 3.6 LLM Reasoning Layer

LLM 负责规划、主动取证决策、风险判断、误报复核和修复建议。LLM 只输出结构化对象，不直接接触 shell，也不能绕过工具网关。

### 3.7 Report & Integration Layer

该层生成 Markdown、JSON 和 SARIF，展示 Agent trace，并向 GitHub Action、PR Comment 或其他平台提供集成结果。

## 4. Node、Tool 与 LLM Role

这三个概念在系统中职责不同。

### 4.1 Node

Node 是 LangGraph 中的状态转换步骤。节点读取 `AuditState` 的一部分，执行一个明确职责，再把结构化结果写回状态。

例如：

- `project_reader_node` 生成项目画像。
- `audit_planner_node` 生成审计计划。
- `audit_reasoner_node` 判断是否继续调用工具。
- `reporter_node` 生成报告。

### 4.2 Tool

Tool 是可以被节点或 LLM 请求使用的原子能力，例如扫描、检索和上下文提取。每个工具必须具有固定输入 Schema、固定输出 Schema 和明确的只读权限。

扫描工具不能决定工作流下一步，工具只负责执行一次能力并返回结果。

### 4.3 LLM Role

LLM Role 是某个节点内部的推理职责，不等于独立进程，也不要求每个角色都进行一次单独 API 调用。

系统包含以下逻辑角色：

- Audit Planner：规划风险阶段、目标文件和证据目标。
- Audit Reasoner：根据当前证据决定继续调用工具、形成 finding 或结束阶段。
- Risk Analyzer：解释风险、攻击条件和严重程度。
- False Positive Reviewer：复核证据充分性和误报可能。
- Fix Advisor：生成与框架和上下文匹配的修复建议。

Risk Analyzer 和 False Positive Reviewer 可以在一次批量 LLM 请求中返回两个结构化结果，减少调用次数。角色划分用于明确责任，不用于机械增加节点和模型调用。

## 5. 核心数据模型

### 5.1 AuditState

`AuditState` 是整个 LangGraph 的共享状态，包含：

```text
request
  -> mode
  -> repo_path
  -> diff_text
  -> user_task

project_context
  -> scanned_files
  -> changed_files
  -> project_profile
  -> retrieved_knowledge

planning
  -> audit_plan
  -> stage_queue
  -> current_stage
  -> stage_results

execution
  -> tool_requests
  -> validated_tool_calls
  -> tool_results
  -> evidence_pool
  -> audit_hypotheses

findings
  -> candidate_findings
  -> merged_findings
  -> review_results
  -> confirmed_findings
  -> fix_suggestions

runtime
  -> budget
  -> metrics
  -> fallbacks
  -> errors
  -> traces
  -> final_report
```

节点只更新自己负责的字段，列表字段使用 reducer 追加，避免循环节点覆盖历史工具结果和 trace。

### 5.2 ProjectProfile

`ProjectProfile` 描述项目是什么以及可能暴露哪些风险面：

```text
languages
frameworks
dependency_files
entrypoints
route_files
auth_files
db_files
upload_files
risk_surfaces
security_signals
profile_scope
profile_confidence
missing_context
```

其中：

- `risk_surfaces` 是根据项目结构推断的审计方向，例如存在数据库访问层意味着需要审计注入风险。
- `security_signals` 是危险 API、敏感配置名等线索，但不是最终漏洞结论。
- `profile_scope` 取值为 `full_repo`、`diff_enriched` 或 `diff_only`。
- `profile_confidence` 表示画像完整度。
- `missing_context` 记录缺失的依赖文件、源码文件或调用链上下文。

### 5.3 VulnKnowledge

`VulnKnowledge` 表示一次知识库检索命中：

```text
knowledge_id
risk_type
languages
frameworks
dangerous_patterns
recommended_capabilities
audit_focus
fix_guidance
relevance_score
match_reasons
```

### 5.4 AuditPlan 与 AuditStagePlan

`AuditPlan` 由多个 `AuditStagePlan` 组成：

```json
{
  "summary": "优先检查密钥、SQL 注入和访问控制",
  "stages": [
    {
      "stage": "injection",
      "priority": "high",
      "risk_types": ["SQL Injection"],
      "target_files": ["api/users.py", "repositories/user_repo.py"],
      "required_capabilities": ["scan_sql_patterns", "extract_call_chain"],
      "evidence_goals": ["确认用户输入是否到达 SQL 拼接点"],
      "reason": "项目存在路由层和数据库访问层"
    }
  ]
}
```

Planner 描述需要完成什么审计目标，不直接决定使用某个具体工具。

### 5.5 ToolRequest 与 ValidatedToolCall

`ToolRequest` 表示节点或 LLM 对一种能力的请求：

```text
stage
required_capability
target_files
risk_types
reason
requested_context
```

Tool Selector 根据注册表把它转换成 `ValidatedToolCall`：

```text
call_id
tool_name
arguments
timeout
target_files
validation_status
selection_reason
fallback_tool
```

### 5.6 ToolRunResult

所有初始扫描和补充调用统一输出 `ToolRunResult`：

```text
call_id
tool_name
stage
status
findings
observations
artifacts
duration_ms
fallback_used
error_message
```

`findings` 用于承载扫描器直接发现的候选风险，`observations` 用于承载源码上下文、调用关系和其他辅助证据。统一结果模型可以避免根据调用来源维护两套执行逻辑。

### 5.7 Evidence

`Evidence` 是风险结论的事实依据：

```text
evidence_id
file_path
start_line
end_line
code_snippet
symbol_name
imports
dataflow_steps
is_changed_line
source_tool
```

发送给 LLM 的 Evidence 会先经过脱敏和长度限制。

### 5.8 AuditDecision

`audit_reasoner` 每轮只能返回以下决策之一：

- `CALL_TOOL`：现有证据不足，需要继续取证。
- `EMIT_FINDING`：证据足以形成候选风险。
- `FINISH_STAGE`：当前阶段没有更多有效发现。

```json
{
  "decision": "CALL_TOOL",
  "reason": "需要确认路由参数是否传入 SQL 拼接点",
  "tool_request": {
    "required_capability": "extract_call_chain",
    "target_files": ["api/users.py", "repositories/user_repo.py"],
    "risk_types": ["SQL Injection"]
  }
}
```

### 5.9 Finding 生命周期

Finding 按以下状态流转：

```text
candidate
  -> merged
  -> confirmed / dismissed / needs_review
  -> reported
```

每条 Finding 至少记录：

```text
finding_id
rule_id
risk_type
severity
confidence
file_path
line_number
evidence_ids
source
stage
status
analysis_source
fallback_reason
```

LLM 产生的 Finding 必须引用 `evidence_ids`。只有描述、没有代码证据的内容保留为 `AuditHypothesis`，不能进入最终风险列表。

### 5.10 AuditBudget

`AuditBudget` 控制 Agent 的有限自主行为：

- 每个阶段最多补充取证 2 轮。
- 每轮最多请求 2 个工具调用。
- 单次调用最多处理 5 个目标文件。
- 单文件最多向 LLM 提供 80 行代码。
- 限制单阶段 Token、工具耗时和总审计耗时。
- 达到预算后进入 `FINISH_STAGE`，并记录 `budget_exhausted`。

## 6. 项目理解与漏洞知识检索

### 6.1 Project Reader

Project Reader 通过确定性规则读取文件树和有限源码内容，不执行项目代码。

处理流程：

```text
repo_path / changed files
  -> 校验扫描根目录
  -> 遍历文件树
  -> 应用忽略规则和大小限制
  -> 统计文件后缀与依赖文件
  -> 读取关键配置和有限源码
  -> 识别语言、框架和关键模块
  -> 生成 ProjectProfile
```

默认忽略：

- `.git`、`.venv`、`node_modules`
- `dist`、`build`、`target`
- 二进制文件、软链接和超大文件
- `.env`、证书、私钥等敏感文件内容

语言识别依据文件后缀和构建文件，例如：

- `.py`、`requirements.txt`、`pyproject.toml` -> Python
- `.java`、`pom.xml`、`build.gradle` -> Java

框架识别同时使用依赖声明和源码特征，例如：

- `fastapi` 依赖或 `from fastapi import FastAPI` -> FastAPI
- `django` 依赖、`settings.py` 和 `urls.py` -> Django
- Spring Boot 依赖或 `@SpringBootApplication` -> Spring Boot
- `@RestController`、`@RequestMapping` -> Spring MVC
- `@Mapper`、`Mapper.xml` -> MyBatis

关键文件通过路径、文件名、imports、注解和有限源码特征识别。Project Reader 只生成画像和线索，不产出 Finding。

### 6.2 VulnKB Retriever

漏洞知识库位于 `knowledge_base/`：

```text
sql_injection.md
command_injection.md
secret_leak.md
path_traversal.md
unsafe_deserialization.md
broken_access_control.md
```

每个文档使用结构化元数据描述：

- 风险类型
- 适用语言和框架
- 适用风险面
- 危险代码模式
- 推荐检测能力
- 审计关注点
- 修复建议

检索流程：

```text
ProjectProfile + user_task
  -> 按 languages、frameworks、risk_surfaces 和关键词召回
  -> 规则打分
  -> 返回 Top-K VulnKnowledge
  -> 可选 LLM rerank 和优先级解释
```

规则召回决定候选集合，LLM 只做可选重排，避免知识检索完全依赖模型判断。知识条目会被 Planner 用于生成风险阶段、证据目标和所需工具能力。

## 7. 工具注册与统一执行

### 7.1 Tool Registry

工具能力注册在 `config/security_tools.yaml`。每个工具包含：

```text
name
adapter
supported_languages
risk_types
capabilities
supported_modes
cost_level
requires_install
read_only
timeout
description
```

示例映射：

```text
scan_secrets
  -> gitleaks
  -> secret_scanner fallback

scan_python_security
  -> bandit
  -> custom_rule_scanner fallback

scan_sql_patterns
  -> semgrep
  -> custom_rule_scanner fallback

extract_call_chain
  -> context_extractor
```

Planner 面向 capability 规划，Selector 面向具体工具选择，因此增加或替换工具时不需要修改 Planner 提示词。

### 7.2 Tool Selector

Tool Selector 是全局工具策略网关，负责：

- 根据 capability 匹配候选工具。
- 校验语言、风险类型和 scan mode。
- 校验工具是否只读。
- 校验目标路径位于扫描范围内。
- 校验调用轮次、文件数量和上下文长度。
- 根据安装状态、成本和优先级选择具体工具。
- 为不可用工具选择 fallback。

LLM 不能直接指定命令行，只能提交符合 Schema 的 `ToolRequest`。

### 7.3 Tool Executor

Tool Executor 负责统一执行 `ValidatedToolCall`：

- 使用固定命令模板调用外部工具。
- 不拼接 LLM 生成的 shell 参数。
- 将工作目录限制在 `repo_path`。
- 设置超时和输出大小限制。
- 并行执行相互独立的只读扫描工具。
- 将不同工具输出转换成统一 `ToolRunResult`。
- 记录 success、skipped、fallback、timeout 和 error。

MCP 工具先通过 MCP Adapter 转换成内部 SecurityTool 描述，再进入 Tool Selector 和 Tool Executor。MCP Tool Server 不会绕过项目的权限校验和调用预算。

## 8. Agent 工作流

### 8.1 总体流程

```text
router
  -> input_loader
  -> project_reader
  -> vulnkb_retriever
  -> audit_planner
  -> stage_scheduler
  -> tool_selector
  -> tool_executor
  -> evidence_builder
  -> audit_reasoner
       |-- CALL_TOOL ------> tool_selector
       |                       -> tool_executor
       |                       -> evidence_builder
       |                       -> audit_reasoner
       |
       |-- EMIT_FINDING ---> finding_builder
       |                       -> audit_reasoner
       |
       |-- FINISH_STAGE ---> stage_finalize
                                |-- HAS_NEXT_STAGE -> stage_scheduler
                                |-- ALL_FINISHED --> finding_merger
                                                       -> finding_assessor
                                                       -> fix_advisor
                                                       -> reporter
```

该工作流包含两个条件循环：

- 工具调用内循环：`audit_reasoner` 在证据不足时继续请求工具。
- 审计阶段外循环：`stage_finalize` 完成当前阶段后切换到下一个阶段。

### 8.2 生命周期阶段与风险阶段

系统生命周期分为：

```text
understanding -> planning -> auditing -> review -> reporting
```

真正的风险审计阶段包括：

- `secret`
- `injection`
- `command`
- `file`
- `auth`

Planner 根据项目画像动态生成阶段队列。没有上传模块时可以不创建 `file` 阶段，没有认证和路由模块时可以降低 `auth` 阶段优先级。

### 8.3 router

`router` 校验请求并选择模式：

- `repo_scan`：读取本地项目目录。
- `diff_scan`：读取用户提供的 unified diff，或在指定仓库中执行只读 Git diff。

### 8.4 input_loader

`input_loader` 负责准备扫描范围：

- repo_scan 生成仓库文件候选集合。
- diff_scan 解析 changed files、hunks、新旧行号和新增行。
- 有 `repo_path` 的 diff_scan 补充读取变更文件及必要配置。
- 只有 diff 文本时进入 `diff_only` 模式并记录缺失上下文。

该节点不做漏洞判断。

### 8.5 project_reader

`project_reader` 调用 Project Reader 生成 `ProjectProfile`。它回答“这是什么项目、哪些模块与安全相关”，不回答“项目中已经存在什么漏洞”。

### 8.6 vulnkb_retriever

`vulnkb_retriever` 根据 ProjectProfile 和用户任务返回相关 VulnKnowledge，为 Planner 提供危险模式、审计重点和能力建议。

### 8.7 audit_planner

`audit_planner` 是 LLM 第一次正式参与审计的节点。它读取：

- ProjectProfile
- VulnKnowledge
- 用户任务
- scan mode
- Tool Registry 的 capability 摘要

它输出 `AuditPlan` 和按优先级排列的 `AuditStagePlan`。Planner 只描述风险目标、目标文件、所需能力和证据目标，不输出 Finding，也不生成可执行命令。

未配置 LLM 时，系统根据 `risk_surfaces`、知识库命中和确定性映射生成模板化 AuditPlan。

### 8.8 stage_scheduler

`stage_scheduler` 从 `stage_queue` 选择当前阶段，初始化阶段预算、目标文件、已有证据和工具请求。

第一次进入阶段时，根据 `required_capabilities` 产生初始 ToolRequest。阶段结束后，该节点根据剩余队列切换到下一阶段。

### 8.9 tool_selector

`tool_selector` 接收初始 ToolRequest 或 Audit Reasoner 的补充 ToolRequest，完成工具匹配与安全校验，输出 ValidatedToolCall。

校验失败时不会直接终止整个审计：

- 有 fallback 时选择内置工具。
- 无 fallback 时生成 skipped ToolRunResult。
- 路径越界或非只读调用标记为 rejected，并写入安全 trace。

### 8.10 tool_executor

`tool_executor` 执行已校验调用并返回 ToolRunResult。初始调用通常负责广度扫描，补充调用通常负责局部上下文、调用关系或针对性规则验证。

### 8.11 evidence_builder

`evidence_builder` 位于首次工具执行之后、LLM 主动审计之前，负责解决 LLM 上下文来源问题。

它会：

- 将扫描器 finding 转换为候选 Evidence。
- 提取命中行附近的函数、类和 imports。
- 关联 diff 新增行和仓库原始行号。
- 合并 context_extractor 返回的调用关系。
- 对发送给 LLM 的代码和 Secret 值进行脱敏。
- 将证据加入 `evidence_pool`。

### 8.12 audit_reasoner

`audit_reasoner` 是 Agent 主动审计的核心节点。它只处理当前风险阶段，读取：

- 当前 AuditStagePlan
- ProjectProfile
- 相关 VulnKnowledge
- 已执行工具及其结果
- evidence_pool
- audit_hypotheses
- 剩余 AuditBudget

每轮返回一个 `AuditDecision`。

#### CALL_TOOL

当证据不足但存在明确取证方向时，生成新的 ToolRequest：

```text
audit_reasoner
  -> CALL_TOOL
  -> tool_selector
  -> tool_executor
  -> evidence_builder
  -> audit_reasoner
```

例如初始规则发现 repository 中存在 SQL 拼接，但尚不能确认参数来源，Audit Reasoner 可以请求 `extract_call_chain`，读取路由、service 和 repository 的局部调用关系。

#### EMIT_FINDING

当证据充分时，输出 FindingDraft 和引用的 evidence_ids：

```text
audit_reasoner
  -> EMIT_FINDING
  -> finding_builder
  -> candidate_findings
  -> audit_reasoner
```

生成一条 finding 后回到 Audit Reasoner，使其判断当前阶段是否还有其他风险或是否可以结束。

#### FINISH_STAGE

以下情况结束当前阶段：

- 已覆盖阶段内的证据目标。
- 没有发现足够证据。
- 没有新的有效工具调用方向。
- 达到阶段调用预算或耗时预算。
- 连续工具调用未产生新证据。

LangGraph 使用条件边路由：

```python
graph.add_conditional_edges(
    "audit_reasoner",
    route_audit_decision,
    {
        "call_tool": "tool_selector",
        "emit_finding": "finding_builder",
        "finish_stage": "stage_finalize",
    },
)
```

### 8.13 finding_builder

`finding_builder` 校验 LLM FindingDraft：

- 文件和行号必须存在于扫描范围内。
- evidence_ids 必须存在。
- 证据片段必须支持对应风险类型。
- Finding 不能只包含泛化安全建议。
- 相同阶段内的明显重复项不重复写入。

校验失败时只保留 AuditHypothesis，不产生 candidate finding。

### 8.14 stage_finalize

`stage_finalize` 汇总本阶段的：

- 工具调用和执行状态
- 新增 Evidence
- candidate findings
- 未验证假设
- fallback 和错误
- 调用次数、Token 和耗时

随后通过条件边决定：

```text
HAS_NEXT_STAGE -> stage_scheduler
ALL_FINISHED   -> finding_merger
```

### 8.15 finding_merger

`finding_merger` 合并以下来源：

- 内置规则扫描。
- Semgrep、Bandit 和 Gitleaks。
- Audit Reasoner 基于证据形成的 LLM finding。
- MCP Adapter 接入工具产生的 finding。

系统综合文件、行号、风险类型、规则、代码片段和数据流信息去重，并保留所有来源和 evidence_ids。

### 8.16 finding_assessor

`finding_assessor` 批量处理 merged findings，内部包含两个逻辑角色：

- Risk Analyzer：解释风险原因、攻击前提、影响范围、严重程度和置信度。
- False Positive Reviewer：检查参数化查询、权限校验、路径白名单、测试代码、不可达路径和框架保护机制。

输出结果为 `confirmed`、`dismissed` 或 `needs_review`。LLM 不可用时，系统通过确定性复核规则和模板分析降级，并记录 `analysis_source` 与 `fallback_reason`。

### 8.17 fix_advisor

`fix_advisor` 对 confirmed findings 批量生成修复建议，结合语言、框架和 Evidence 给出：

- 修复原则
- 推荐安全 API 或框架机制
- 安全代码示例
- 修复验证建议

系统不自动修改代码，也不自动提交 patch。

### 8.18 reporter

`reporter` 汇总 AuditState，生成：

- Markdown 完整报告。
- JSON 结构化报告。
- SARIF 标准结果。
- Agent trace。
- PR Comment 摘要数据。

## 9. 两种审计模式

### 9.1 repo_scan

输入示例：

```json
{
  "repo_path": "D:/project/demo-app",
  "user_task": "检查认证、SQL 注入和密钥泄露"
}
```

处理特点：

- Project Reader 读取完整文件树和必要源码。
- `profile_scope` 为 `full_repo`。
- Planner 可以围绕跨文件调用关系规划阶段。
- 工具默认扫描规划目标和必要的仓库范围。

### 9.2 diff_scan

直接传入 diff：

```json
{
  "diff_text": "diff --git a/app.py b/app.py\n..."
}
```

或者读取指定仓库的 Git diff：

```json
{
  "repo_path": "D:/project/demo-app",
  "diff_mode": "cached"
}
```

处理特点：

- 扫描重点始终是 changed files 和新增、修改行。
- 有 repo_path 时读取依赖文件和必要上下文，`profile_scope` 为 `diff_enriched`。
- 只有 diff 文本时，`profile_scope` 为 `diff_only`，并降低画像和跨文件结论置信度。
- Agent 不会因为缺失仓库上下文而虚构调用链。

diff finding 分为：

- `changed_line_finding`：风险直接位于新增或修改行。
- `context_related_finding`：风险点位于上下文，但被本次变更调用、触发或暴露。

报告必须说明 finding 与本次变更的关系，避免把仓库历史问题误报为 PR 新增问题。

## 10. LLM 参与方式

LLM 在四个位置参与：

### 10.1 审计规划

根据项目画像和漏洞知识生成 AuditPlan，确定优先风险阶段、目标文件、所需能力和证据目标。

### 10.2 主动取证

Audit Reasoner 根据当前证据决定是否继续调用工具。LLM 不扫描整个仓库，而是围绕当前阶段逐步缩小范围并补齐证据。

### 10.3 风险复核

批量分析 finding 的利用条件、严重程度、证据充分性和误报可能。

### 10.4 修复建议

根据语言、框架和代码上下文生成针对性建议。

LLM 不承担以下职责：

- 不直接执行扫描器命令。
- 不绕过 Tool Selector 访问文件。
- 不执行项目代码。
- 不自动利用漏洞。
- 不自动修改或提交代码。
- 不把没有 Evidence 的推测写入最终报告。

## 11. Fallback 与错误恢复

### 11.1 LLM fallback

出现以下情况时使用模板和规则降级：

- 未配置 API key。
- 请求超时或网络失败。
- LLM 返回无法解析的 JSON。
- Pydantic 结构校验失败。
- 输出引用不存在的文件或 Evidence。

每次 fallback 都记录节点、原因、替代策略和结果来源。

### 11.2 工具 fallback

- Semgrep 不可用 -> `custom_rule_scanner`。
- Bandit 不可用 -> Python 内置安全规则。
- Gitleaks 不可用 -> `secret_scanner`。
- context extractor 无法生成调用关系 -> 返回局部函数上下文并降低证据置信度。

### 11.3 节点错误

- 非关键工具失败不会中断其他阶段。
- Project Reader 或输入解析失败属于阻断错误，直接生成失败报告。
- 单阶段失败会记录 `partial` StageResult，并继续执行不依赖该阶段的其他阶段。
- Reporter 即使在部分失败时也生成可诊断报告。

## 12. 安全与隐私边界

### 12.1 被审计项目安全

系统只读取源码和 Git diff，不运行：

- 项目入口。
- 测试代码。
- 安装脚本。
- 构建脚本。
- 数据库迁移。
- 漏洞利用代码。

外部扫描器必须是只读静态分析工具，并通过固定适配器调用。

### 12.2 路径和命令安全

- 所有目标路径解析后必须位于 repo_path 内。
- 跳过软链接、二进制文件和超大文件。
- 不允许 LLM 提供 shell command。
- 外部工具参数通过适配器生成，不进行字符串命令拼接。
- 每个工具设置 timeout、输出限制和工作目录。

### 12.3 LLM 数据最小化

`PromptContextSanitizer` 在每次 LLM 调用前执行：

- 不发送 `.env`、私钥、证书和完整凭据文件。
- 对 secret finding 中的真实值进行掩码。
- 只发送当前阶段和当前证据目标相关的代码。
- 限制文件数、代码行数和总字符数。
- 保留文件路径、行号和 evidence_id，方便校验模型输出。

## 13. Agent Trace 与可观测性

每个节点记录：

```text
node_name
stage
started_at
duration_ms
input_summary
output_summary
decision
tool_calls
llm_used
token_usage
fallback_used
fallback_reason
error
```

关键 Agent 决策必须可追踪：

- Planner 为什么创建某个审计阶段。
- Selector 为什么选择或拒绝某个工具。
- Reasoner 为什么继续取证或结束阶段。
- Finding 引用了哪些 Evidence。
- Reviewer 为什么确认或排除风险。

基础指标包括：

- `detected_findings`
- `confirmed_findings`
- `dismissed_findings`
- `tool_call_count`
- `llm_call_count`
- `fallback_count`
- `total_tokens`
- `total_latency`
- `stage_coverage`

## 14. Streamlit 展示

Streamlit 页面按审计过程展示：

- 请求模式和扫描范围。
- ProjectProfile 项目画像及完整度。
- VulnKnowledge 命中与匹配原因。
- AuditPlan 和风险阶段队列。
- 当前阶段、阶段状态和预算使用。
- 工具选择理由与执行结果。
- Audit Reasoner 的条件决策和循环次数。
- Evidence 和风险列表。
- 误报复核和修复建议。
- fallback、错误和 Agent trace。
- Markdown、JSON 和 SARIF 报告。

界面明确区分：

- 扫描器直接发现的风险。
- LLM 基于证据补充的风险。
- 被复核排除的候选风险。
- 因上下文不足而保留的审计假设。

## 15. Demo 场景

### 15.1 Python 后端仓库

演示 FastAPI 或 Flask 项目中的硬编码 Secret、SQL 拼接、命令执行、不安全反序列化和路径穿越。系统展示完整项目画像、动态阶段规划、外部工具与内置规则结果，以及 LLM 对路由到数据库调用链的补充取证。

### 15.2 Java 后端仓库

演示 Spring Boot / MyBatis 项目中的 Mapper XML `${}` 拼接、`Runtime.exec` 和缺少权限控制。系统识别 Controller、Service、Mapper、Spring Security 配置，并规划 injection、command 和 auth 阶段。

### 15.3 Git diff

演示 PR 新增 SQL 拼接、命令执行或 Secret。系统只围绕变更行和必要上下文审计，并区分 `changed_line_finding` 与 `context_related_finding`。

### 15.4 外部工具降级

演示 Semgrep、Bandit 或 Gitleaks 可用时的执行结果，以及工具未安装时如何自动选择内置 fallback。报告和 trace 会明确展示实际调用了什么工具，而不是把规划能力描述成已经执行。

## 16. 设计总结

CodeAudit-Agent 的核心不是节点数量，而是三个闭环：

```text
理解闭环
  -> 项目画像 -> 漏洞知识 -> 审计计划

审计闭环
  -> 选择工具 -> 执行工具 -> 构建证据 -> LLM 决策 -> 继续取证或形成风险

质量闭环
  -> 合并去重 -> 风险分析 -> 误报复核 -> 修复建议 -> 可追踪报告
```

Project Reader 和知识库让 Agent 知道应该审计什么，Tool Registry 和统一执行网关让 Agent 知道可以安全使用什么能力，Audit Reasoner 的条件循环让 Agent 能根据证据主动决定下一步。多阶段调度、结构化状态、预算控制和 fallback 共同保证流程既具有 Agent 自主性，又能够稳定运行和清晰解释。
