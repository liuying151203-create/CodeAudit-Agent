# CodeAudit-Agent 项目说明书

CodeAudit-Agent 是一个面向源码安全审计和 Git diff 风险分析的 Agent 系统。系统读取本地项目源码或 Git diff，先形成项目画像，再结合漏洞知识库、工具注册表和 LLM 审计规划选择安全工具，最后完成扫描、补充审计、风险分析、误报复核、修复建议和报告生成。

系统当前支持 Python 后端项目审计，并对 Java Spring Boot / MyBatis 项目提供基础项目画像、规则识别和工具规划能力。后续可通过扩展语言识别规则、漏洞知识库标签和工具注册表继续支持 JavaScript、TypeScript、Go 等项目。

## 技术栈与集成能力

### 核心技术栈

- Python：实现 Agent、工具层、扫描规则和报告生成。
- LangGraph：编排多阶段审计工作流。
- LangChain Tools：抽象 ProjectReader、VulnKBRetriever、ToolSelector、ToolExecutor 等工具能力。
- FastAPI：提供 `repo_scan` 和 `diff_scan` API。
- Streamlit：展示项目画像、工具计划、审计结果、Agent trace 和报告。
- Pydantic：定义 `ProjectProfile`、`ToolPlan`、`Finding`、`Evidence`、`AuditReport` 等结构化数据模型。
- LLM API：用于审计规划、受控工具调用、风险分析、误报复核和修复建议。

### 当前核心集成

- 内置规则扫描：提供无外部依赖的基础风险识别能力。
- Semgrep / Bandit / Gitleaks：作为注册的只读扫描工具接入，外部工具不可用时降级到内置规则。
- Markdown / JSON 报告：输出本地可读和可机器解析的审计结果。
- Streamlit trace 展示：展示项目画像、工具计划、执行结果、finding 和 Agent trace。

### 扩展集成

- SARIF：作为标准静态分析报告格式，用于接入 GitHub Code Scanning 或安全平台。
- GitHub Action：作为 CI 集成入口，用于在 push、PR 或定时任务中触发审计流程。
- GitHub PR Comment：作为 PR 审计摘要回写能力，用于展示风险数量、关键 finding 和报告链接。
- MCP Adapter：作为工具协议扩展方向，将外部 MCP Tool Server 暴露的工具映射为项目内部 SecurityTool，再由 ToolExecutor 统一调用。

## 分层架构

CodeAudit-Agent 按职责拆分为七层。

```text
API / UI Layer
  -> Agent Orchestration Layer
  -> Project Understanding Layer
  -> Knowledge & Planning Layer
  -> Tool Execution Layer
  -> LLM Reasoning Layer
  -> Report & Integration Layer
```

### 1. API / UI Layer

这一层负责接收用户输入和展示审计结果。

- FastAPI 提供 `repo_scan`、`diff_scan` 接口。
- Streamlit 提供交互式页面，展示项目画像、工具选择理由、工具执行结果、finding、修复建议和审计报告。

### 2. Agent Orchestration Layer

这一层由 LangGraph 负责编排。

它不直接扫描漏洞，而是控制每个节点的执行顺序、状态传递和 trace 记录。

### 3. Project Understanding Layer

这一层负责静态理解项目。

核心组件是 `ProjectReaderTool`，它读取文件树和源码文本，识别语言、框架、依赖、入口、路由、认证、数据库访问和文件上传相关文件，输出 `ProjectProfile`。

### 4. Knowledge & Planning Layer

这一层负责把项目画像转换成审计计划。

- `VulnKBRetrieverTool` 根据项目画像检索漏洞知识库。
- `LLM Risk Planner` 根据项目画像、漏洞知识和工具能力生成审计重点。
- `ToolSelectorTool` 校验并合并 LLM 计划与确定性规则，输出最终 `ToolPlan`。

### 5. Tool Execution Layer

这一层负责安全执行工具。

所有工具都必须先注册到 Tool Registry，执行结果统一转换为 `ToolExecutionResult`。外部工具不可用时，系统降级到内置规则扫描。

### 6. LLM Reasoning Layer

这一层负责语义推理，不负责直接执行命令。

LLM 不直接负责扫描全仓库，而是分四类参与：

- 规划类：`risk_planner` 根据项目画像和漏洞知识库规划审计重点。
- 工具调度类：`llm_tool_calling_auditor` 提出受控工具调用，补充上下文或验证风险假设。
- 补充发现类：`llm_supplemental_auditor` 基于工具观察和源码上下文补充 finding。
- 分析复核类：`risk_analyzer`、`false_positive_reviewer`、`fix_advisor` 分别负责风险解释、误报复核和修复建议。

LLM 只能输出结构化计划、工具调用请求和分析结果，不能直接执行任意 shell，不能执行被审计项目代码，不能自动利用漏洞，不能自动修改用户代码。

### 7. Report & Integration Layer

这一层负责输出可消费的审计结果。

- Markdown / JSON 报告用于本地查看和归档。
- Agent trace 用于解释每个节点的输入、输出、耗时和 fallback 情况。
- SARIF、GitHub Action 和 PR Comment 作为工程集成格式和平台扩展能力。

## 全局数据对象

### ProjectProfile

`ProjectProfile` 是项目画像，用于回答“这是一个什么项目，风险面在哪里”。

字段包括：

- `languages`
- `frameworks`
- `dependency_files`
- `entrypoints`
- `route_files`
- `auth_files`
- `db_files`
- `upload_files`
- `risk_surfaces`

示例：

```json
{
  "languages": ["Python"],
  "frameworks": ["FastAPI", "SQLAlchemy"],
  "dependency_files": ["requirements.txt"],
  "entrypoints": ["main.py"],
  "route_files": ["api/users.py"],
  "auth_files": ["auth/jwt.py"],
  "db_files": ["db/session.py", "models/user.py"],
  "upload_files": ["api/upload.py"],
  "risk_surfaces": ["SQL Injection", "Secret Leak", "Broken Access Control"]
}
```

`ProjectReaderTool` 不产出漏洞 finding。它只负责项目理解，真正的漏洞发现发生在工具执行和 LLM 补充审计阶段。

### VulnKnowledge

`VulnKnowledge` 是漏洞知识库命中结果，用于回答“这个项目应该参考哪些漏洞知识进行审计”。

本地知识库位于：

```text
knowledge_base/
  sql_injection.md
  command_injection.md
  secret_leak.md
  path_traversal.md
  unsafe_deserialization.md
  broken_access_control.md
```

每个知识条目包含：

- 适用场景
- 危险代码模式
- 推荐检测工具
- 审计关注点
- 修复建议

### Tool Registry

Tool Registry 记录系统可以调用哪些工具、适合哪些语言和风险类型。

配置文件：

```text
config/security_tools.yaml
```

工具注册字段包括：

- `supported_languages`
- `risk_types`
- `supported_modes`
- `cost_level`
- `requires_install`
- `description`

ToolSelector / ToolExecutor 是全局工具网关。无论工具调用来自 `risk_planner` 的初始审计计划，还是来自 `llm_tool_calling_auditor` 的补充工具调用，都必须经过这两个组件：

```text
ToolSelector
  -> 校验工具是否注册
  -> 校验语言、风险类型和 scan mode 是否匹配
  -> 校验目标文件和只读权限
  -> 校验调用轮次、文件数量和上下文长度
  -> 校验 ToolInvocation JSON Schema
  -> 生成可执行 ToolPlan / ToolInvocation

ToolExecutor
  -> 统一执行工具
  -> 捕获 skipped / fallback / error
  -> 输出 ToolExecutionResult / ToolObservation
```

因此 LLM 节点只提出“想调用什么工具、为什么调用、目标文件是什么”，不会绕过工具注册表直接执行工具。

受控 Tool Calling 的工程限制：

- 补充工具调用默认最多执行 1-2 轮。
- 每轮最多请求 2 个工具调用。
- 每个工具调用最多读取 5 个文件。
- 单文件上下文最多提取 80 行。
- 每次调用必须绑定 `risk_type` 和 `reason`。
- `ToolInvocation` 只允许 JSON Schema 中定义的字段。
- 不允许传入任意 shell command，也不允许把 LLM 输出拼接进命令参数。

### Finding 与 Evidence

`Finding` 表示一个候选风险，`Evidence` 表示支撑 finding 的代码证据。

Finding 需要记录：

- 文件路径
- 行号
- 风险类型
- 严重等级
- 工具来源
- 证据片段
- 置信度

Evidence 需要记录：

- 前后代码上下文
- 所在函数或类
- imports
- 是否来自 diff 新增行
- 相关调用链片段

## Agent 工作流

### 总览

CodeAudit-Agent 的工作流按以下顺序执行：

```text
router
  -> loader
  -> project_reader
  -> vulnkb_retriever
  -> risk_planner
  -> tool_selector
  -> tool_executor
  -> llm_tool_calling_auditor
      -> tool_selector
      -> tool_executor
      -> ToolObservation
      -> llm_tool_calling_auditor / llm_supplemental_auditor
  -> llm_supplemental_auditor
  -> finding_merger
  -> context_extractor
  -> risk_analyzer
  -> false_positive_reviewer
  -> fix_advisor
  -> reporter
```

其中 `llm_tool_calling_auditor -> tool_selector -> tool_executor -> ToolObservation` 是受控 Tool Calling 循环。补充工具调用默认最多执行 1-2 轮，避免 Agent 无限循环、上下文膨胀和工具成本失控。

这个顺序体现了 Agent 的核心逻辑：

```text
先理解项目
  -> 再匹配漏洞知识
  -> 再规划审计重点和工具
  -> 再执行扫描
  -> 再让 LLM 基于结果补充审计和复核
```

### 1. router

`router` 根据用户输入决定审计模式：

- `repo_scan`：扫描本地仓库。
- `diff_scan`：扫描 Git diff 或用户传入的 diff 文本。

### 2. loader

`loader` 准备待审计内容。

在 `repo_scan` 中，系统读取本地仓库文件。  
在 `diff_scan` 中，系统读取 unified diff 或执行 Git diff，并解析 changed files、hunks 和新增行。

loader 只做输入准备，不做风险判断。

### 3. project_reader

`project_reader` 调用 `ProjectReaderTool` 生成项目画像。

读取流程：

```text
repo_path / diff files
  -> 遍历文件树
  -> 过滤 .git、.venv、node_modules、dist、build、target 等目录
  -> 保留源码和配置文件
  -> 读取文件名、路径、后缀和有限源码内容
  -> 输出 ProjectProfile
```

语言识别：

- `.py`、`requirements.txt`、`pyproject.toml` -> Python
- `.java`、`pom.xml`、`build.gradle` -> Java
- `package.json`、`.js`、`.ts` -> JavaScript / TypeScript 扩展方向
- `go.mod`、`.go` -> Go 扩展方向

框架识别：

- `fastapi`、`from fastapi import FastAPI` -> FastAPI
- `flask`、`from flask import` -> Flask
- `django`、`settings.py`、`urls.py` -> Django
- `spring-boot`、`@SpringBootApplication` -> Spring Boot
- `@RestController`、`@RequestMapping` -> Spring MVC
- `@Mapper`、`Mapper.xml` -> MyBatis

关键文件识别：

- 路由文件：路径或内容包含 `api`、`router`、`controller`、`@app.get`、`@RestController`。
- 认证文件：路径或内容包含 `auth`、`jwt`、`security`、`permission`、`login`。
- 数据库文件：路径或内容包含 `db`、`model`、`repository`、`mapper`、`dao`、`SQLAlchemy`、`JDBC`。
- 上传文件：路径或内容包含 `upload`、`file`、`multipart`、`UploadFile`、`MultipartFile`。

风险面推断：

- 有数据库访问文件 -> SQL Injection。
- 有认证和路由文件 -> Broken Access Control。
- 有上传文件 -> Path Traversal / File Upload。
- 出现 `os.system`、`subprocess`、`Runtime.exec` -> Command Injection。
- 出现 `password`、`api_key`、`secret`、`token` -> Secret Leak。
- 出现 `pickle.loads`、`yaml.load`、`readObject` -> Unsafe Deserialization。

这里的风险面是审计线索，不是漏洞结论。

### 4. vulnkb_retriever

`vulnkb_retriever` 调用 `VulnKBRetrieverTool`，根据 `ProjectProfile` 检索漏洞知识库。

检索流程：

```text
ProjectProfile + 用户任务
  -> 读取 knowledge_base/*.md
  -> 解析知识条目的 risk_types、languages、frameworks、keywords、tools
  -> 根据项目画像打分
  -> 返回 Top-K VulnKnowledge
```

打分规则：

- `risk_surfaces` 命中：高权重。
- `frameworks` 命中：中高权重。
- `languages` 命中：中权重。
- 用户任务关键词命中：中权重。
- 关键文件类型命中：低权重。

示例：

```text
ProjectProfile:
  languages = ["Python"]
  frameworks = ["FastAPI"]
  db_files = ["db/session.py"]
  risk_surfaces = ["SQL Injection"]

命中:
  sql_injection.md
```

知识库检索结果会影响 `risk_planner` 和 `tool_selector`：

- 命中 SQL Injection -> 优先考虑 Semgrep SQL 规则和自定义 SQL 规则。
- 命中 Secret Leak -> 优先考虑 secret_scanner 和 Gitleaks。
- 命中 Broken Access Control -> LLM 重点阅读路由、认证和权限相关代码。

LLM 可以作为可选 reranker 参与该阶段：先由确定性检索召回候选知识，再由 LLM 根据项目画像解释优先级。但事实匹配仍以结构化字段和规则打分为主。

### 5. risk_planner

`risk_planner` 是 LLM 正式参与审计规划的节点。它发生在第一次工具执行之前，负责回答“这个项目应该重点审计什么、先调用哪些工具”。

输入：

- `ProjectProfile`
- `VulnKnowledge`
- 用户任务
- Tool Registry 摘要
- scan mode

输出：

```json
{
  "priority_risk_types": ["SQL Injection", "Broken Access Control", "Secret Leak"],
  "recommended_tools": ["semgrep", "custom_rule_scanner", "secret_scanner"],
  "target_files": ["api/users.py", "db/session.py", "auth/jwt.py"],
  "reason": "项目存在 FastAPI 路由、认证和数据库访问，应优先检查输入到 SQL 和权限校验链路"
}
```

Risk Planner 不直接执行工具，也不产出 finding。它只产出 `RiskPlan`：

```text
RiskPlan
  -> priority_risk_types
  -> recommended_tools
  -> target_files
  -> planning_reason
```

`RiskPlan` 会交给全局 `tool_selector` 校验和转换，形成真正可执行的 `ToolPlan`。Risk Planner 只产生建议，不产生最终执行计划；ToolSelector 才是唯一生成可执行 `ToolPlan` 的组件。

### 6. tool_selector

`tool_selector` 调用 `ToolSelectorTool`，是全局工具校验和选择节点。它既处理 `risk_planner` 产生的初始 `RiskPlan`，也处理后续 `llm_tool_calling_auditor` 产生的补充 `ToolInvocation`。

处理逻辑：

- 校验推荐工具或补充工具调用是否存在于 Tool Registry。
- 校验工具是否支持当前语言。
- 校验工具是否支持 `repo_scan` 或 `diff_scan`。
- 校验目标文件是否位于被审计项目内。
- 校验工具是否为只读扫描或上下文提取工具。
- 合并确定性规则推荐的工具。
- 补充 fallback 工具，例如 `custom_rule_scanner` 和 `secret_scanner`。

ToolSelector 是 LLM 和工具执行之间的安全边界。LLM 节点只能提出计划或调用请求，不能直接执行工具。

### 7. tool_executor

`tool_executor` 调用 `ToolExecutorTool` 执行工具，是全局工具执行节点。所有工具执行都从这里进入，包括初始扫描和 LLM 后续补充调用。

工具分三类：

- 内置工具：`secret_scanner`、`custom_rule_scanner`、`context_extractor`。
- 外部工具：Semgrep、Bandit、Gitleaks。
- 扩展工具：后续可通过 MCP Adapter 接入外部 Tool Server。

执行原则：

- 不执行被审计项目代码。
- 不自动利用漏洞。
- 外部工具不可用时记录 skipped，并降级到内置规则。
- 初始扫描结果统一转换为 `ToolExecutionResult`。
- LLM 补充调用结果统一转换为 `ToolObservation`。

### 8. llm_tool_calling_auditor

`llm_tool_calling_auditor` 是扫描后的 LLM 主动审计调度节点。它发生在第一次 `tool_executor` 之后，负责回答“基于当前工具结果，还需要补充查什么”。

它读取：

- ProjectProfile
- VulnKnowledge
- ToolPlan
- ToolExecutionResult
- 已有 findings
- 源码上下文

它输出受控工具调用请求 `ToolInvocation`，再交给全局 `tool_selector` 校验，最后由 `tool_executor` 执行：

```text
llm_tool_calling_auditor
  -> ToolInvocation
  -> tool_selector 校验
  -> tool_executor 执行
  -> ToolObservation
```

```json
{
  "tool_name": "context_extractor",
  "reason": "SQL 拼接出现在 repository 层，需要查看 controller 到 service 的调用链",
  "target_files": ["api/users.py", "services/user_service.py", "repositories/user_repo.py"],
  "risk_types": ["SQL Injection"],
  "mode": "read_only"
}
```

`tool_selector` 会校验：

- 工具必须在 allowlist 或 Tool Registry 中。
- 目标文件必须位于被审计项目内。
- 工具必须是只读工具。
- 调用轮次、文件数量和上下文长度必须在限制内。

校验通过后，`tool_executor` 执行工具并返回 `ToolObservation`。LLM 再根据 observation 形成或更新 `AuditHypothesis`。

该节点的输出包括：

- `ToolInvocation`：下一步要调用的工具、目标文件、风险类型和调用原因。
- `ToolObservation`：系统执行工具后返回的上下文、证据或工具结果。
- `AuditHypothesis`：尚未形成 finding 的审计假设，例如“可能存在从路由到 SQL 拼接点的数据流”。

该节点不直接写入最终 finding 列表。它的作用是为后续 `llm_supplemental_auditor` 提供更充分的上下文、工具观察和审计假设。

### 9. llm_supplemental_auditor

`llm_supplemental_auditor` 是补充发现节点。它发生在补充工具调用之后，负责回答“这些工具观察和审计假设是否足以形成新的漏洞发现”。

它读取：

- `ProjectProfile`
- `VulnKnowledge`
- 初始 `ToolExecutionResult`
- 补充 `ToolObservation`
- `AuditHypothesis`
- 已有工具 findings
- 源码证据

它重点关注：

- 访问控制缺陷。
- 多层调用后的 SQL 注入。
- 文件上传缺少校验。
- 认证和路由之间的权限缺口。
- diff 新增代码引入的新风险。

它输出结构化 `Finding`，并且必须包含文件路径、行号、风险类型和证据片段。无法定位证据的泛泛建议不会进入最终 finding 列表。

LLM supplemental finding 必须引用 `ToolObservation` 或 `Evidence` 中的代码片段，否则只能保留为 `AuditHypothesis`，不能进入最终报告。

它不再调用工具。如果发现证据不足，只能输出“无法形成 finding”的结论；需要更多上下文时，应回到 `llm_tool_calling_auditor` 产生新的 `ToolInvocation`，再走 `tool_selector -> tool_executor`。

两者的职责边界是：

```text
llm_tool_calling_auditor
  -> 过程控制
  -> 提出工具调用
  -> 走 tool_selector / tool_executor
  -> 形成审计假设
  -> 不产出最终 finding

llm_supplemental_auditor
  -> 风险判定
  -> 消费工具观察和审计假设
  -> 不再调用工具
  -> 产出 LLM supplemental finding
```

这样报告中的 trace 能解释清楚：LLM 为什么要多看某些文件、工具实际返回了什么、最终 finding 是基于哪些证据形成的。

### 10. finding_merger

`finding_merger` 合并以下来源的 finding：

- 内置规则扫描。
- Semgrep / Bandit / Gitleaks。
- LLM supplemental finding。
- MCP Adapter 等扩展工具产生的 finding 会在接入后按同一规则合并。

合并时按文件、行号、规则、证据片段和风险类型去重。

### 11. context_extractor

`context_extractor` 在两个阶段复用。

第一类是补充审计阶段的 PreContextExtractor：为 `llm_tool_calling_auditor` 和 `llm_supplemental_auditor` 提供候选上下文，例如目标文件片段、函数上下文和局部调用链。

第二类是最终报告阶段的 PostContextExtractor：在 finding 合并后，为最终 finding 生成标准 `Evidence`。

输出包括：

- 前后代码上下文。
- 所在函数或类。
- imports。
- 是否来自 diff 新增行。
- 相关调用链片段。

这些证据会提供给后续 LLM 分析和报告生成。

### 12. risk_analyzer

`risk_analyzer` 使用 LLM 分析每个 finding 的风险。

它回答：

- 为什么危险？
- 可能如何被利用？
- 当前上下文下严重程度如何？
- 证据是否足够？
- 置信度是多少？

输出会记录 `analysis_source` 和 fallback 状态。

### 13. false_positive_reviewer

`false_positive_reviewer` 使用 LLM 复核误报。

它检查：

- 是否为测试代码或示例代码。
- 是否存在参数化查询。
- 是否存在权限校验。
- 是否存在路径白名单。
- scanner 命中是否缺少真实可达性。

输出包括是否误报、复核原因和最终严重等级。

### 14. fix_advisor

`fix_advisor` 使用 LLM 生成修复建议。

建议会结合框架和代码上下文，例如：

- FastAPI 权限依赖。
- Spring Security 注解。
- 参数化 SQL。
- 文件路径白名单。
- secret 改为环境变量或密钥管理服务。

系统只生成修复建议，不自动修改代码。

### 15. reporter

`reporter` 汇总所有结构化结果，输出：

- Markdown 报告。
- JSON 报告。
- Agent trace。
- SARIF 和 PR comment 摘要作为集成格式生成或扩展能力，不作为核心报告输出强依赖。

## 审计模式

### repo_scan

`repo_scan` 输入本地项目路径：

```json
{
  "repo_path": "D:/project/demo-app"
}
```

系统会读取整个项目，生成项目画像，并对仓库进行完整审计。

### diff_scan

`diff_scan` 支持直接传入 diff 文本：

```json
{
  "diff_text": "diff --git a/app.py b/app.py\n..."
}
```

也支持传入仓库路径和 diff 模式：

```json
{
  "repo_path": "D:/project/demo-app",
  "diff_mode": "cached"
}
```

diff_scan 的重点是变更代码。ProjectReader 会优先基于 changed files 生成局部项目画像，并补充读取必要的配置文件、入口文件和相关上下文。

diff_scan 中 finding 分为两类：

- `changed_line_finding`：风险直接出现在新增或修改行。
- `context_related_finding`：风险位于上下文代码中，但被本次变更触发、调用或暴露。

例如旧代码中已有危险函数，但本次 diff 新增代码调用了它，系统会标记为 `context_related_finding`，而不是 `changed_line_finding`。

## UI 展示

Streamlit 页面展示：

- ProjectProfile 项目画像。
- 命中的漏洞知识库条目。
- Risk Planner 的审计重点。
- ToolPlan 工具选择理由。
- ToolExecutionResult 工具执行结果。
- Finding 风险列表。
- Evidence 代码证据。
- 误报复核结果。
- 修复建议。
- Agent trace。
- Markdown / JSON 报告。
- SARIF 作为扩展报告格式展示。

## 安全边界

系统不做：

- 不执行被审计项目代码。
- 不自动利用漏洞。
- 不自动修改用户代码。
- 不自动提交 patch。
- 不让 LLM 直接执行任意 shell。
- 不把 LLM 输出拼接进 shell command。

系统允许：

- 读取源码文本。
- 读取 Git diff。
- 执行注册过的只读安全扫描工具。
- 调用 LLM 生成结构化审计计划和分析结果。
- 输出报告和修复建议。

外部工具执行限制：

- 外部扫描工具只允许通过 ToolExecutor 调用固定命令模板。
- 工具执行目录限制在 `repo_path` 内。
- 工具执行必须设置 timeout。
- 跳过软链接、超大文件、二进制文件和敏感目录。
- 所有工具输出按 schema 解析，解析失败则标记为 `tool_error`，不会进入最终 finding。

## Demo 与评估

### Python 后端项目

`sample_python_app` 包含 hardcoded secret、SQL 拼接、`os.system`、`pickle.load`、路径穿越等风险。系统识别 FastAPI、SQLAlchemy、路由文件、认证文件和数据库访问文件，命中 SQL Injection、Secret Leak、Broken Access Control 知识条目，并由 LLM 补充检查路由到数据库访问的风险链路。

### Java 后端项目

Java 后端场景用于演示 Spring Boot / MyBatis 项目画像和工具规划能力。系统识别 Controller、Service、Mapper、MyBatis XML 和 Spring Security 配置，并将 MyBatis `${}` 拼接、`Runtime.exec`、缺少权限注解等风险作为知识库和工具规划重点。

### Git diff 审计

`sample.diff` 用于模拟 PR 新增风险。系统解析 changed files、hunks 和新增行，只围绕本次变更生成局部项目画像、匹配漏洞知识、选择工具和执行审计。报告会区分 `changed_line_finding` 和 `context_related_finding`。

### 评估指标

Demo 报告记录以下基础指标。当前演示样例以 `data/sample_repos/small_python_app` 和 `data/sample_repos/sample.diff` 为主，Java 场景用于验证项目画像和工具规划链路。

- `detected_findings`：工具和 LLM 发现的候选风险数量。
- `confirmed_findings`：误报复核后保留的风险数量。
- `false_positive_count`：被复核为误报的数量。
- `tool_call_count`：工具调用次数。
- `llm_call_count`：LLM 调用次数。
- `total_latency`：完整审计耗时。
