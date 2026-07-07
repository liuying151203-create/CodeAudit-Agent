# CodeAudit-Agent 项目说明书

CodeAudit-Agent 是一个面向源码安全审计和 Git diff 变更审计的 Agent 系统。系统能够读取本地项目源码，理解项目结构，识别语言、框架、依赖和风险面，结合漏洞知识库选择安全工具，对代码进行多阶段审计，并输出可解释的 Markdown / JSON 报告。

系统支持两类核心任务：

- `repo_scan`：扫描一个本地源码项目。
- `diff_scan`：扫描一段 Git diff 或仓库中的 Git 变更。

当前主要面向 Python 项目，同时也能对一般 Java 后端项目做项目画像、风险面识别、漏洞知识库匹配和工具计划生成。对于 Java 项目，系统会识别 Spring Controller、Mapper、XML、数据库访问、认证和路由相关文件，并将 Semgrep、自定义规则和 LLM 审计作为主要扩展路径。

## 系统能力总览

CodeAudit-Agent 的审计流程不是直接把源码发给 LLM，而是由 Agent 组织多个阶段：

```text
项目输入
  -> 项目画像
  -> 风险面识别
  -> 漏洞知识库检索
  -> 安全工具选择
  -> 工具扫描
  -> LLM 补充审计
  -> Finding 合并
  -> 证据提取
  -> 风险分析
  -> 误报复核
  -> 修复建议
  -> 报告生成
```

系统在每个阶段都会记录 trace，因此最终报告不仅展示发现了什么问题，也展示 Agent 是如何理解项目、为什么选择这些工具、哪些工具执行成功、哪些工具 fallback，以及 LLM 在哪些环节参与了判断。

除扫描和报告能力外，系统还提供标准化集成能力：

- SARIF 输出：将 finding 转换为通用静态分析报告格式，便于接入 GitHub Code Scanning、代码质量平台或企业安全看板。
- GitHub Action：在 PR、push 或定时任务中触发 `repo_scan` / `diff_scan`，把审计流程放进 CI。
- GitHub PR comment：将本次变更中的高风险 finding、误报复核结论和报告链接回写到 PR 讨论区。
- Semgrep 官方规则集：在本地可用时加载社区和官方规则，覆盖更多语言和框架风险。
- Gitleaks：作为专业 secret 扫描器接入工具注册表，和内置 secret scanner 形成双层检测。
- MCP Tool Server：通过统一工具协议接入外部扫描器、代码索引服务、漏洞知识库和企业内部安全平台。
- 向量化漏洞知识库：对漏洞文档、规则说明和历史案例做语义检索，而不是只依赖关键词匹配。
- 多语言项目画像：对 Python、Java、JavaScript、Go 后端项目识别入口、路由、依赖、数据库、认证和文件上传相关代码。

## 支持的审计模式

### repo_scan

`repo_scan` 输入一个本地项目路径：

```json
{
  "repo_path": "D:/project/demo-app"
}
```

系统会读取项目结构和源码文本，生成完整项目画像。

对 Python 项目，系统重点识别：

- `requirements.txt`
- `pyproject.toml`
- `app.py`
- `main.py`
- FastAPI / Flask / Django 相关代码
- 路由文件
- 数据库访问文件
- 认证相关文件
- 文件上传和文件读取逻辑

对 Java 后端项目，系统重点识别：

- `pom.xml`
- `build.gradle`
- Spring Boot 启动类
- Controller
- Service
- Repository / Mapper
- MyBatis XML
- Spring Security 配置
- 文件上传接口

repo_scan 的输出包括：

- 项目画像
- 命中的漏洞知识库
- 工具选择计划
- 工具执行结果
- 候选 finding
- LLM 分析和复核结果
- 修复建议
- Markdown / JSON 报告

### diff_scan

`diff_scan` 支持两种输入方式。

第一种是直接传入 unified diff：

```json
{
  "diff_text": "diff --git a/app.py b/app.py\n..."
}
```

第二种是传入仓库路径，让系统读取 Git diff：

```json
{
  "repo_path": "D:/project/demo-app",
  "diff_mode": "cached"
}
```

如果传入 `diff_text`，系统只解析这段 diff 文本，不执行 Git 命令。  
如果没有传入 `diff_text`，但传入了 `repo_path`，系统会根据 `diff_mode` 执行 Git diff。

diff_scan 的重点是只检查本次变更涉及的代码。系统会解析：

- changed files
- hunks
- 新增代码行
- 变更后的局部代码片段

下游的项目画像、工具选择、扫描、LLM 审计和报告生成都围绕这些变更内容展开。

## 项目画像 ProjectProfile

项目画像是 Agent 做下游决策的基础。Project Reader 会读取项目目录和源码文本，输出 `ProjectProfile`。

`ProjectReaderTool` 不执行被审计项目代码，也不产出漏洞 finding。它只做静态项目理解：识别项目结构、技术栈、关键文件和潜在风险面。真正的漏洞发现发生在 `tool_executor`、`llm_tool_calling_auditor` 和 `llm_supplemental_auditor` 阶段。

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
  "risk_surfaces": [
    "Secrets",
    "SQL Injection",
    "Command Execution",
    "Path Traversal",
    "Broken Access Control"
  ]
}
```

项目画像的作用：

- 决定需要关注哪些漏洞类型。
- 决定检索哪些漏洞知识。
- 决定选择哪些安全工具。
- 决定 LLM 应该重点阅读哪些文件。
- 决定报告中如何解释项目风险面。

## 漏洞知识库 VulnKB

系统内置本地漏洞知识库：

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

Agent 会根据 `ProjectProfile.risk_surfaces` 和用户任务检索相关知识。例如：

```text
项目存在 db_files
  -> 命中 SQL Injection 知识
  -> ToolSelector 优先考虑 SQL 相关规则和 Semgrep
  -> LLM 审计时关注 SQL 拼接、ORM 原生查询、Mapper XML 等风险
```

```text
项目存在 upload_files
  -> 命中 Path Traversal 知识
  -> ToolSelector 选择路径相关规则
  -> LLM 审计时检查文件名清洗和目录限制
```

知识库不只是文档说明，它参与 Agent 的审计计划和工具选择。

## 工具注册和扩展

工具注册表位于：

```text
config/security_tools.yaml
```

每个工具声明：

- `supported_languages`
- `risk_types`
- `supported_modes`
- `cost_level`
- `requires_install`
- `description`

系统通过 `ToolSelectorTool` 读取注册表，并根据项目画像、漏洞知识库命中内容和 LLM 审计规划选择工具。

工具选择分为两层：

```text
LLM Risk Planner
  -> 根据 ProjectProfile、VulnKnowledge、用户任务提出审计重点和候选工具

ToolSelectorTool
  -> 根据 Tool Registry 校验工具能力
  -> 合并 LLM 建议和确定性规则
  -> 补充必要 fallback 工具
  -> 输出最终 ToolPlan
```

这样设计的原因是：

- LLM 负责判断“这个项目最应该查什么”，例如 FastAPI + db_files 优先查 SQL 注入和访问控制，Spring Controller + Mapper XML 优先查 SQL 拼接和越权。
- ToolSelector 负责判断“这些工具能不能安全、可控地执行”，避免 LLM 直接调用任意命令。
- 内置规则始终作为 fallback，保证没有外部工具或 LLM 调用失败时仍然可以跑通审计。

### 当前内置和注册的工具

#### secret_scanner

用途：

- 检测 hardcoded password、token、api_key、private_key、secret 等。

特点：

- 不依赖外部安装。
- 支持 repo_scan 和 diff_scan。
- 适合作为稳定 fallback。

#### custom_rule_scanner

用途：

- 执行项目内置 Python 安全规则。

覆盖：

- Secrets 泄露
- SQL 字符串拼接
- 命令执行
- 路径穿越
- 不安全反序列化
- Python 危险函数

特点：

- 不依赖外部安装。
- 是当前 demo 的基础扫描能力。

#### bandit

用途：

- Python 安全扫描。
- 检测危险 API、命令执行、不安全反序列化等问题。

接入方式：

```text
bandit -r <repo_path> -f json
```

如果环境中未安装 Bandit，系统会记录 skipped，并继续使用内置规则。

#### semgrep

用途：

- 多语言规则扫描。
- Python 和 Java 后端项目都可以通过 Semgrep 扩展规则覆盖。

接入方式：

```text
semgrep scan --json --config <ruleset> <target>
```

在 Python 项目中可用于补充 SQL 注入、命令注入、路径穿越等规则。  
在 Java Spring 项目中可用于 Controller、Mapper、权限校验、SQL 拼接等风险检测。

如果环境中未安装 Semgrep，系统会记录 skipped，并继续使用内置规则。

#### context_extractor

用途：

- 为每个 finding 提取源码上下文。

输出包括：

- 前后若干行代码
- 所在函数
- imports
- 是否来自 diff 新增行

这些上下文会提供给 LLM。

### 外部工具扩展方式

新增外部工具时，只需要补三部分：

1. 在 `config/security_tools.yaml` 注册工具能力。
2. 在工具执行层实现 runner。
3. 将工具输出归一化为 `Finding`。

推荐所有外部工具都统一输出：

```python
ToolExecutionResult(
    tool_name="semgrep",
    status="success",
    findings=[...],
    output_summary="...",
    skipped_reason=None,
)
```

这样报告和 UI 不需要关心工具来源差异。

## LLM 如何参与审计

LLM 在 CodeAudit-Agent 中不是简单地“读一遍代码并给建议”，而是作为受控工具调用审计者参与流程。它可以基于项目画像、漏洞知识库和已有扫描结果决定下一步要补充查看哪些代码、调用哪些只读工具、验证哪些风险假设。真正的工具执行由系统完成，LLM 只负责提出结构化审计动作并解释观察结果。

### 1. LLM Risk Planner

Risk Planner 位于 `project_reader` 和 `tool_selector` 之间。它不是漏洞扫描器，而是审计计划生成器。

它接收：

- `ProjectProfile`
- `VulnKnowledge`
- 用户任务
- Tool Registry 中的工具能力摘要
- scan mode

它输出结构化审计计划：

```json
{
  "priority_risk_types": ["sql_injection", "broken_access_control", "secret_leak"],
  "recommended_tools": ["secret_scanner", "semgrep", "custom_rule_scanner", "context_extractor"],
  "target_files": ["app/api/user.py", "app/services/user_service.py", "app/repositories/user_repo.py"],
  "reason": "项目是 FastAPI 后端，存在路由、认证和数据库访问文件，应优先审计用户输入到 SQL 和权限校验链路"
}
```

`ToolSelectorTool` 会校验这个计划：

- 推荐工具必须在 Tool Registry 中。
- 工具必须支持当前语言和扫描模式。
- 目标文件必须来自 ProjectProfile 或 diff。
- 如果 LLM 没有推荐基础扫描工具，系统会补充 `custom_rule_scanner` 和 `secret_scanner`。

因此设计版里的工具选择不是纯静态规则，也不是 LLM 直接执行工具，而是：

```text
LLM 根据项目画像和漏洞知识库提出审计计划
  -> ToolSelector 校验、合并和补 fallback
  -> ToolExecutor 安全执行
```

### 2. Tool-Calling Auditor

Tool-Calling Auditor 是 Agent 主动审计能力的核心。

它接收：

- `ProjectProfile`：语言、框架、入口、路由、认证、数据库、上传相关文件。
- `VulnKnowledge`：与当前项目匹配的漏洞知识库条目。
- `ToolPlan`：ToolSelector 选出的初始工具计划。
- `ToolExecutionResult`：已执行工具的结果、跳过原因、fallback 情况。
- `Evidence`：finding 周边代码、函数、imports、diff 新增行标记。
- 用户任务：例如 repo_scan、diff_scan、重点关注 SQL 注入或 secret 泄露。

它输出结构化的 `ToolInvocation`，例如：

```json
{
  "tool_name": "context_extractor",
  "reason": "SQL 拼接发生在 service 层，需要补充查看 controller 到 service 的调用链",
  "target_files": ["app/api/user_controller.py", "app/services/user_service.py"],
  "risk_types": ["sql_injection"],
  "mode": "read_only"
}
```

系统收到 `ToolInvocation` 后会做校验：

- 工具必须存在于 `config/security_tools.yaml` 或内置 allowlist。
- 工具必须支持当前语言和 `repo_scan` / `diff_scan` 模式。
- 目标文件必须位于被审计项目目录内。
- 工具只能做只读扫描、上下文抽取或知识库检索。
- 调用轮次、文件数量和上下文长度有上限。
- 不允许任意 shell、不允许执行被审计项目代码、不允许修改代码、不允许自动利用漏洞。

校验通过后，`ToolExecutor` 执行工具并返回 `ToolObservation`：

```json
{
  "tool_name": "context_extractor",
  "status": "success",
  "summary": "提取到 controller -> service -> repository 的调用链片段",
  "findings": [],
  "evidence": [
    {
      "file_path": "app/services/user_service.py",
      "line_start": 18,
      "line_end": 26,
      "code_context": "query = \"select * from users where name = '\" + name + \"'\""
    }
  ]
}
```

LLM 基于 observation 再决定下一步：

```text
审计假设 -> 调用工具 -> 观察结果 -> 缩小范围 -> 生成 finding 或放弃假设
```

这个闭环让 LLM 不只是解释 scanner 的结果，而是可以主动提出“我需要再看这个文件”“我需要用 Semgrep 规则验证这个风险”“我需要补充提取路由和数据库访问之间的上下文”。它体现的是 Agent 的决策能力，执行仍然是受控的工程流程。

Tool-Calling Auditor 和 Risk Planner 的区别是：

- Risk Planner 发生在初始扫描前，负责制定第一版审计计划和工具候选。
- Tool-Calling Auditor 发生在初始扫描后，负责根据工具结果、源码上下文和未验证假设继续提出补充工具调用。

### 3. LLM Supplemental Auditor

Supplemental Auditor 负责补充工具可能漏掉的问题。

它关注静态规则不容易完整判断的风险：

- 访问控制缺陷。
- 框架路由缺少权限校验。
- 业务对象 ID 未做所有权校验。
- 文件上传缺少类型、大小、扩展名和路径限制。
- SQL 查询在 controller、service、repository 多层传递后才出现风险。
- diff 新增代码引入了新的危险数据流。

输出是结构化 `Finding`：

```json
{
  "rule_id": "LLM_SUPPLEMENTAL_BROKEN_ACCESS_CONTROL",
  "file_path": "api/users.py",
  "line_start": 32,
  "line_end": 38,
  "severity": "medium",
  "category": "Broken Access Control",
  "message": "用户可通过传入任意 user_id 访问他人数据",
  "evidence_text": "user = get_user(user_id)",
  "source": "llm_supplemental"
}
```

LLM finding 必须经过 schema 校验。无法定位文件、行号、证据片段和风险类型的泛泛建议不会进入最终 finding 列表。

Tool-Calling Auditor 和 Supplemental Auditor 的区别是：

- Tool-Calling Auditor 关注“下一步还要调用什么工具、读取什么上下文、验证什么假设”。
- Supplemental Auditor 关注“基于已有观察结果，是否要产出新的 LLM finding”。

也就是说，Tool-Calling Auditor 是过程控制角色，Supplemental Auditor 是 finding 生产角色。二者可以由同一个 LLM 调用实现，但在报告和 trace 中应分开记录。

### 4. Risk Analyzer

Risk Analyzer 对所有 finding 做风险解释，包括内置规则、外部工具和 LLM supplemental finding。

输入：

- finding
- evidence
- code_context
- function_name
- imports
- changed_line
- tool_observations

输出：

- 风险类型
- 风险原因
- 攻击场景
- 置信度
- 严重等级
- `analysis_source`
- 是否 fallback

它回答的问题是：

```text
这个 finding 为什么危险？
攻击者如何利用？
在当前上下文中严重程度如何？
工具证据是否足够支持这个结论？
```

### 5. False Positive Reviewer

False Positive Reviewer 负责复核误报。

它结合：

- 静态规则命中原因。
- 外部工具输出。
- LLM 主动补充的上下文。
- 是否为测试代码、示例代码或 placeholder。
- 是否存在参数化查询、权限校验、路径归一化、白名单校验等保护逻辑。

输出：

- `is_false_positive`
- `reason`
- `final_severity`
- `confidence`

### 6. Fix Advisor

Fix Advisor 负责生成修复建议。

它结合当前代码上下文给出：

- 修复建议。
- 安全代码示例。
- patch hint。
- 框架相关修复方式，例如 FastAPI 依赖注入权限校验、Spring Security 注解、参数化 SQL、路径白名单等。

系统不会自动修改用户代码，只提供建议。

### 7. 受控工具调用的审计轮次

LLM 工具调用不是无限循环，而是有明确阶段和边界：

```text
初始工具计划
  -> 执行内置 / 外部工具
  -> LLM 读取结果和项目画像
  -> LLM 提出补充工具调用
  -> 系统校验并执行
  -> LLM 根据 observation 生成或放弃 finding
  -> 进入误报复核和修复建议
```

典型轮次：

1. ToolSelector 发现 Python + FastAPI + database files，选择 `secret_scanner`、`custom_rule_scanner`、`bandit`、`semgrep`。
2. ToolExecutor 运行可用工具，未安装的工具记录 skipped，内置规则继续执行。
3. LLM 发现 SQL finding 的证据只在 repository 层，调用 `context_extractor` 查看 controller 和 service。
4. 系统返回调用链上下文。
5. LLM 判断用户输入可到达 SQL 拼接位置，生成更完整的 finding，并降低缺少可达性的 finding 置信度。
6. False Positive Reviewer 再检查是否存在参数化查询或白名单保护。
7. Fix Advisor 输出对应框架的修复建议。

## LLM 的安全约束

LLM 调用必须遵守：

- 不执行被审计项目代码。
- 不自动利用漏洞。
- 不自动修改代码。
- 不直接执行任意 shell 命令。
- 只能请求 allowlist 中的只读工具。
- 每次工具请求必须包含目标、原因、风险类型和预期产出。
- 工具调用由系统校验和执行，LLM 不能绕过 `ToolExecutor`。
- 不能编造不存在的文件和行号。
- 输出必须经过结构化校验。
- 调用失败时 fallback 到模板或跳过该阶段。

报告中会记录：

- `analysis_source`
- `fallback_reasons`
- LLM 是否参与
- 哪些 finding 来自 LLM supplemental
- LLM 请求过哪些工具
- 哪些工具调用被允许、跳过或 fallback

## Finding 生命周期

Finding 的生命周期如下：

```text
工具扫描 / LLM 补充
  -> Finding
  -> FindingMerger
  -> EvidenceExtractor
  -> RiskAnalyzer
  -> FalsePositiveReviewer
  -> FixAdvisor
  -> Report
```

Finding 来源包括：

- `builtin`
- `secret_scanner`
- `bandit`
- `semgrep`
- `gitleaks`
- `llm_supplemental`

Finding 合并后，系统会统一做上下文提取、风险分析、误报复核和修复建议。

## Agent 工作流

### 节点、工具和 LLM 角色对应关系

| 工作流节点 | 主要工具 | 是否使用 LLM | 作用 |
| --- | --- | --- | --- |
| `router` | - | 否 | 判断 `repo_scan` 或 `diff_scan`。 |
| `repo_loader` / `diff_loader` | `RepoLoaderTool` / `GitDiffTool` | 否 | 准备待审计源码或 diff。 |
| `project_reader` | `ProjectReaderTool` | 否 | 静态读取项目结构，生成项目画像，不做漏洞判断。 |
| `vulnkb_retriever` | `VulnKBRetrieverTool` | 可选 | 根据项目画像检索漏洞知识库，可用 LLM rerank。 |
| `risk_planner` | `LLMRiskPlanner` | 是 | 根据项目画像和漏洞知识库提出审计重点、候选工具和目标文件。 |
| `tool_selector` | `ToolSelectorTool` | 可选 | 校验 LLM 计划，合并确定性规则，输出最终 `ToolPlan`。 |
| `tool_executor` | `ToolExecutorTool` | 否 | 执行内置工具和注册外部工具，产出原始 findings。 |
| `llm_tool_calling_auditor` | `ToolExecutorTool` + allowlist 工具 | 是 | 根据初始扫描结果继续提出受控工具调用。 |
| `llm_supplemental_auditor` | LLM structured output | 是 | 基于工具观察和源码上下文补充 LLM finding。 |
| `finding_merger` | `FindingMergerTool` | 否 | 合并内置工具、外部工具和 LLM finding。 |
| `context_extractor` | `ContextExtractorTool` | 否 | 为 finding 提取源码上下文和证据。 |
| `risk_analyzer` | `RiskAnalyzeTool` | 是 | 解释风险原因、攻击场景、严重程度和置信度。 |
| `false_positive_reviewer` | `FalsePositiveReviewTool` | 是 | 判断是否误报，调整最终严重等级。 |
| `fix_advisor` | `FixSuggestTool` | 是 | 生成框架相关修复建议和 patch hint。 |
| `reporter` | `ReportWriterTool` | 否 | 输出 Markdown、JSON、SARIF、trace 和 PR comment 摘要。 |

这张表里最关键的边界是：`project_reader` 只是静态项目理解，`risk_planner` 才是 LLM 根据项目画像参与工具规划；`tool_executor` 只负责执行工具，`llm_tool_calling_auditor` 才负责根据结果提出补充调用。

### repo_scan

```text
scan_repo API
  -> router
  -> project_reader
  -> vulnkb_retriever
  -> risk_planner
  -> tool_selector
  -> tool_executor
      -> builtin rules
      -> secret scanner
      -> bandit
      -> semgrep
  -> llm_tool_calling_auditor
  -> llm_supplemental_auditor
  -> finding_merger
  -> context_extractor
  -> risk_analyzer
  -> false_positive_reviewer
  -> fix_advisor
  -> reporter
```

### diff_scan

```text
scan_diff API
  -> router
  -> diff_loader
  -> project_reader
  -> vulnkb_retriever
  -> risk_planner
  -> tool_selector
  -> diff_tool_executor
      -> builtin rules on changed lines
      -> semgrep on changed files
  -> llm_tool_calling_auditor on diff context
  -> llm_supplemental_auditor on diff context
  -> finding_merger
  -> context_extractor
  -> risk_analyzer
  -> false_positive_reviewer
  -> fix_advisor
  -> reporter
```

## UI 展示

Streamlit 页面展示完整审计过程，而不是只展示最终 finding。

页面分为：

### 1. Project Profile

展示项目画像：

- 语言
- 框架
- 依赖文件
- 入口文件
- 路由文件
- 认证文件
- DB 文件
- 上传文件
- 风险面

### 2. Agent Plan

展示 Agent 审计计划：

- 命中的漏洞知识库
- 选择的工具
- 选择理由
- 目标文件
- 关注风险类型

### 3. Tool Execution

展示工具执行情况：

- executed
- skipped
- fallback
- finding 数量
- skipped reason

### 4. Findings

展示所有风险：

- 来源
- 严重等级
- 文件和行号
- 证据
- 风险解释
- 是否误报

### 5. Fix & Report

展示：

- 修复建议
- 安全代码示例
- Markdown 报告
- JSON 报告路径

### 6. Trace

展示每个节点：

- node_name
- tool_name
- input_summary
- output_summary
- elapsed_ms
- status

## Demo 场景

### Demo 1：Python 小项目

样例项目：

```text
data/sample_repos/small_python_app
```

演示点：

- 识别 Python 项目。
- 识别 DB、命令执行、文件操作、反序列化风险面。
- 选择内置规则、secret scanner、Bandit、Semgrep。
- 外部工具未安装时显示 skipped。
- 内置规则发现典型风险。
- LLM 对重点源码进行补充审计和风险解释。
- 报告展示 finding 来源和 trace。

### Demo 2：Java 后端项目

输入一个简单 Spring Boot 项目。

演示点：

- 识别 Java、Spring、Controller、Mapper、XML、认证配置。
- 识别 SQL Injection、Broken Access Control、Secrets 风险面。
- ToolPlan 选择 Semgrep、自定义规则、LLM supplemental。
- 如果 Java 专用规则未完全实现，报告中明确展示 planned / skipped / fallback。

### Demo 3：Git diff

输入：

```text
data/sample_repos/sample.diff
```

演示点：

- 解析 changed files。
- 只扫描新增代码。
- 生成局部项目画像。
- 只选择支持 diff_scan 的工具。
- LLM 只阅读 diff 上下文。
- 报告标识 finding 来自变更代码。

## 当前边界

系统不做：

- 执行被审计项目代码。
- 自动利用漏洞。
- 自动修改用户代码。
- 自动提交 patch。
- 未经确认调用高风险外部命令。

系统允许：

- 读取源码文本。
- 读取 Git diff。
- 执行安全扫描工具。
- 调用 LLM 做结构化审计分析。
- 生成修复建议。
- 生成报告。

## 集成能力逐项说明

### SARIF 输出

SARIF 是静态分析工具常用的标准报告格式。CodeAudit-Agent 将内部 `Finding` 映射为 SARIF result：

- `rule_id` 对应 SARIF rule。
- `severity` 对应 level。
- `file_path`、`line_start`、`line_end` 对应 location。
- `evidence_text`、`analysis_result`、`fix_suggestion` 对应 message 和 properties。

这样同一份审计结果既可以生成 Markdown 报告，也可以被 GitHub Code Scanning、企业安全平台或 IDE 插件消费。

### GitHub Action

GitHub Action 是 CI 入口。项目可以在 PR 或 push 时执行：

- `diff_scan`：只审计当前 PR 变更代码，适合代码评审场景。
- `repo_scan`：定时或手动扫描整个仓库，适合基线审计。

Action 不直接修改代码，只输出报告、SARIF 和 PR comment。外部工具未安装时仍然使用内置规则和 LLM 结构化分析。

### GitHub PR Comment

PR comment 用于把审计结论放回开发协作流程。评论内容聚焦：

- 本次 diff 新增的高风险 finding。
- 是否被误报复核判定为可疑或误报。
- 修复建议摘要。
- Markdown / SARIF 报告链接。

它不把所有细节都塞进评论区，完整证据仍保存在报告中。

### Semgrep 官方规则集

Semgrep 官方规则集提供大量多语言安全规则。CodeAudit-Agent 将 Semgrep 作为注册工具使用：

- Python 项目用于补充 SQL 注入、命令执行、路径穿越、危险反序列化等规则。
- Java Spring 项目用于补充 Controller、Mapper、权限校验、SQL 拼接等规则。
- JavaScript / TypeScript 项目用于补充 Express、Node.js、前后端混合仓库的常见风险。

如果本地没有 Semgrep，`ToolExecutor` 会记录 skipped，并使用 `custom_rule_scanner` 作为 fallback。

### Gitleaks

Gitleaks 是专门用于 secret 泄露检测的外部工具。它和内置 `secret_scanner` 的关系是：

- `secret_scanner` 提供稳定、轻量、无依赖的基础检测。
- Gitleaks 提供更完整的 secret pattern、熵检测和历史仓库扫描能力。

两者结果进入同一个 `FindingMerger`，按文件、行号、规则和证据去重。

### MCP Tool Server

MCP Tool Server 用来把外部能力标准化成 Agent 可调用工具。它适合接入：

- 企业内部代码索引服务。
- 私有漏洞知识库。
- 安全扫描平台。
- 依赖漏洞查询服务。
- 统一日志和审计系统。

在 CodeAudit-Agent 中，MCP 工具仍然走 allowlist、schema 校验和 `ToolExecutor`，不会让 LLM 直接获得任意系统权限。

### 向量化漏洞知识库

向量化漏洞知识库用于解决关键词检索不够准确的问题。比如用户任务写的是“越权”，知识库文档可能叫 `broken_access_control`；用户任务写的是“反序列化风险”，代码里可能表现为 `pickle.loads`、`readObject` 或 Jackson default typing。

向量检索会基于语义召回相关条目，再交给 VulnKB reranker 或 LLM 判断是否适用于当前项目。最终命中的知识库条目会记录在报告里，便于解释 Agent 为什么关注某类风险。

### 多语言项目画像

项目画像不只覆盖 Python，也覆盖常见后端项目结构：

- Python：FastAPI、Flask、Django、requirements、pyproject、路由、ORM、上传处理。
- Java：Spring Boot、Controller、Service、Mapper、Repository、pom、gradle、XML Mapper。
- JavaScript / TypeScript：Express、NestJS、Next.js API routes、package.json、ORM、上传中间件。
- Go：main、router、handler、service、database、go.mod。

不同语言的项目画像会影响漏洞知识库检索和工具选择。例如 Java + Spring Controller + Mapper XML 会优先关注访问控制、SQL 拼接、MyBatis 参数绑定；Python + FastAPI + upload files 会优先关注 secret、SQL 注入、路径穿越和上传校验。
