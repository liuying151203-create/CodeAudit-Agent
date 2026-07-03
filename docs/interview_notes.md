# 技术说明

本文档整理 CodeAudit-Agent 的关键技术点，帮助理解项目为什么采用当前实现方式。

## 与普通 LLM 代码审查的区别

普通 LLM 代码审查通常会把大段代码直接发送给模型，然后让模型给出建议。这种方式容易出现上下文过大、结果不可复现、误报难解释和幻觉等问题。

CodeAudit-Agent 采用扫描优先的方式：

1. 静态扫描器先发现确定性的候选风险。
2. Agent 提取候选风险附近的证据。
3. 分析节点只围绕 finding 和证据进行判断。
4. 报告中保留完整 trace，方便追踪结论来源。

## LangGraph 的作用

LangGraph 用于表达 Agent 的流程编排。

在本项目中，它负责把以下节点串联起来：

- 路由
- 仓库加载
- diff 加载
- 静态扫描
- 上下文提取
- 风险分析
- 误报复核
- 修复建议
- 报告生成

每个节点输入和输出都通过 `AuditState` 传递，使流程更清晰，也方便后续增加分支、重试和人工复核节点。

## Tool Calling 的体现

项目把每个关键能力封装成工具类：

- `RepoLoaderTool`
- `GitDiffTool`
- `StaticScanTool`
- `SecretScanTool`
- `ContextExtractorTool`
- `RiskAnalyzeTool`
- `FalsePositiveReviewTool`
- `FixSuggestTool`
- `ReportWriterTool`

节点调用工具完成具体任务，工具边界清晰，后续可以替换实现或接入外部服务。

## 各角色职责

- Scanner：负责发现确定性的风险模式。
- Analyzer：负责解释风险原因、攻击场景、置信度和严重等级。
- Reviewer：负责复核可能的误报。
- FixAdvisor：负责给出安全写法和 patch 提示。
- Reporter：负责生成 Markdown / JSON 报告并暴露 trace。

## 如何降低 LLM 幻觉

项目通过以下方式控制 LLM 输出：

- LLM 不直接扫描整个仓库。
- LLM 只分析静态扫描产生的候选 finding。
- 输入中包含明确的规则 ID、文件路径、行号和证据文本。
- 输出通过结构化 schema 承载。
- LLM 调用失败时自动回退到规则模板。

## 如何处理误报

误报复核节点会结合 finding 的类别、证据文本和规则信息进行判断。

当前 MVP 使用轻量规则和可选 LLM 复核。后续可以扩展：

- 测试文件和示例文件识别。
- 数据流分析。
- 框架语义识别。
- 多扫描器结果交叉验证。

## Git Diff 检测实现

`GitDiffTool` 支持直接接收 unified diff 文本，也可以从本地仓库读取 Git diff。

`diff_parser` 会重建变更后的 Python 代码片段，并记录新增行位置。这样静态扫描可以只关注本次变更，适合提交前检查和 PR 检测。

## 为什么不执行被审计代码

被审计项目中的代码可能包含未知副作用，例如：

- 删除文件
- 发起网络请求
- 读取环境变量
- 执行系统命令
- 修改本地数据

因此 CodeAudit-Agent 只读取源代码文本和 diff 文本，不运行被审计项目代码。

## 后续可扩展方向

- 接入 Semgrep、Bandit、Gitleaks。
- 输出 SARIF，接入 GitHub Code Scanning。
- 增加 GitHub Action。
- 支持更多语言。
- 使用 SQLite 保存历史报告。
- 增加更严格的 Pydantic 输出校验。

## 升级后的 Agent 设计

新版本不再只是 Scanner-first 的解释器，而是增加了项目理解和工具选择能力。

参考 Strix、PentAGI、CodeScan、OpenCodeReview 的设计思想后，流程拆成四层：

1. Project Reader：读取源码结构，识别语言、框架、依赖、入口、路由、认证、数据库和上传相关文件。
2. VulnKB Retriever：根据项目画像检索 SQL 注入、命令注入、密钥泄露、路径穿越、不安全反序列化、访问控制缺陷等漏洞知识。
3. Tool Selector / Executor：根据项目技术栈、风险面和扫描模式选择内置规则、secret scanner、Bandit、Semgrep、context extractor 等工具。
4. LLM Reviewer：结合 finding、源码上下文、知识库和工具结果做风险解释、误报复核和修复建议。

这和普通 GPT 审代码的区别是：Agent 不是直接让模型读一堆代码后自由发挥，而是先建立项目画像，再检索漏洞知识，再选择工具，最后让 LLM 基于结构化证据做判断。

## 源码理解如何体现

`ProjectReaderTool` 会扫描项目结构并生成 `ProjectProfile`：

- `languages`
- `frameworks`
- `dependency_files`
- `entrypoints`
- `route_files`
- `auth_files`
- `db_files`
- `upload_files`
- `risk_surfaces`

这些信息会影响漏洞知识库检索和工具选择。例如 Python + FastAPI + DB 文件会优先关注 SQL 注入、命令执行、Secrets 和路径穿越。

## 安全工具如何选择

工具能力注册在 `config/security_tools.yaml`。

`ToolSelectorTool` 会根据 `ProjectProfile`、漏洞知识库命中结果和 scan mode 输出 `ToolPlan`：

- `selected_tools`
- `selected_risk_types`
- `target_files`
- `selection_reason`

外部工具未安装时不会强行执行，会记录 skipped，并降级到内置规则扫描。

## 漏洞知识库如何参与审计

`knowledge_base/` 下的漏洞文档描述适用场景、危险代码模式、推荐检测工具、审计关注点和修复建议。

Agent 会把这些知识作为工具选择和风险分析的依据，而不是只依赖静态规则命中。

## 多阶段审计

当前支持阶段：

- init
- secret
- injection
- command
- file
- auth
- review
- report

MVP 已实现 secret、injection、command 的实际扫描统计，其余阶段作为规划或聚合节点保留。这样后续可以继续扩展成更完整的分阶段审计流程。

## 后续集成方向

- SARIF 输出，用于 GitHub Code Scanning。
- GitHub Action，用于 PR 自动审计。
- Semgrep 官方规则集。
- MCP Tool Server，用于将外部扫描器、知识库或代码索引服务标准化接入。
