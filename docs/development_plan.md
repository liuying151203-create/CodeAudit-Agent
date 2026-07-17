# CodeAudit-Agent 开发计划

本文档记录 CodeAudit-Agent 从当前可运行版本演进到 [design.md](design.md) 所描述完整架构的实施计划。它用于跟踪代码改造、阶段验收和开发顺序，不作为对外功能说明。

## 1. 当前基线

当前代码已经具备以下可运行能力：

- `repo_scan` 和 `diff_scan` 两种入口。
- 本地仓库文件读取、Git diff 读取和 unified diff 解析。
- Python/Java 内置规则和 Secret 扫描。
- 支持 Python 与 Java 的 ProjectProfile、结构化漏洞知识检索和动态审计计划。
- 统一只读工具网关，以及 Semgrep、Bandit、Gitleaks 外部工具适配器。
- LangGraph 阶段调度外循环、工具调用内循环及无 LangGraph 环境下的 fallback。
- LLM 风险分析、误报复核和修复建议。
- LLM 未配置或调用失败时的模板降级。
- Markdown、JSON 报告和基础 Agent trace。
- FastAPI 接口和 Streamlit 演示页面。

当前实现与目标设计的主要差距：

- Stage Scheduler 与 Audit Reasoner 双层循环已完成，后续需要统一 Finding、Evidence 和 ReviewResult 生命周期。
- Finding、Evidence、ReviewResult 和 fallback 的生命周期尚未完全统一。
- Streamlit 只能在审计完成后集中展示结果，尚未消费 LangGraph 事件流。
- SARIF、GitHub Action、PR Comment 和 MCP Adapter 尚未完成集成。

## 2. 实施原则

- 不推倒现有项目，按可验证的小阶段逐步替换。
- 每个阶段结束后，`repo_scan` 和 `diff_scan` 都必须保持可运行。
- 先稳定 Schema 和状态，再修改图编排与 UI。
- 新旧实现短期并存时，通过适配层转换，不在业务节点中散落兼容判断。
- 外部工具不可用时必须保留内置 fallback。
- 不执行被审计项目代码，不自动利用漏洞，不自动修改用户代码。
- 每个阶段补齐单元测试和端到端回归测试。

## 3. 阶段一：统一 Schema 与 AuditState

状态：已完成（2026-07-12）。

### 开发内容

- 新增或重构 `AuditPlan`、`AuditStagePlan`、`ToolRequest`、`ValidatedToolCall`。
- 统一初始扫描和补充调用结果为 `ToolRunResult`。
- 完善 `ProjectProfile`，增加 `security_signals`、`profile_scope`、`profile_confidence` 和 `missing_context`。
- 完善 `Evidence`、`AuditDecision`、`AuditHypothesis` 和 Finding 状态。
- 新增 `AuditBudget`、StageResult、运行指标和 fallback 记录。
- 重构 `AuditState`，明确 request、project_context、planning、execution、findings 和 runtime 字段。

### 验收标准

- 所有 Schema 可以独立序列化和反序列化。
- JSON 报告可以完整保存新状态对象。
- 旧流程通过适配函数继续输出原有报告。
- Schema 单元测试覆盖正常、缺失字段和非法枚举场景。

## 4. 阶段二：项目理解与知识规划

状态：已完成（2026-07-14）。

### 开发内容

- 重构 Project Reader 的文件过滤、语言识别、框架识别和关键文件分类。
- 区分 `risk_surfaces`、`security_signals` 和 Finding。
- 为 repo、diff enriched、diff only 三种画像范围计算完整度。
- 为漏洞知识文档增加可解析元数据。
- 实现规则召回、打分、Top-K 和可选 LLM rerank。
- 实现 capability-based Audit Planner 和无 LLM 模板 Planner。

### 验收标准

- Python FastAPI/Flask 项目画像准确识别关键模块。
- Java Spring Boot/MyBatis 示例可以生成基础项目画像。
- pasted diff 不会伪造仓库依赖和调用链信息。
- AuditPlan 包含动态阶段、目标文件、所需能力和证据目标。

## 5. 阶段三：统一工具网关

状态：已完成（2026-07-15）。

### 开发内容

- 扩展 `config/security_tools.yaml` 的 capability、adapter、read_only 和 timeout 字段。
- 实现 Tool Selector 的工具匹配、路径校验、预算校验和 fallback 选择。
- 实现 Tool Executor 的固定命令模板、超时、输出限制和并行执行。
- 统一内置扫描器和外部工具的 `ToolRunResult`。
- 完成 Semgrep、Bandit 和 Gitleaks 的安装探测、执行与结果归一化。
- 为 MCP Adapter 预留 SecurityTool 转换接口。

### 验收标准

- LLM 不能传入任意 shell command。
- 工具不能读取 repo_path 之外的目标文件。
- 外部工具未安装时能够自动选择内置 fallback。
- 同一 finding 的多工具来源可以保留并去重。

## 6. 阶段四：LangGraph 双层循环

状态：已完成（2026-07-17）。

### 开发内容

- 实现 `stage_scheduler`、`evidence_builder`、`audit_reasoner`、`finding_builder` 和 `stage_finalize` 节点。
- 为 Audit Reasoner 增加 `CALL_TOOL`、`EMIT_FINDING` 和 `FINISH_STAGE` 条件边。
- 为 Stage Finalize 增加 `HAS_NEXT_STAGE` 和 `ALL_FINISHED` 条件边。
- 实现工具轮次、文件数量、上下文行数、Token 和耗时预算。
- 检测连续工具调用没有新增证据的情况，主动终止循环。
- 保留节点级 trace、错误恢复和部分成功报告。

### 验收标准

- Agent 可以在证据不足时主动调用 Context Extractor。
- Agent 可以在同一风险阶段生成多个 finding 后继续判断。
- 达到预算时不会无限循环，并记录 `budget_exhausted`。
- secret、injection、command、file、auth 阶段按项目画像动态启用。

## 7. 阶段五：Finding 质量闭环

### 开发内容

- 实现 Evidence Builder 的函数、类、imports、diff 行号和局部调用关系提取。
- 实现 PromptContextSanitizer，限制代码范围并掩码 Secret。
- 重构 Finding Merger，保留规则、工具、LLM 和 MCP 来源。
- 合并 Risk Analyzer 和 False Positive Reviewer 的批量 LLM 调用。
- 根据 confirmed、dismissed、needs_review 管理 Finding 生命周期。
- 重构 Fix Advisor 和 Markdown、JSON、SARIF 输出。

### 验收标准

- LLM finding 必须引用真实 evidence_id。
- 无证据推测不会进入最终风险列表。
- 报告能解释 Finding 的来源、复核结果和 fallback。
- Secret 原值不会出现在 LLM prompt、trace 和报告中。

## 8. 阶段六：Streamlit Demo

### 开发内容

- 将输入区移动到侧边栏，统一 repo_scan 和 diff_scan 配置。
- 展示外部工具、LLM 和 fallback 可用状态。
- 使用 LangGraph 事件流实时更新当前阶段和总体进度。
- 增加项目画像、审计计划、工具执行、风险证据、Agent Trace 和报告 Tabs。
- 为 Finding 增加严重等级、来源、代码证据、复核和修复视图。
- 增加空状态、错误状态、部分成功和预算耗尽提示。
- 优化桌面和窄屏布局，避免表格和代码块溢出。

### 验收标准

- repo_scan 和 diff_scan 都可以从页面直接运行。
- 长耗时审计期间持续显示阶段与工具执行进度。
- 页面明确区分扫描器 finding、LLM finding、误报和审计假设。
- Demo 可以完整展示至少一个 Python 仓库和一个 Git diff 场景。

## 9. 阶段七：工程集成

### 开发内容

- 输出符合规范的 SARIF 结果。
- 增加 GitHub Action，按事件选择 repo_scan 或 diff_scan。
- 生成并回写 PR Comment 摘要。
- 完成 MCP Adapter 的工具发现、Schema 映射和安全调用。
- 增加报告保留策略和必要的运行指标。

### 验收标准

- SARIF 可以被 GitHub Code Scanning 解析。
- Pull Request 可以自动触发变更审计。
- PR Comment 只展示摘要和关键风险，不泄露敏感代码。
- MCP 工具继续受 Tool Selector、Tool Executor 和 AuditBudget 限制。

## 10. 测试策略

### 单元测试

- Schema 校验和 reducer。
- Project Reader 语言、框架和关键文件识别。
- VulnKB 打分和 Planner fallback。
- Tool Selector 校验和工具 fallback。
- diff 行号映射和 Evidence 构建。
- AuditDecision 路由和预算终止。
- Finding 合并与误报状态转换。

### 集成测试

- 无 LLM、无外部工具的 repo_scan。
- 配置 LLM、无外部工具的 repo_scan。
- Semgrep/Bandit/Gitleaks 可用时的工具执行。
- pasted diff、cached diff 和 HEAD diff。
- LLM 超时、非法 JSON 和结构校验失败。
- 工具超时、解析失败和部分阶段失败。

### Demo 回归

- Python 仓库中的 Secret、SQL 注入、命令执行和文件风险。
- Java Spring Boot/MyBatis 项目画像和工具规划。
- Git diff 中的 changed_line_finding 和 context_related_finding。
- Agent 主动补充上下文后形成 Finding 的完整 trace。

## 11. 开发顺序

严格按以下顺序推进：

```text
Schema / AuditState
  -> Project Reader / VulnKB / Planner
  -> Tool Gateway
  -> LangGraph 双层循环
  -> Finding 质量闭环
  -> Streamlit Demo
  -> 工程集成
```

UI 依赖稳定的事件和状态模型，因此在双层循环和 Finding 生命周期稳定后集中升级。每个阶段完成后独立提交，提交前运行编译检查、单元测试、repo_scan 回归和 diff_scan 回归。
