# 架构设计

本文档说明 CodeAudit-Agent 的整体设计思路、模块边界和安全约束。

## 设计目标

CodeAudit-Agent 的目标是把代码审计拆成可追踪、可扩展的工程流程，而不是直接把整个仓库交给 LLM 做泛化分析。

核心思路是：

1. 先用确定性的静态规则发现候选风险。
2. 再围绕候选风险提取必要上下文。
3. 最后由分析节点生成风险解释、误报复核和修复建议。

这样可以降低 LLM 幻觉，让每个结论都有明确证据来源，也便于后续接入 Semgrep、Bandit、Gitleaks 等外部扫描工具。

## 模块划分

```text
app/
  api/       FastAPI 接口
  agent/     Agent 状态、节点、图编排和工具封装
  scanners/  内置扫描规则和外部扫描器适配
  diff/      Git diff 加载与解析
  context/   代码上下文提取
  schemas/   Pydantic 数据结构
  storage/   报告读取与后续持久化扩展
  utils/     文件过滤、trace 等通用能力

frontend/
  Streamlit 演示页面

data/
  示例项目、报告输出和 SARIF 输出目录
```

## Agent 工作方式

Agent 通过 `AuditState` 保存执行过程中的状态，包括扫描模式、仓库路径、diff 内容、候选风险、证据、风险分析、误报复核结果、修复建议、最终报告和 trace。

每个节点只负责一个明确职责：

- 加载文件或 diff。
- 执行静态扫描。
- 提取上下文证据。
- 分析风险。
- 复核误报。
- 生成修复建议。
- 写入报告。

这种拆分可以让流程更容易测试、替换和扩展。

## 安全边界

系统只读取被审计项目的文件和 Git diff 文本，不执行被审计项目中的代码。

MVP 阶段不会自动修改用户代码，只生成 `patch_hint` 和安全写法示例。这样可以避免误修复、破坏业务逻辑或触发未知脚本。

## LLM 使用策略

LLM 是可选能力，不是系统运行的强依赖。

配置 LLM API 后，风险分析、误报复核和修复建议会优先调用 LLM；如果没有 API key 或调用失败，系统会回退到本地规则模板。

LLM 只接收静态扫描产生的候选 finding 和相关证据，不直接扫描整个仓库。

## 主动 Agent 能力

升级后的设计增加了四个主动审计能力：

- Project Reader：理解项目结构并生成安全画像。
- VulnKB Retriever：根据项目画像检索漏洞知识库。
- Tool Selector：根据语言、框架、风险面和扫描模式选择工具。
- Tool Executor：执行内置扫描器或记录外部工具跳过原因。

这使 Agent 不再只是解释静态扫描结果，而是能先理解项目，再决定应该关注哪些风险、调用哪些工具、审计哪些文件。

## 多阶段审计

系统保留以下审计阶段：

- init
- secret
- injection
- command
- file
- auth
- review
- report

MVP 中 secret、injection、command 已有实际扫描统计。file、auth、review、report 阶段作为后续增强点保留。
