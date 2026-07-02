# 路线图

本文档记录 CodeAudit-Agent 的后续演进方向。

## Phase 1：项目骨架

已完成：

- 创建基础目录结构。
- 搭建 FastAPI 应用。
- 搭建 Streamlit 页面。
- 定义核心 schema。
- 准备示例项目和示例 diff。

## Phase 2：内置规则扫描

已完成：

- 实现本地仓库文件加载。
- 实现 Python 内置扫描规则。
- 支持 secrets、危险函数、命令执行、SQL 拼接和路径穿越检测。
- 输出结构化 `Finding`。

后续可优化：

- 增加更多 Python 风险规则。
- 引入规则 ID 分级体系。
- 为规则增加单元测试覆盖。

## Phase 3：Git Diff 检测

已完成：

- 支持 pasted diff。
- 支持 Git diff 加载。
- 解析 changed files 和 hunk。
- 聚焦新增代码行进行扫描。

后续可优化：

- 支持 rename、delete、binary file 等 diff 场景。
- 保留原始文件行号和 diff 行号的映射。
- 输出 PR 级别摘要。

## Phase 4：Agent 工作流

已完成：

- 定义 `AuditState`。
- 实现核心节点。
- 接入 LangGraph 工作流。
- 为每个节点记录 trace。
- 提供无 LangGraph 环境下的顺序执行 fallback。

后续可优化：

- 增加节点级错误恢复。
- 增加人工复核节点。
- 增加多扫描器并行执行。

## Phase 5：LLM 分析与修复建议

已完成：

- 支持 OpenAI-compatible LLM API 配置。
- 实现风险分析、误报复核和修复建议的 LLM 调用。
- 未配置 LLM 时自动回退到规则模板。

后续可优化：

- 增加更严格的结构化输出校验。
- 为不同风险类型设计专用 prompt。
- 增加 LLM 调用日志和成本统计。

## Phase 6：报告与展示

已完成：

- 生成 Markdown 报告。
- 生成 JSON 报告。
- 在 Streamlit 中展示扫描结果。
- 通过 FastAPI 查询报告。

后续可优化：

- 增加 SARIF 输出。
- 增加 HTML 报告。
- 支持报告对比和历史趋势。

## Phase 7：工程化集成

计划：

- 接入 Semgrep、Bandit、Gitleaks。
- 增加 GitHub Action。
- 在 PR 中自动发布审计评论。
- 使用 SQLite 保存报告元数据。
- 增加 Dockerfile 和部署说明。
