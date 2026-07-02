# 工作流说明

本文档说明 CodeAudit-Agent 从接收请求到生成报告的完整执行流程。

## 总体流程

```text
接收请求
  -> 判断扫描模式
  -> 加载仓库文件或 Git diff
  -> 执行静态扫描
  -> 提取代码上下文
  -> 分析风险
  -> 复核误报
  -> 生成修复建议
  -> 输出 Markdown / JSON 报告
```

## 1. 路由阶段

`router_node` 根据输入判断扫描模式：

- 如果传入 `diff_text`，走 `diff_scan`。
- 如果传入 `repo_path`，走 `repo_scan`。

如果必要输入缺失，节点会抛出错误，避免后续节点在不完整状态下继续执行。

## 2. 仓库扫描加载

`repo_loader_node` 读取本地仓库中的 `.py` 文件。

默认忽略：

- `.git`
- `.venv`
- `venv`
- `node_modules`
- `target`
- `dist`
- `__pycache__`

加载结果会写入 `scanned_files`。

## 3. Git Diff 加载

`diff_loader_node` 支持两种输入：

- 用户直接传入 `diff_text`。
- 根据 `repo_path` 执行 Git diff 读取变更内容。

`diff_parser` 会解析 changed files、hunks 和新增代码行，使后续扫描只聚焦本次变更。

## 4. 静态扫描

`static_scan_node` 调用内置规则，对代码文本进行扫描。

当前规则覆盖：

- Secrets 泄露
- Python 危险函数
- 命令执行风险
- SQL 字符串拼接
- 路径穿越

扫描结果写入 `candidate_findings`。

## 5. 上下文提取

`context_extract_node` 为每个 finding 提取证据：

- 前后若干行代码
- 所在函数名
- import 信息
- 是否来自 diff 新增行

这些信息会写入 `evidences`，供后续分析使用。

## 6. 风险分析

`risk_analyze_node` 对候选 finding 生成结构化分析：

- 风险类型
- 风险原因
- 可能攻击场景
- 置信度
- 严重等级

配置 LLM API 时优先使用 LLM；未配置时使用规则模板。

## 7. 误报复核

`false_positive_review_node` 判断 finding 是否可能为误报，并输出：

- `is_false_positive`
- `reason`
- `final_severity`

## 8. 修复建议

`fix_suggest_node` 对非误报 finding 生成：

- 修复建议
- 安全代码示例
- patch 提示

系统不会自动修改用户代码。

## 9. 报告生成

`report_node` 生成 Markdown 和 JSON 报告。

报告包含：

- 风险概览
- 严重等级统计
- 具体风险列表
- 代码证据
- 风险解释
- 修复建议
- Agent trace
