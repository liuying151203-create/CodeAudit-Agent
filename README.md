# CodeAudit-Agent

CodeAudit-Agent 是一个面向代码审计和 Git Diff 风险分析的 AI Agent 项目。

项目基于 LangGraph 风格的工作流编排，将静态扫描、上下文提取、风险分析、误报复核、修复建议和审计报告生成串联为一个完整流程。系统优先使用确定性的扫描规则发现候选风险，再对候选结果进行分析和整理，避免直接把整仓代码交给大模型进行泛化判断。

## 核心能力

- 本地仓库扫描：输入 `repo_path`，扫描 Python 项目中的潜在安全风险。
- Git Diff 检测：输入 `diff_text` 或通过 Git 获取 diff，只分析本次变更代码。
- 内置静态规则扫描：MVP 阶段不依赖外部安全工具即可运行。
- Agent 工作流编排：通过多个节点组织完整审计流程。
- 工具封装：将加载、扫描、分析、复核、修复建议、报告生成封装为独立工具。
- Agent Trace：记录每个节点的执行过程，方便排查和审计。
- 报告输出：生成 Markdown 和 JSON 两种审计报告。
- Web API：提供 FastAPI 接口。
- 可视化页面：提供 Streamlit 页面。

## 支持的扫描模式

### `repo_scan`

扫描本地仓库中的 `.py` 文件。

默认忽略以下目录：

- `.git`
- `.venv`
- `venv`
- `node_modules`
- `target`
- `dist`
- `__pycache__`

### `diff_scan`

扫描 Git diff 中新增或变更的 Python 代码，适用于提交前检查、Pull Request 检测和 CI/CD 集成。

## 支持的风险类型

MVP 阶段支持以下风险识别：

- Secrets 泄露：`api_key`、`token`、`password`、`private_key`、`secret`
- Python 危险函数：`eval`、`exec`、`pickle.load`、`yaml.load`
- 命令执行风险：`os.system`、`subprocess(..., shell=True)`
- SQL 字符串拼接风险
- 路径穿越风险

## 系统架构

```text
FastAPI / Streamlit
      |
LangGraph Agent Workflow
      |
RepoLoaderTool / GitDiffTool
      |
StaticScanTool + SecretScanTool
      |
ContextExtractorTool
      |
RiskAnalyzeTool
      |
FalsePositiveReviewTool
      |
FixSuggestTool
      |
ReportWriterTool
```

## 工作流

核心节点包括：

- `router_node`：判断执行本地仓库扫描还是 Git Diff 扫描。
- `repo_loader_node`：读取本地仓库文件。
- `diff_loader_node`：读取并解析 Git diff。
- `static_scan_node`：执行内置静态扫描规则。
- `context_extract_node`：提取代码上下文、函数名、import 信息和变更行信息。
- `risk_analyze_node`：分析风险原因、攻击场景、置信度和严重等级。
- `false_positive_review_node`：复核可能的误报。
- `fix_suggest_node`：生成安全修复建议。
- `report_node`：生成 Markdown 和 JSON 审计报告。

## Agent 设计

项目通过显式的状态、节点和工具边界组织审计流程：

- `AuditState` 保存执行过程中的中间状态。
- 每个节点只负责一个明确任务。
- 工具类封装外部能力和内部扫描能力。
- Agent 根据输入模式选择不同路径。
- 每个节点都会产生 trace，最终流程可追踪、可解释。
- 风险分析只基于静态扫描产生的候选 finding 和提取到的证据，降低幻觉和误判。

即使没有 LLM API，系统也可以通过规则模板完成基础风险分析和报告生成。

## 安装

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

## LLM API 配置

系统支持 OpenAI-compatible 的 Chat Completions 接口。配置 API 后，`RiskAnalyzeTool`、`FalsePositiveReviewTool` 和 `FixSuggestTool` 会优先调用 LLM；如果没有配置 API key，或者调用失败，系统会自动使用本地规则模板继续生成分析、复核和修复建议。

复制 `.env.example` 为 `.env`：

```powershell
Copy-Item .env.example .env
```

然后填写：

```env
CODEAUDIT_REPORT_DIR=data/reports

LLM_API_KEY=你的_API_Key
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-4o-mini
LLM_TIMEOUT_SECONDS=30
```

也可以只填写 `OPENAI_API_KEY`，系统会在 `LLM_API_KEY` 为空时自动读取它：

```env
OPENAI_API_KEY=你的_OpenAI_API_Key
```

如果使用其他兼容 OpenAI API 格式的服务，只需要替换：

```env
LLM_BASE_URL=https://你的服务地址/v1
LLM_MODEL=你的模型名称
LLM_API_KEY=你的_API_Key
```

注意：

- 不要把真实 API key 提交到 Git。
- `.env` 只用于本地配置。
- LLM 只分析静态扫描产生的候选 finding，不会直接扫描整个仓库。
- 即使不配置 LLM API，基础扫描流程也可以完整运行。

## 启动 FastAPI

```powershell
uvicorn app.main:app --reload
```

启动后可访问：

```text
http://127.0.0.1:8000
```

## 启动 Streamlit

```powershell
streamlit run frontend/streamlit_app.py
```

## API

### 本地仓库扫描

```http
POST /scan/repo
```

请求示例：

```json
{
  "repo_path": "data/sample_repos/small_python_app"
}
```

### Git Diff 扫描

```http
POST /scan/diff
```

请求示例：

```json
{
  "diff_text": "diff --git a/app.py b/app.py\n..."
}
```

### 报告查询

```http
GET /reports
GET /reports/{report_id}
```

## 示例数据

项目内置了一个包含风险代码的示例仓库：

```text
data/sample_repos/small_python_app
```

示例风险包括：

- 硬编码密码
- `eval(user_input)`
- `subprocess.run(..., shell=True)`
- `pickle.load`
- SQL 字符串拼接
- 路径穿越

同时提供了一个演示用 diff 文件：

```text
data/sample_repos/sample.diff
```

## 报告输出

扫描完成后会在 `data/reports` 下生成：

- Markdown 审计报告
- JSON 审计报告

报告内容包括：

- 风险概览
- 严重等级统计
- 具体 finding
- 代码证据
- 风险解释
- 修复建议
- Agent trace

## 后续规划

- 接入 Semgrep、Bandit、Gitleaks。
- 输出 SARIF，接入 GitHub Code Scanning。
- 增加 GitHub Action，实现 PR 自动审计。
- 接入真实 LLM API，并通过 Pydantic 校验结构化输出。
- 使用 SQLite 保存历史报告。
- 支持 JavaScript、Java 等更多语言。

## Agent 审计升级

当前版本在保留 repo_scan / diff_scan 的基础上，增加了更主动的 Agent 审计流程：

```text
router
  -> project_reader
  -> vulnkb_retriever
  -> tool_selector
  -> tool_executor
  -> finding_merger
  -> context_extractor
  -> risk_analyzer
  -> false_positive_reviewer
  -> fix_advisor
  -> reporter
```

设计上参考了 Strix、PentAGI、CodeScan、OpenCodeReview 这类系统的思路：

- 先理解项目源码，形成 ProjectProfile。
- 根据语言、框架、依赖、路由、认证、数据库和上传面识别风险面。
- 从漏洞知识库检索相关审计知识。
- 根据项目画像和知识库命中内容选择安全工具。
- 使用多阶段审计降低漏报和误报。
- LLM 不直接无约束扫描整仓，而是结合 finding、源码上下文和漏洞知识做分析、复核和修复建议。

新增输出包括：

- ProjectProfile 项目画像
- VulnKB 命中条目
- ToolPlan 工具选择计划
- ToolExecutionResult 工具执行结果
- AuditStageResult 多阶段审计结果

外部工具未安装时，系统会降级到内置规则扫描。系统不会执行被审计项目代码，不会自动利用漏洞，也不会自动修改用户代码。
