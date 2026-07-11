# CodeAudit-Agent

CodeAudit-Agent 是一个基于 LangGraph 的源码安全审计与 Git diff 风险分析 Agent。系统先理解项目结构和风险面，再结合漏洞知识库规划审计阶段，通过统一工具网关执行内置规则或外部安全工具，并由 LLM 围绕真实代码证据主动补充审计、复核风险和生成修复建议。

项目提供 FastAPI 接口、Streamlit 演示页面，以及 Markdown、JSON 等结构化审计结果。

## 核心能力

- 项目源码理解：识别语言、框架、依赖、入口、路由、认证、数据库和文件上传模块。
- 双模式审计：支持本地仓库 `repo_scan` 和 Git 变更 `diff_scan`。
- 漏洞知识检索：根据项目画像匹配注入、密钥泄露、命令执行、路径穿越、反序列化和访问控制知识。
- 动态审计规划：根据风险面生成 secret、injection、command、file、auth 等审计阶段。
- 受控工具调用：通过 Tool Registry、Tool Selector 和 Tool Executor 统一管理扫描工具。
- 主动补充取证：LLM 根据现有证据决定继续调用工具、形成 finding 或结束当前阶段。
- 风险质量控制：合并多工具结果，完成风险分析、误报复核和修复建议。
- 可解释执行：记录审计计划、工具选择原因、条件分支、fallback 和 Agent trace。

## Agent 架构

完整设计采用“项目理解、阶段规划、工具执行、证据推理、质量复核”五步主线：

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
       |-- CALL_TOOL ------> tool_selector -> tool_executor -> evidence_builder
       |                                            ^                  |
       |                                            +------------------+
       |-- EMIT_FINDING ---> finding_builder -> audit_reasoner
       |-- FINISH_STAGE ---> stage_finalize
                                |-- HAS_NEXT_STAGE -> stage_scheduler
                                |-- ALL_FINISHED --> finding_merger
                                                       -> finding_assessor
                                                       -> fix_advisor
                                                       -> reporter
```

工作流包含两个受控循环：

- 工具调用内循环：证据不足时，Audit Reasoner 请求更多源码上下文或安全工具结果。
- 审计阶段外循环：完成当前风险阶段后，Stage Scheduler 切换到下一阶段。

每个阶段都受到工具调用轮次、目标文件数、上下文行数、Token 和耗时预算限制，避免无限循环和成本失控。

详细设计见 [docs/design.md](docs/design.md)。

## Agent 如何工作

### 1. 理解项目

Project Reader 读取文件树、构建文件和有限源码内容，生成 `ProjectProfile`：

```text
languages / frameworks / dependency_files / entrypoints
route_files / auth_files / db_files / upload_files
risk_surfaces / security_signals / profile_scope
```

项目画像只描述项目结构和审计线索，不直接产生漏洞结论。

### 2. 检索知识与规划阶段

VulnKB Retriever 根据语言、框架、风险面和用户任务检索本地漏洞知识。Audit Planner 将知识命中转换为 `AuditPlan`，描述风险阶段、目标文件、所需能力和证据目标。

Planner 面向能力进行规划，例如 `scan_sql_patterns` 或 `extract_call_chain`，不直接拼接命令或决定外部工具参数。

### 3. 选择并执行工具

Tool Selector 根据 `config/security_tools.yaml` 将能力映射到具体工具，并检查语言、扫描模式、目标路径、安装状态和只读权限。

工具分为两类：

- 内置工具：Secret Scanner、Custom Rule Scanner、Context Extractor。
- 外部适配器：Semgrep、Bandit、Gitleaks，以及通过 MCP Adapter 接入的工具。

外部工具不可用时自动记录 skipped 或 fallback，并切换到对应的内置规则。

### 4. LLM 主动审计

Audit Reasoner 不会无约束读取整个仓库，而是围绕当前风险阶段、工具结果和 Evidence 做结构化决策：

```text
CALL_TOOL     证据不足，继续调用受控工具
EMIT_FINDING  证据充分，形成候选风险
FINISH_STAGE  当前阶段完成或预算耗尽
```

LLM finding 必须引用真实 `evidence_id`、文件路径和代码行号。没有证据的推测只保留为审计假设，不进入最终报告。

### 5. 复核与报告

Finding Merger 对内置规则、外部工具和 LLM finding 去重。Finding Assessor 批量完成风险解释和误报复核，Fix Advisor 生成与语言、框架和上下文匹配的修复建议。

## 扫描模式

### `repo_scan`

读取本地项目目录，生成完整项目画像，并允许围绕必要的跨文件调用关系进行审计。

```json
{
  "repo_path": "D:/project/demo-app"
}
```

### `diff_scan`

支持直接传入 unified diff，也支持从本地仓库读取 staged 或 HEAD diff。

```json
{
  "diff_text": "diff --git a/app.py b/app.py\n..."
}
```

```json
{
  "repo_path": "D:/project/demo-app",
  "diff_mode": "cached"
}
```

有仓库路径时，系统补充读取依赖文件和必要上下文；只有 diff 文本时，报告会标记为 `diff_only` 并降低跨文件结论置信度。

diff 报告区分：

- `changed_line_finding`：风险直接位于新增或修改行。
- `context_related_finding`：历史代码风险被本次变更调用、触发或暴露。

## 当前开发状态

项目当前保留了一条可运行的基础链路，并正在按新设计逐步重构。

| 能力 | 当前状态 |
| --- | --- |
| 本地仓库与 pasted diff 扫描 | 可运行 |
| Git diff 读取与解析 | 可运行 |
| Python 内置安全规则 | 可运行 |
| ProjectProfile 与 VulnKB | 可运行的基础版本 |
| Tool Registry 与 fallback | 可运行的基础版本 |
| LLM 风险分析、复核与修复建议 | 可配置，失败时模板降级 |
| Markdown / JSON 报告 | 可运行 |
| Streamlit 演示页 | 可运行，待按新工作流升级 |
| 多阶段调度与 Audit Reasoner 条件循环 | 重构目标 |
| Semgrep / Bandit / Gitleaks 完整适配 | 重构目标 |
| SARIF / GitHub Action / PR Comment | 集成目标 |

Python 示例项目是当前主要演示对象。Java Spring Boot / MyBatis 已纳入项目画像、知识库和工具规划设计，完整扫描规则与演示仓库将在工具层重构中补齐。

## 项目结构

```text
app/
  agent/            LangGraph 状态、节点、图和 Agent 工具
  api/              FastAPI 扫描与报告接口
  context/          源码上下文和证据提取
  diff/             Git diff 读取与解析
  scanners/         内置扫描器和外部工具适配器
  schemas/          Pydantic 结构化模型
  storage/          报告存储
  utils/            文件过滤和 trace

config/
  security_tools.yaml

knowledge_base/     本地漏洞知识库
frontend/           Streamlit 演示页面
data/sample_repos/  演示项目与示例 diff
docs/design.md      完整系统设计说明
tests/              自动化测试
```

## 快速开始

### 1. 创建环境

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. 配置环境变量

```powershell
Copy-Item .env.example .env
```

不配置 LLM 也可以运行基础扫描。需要启用 LLM 时填写：

```env
CODEAUDIT_REPORT_DIR=data/reports

LLM_API_KEY=your_api_key
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-4o-mini
LLM_TIMEOUT_SECONDS=30
```

系统支持 OpenAI-compatible Chat Completions 接口，也会在 `LLM_API_KEY` 为空时读取 `OPENAI_API_KEY`。

不要提交 `.env`、API key、访问令牌或其他真实凭据。

### 3. 启动 Streamlit Demo

```powershell
streamlit run frontend/streamlit_app.py
```

默认地址：

```text
http://localhost:8501
```

页面可以直接使用：

```text
data/sample_repos/small_python_app
data/sample_repos/sample.diff
```

### 4. 启动 FastAPI

```powershell
uvicorn app.main:app --reload
```

API 地址和交互文档：

```text
http://127.0.0.1:8000
http://127.0.0.1:8000/docs
```

## API 示例

### 扫描本地仓库

```http
POST /scan/repo
Content-Type: application/json

{
  "repo_path": "data/sample_repos/small_python_app"
}
```

### 扫描 Git diff

```http
POST /scan/diff
Content-Type: application/json

{
  "diff_text": "diff --git a/app.py b/app.py\n..."
}
```

### 查询报告

```http
GET /reports
GET /reports/{report_id}
```

## Demo 前端方案

当前阶段继续使用 Streamlit。它已经能够直接调用 Python Agent，无需维护额外的前端构建链，适合展示长耗时任务、结构化结果、代码证据和审计报告。

重构后的页面按以下信息架构组织：

```text
侧边栏
  -> 扫描模式、仓库路径、diff 输入、LLM 与工具状态

执行概览
  -> 当前阶段、进度、耗时、工具调用数、finding 统计

主内容 Tabs
  -> 项目画像
  -> 审计计划
  -> 工具执行
  -> 风险与证据
  -> Agent Trace
  -> Markdown / JSON / SARIF 报告
```

Streamlit 足以完成本地 Demo 和完整功能验证。只有在需要多人访问、复杂实时交互、独立权限系统或产品级视觉定制时，才需要将前端替换为 React/Vue，并让 FastAPI 成为独立后端。

## 报告输出

默认报告目录：

```text
data/reports/
```

报告包含：

- 项目画像与画像完整度。
- 漏洞知识库命中。
- 审计阶段与工具选择理由。
- 工具执行结果和 fallback。
- Finding、Evidence 和来源。
- 风险分析、误报复核和修复建议。
- Agent trace、Token、耗时和调用统计。

## 安全边界

CodeAudit-Agent 只执行只读分析：

- 不执行被审计项目代码、测试、构建脚本或安装脚本。
- 不自动利用漏洞。
- 不自动修改或提交用户代码。
- 不允许 LLM 生成并直接执行 shell command。
- 外部工具只能通过注册表和固定适配器调用。
- 发给 LLM 的源码经过范围限制和 Secret 脱敏。

## 重构计划

代码按以下顺序演进，每个阶段都保持 `repo_scan` 和 `diff_scan` 可运行：

1. 重构 Pydantic Schema 与 `AuditState`，统一 ToolRunResult、Evidence 和 Finding 生命周期。
2. 重构 Project Reader、VulnKB Retriever 和 capability-based Audit Planner。
3. 建立 Tool Registry、Tool Selector、Tool Executor 和外部工具适配器。
4. 实现 Stage Scheduler 外循环与 Audit Reasoner 工具调用内循环。
5. 重构 finding 合并、批量风险复核、修复建议和多格式报告。
6. 升级 Streamlit 页面，展示实时阶段、工具调用、Evidence 和 Agent Trace。
7. 接入 SARIF、GitHub Action、PR Comment 和 MCP Adapter。

每个阶段完成后补齐单元测试、repo_scan 回归测试和 diff_scan 回归测试，避免架构重构破坏现有可运行链路。
