# CodeAudit-Agent 协作规范

本文档记录本项目中 Codex 协作时应遵守的项目约定。

## 提交信息规范

提交信息使用 Conventional Commits 风格，并在英文摘要后追加中文翻译。

格式：

```text
<type>(optional-scope): <English summary> / <中文翻译>
```

示例：

```text
feat: add configurable LLM integration / 新增可配置的 LLM 集成
fix(streamlit): resolve project import path / 修复 Streamlit 项目导入路径
docs: update API usage guide / 更新 API 使用说明
chore: ignore generated runtime files / 忽略运行时生成文件
```

常用 `type`：

- `feat`：新增功能
- `fix`：修复问题
- `docs`：文档变更
- `test`：测试相关变更
- `refactor`：重构，不改变外部行为
- `chore`：工程配置、依赖、构建或清理类变更

## 阶段性提交要求

每完成一个小阶段的代码改动或文档变动，都需要给出对应的规范提交命令。除非明确说明，否则不主动帮我提交，只给命令。

可以提前规划下一步要做什么，但不要在实际代码或文档改动完成前提前给出提交命令。提交命令只在该阶段改动完成、并完成必要检查后再给出。

提交命令格式：

```powershell
git add <changed-files>
git commit -m "<type>: <English summary> / <中文翻译>"
```

如果一个阶段同时包含代码和文档，应根据主要变更选择 `type`：

- 主要是功能：使用 `feat`
- 主要是修复：使用 `fix`
- 主要是文档：使用 `docs`
- 主要是配置或清理：使用 `chore`

## 提交前检查

提交前需要检查：

- 不提交 `.env`、API key、访问令牌或其他敏感信息。
- 不提交 `.venv/`、`__pycache__/`、`.pyc`、生成报告等运行时产物。
- 文档变更应保持中文为主。
- 能运行的情况下，先执行基础验证命令。

推荐检查命令：

```powershell
git status --short
python -m compileall app tests
```
