---
id: command_injection
risk_type: Command Execution
languages: [Python, Java]
frameworks: [FastAPI, Flask, Django, Spring Boot, Spring MVC]
keywords: [command injection, 命令注入, shell, subprocess, Runtime.exec]
capabilities: [scan_command_execution, extract_call_chain]
---
# 命令注入

## 适用场景

项目中存在系统命令执行、脚本调用、压缩解压、文件转换、CI/CD 操作或运维自动化逻辑。

## 危险代码模式

- `os.system(user_input)`
- `subprocess.run(command, shell=True)`
- 将请求参数拼接进 shell 命令。
- 未限制命令参数和可执行文件路径。

## 推荐检测工具

- custom_rule_scanner
- semgrep
- bandit

## 审计关注点

- 命令字符串是否包含用户可控输入。
- 是否启用 `shell=True`。
- 是否对参数做白名单校验。
- 是否需要调用 shell，还是可以使用参数数组。

## 修复建议

避免 `shell=True`，使用参数列表调用 subprocess，并对用户输入做白名单校验。
