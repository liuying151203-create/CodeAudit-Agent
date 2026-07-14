---
id: path_traversal
risk_type: Path Traversal
languages: [Python, Java]
frameworks: [FastAPI, Flask, Django, Spring Boot, Spring MVC]
keywords: [path traversal, 路径穿越, upload, download, file]
capabilities: [scan_file_paths, extract_file_context]
---
# 路径穿越

## 适用场景

存在文件上传、下载、预览、模板加载、日志读取或用户输入参与路径拼接的项目。

## 危险代码模式

- 拼接 `../` 或 `..\\`。
- 直接 `open(user_input)`。
- 使用用户输入拼接文件路径。
- 下载接口未限制访问目录。

## 推荐检测工具

- custom_rule_scanner
- semgrep
- bandit

## 审计关注点

- 用户是否能控制文件名或路径。
- 是否做路径规范化。
- 最终路径是否被限制在允许目录下。
- 上传文件名是否被清洗。

## 修复建议

对路径做 `resolve` 规范化，并校验最终路径必须位于允许的 base directory 内。
