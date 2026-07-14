---
id: secret_leak
risk_type: Secrets
languages: [Python, Java]
frameworks: []
keywords: [secret, credential, API key, 密钥, 凭据]
capabilities: [scan_secrets]
---
# Secrets 泄露

## 适用场景

项目包含 API key、Token、密码、私钥、数据库连接串、云服务凭据或第三方服务密钥。

## 危险代码模式

- `password = "..."`
- `api_key = "..."`
- `token = "..."`
- 私钥内容直接出现在源码中。
- 配置文件中包含生产密钥。

## 推荐检测工具

- secret_scanner
- custom_rule_scanner
- semgrep

## 审计关注点

- 值是否看起来像真实凭据。
- 是否是测试、示例或 placeholder。
- 凭据是否出现在 Git 历史或报告输出中。
- 泄露后是否需要轮换。

## 修复建议

将密钥放入环境变量、密钥管理系统或安全配置中心。发现真实泄露后立即轮换。
