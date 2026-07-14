---
id: sql_injection
risk_type: SQL Injection
languages: [Python, Java]
frameworks: [FastAPI, Flask, Django, SQLAlchemy, Spring Boot, Spring MVC, MyBatis]
keywords: [SQL injection, SQL 注入, database, query, mapper]
capabilities: [scan_sql_patterns, extract_call_chain]
---
# SQL 注入

## 适用场景

存在数据库查询、ORM 原生 SQL、Mapper XML、字符串拼接查询或用户输入参与查询条件的项目。

## 危险代码模式

- 使用字符串拼接构造 SQL。
- 使用 f-string、`format` 或 `%` 拼接查询。
- Mapper XML 中直接拼接 `${}`。
- 将请求参数直接传入原生 SQL。

## 推荐检测工具

- custom_rule_scanner
- semgrep
- bandit

## 审计关注点

- 输入是否来自 HTTP 参数、表单、JSON 或路径变量。
- 是否使用参数化查询。
- ORM 是否退化为原生 SQL 拼接。
- 查询结果是否涉及敏感数据。

## 修复建议

使用参数化查询、ORM 安全查询 API 或预编译语句。禁止将用户输入直接拼接到 SQL 字符串中。
