---
id: broken_access_control
risk_type: Broken Access Control
languages: [Python, Java]
frameworks: [FastAPI, Flask, Django, Spring Boot, Spring MVC, Spring Security]
keywords: [access control, authorization, 访问控制, 权限, authentication]
capabilities: [inspect_access_control, extract_route_auth_context]
---
# 访问控制缺陷

## 适用场景

存在用户登录、角色权限、后台管理、租户隔离、对象级访问控制或路由权限装饰器的项目。

## 危险代码模式

- 路由缺少认证或授权检查。
- 只在前端控制权限。
- 用户可传入任意对象 ID 访问他人数据。
- 管理接口缺少角色校验。

## 推荐检测工具

- semgrep
- context_extractor

## 审计关注点

- 敏感路由是否有认证。
- 对象级权限是否校验所有权。
- 管理接口是否限制角色。
- 多租户数据是否按 tenant 隔离。

## 修复建议

在服务端统一做认证和授权校验。对对象访问增加所有权校验和最小权限控制。
