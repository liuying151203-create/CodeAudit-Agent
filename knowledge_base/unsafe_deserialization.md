# 不安全反序列化

## 适用场景

项目使用 pickle、yaml、marshal、Java serialization 或其他可执行对象反序列化机制。

## 危险代码模式

- `pickle.load(...)`
- `pickle.loads(...)`
- `yaml.load(...)` 未指定安全 Loader。
- 反序列化来自用户上传或网络输入的数据。

## 推荐检测工具

- custom_rule_scanner
- semgrep
- bandit

## 审计关注点

- 输入数据是否可信。
- 是否能被用户上传或篡改。
- 是否存在完整性校验。
- 是否可以改用 JSON 等安全格式。

## 修复建议

避免反序列化不可信数据。优先使用 JSON；YAML 使用 `safe_load`；必须使用 pickle 时加入签名校验和来源限制。
