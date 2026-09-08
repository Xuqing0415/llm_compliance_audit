# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 风格，版本号遵循 [SemVer](https://semver.org/lang/zh-CN/)。

## [v0.1.0] - 2026-09-08

首个公开版本。本版基于一轮完整源码安全审查（拦截先于泄露、鉴权可伪造、审计可篡改等），修复清单如下。

### 安全修复（拦截与绕过）

- **流式响应不再先泄露后拦截**：SSE 输出改为滑动窗口「先检测、干净才放行」，命中敏感内容先回终止帧再掐流（`internal/proxy/handler.go`）。
- **非流式响应先缓冲再下发**：响应整体缓冲→扫描→写回，命中即 403；新增 64MB 缓冲上限，超限返回 502 而不放行未审内容。
- **修复请求头伪造绕过链**：`X-Request-Purpose` / `X-Flow-Type` 不再被信任，purpose 仅由服务端按路径推导；`force_audit` 只对 export 类 purpose 生效。
- **转发修复**：上游转发用完整请求体（截断只作用于检测视图）；修复 `/v1/v1` 路径拼接；`max_request_body_size` 真正限制请求体（`http.MaxBytesReader`）；转发前剥离 hop-by-hop 头与 `Accept-Encoding`。
- **注入检测启用**：指纹规则改为任一特征命中即触发（原先 AND 语义使检测近似死代码）；`regex_rules` 配置被真正加载并可热重载；收紧命令注入正则，消除裸分号/`cat`/`curl` 误杀。

### 功能修复

- 移除 30s 服务端写超时与上游请求级 `Timeout`：长流式生成不再被网关掐断。
- 并行检测首命中即返回，并补记各检测器延迟（原先默认并行模式下延迟统计恒为 0）。
- 配置热重载生效：检测闭包按调用时读最新配置；文件 watcher 支持「先删后建」式保存（vim/IDE）并自动重建监听。
- `enable:false` 不再被 `binding:"required"` 拒绝：bypass / 规则开关可正常关闭。
- 磁盘占用保护实现真实统计（`golang.org/x/sys`，win/unix 双实现），85% 阈值不再形同虚设。
- `/metrics` 挂载到管理端口（9090），`metrics_port` 配置生效。

### 审计完整性

- 审计正文脱敏 + 截断：身份证/手机号/银行卡/邮箱打码后落盘，原文另存 SHA-256 摘要。
- 哈希链覆盖脱敏正文与原文摘要：修改正文会破坏链路。
- 日志缓冲满不再静默丢弃（同步写兜底）；`Close()` 排空缓冲、落盘未完成的流式会话。
- 审计日志写盘目录可配置（`SetLogDir`），测试不再污染仓库。

### 管理与部署

- 管理接口鉴权：配置 `server.admin_token` 后用 `X-Admin-Token` 访问；未配置则仅 loopback 可访问。
- 白名单增删持久化回 `configs/exemptions.yaml`（不再因配置文件重载丢失）。
- Docker Compose 挂载路径修正，镜像/Compose 可真实构建运行。
- Kubernetes：审计日志挂 PVC、`exemptions.yaml` 以 ConfigMap 挂载；文件型审计改为单副本部署（多副本需先接集中存储）。
- 依赖升级：`golang.org/x/net` → v0.23.0（修复 HTTP/2 已知漏洞）、`golang.org/x/crypto` → v0.21.0，新增 `golang.org/x/sys` v0.18.0。

### 已知限制

- tier2 PII / tier3 语义检测仍为占位实现（默认关闭）。
- Kafka / ClickHouse 等审计存储适配未实现，`file` 存储仅适合单实例。

## [0.0.1-pre] - 2026-08-23

未打 tag 的开发期基线：

- 完成网关骨架：config 热监听、tier1 正则 / tier2 / tier3 检测器、串并行流水线、SSE 流式窗口、审计日志哈希链初版、管理面 API、Docker/K8s 部署文件。
- 修复启动路由冲突 panic、审计按 trace_id 查不回（多行 JSON 解析）、流式 `Content-Length` 与 `chunked` 冲突导致拦截通知丢失三个缺陷。